package controller

import (
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/setting/system_setting"

	"github.com/gin-gonic/gin"
)

const (
	scimUserSchema   = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimContentType  = "application/scim+json"
	scimBodyLimit    = 1 << 20
	scimDefaultCount = 100
)

func scimFail(c *gin.Context, err error) {
	scim := orgsvc.AsScimError(err)
	middleware.WriteScimError(c, scim.Status, scim.ScimType, scim.Detail)
}

func scimOK(c *gin.Context, status int, body any) {
	c.Header("Content-Type", scimContentType)
	c.Header("Cache-Control", "no-store")
	c.JSON(status, body)
}

func scimBody(c *gin.Context, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, scimBodyLimit))
	if err == nil {
		err = common.Unmarshal(raw, dst)
	}
	if err != nil {
		middleware.WriteScimError(c, http.StatusBadRequest, "invalidSyntax", "The request body is not valid JSON")
		return false
	}
	return true
}

func scimTime(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }

func scimLocation(c *gin.Context, resource string, id int) string {
	return strings.TrimRight(system_setting.ServerAddress, "/") + "/scim/v2/" + resource + "/" + strconv.Itoa(id)
}

func scimUserResource(c *gin.Context, view orgsvc.ScimUserView) gin.H {
	resource := gin.H{
		"schemas": []string{scimUserSchema}, "id": strconv.Itoa(view.ID), "userName": view.UserName,
		"displayName": view.DisplayName, "active": view.Active,
		"meta": gin.H{"resourceType": "User", "created": scimTime(view.Created), "lastModified": scimTime(view.Modified),
			"location": scimLocation(c, "Users", view.ID)},
	}
	if view.ExternalID != "" {
		resource["externalId"] = view.ExternalID
	}
	return resource
}

func scimGroupResource(c *gin.Context, view orgsvc.ScimGroupView) gin.H {
	members := make([]gin.H, 0, len(view.Members))
	for _, id := range view.Members {
		members = append(members, gin.H{"value": strconv.Itoa(id), "$ref": scimLocation(c, "Users", id)})
	}
	return gin.H{"schemas": []string{scimGroupSchema}, "id": strconv.Itoa(view.ID), "displayName": view.DisplayName,
		"members": members, "meta": gin.H{"resourceType": "Group", "location": scimLocation(c, "Groups", view.ID)}}
}

func scimID(c *gin.Context) (int, bool) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		middleware.WriteScimError(c, http.StatusNotFound, "", "Resource not found")
		return 0, false
	}
	return id, true
}

type scimUserRequest struct {
	UserName    string `json:"userName"`
	ExternalID  string `json:"externalId"`
	DisplayName string `json:"displayName"`
	Name        struct {
		Formatted string `json:"formatted"`
	} `json:"name"`
	Active   *bool `json:"active"`
	Identity struct {
		OIDCSub string `json:"oidcSub"`
	} `json:"urn:ietf:params:scim:schemas:extension:newapi:2.0:Identity"`
}

// ScimCreateUser handles POST /scim/v2/Users.
func ScimCreateUser(c *gin.Context) {
	var request scimUserRequest
	if !scimBody(c, &request) {
		return
	}
	input := orgsvc.ScimUserInput{UserName: request.UserName, ExternalID: request.ExternalID, OIDCSub: request.Identity.OIDCSub,
		DisplayName: request.DisplayName, Active: request.Active == nil || *request.Active}
	if input.DisplayName == "" {
		input.DisplayName = request.Name.Formatted
	}
	view, created, err := orgsvc.CreateScimUser(orgContext(c), middleware.ScimOrgID(c), input)
	if err != nil {
		scimFail(c, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		c.Header("Location", scimLocation(c, "Users", view.ID))
	}
	scimOK(c, status, scimUserResource(c, view))
}

// ScimGetUser handles GET /scim/v2/Users/:id.
func ScimGetUser(c *gin.Context) {
	id, ok := scimID(c)
	if !ok {
		return
	}
	view, err := orgsvc.GetScimUser(orgContext(c), middleware.ScimOrgID(c), id)
	if err != nil {
		scimFail(c, err)
		return
	}
	scimOK(c, http.StatusOK, scimUserResource(c, view))
}

func scimPaging(c *gin.Context) (start, count int, ok bool) {
	start, count = 1, scimDefaultCount
	for name, dst := range map[string]*int{"startIndex": &start, "count": &count} {
		if raw := c.Query(name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil {
				middleware.WriteScimError(c, http.StatusBadRequest, "invalidValue", name+" must be a number")
				return 0, 0, false
			}
			*dst = value
		}
	}
	return start, count, true
}

// ScimListUsers handles GET /scim/v2/Users.
func ScimListUsers(c *gin.Context) {
	start, count, ok := scimPaging(c)
	if !ok {
		return
	}
	views, total, err := orgsvc.ListScimUsers(orgContext(c), middleware.ScimOrgID(c), c.Query("filter"), start, count)
	if err != nil {
		scimFail(c, err)
		return
	}
	resources := make([]gin.H, 0, len(views))
	for _, view := range views {
		resources = append(resources, scimUserResource(c, view))
	}
	scimOK(c, http.StatusOK, gin.H{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": max(start, 1),
		"itemsPerPage": len(resources), "Resources": resources})
}

type scimPatchRequest struct {
	Operations []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	} `json:"Operations"`
}

// ScimPatchUser handles PATCH /scim/v2/Users/:id.
func ScimPatchUser(c *gin.Context) {
	id, ok := scimID(c)
	if !ok {
		return
	}
	var request scimPatchRequest
	if !scimBody(c, &request) {
		return
	}
	ops := make([]orgsvc.ScimPatchOp, 0, len(request.Operations))
	for _, op := range request.Operations {
		ops = append(ops, orgsvc.ScimPatchOp{Op: op.Op, Path: op.Path, Value: op.Value})
	}
	changes, err := orgsvc.ParseScimPatch(ops)
	if err != nil {
		scimFail(c, err)
		return
	}
	view, err := orgsvc.PatchScimUser(orgContext(c), middleware.ScimOrgID(c), id, changes)
	if err != nil {
		scimFail(c, err)
		return
	}
	scimOK(c, http.StatusOK, scimUserResource(c, view))
}

// ScimDeleteUser handles DELETE /scim/v2/Users/:id.
func ScimDeleteUser(c *gin.Context) {
	id, ok := scimID(c)
	if !ok {
		return
	}
	if err := orgsvc.DeleteScimUser(orgContext(c), middleware.ScimOrgID(c), id); err != nil {
		scimFail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

type scimGroupRequest struct {
	DisplayName string `json:"displayName"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

func scimMemberIDs(c *gin.Context, values []string) ([]int, bool) {
	ids := make([]int, 0, len(values))
	for _, value := range values {
		id, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || id <= 0 {
			middleware.WriteScimError(c, http.StatusBadRequest, "invalidValue", "Unknown group member")
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

// ScimCreateGroup handles POST /scim/v2/Groups.
func ScimCreateGroup(c *gin.Context) {
	var request scimGroupRequest
	if !scimBody(c, &request) {
		return
	}
	values := make([]string, 0, len(request.Members))
	for _, member := range request.Members {
		values = append(values, member.Value)
	}
	ids, ok := scimMemberIDs(c, values)
	if !ok {
		return
	}
	view, err := orgsvc.CreateScimGroup(orgContext(c), middleware.ScimOrgID(c), request.DisplayName, ids)
	if err != nil {
		scimFail(c, err)
		return
	}
	c.Header("Location", scimLocation(c, "Groups", view.ID))
	scimOK(c, http.StatusCreated, scimGroupResource(c, view))
}

// ScimGetGroup handles GET /scim/v2/Groups/:id.
func ScimGetGroup(c *gin.Context) {
	id, ok := scimID(c)
	if !ok {
		return
	}
	view, err := orgsvc.GetScimGroup(orgContext(c), middleware.ScimOrgID(c), id)
	if err != nil {
		scimFail(c, err)
		return
	}
	scimOK(c, http.StatusOK, scimGroupResource(c, view))
}

// ScimListGroups handles GET /scim/v2/Groups.
func ScimListGroups(c *gin.Context) {
	start, count, ok := scimPaging(c)
	if !ok {
		return
	}
	views, total, err := orgsvc.ListScimGroups(orgContext(c), middleware.ScimOrgID(c), c.Query("filter"), start, count)
	if err != nil {
		scimFail(c, err)
		return
	}
	resources := make([]gin.H, 0, len(views))
	for _, view := range views {
		resources = append(resources, scimGroupResource(c, view))
	}
	scimOK(c, http.StatusOK, gin.H{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": max(start, 1),
		"itemsPerPage": len(resources), "Resources": resources})
}

// ScimReplaceGroup handles PUT /scim/v2/Groups/:id: the member list becomes exactly the given one.
func ScimReplaceGroup(c *gin.Context) {
	id, ok := scimID(c)
	if !ok {
		return
	}
	var request scimGroupRequest
	if !scimBody(c, &request) {
		return
	}
	values := make([]string, 0, len(request.Members))
	for _, member := range request.Members {
		values = append(values, member.Value)
	}
	ids, ok := scimMemberIDs(c, values)
	if !ok {
		return
	}
	view, err := orgsvc.ReplaceScimGroupMembers(orgContext(c), middleware.ScimOrgID(c), id, ids)
	if err != nil {
		scimFail(c, err)
		return
	}
	scimOK(c, http.StatusOK, scimGroupResource(c, view))
}

var scimMemberPath = regexp.MustCompile(`^members\[value\s+eq\s+"(\d+)"\]$`)

// ScimPatchGroup handles PATCH /scim/v2/Groups/:id (members add/remove/replace).
func ScimPatchGroup(c *gin.Context) {
	id, ok := scimID(c)
	if !ok {
		return
	}
	var request scimPatchRequest
	if !scimBody(c, &request) {
		return
	}
	changes := make([]orgsvc.ScimGroupChange, 0, len(request.Operations))
	for _, op := range request.Operations {
		change := orgsvc.ScimGroupChange{Op: strings.ToLower(op.Op)}
		var values []string
		switch match := scimMemberPath.FindStringSubmatch(op.Path); {
		case match != nil:
			values = []string{match[1]}
		case strings.EqualFold(op.Path, "members"):
			items, _ := op.Value.([]any)
			for _, item := range items {
				if object, ok := item.(map[string]any); ok {
					if value, ok := object["value"].(string); ok {
						values = append(values, value)
					}
				}
			}
		default:
			middleware.WriteScimError(c, http.StatusBadRequest, "invalidPath", "Only members can be patched")
			return
		}
		ids, ok := scimMemberIDs(c, values)
		if !ok {
			return
		}
		change.Members = ids
		changes = append(changes, change)
	}
	view, err := orgsvc.PatchScimGroup(orgContext(c), middleware.ScimOrgID(c), id, changes)
	if err != nil {
		scimFail(c, err)
		return
	}
	scimOK(c, http.StatusOK, scimGroupResource(c, view))
}

// ScimDeleteGroup handles DELETE /scim/v2/Groups/:id.
func ScimDeleteGroup(c *gin.Context) {
	id, ok := scimID(c)
	if !ok {
		return
	}
	if err := orgsvc.DeleteScimGroup(orgContext(c), middleware.ScimOrgID(c), id); err != nil {
		scimFail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ScimServiceProviderConfig handles GET /scim/v2/ServiceProviderConfig.
func ScimServiceProviderConfig(c *gin.Context) {
	scimOK(c, http.StatusOK, gin.H{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          gin.H{"supported": true},
		"bulk":           gin.H{"supported": false},
		"filter":         gin.H{"supported": true, "maxResults": orgsvc.ScimPageMax},
		"changePassword": gin.H{"supported": false},
		"sort":           gin.H{"supported": false},
		"etag":           gin.H{"supported": false},
		"authenticationSchemes": []gin.H{{"type": "oauthbearertoken", "name": "Bearer token",
			"description": "A scim_service credential of the organization"}},
	})
}
