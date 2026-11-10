package controller

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// ListMyOrganizations returns the caller's organizations with role and seats.
func ListMyOrganizations(c *gin.Context) {
	list, err := orgsvc.ListOrganizations(orgContext(c), c.GetInt("id"))
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, list)
}

// CreateOrganization creates an organization owned by the caller. Only name and
// slug are accepted; plan, seats, billing group and status are platform fields.
func CreateOrganization(c *gin.Context) {
	fields, ok := decodeOrgFields(c, "name", "slug")
	if !ok {
		return
	}
	var input orgsvc.CreateOrganizationInput
	if _, err := orgField(fields, "name", &input.Name); err != nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	if _, err := orgField(fields, "slug", &input.Slug); err != nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	created, err := orgsvc.CreateOrganization(orgContext(c), c.GetInt("id"), input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{
		"organization":      newOrgView(&created.Org, types.OrgRoleOwner),
		"default_workspace": created.DefaultWorkspace,
	})
}

// GetOrganization returns the organization the caller belongs to.
func GetOrganization(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	common.ApiSuccess(c, newOrgView(access.Org, access.Member.Role))
}

// UpdateOrganization is the owner-only PATCH. Unknown fields are a 400.
func UpdateOrganization(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "name", "display_timezone")
	if !ok {
		return
	}
	var input orgsvc.UpdateOrganizationInput
	for name, dst := range map[string]**string{"name": &input.Name, "display_timezone": &input.DisplayTimezone} {
		var value string
		present, err := orgField(fields, name, &value)
		if err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
		if present {
			*dst = &value
		}
	}
	updated, err := orgsvc.UpdateOrganization(orgContext(c), c.GetInt("id"), access.Org.Id, input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, newOrgView(updated, types.OrgRoleOwner))
}

// TransferOrganizationOwnership hands the primary ownership to another member.
func TransferOrganizationOwnership(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "user_id")
	if !ok {
		return
	}
	var target int
	if present, err := orgField(fields, "user_id", &target); err != nil || !present || target <= 0 {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	if !requireSensitive(c, types.SensitiveOwnershipTransfer, access.Org.Id, ownershipResource(target)) {
		return
	}
	if err := orgsvc.TransferOwnership(orgContext(c), c.GetInt("id"), access.Org.Id, target); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"owner_user_id": target})
}

// memberView is the administrators' view of one member.
type memberView struct {
	UserId      int    `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Role        string `json:"role"`
	Status      int    `json:"status"`
	Source      string `json:"source"`
	JoinedAt    int64  `json:"joined_at"`
}

// ListOrganizationMembers lists members for organization owners and admins.
func ListOrganizationMembers(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	var members []model.OrganizationMember
	if err := model.DB.Where("org_id = ? AND status <> ?", access.Org.Id, types.OrgMemberStatusRemoved).
		Order("id").Limit(1000).Find(&members).Error; err != nil {
		respondOrgError(c, err)
		return
	}
	views := make([]memberView, 0, len(members))
	for _, member := range members {
		var user model.User
		if err := model.DB.Select("id", "username", "display_name", "email").Where("id = ?", member.UserId).
			Limit(1).Find(&user).Error; err != nil {
			respondOrgError(c, err)
			return
		}
		views = append(views, memberView{UserId: member.UserId, Username: user.Username, DisplayName: user.DisplayName,
			Email: user.Email, Role: member.Role, Status: member.Status, Source: member.Source, JoinedAt: member.JoinedAt})
	}
	common.ApiSuccess(c, views)
}
