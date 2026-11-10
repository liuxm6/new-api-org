package controller

import (
	"github.com/QuantumNous/new-api/common"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// ListManagementKeys lists the organization's credentials, without secrets.
func ListManagementKeys(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	views, err := orgsvc.ListCredentials(orgContext(c), access.Org.Id)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, views)
}

// CreateManagementKey issues a credential. It needs a human session and a
// single-use proof bound to this exact grant; the plaintext is in this one
// response and nowhere else.
func CreateManagementKey(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "name", "kind", "scopes", "expires_at")
	if !ok {
		return
	}
	var input orgsvc.CreateCredentialInput
	for name, dst := range map[string]any{"name": &input.Name, "kind": &input.Kind, "scopes": &input.Scopes, "expires_at": &input.ExpiresAt} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
	}
	if !requireSensitive(c, types.SensitiveManagementKeyCreate, access.Org.Id,
		credentialGrantResource(input.Kind, input.Scopes, input.ExpiresAt)) {
		return
	}
	created, err := orgsvc.CreateCredential(orgContext(c), c.GetInt("id"), access.Org.Id, input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	common.ApiSuccess(c, gin.H{"credential": created.Credential, "token": created.Plaintext})
}

// RenameManagementKey changes the display name only.
func RenameManagementKey(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	id, ok := pathID(c, "mkid")
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "name")
	if !ok {
		return
	}
	var name string
	if present, err := orgField(fields, "name", &name); err != nil || !present {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	if err := orgsvc.RenameCredential(orgContext(c), c.GetInt("id"), access.Org.Id, id, name); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}

// RevokeManagementKey ends a credential; it needs a proof bound to that credential.
func RevokeManagementKey(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	id, ok := pathID(c, "mkid")
	if !ok {
		return
	}
	if !requireSensitive(c, types.SensitiveManagementKeyRevoke, access.Org.Id, credentialResource(id)) {
		return
	}
	if err := orgsvc.RevokeCredential(orgContext(c), c.GetInt("id"), access.Org.Id, id); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}

// ListScimMappings lists the organization's SCIM group mappings.
func ListScimMappings(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	views, err := orgsvc.ListMappings(orgContext(c), access.Org.Id)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, views)
}

// CreateScimMapping maps an IdP group to a workspace role.
func CreateScimMapping(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	input, ok := decodeMapping(c)
	if !ok {
		return
	}
	view, err := orgsvc.SaveMapping(orgContext(c), c.GetInt("id"), access.Org.Id, input.group, input.workspace, input.role)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, view)
}

// UpdateScimMapping retargets a mapping and moves its members.
func UpdateScimMapping(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	id, ok := pathID(c, "mid")
	if !ok {
		return
	}
	input, ok := decodeMapping(c)
	if !ok {
		return
	}
	view, err := orgsvc.UpdateMapping(orgContext(c), c.GetInt("id"), access.Org.Id, id, input.workspace, input.role)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, view)
}

// DeleteScimMapping removes a mapping and the grants it handed out.
func DeleteScimMapping(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	id, ok := pathID(c, "mid")
	if !ok {
		return
	}
	if err := orgsvc.DeleteMapping(orgContext(c), c.GetInt("id"), access.Org.Id, id); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}

type mappingInput struct {
	group     string
	workspace int
	role      string
}

func decodeMapping(c *gin.Context) (mappingInput, bool) {
	fields, ok := decodeOrgFields(c, "idp_group", "workspace_id", "ws_role")
	if !ok {
		return mappingInput{}, false
	}
	var input mappingInput
	for name, dst := range map[string]any{"idp_group": &input.group, "workspace_id": &input.workspace, "ws_role": &input.role} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return input, false
		}
	}
	return input, true
}

// GetOrgSSO shows the organization's SSO settings to its owner.
func GetOrgSSO(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	view, err := orgsvc.GetSSOConfig(orgContext(c), access.Org)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, view)
}

// UpdateOrgSSO creates or edits the organization's IdP. It needs a proof and
// cannot change the issuer once set.
func UpdateOrgSSO(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "issuer", "client_id", "client_secret", "scopes", "enabled", "jit_enabled", "default_workspace_id")
	if !ok {
		return
	}
	var input orgsvc.SSOConfigInput
	for name, dst := range map[string]any{"issuer": &input.Issuer, "client_id": &input.ClientID, "client_secret": &input.ClientSecret,
		"scopes": &input.Scopes, "enabled": &input.Enabled, "jit_enabled": &input.JITEnabled, "default_workspace_id": &input.DefaultWorkspaceID} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
	}
	if !requireSensitive(c, types.SensitiveSSOUpdate, access.Org.Id, ssoResource(access.Org.Id)) {
		return
	}
	view, err := orgsvc.UpdateSSOConfig(orgContext(c), c.GetInt("id"), access.Org.Id, input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, view)
}
