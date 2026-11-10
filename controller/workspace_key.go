package controller

import (
	"github.com/QuantumNous/new-api/common"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// Organization keys are managed only here. The generic /api/token endpoints
// cannot see or change them: they select by the signed-in person's user id and
// org_id = 0, and organization keys belong to the wallet. Everything about
// ownership (wallet, organization, workspace, creator, principal) is written by
// the service; the request body only chooses name, owner kind and limits.

func noStore(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
}

// ListWorkspaceKeys lists masked keys: all for admins and auditors, own for members.
func ListWorkspaceKeys(c *gin.Context) {
	access, ok := requestedWorkspace(c)
	if !ok {
		return
	}
	list, err := orgsvc.ListWorkspaceKeys(orgContext(c), access.Org.Id, access.Workspace.Id, c.GetInt("id"), access.Role)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	noStore(c)
	common.ApiSuccess(c, list)
}

// CreateWorkspaceKey creates a key and returns its plaintext once.
func CreateWorkspaceKey(c *gin.Context) {
	access, ok := requestedWorkspace(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "name", "owner", "quota_limit", "expired_time", "model_limits", "allow_ips")
	if !ok {
		return
	}
	var input orgsvc.CreateKeyInput
	for name, dst := range map[string]any{"name": &input.Name, "owner": &input.Owner, "quota_limit": &input.QuotaLimit,
		"expired_time": &input.ExpiredTime, "model_limits": &input.ModelLimits, "allow_ips": &input.AllowIps} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
	}
	issued, err := orgsvc.CreateWorkspaceKey(orgContext(c), c.GetInt("id"), access.Org.Id, access.Workspace.Id, input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	noStore(c)
	common.ApiSuccess(c, issued)
}

// UpdateWorkspaceKey edits name, status, expiry, model limits and IP allowlist.
func UpdateWorkspaceKey(c *gin.Context) {
	access, ok := requestedWorkspace(c)
	if !ok {
		return
	}
	keyID, ok := pathID(c, "kid")
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "name", "status", "expired_time", "model_limits", "allow_ips")
	if !ok {
		return
	}
	var input orgsvc.UpdateKeyInput
	// The input fields are pointers, so a field that is absent stays nil and a
	// present one is allocated by the decoder through the pointer-to-pointer.
	for name, dst := range map[string]any{"name": &input.Name, "status": &input.Status, "expired_time": &input.ExpiredTime,
		"model_limits": &input.ModelLimits, "allow_ips": &input.AllowIps} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
	}
	view, err := orgsvc.UpdateWorkspaceKey(orgContext(c), c.GetInt("id"), access.Org.Id, access.Workspace.Id, keyID, input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, view)
}

// DeleteWorkspaceKey soft-deletes a key.
func DeleteWorkspaceKey(c *gin.Context) {
	access, ok := requestedWorkspace(c)
	if !ok {
		return
	}
	keyID, ok := pathID(c, "kid")
	if !ok {
		return
	}
	if err := orgsvc.DeleteWorkspaceKey(orgContext(c), c.GetInt("id"), access.Org.Id, access.Workspace.Id, keyID); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}

// RotateWorkspaceKey replaces a key and returns the successor's plaintext once.
func RotateWorkspaceKey(c *gin.Context) {
	access, ok := requestedWorkspace(c)
	if !ok {
		return
	}
	keyID, ok := pathID(c, "kid")
	if !ok {
		return
	}
	issued, err := orgsvc.RotateWorkspaceKey(orgContext(c), c.GetInt("id"), access.Org.Id, access.Workspace.Id, keyID)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	noStore(c)
	common.ApiSuccess(c, issued)
}
