package controller

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

func requestedWorkspace(c *gin.Context) (*orgsvc.WorkspaceAccess, bool) {
	access, ok := middleware.WorkspaceAccessFromContext(c)
	if !ok {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrWorkspaceNotFound))
	}
	return access, ok
}

// ListWorkspaces returns the workspaces the caller can see.
func ListWorkspaces(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	list, err := orgsvc.ListWorkspaces(orgContext(c), access.Org.Id, c.GetInt("id"), access.Member.Role)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, list)
}

// CreateWorkspace adds a workspace (owner or admin).
func CreateWorkspace(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "name", "slug")
	if !ok {
		return
	}
	var input orgsvc.CreateWorkspaceInput
	for name, dst := range map[string]*string{"name": &input.Name, "slug": &input.Slug} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
	}
	created, err := orgsvc.CreateWorkspace(orgContext(c), c.GetInt("id"), access.Org.Id, input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, created)
}

// GetWorkspace returns one workspace and the caller's effective role in it.
func GetWorkspace(c *gin.Context) {
	access, ok := requestedWorkspace(c)
	if !ok {
		return
	}
	common.ApiSuccess(c, gin.H{"workspace": access.Workspace, "my_role": access.Role, "implicit": access.Implicit})
}

// UpdateWorkspace renames a workspace; the slug cannot change.
func UpdateWorkspace(c *gin.Context) {
	access, ok := requestedWorkspace(c)
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
	if err := orgsvc.UpdateWorkspaceName(orgContext(c), c.GetInt("id"), access.Org.Id, access.Workspace.Id, name); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}

// workspaceUnderOrg resolves :ws inside the organization OrgAuth proved. Routes
// that must keep working on a suspended workspace (resume, delete) use it
// instead of WorkspaceAuth.
func workspaceUnderOrg(c *gin.Context) (*orgsvc.OrgAccess, *model.Workspace, bool) {
	access, ok := requestedOrg(c)
	if !ok {
		return nil, nil, false
	}
	workspace, err := model.GetWorkspaceByRef(model.DB.WithContext(c.Request.Context()), access.Org.Id, c.Param("ws"))
	if err != nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrWorkspaceNotFound))
		return nil, nil, false
	}
	return access, workspace, true
}

// DeleteWorkspace soft-deletes a non-default workspace (owner or admin).
func DeleteWorkspace(c *gin.Context) {
	access, workspace, ok := workspaceUnderOrg(c)
	if !ok {
		return
	}
	if err := orgsvc.DeleteWorkspace(orgContext(c), c.GetInt("id"), access.Org.Id, workspace.Id); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}

// SuspendWorkspace and ResumeWorkspace are parent-organization routes guarded
// by OrgAuth(owner, admin), so a suspended workspace can always be resumed from
// above.
func SuspendWorkspace(c *gin.Context) { setWorkspaceStatus(c, types.WorkspaceStatusSuspended) }
func ResumeWorkspace(c *gin.Context)  { setWorkspaceStatus(c, types.WorkspaceStatusActive) }

func setWorkspaceStatus(c *gin.Context, status int) {
	access, workspace, ok := workspaceUnderOrg(c)
	if !ok {
		return
	}
	if err := orgsvc.SetWorkspaceStatus(orgContext(c), c.GetInt("id"), access.Org.Id, workspace.Id, status); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"status": status})
}

// ListWorkspaceMembers lists people with access (workspace admins and auditors).
func ListWorkspaceMembers(c *gin.Context) {
	access, ok := requestedWorkspace(c)
	if !ok {
		return
	}
	list, err := orgsvc.ListWorkspaceMembers(orgContext(c), access.Org.Id, access.Workspace.Id)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, list)
}

// SetWorkspaceMember sets a person's manual workspace role (:uid is the user id).
func SetWorkspaceMember(c *gin.Context) {
	access, ok := requestedWorkspace(c)
	if !ok {
		return
	}
	userID, ok := pathID(c, "uid")
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "role")
	if !ok {
		return
	}
	var role string
	if present, err := orgField(fields, "role", &role); err != nil || !present {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	if err := orgsvc.SetWorkspaceMemberRole(orgContext(c), c.GetInt("id"), access.Org.Id, access.Workspace.Id, userID, role); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}

// RemoveWorkspaceMember withdraws a person's manual workspace grant.
func RemoveWorkspaceMember(c *gin.Context) {
	access, ok := requestedWorkspace(c)
	if !ok {
		return
	}
	userID, ok := pathID(c, "uid")
	if !ok {
		return
	}
	if err := orgsvc.RemoveWorkspaceMember(orgContext(c), c.GetInt("id"), access.Org.Id, access.Workspace.Id, userID); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}
