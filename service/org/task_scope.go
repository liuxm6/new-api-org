package org

import (
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
)

// TaskScopeForWorkspaceAccess turns a human's proven workspace standing into
// the tasks they may read: organization owners and admins (implicit workspace
// admins) and workspace admins and auditors read the whole workspace, a plain
// workspace member reads only their own. The organization billing role grants
// nothing here: financial summaries are not task or artifact access, and a
// billing member without a workspace role never reaches this function.
func TaskScopeForWorkspaceAccess(access *WorkspaceAccess, userID int) model.TaskScope {
	if access == nil || access.Org == nil || access.Workspace == nil {
		return model.TaskScope{}
	}
	switch access.Role {
	case types.WorkspaceRoleAdmin, types.WorkspaceRoleAuditor:
		return model.WorkspaceTaskScope(access.Org.Id, access.Workspace.Id)
	case types.WorkspaceRoleMember:
		return model.WorkspaceSelfTaskScope(access.Org.Id, access.Workspace.Id, userID)
	}
	return model.TaskScope{}
}
