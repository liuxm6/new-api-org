package model

import (
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// Workspace access has two tables with one writer. WorkspaceMemberGrant holds
// the facts (one row per source: manual, or each SCIM group). WorkspaceMember
// is the projection the request path reads. Only the functions in this file
// write WorkspaceMember, and every one of them runs inside the caller's
// transaction and advances the organization's policy_version.

const (
	WorkspaceMemberStatusActive  = 1
	WorkspaceMemberStatusRemoved = 3

	// GrantSourceManual is the source of grants made by people.
	GrantSourceManual = "manual"
	GrantSourceSCIM   = "scim"
)

// WorkspaceRoleRank orders workspace roles for "highest effective grant wins".
func WorkspaceRoleRank(role string) int {
	switch role {
	case types.WorkspaceRoleAdmin:
		return 3
	case types.WorkspaceRoleMember:
		return 2
	case types.WorkspaceRoleAuditor:
		return 1
	}
	return 0
}

// ValidWorkspaceRole reports whether role is one of the three workspace roles.
func ValidWorkspaceRole(role string) bool { return WorkspaceRoleRank(role) > 0 }

// ProjectWorkspaceMemberTx recomputes the effective role of one user in one
// workspace from the live grants and writes the projection row. With no grants
// the row is marked removed (kept for history, never deleted). It returns the
// effective role, "" when the user has none.
func ProjectWorkspaceMemberTx(tx *gorm.DB, orgID, workspaceID, userID int) (string, error) {
	var grants []WorkspaceMemberGrant
	if err := tx.Where("org_id = ? AND workspace_id = ? AND user_id = ?", orgID, workspaceID, userID).Find(&grants).Error; err != nil {
		return "", err
	}
	effective := ""
	for _, grant := range grants {
		if WorkspaceRoleRank(grant.Role) > WorkspaceRoleRank(effective) {
			effective = grant.Role
		}
	}
	now := common.GetTimestamp()
	var rows []WorkspaceMember
	if err := tx.Where("workspace_id = ? AND user_id = ?", workspaceID, userID).Limit(1).Find(&rows).Error; err != nil {
		return "", err
	}
	if len(rows) == 0 {
		if effective == "" {
			return "", nil
		}
		return effective, tx.Create(&WorkspaceMember{WorkspaceId: workspaceID, OrgId: orgID, UserId: userID,
			Role: effective, Status: WorkspaceMemberStatusActive, CreatedAt: now, UpdatedAt: now}).Error
	}
	updates := map[string]any{"updated_at": now}
	if effective == "" {
		updates["status"] = WorkspaceMemberStatusRemoved
	} else {
		updates["role"], updates["status"] = effective, WorkspaceMemberStatusActive
	}
	return effective, tx.Model(&WorkspaceMember{}).Where("id = ?", rows[0].Id).Updates(updates).Error
}

// UpsertWorkspaceGrantTx creates or updates one grant and reprojects. Every
// workspace member must be an active organization member and the workspace
// must belong to the organization, so a grant can neither outlive membership
// nor cross organizations. It returns the effective role after the change.
func UpsertWorkspaceGrantTx(tx *gorm.DB, orgID, workspaceID, userID int, source, sourceRef, role string) (string, error) {
	if !ValidWorkspaceRole(role) || source == "" {
		return "", types.NewOrgAccessError(types.OrgErrInvalidInput)
	}
	var workspaceCount int64
	if err := tx.Model(&Workspace{}).Where("id = ? AND org_id = ?", workspaceID, orgID).Count(&workspaceCount).Error; err != nil {
		return "", err
	}
	if workspaceCount == 0 {
		return "", types.NewOrgAccessError(types.OrgErrWorkspaceNotFound)
	}
	member, err := GetOrganizationMember(tx, orgID, userID)
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && member.Status != types.OrgMemberStatusActive) {
		return "", types.NewOrgAccessError(types.OrgErrMemberNotFound)
	}
	if err != nil {
		return "", err
	}
	now := common.GetTimestamp()
	var existing []WorkspaceMemberGrant
	if err := tx.Where("org_id = ? AND workspace_id = ? AND user_id = ? AND source = ? AND source_ref = ?",
		orgID, workspaceID, userID, source, sourceRef).Limit(1).Find(&existing).Error; err != nil {
		return "", err
	}
	if len(existing) == 0 {
		err = tx.Create(&WorkspaceMemberGrant{OrgId: orgID, WorkspaceId: workspaceID, UserId: userID,
			Source: source, SourceRef: sourceRef, Role: role, CreatedAt: now, UpdatedAt: now}).Error
	} else {
		err = tx.Model(&WorkspaceMemberGrant{}).Where("id = ?", existing[0].Id).
			Updates(map[string]any{"role": role, "updated_at": now}).Error
	}
	if err != nil {
		return "", err
	}
	effective, err := ProjectWorkspaceMemberTx(tx, orgID, workspaceID, userID)
	if err != nil {
		return "", err
	}
	return effective, BumpOrgPolicyVersionTx(tx, orgID)
}

// DeleteWorkspaceGrantsTx removes the grants of one source (sourceRef "" with
// matchAnyRef = false removes the manual grant) and reprojects. Grants from
// other sources are untouched, so revoking one SCIM group never erases a
// manual grant. It returns the effective role that remains.
func DeleteWorkspaceGrantsTx(tx *gorm.DB, orgID, workspaceID, userID int, source, sourceRef string) (string, error) {
	if err := tx.Where("org_id = ? AND workspace_id = ? AND user_id = ? AND source = ? AND source_ref = ?",
		orgID, workspaceID, userID, source, sourceRef).Delete(&WorkspaceMemberGrant{}).Error; err != nil {
		return "", err
	}
	effective, err := ProjectWorkspaceMemberTx(tx, orgID, workspaceID, userID)
	if err != nil {
		return "", err
	}
	return effective, BumpOrgPolicyVersionTx(tx, orgID)
}

// DeleteAllWorkspaceGrantsOfUserTx removes every grant a user holds in an
// organization (all workspaces, all sources) and marks the projections
// removed. It is used when the person leaves the organization.
func DeleteAllWorkspaceGrantsOfUserTx(tx *gorm.DB, orgID, userID int) error {
	if err := tx.Where("org_id = ? AND user_id = ?", orgID, userID).Delete(&WorkspaceMemberGrant{}).Error; err != nil {
		return err
	}
	return tx.Model(&WorkspaceMember{}).Where("org_id = ? AND user_id = ?", orgID, userID).
		Updates(map[string]any{"status": WorkspaceMemberStatusRemoved, "updated_at": common.GetTimestamp()}).Error
}
