package org

import (
	"context"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// ApplyGrantTx adds or changes one workspace grant of one source and, in the
// same transaction, reprojects the effective role, advances policy_version,
// disables the member keys the new standing no longer justifies and writes the
// audit row. It is the one entry point for every grant source: the manual
// calls below, and SCIM group mappings (source "scim", sourceRef = the group).
// Callers authorize before calling; actorID 0 records a system actor.
// The returned revocation must be Published after the transaction commits.
func ApplyGrantTx(tx *gorm.DB, orgID, workspaceID, userID int, source, sourceRef, role string, actorID int) (*model.KeyRevocation, error) {
	if _, err := model.UpsertWorkspaceGrantTx(tx, orgID, workspaceID, userID, source, sourceRef, role); err != nil {
		return nil, err
	}
	return finishGrantChange(tx, orgID, workspaceID, userID, actorID, "workspace.grant", source, sourceRef, role)
}

// RevokeGrantTx removes the grant of one source only. Grants of other sources,
// including a manual one, are untouched, so ending one SCIM group membership
// can never erase another source's access.
func RevokeGrantTx(tx *gorm.DB, orgID, workspaceID, userID int, source, sourceRef string, actorID int) (*model.KeyRevocation, error) {
	if _, err := model.DeleteWorkspaceGrantsTx(tx, orgID, workspaceID, userID, source, sourceRef); err != nil {
		return nil, err
	}
	return finishGrantChange(tx, orgID, workspaceID, userID, actorID, "workspace.revoke", source, sourceRef, "")
}

func finishGrantChange(tx *gorm.DB, orgID, workspaceID, userID, actorID int, action, source, ref, role string) (*model.KeyRevocation, error) {
	revocation, err := ReconcileMemberKeysTx(tx, orgID, userID, "workspace_grant_changed")
	if err != nil {
		return nil, err
	}
	actorKind := "user"
	if actorID == 0 {
		actorKind = "system"
	}
	err = model.RecordOrgAuditTx(tx, model.OrgAuditEntry{OrgId: orgID, WorkspaceId: workspaceID, ActorUserId: actorID, ActorKind: actorKind,
		Action: action, TargetType: "member", TargetId: itoa(userID), Detail: map[string]any{"source": source, "source_ref": ref, "role": role}})
	return revocation, err
}

// SetWorkspaceMemberRole sets a person's manual workspace role. Workspace
// admins and organization owners and admins may; the person must already be an
// active organization member. Other sources' grants stay in force, so the
// effective role can still be higher than the one set here.
func SetWorkspaceMemberRole(ctx context.Context, actorID, orgID, workspaceID, userID int, role string) error {
	var revocation *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := RequireWorkspaceAdminTx(tx, orgID, workspaceID, actorID, false); err != nil {
			return err
		}
		var err error
		revocation, err = ApplyGrantTx(tx, orgID, workspaceID, userID, model.GrantSourceManual, "", role, actorID)
		return err
	})
	if err != nil {
		return err
	}
	revocation.Publish()
	return nil
}

// RemoveWorkspaceMember withdraws the manual workspace grant. Access granted
// by other sources (for example a SCIM group) remains until that source ends.
func RemoveWorkspaceMember(ctx context.Context, actorID, orgID, workspaceID, userID int) error {
	var revocation *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := RequireWorkspaceAdminTx(tx, orgID, workspaceID, actorID, false); err != nil {
			return err
		}
		var err error
		revocation, err = RevokeGrantTx(tx, orgID, workspaceID, userID, model.GrantSourceManual, "", actorID)
		return err
	})
	if err != nil {
		return err
	}
	revocation.Publish()
	return nil
}

// WorkspaceMemberView is one row of a workspace's member list.
type WorkspaceMemberView struct {
	UserId      int    `json:"user_id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	// Sources lists where the access comes from ("manual", "scim:<group>").
	Sources []string `json:"sources"`
}

// ListWorkspaceMembers returns the people with active access to a workspace.
func ListWorkspaceMembers(ctx context.Context, orgID, workspaceID int) ([]WorkspaceMemberView, error) {
	db := model.DB.WithContext(ctx)
	var rows []model.WorkspaceMember
	if err := db.Where("workspace_id = ? AND org_id = ? AND status = ?", workspaceID, orgID, model.WorkspaceMemberStatusActive).
		Order("user_id").Limit(1000).Find(&rows).Error; err != nil {
		return nil, err
	}
	views := make([]WorkspaceMemberView, 0, len(rows))
	for _, row := range rows {
		var user model.User
		if err := db.Select("id", "username", "display_name").Where("id = ?", row.UserId).Limit(1).Find(&user).Error; err != nil {
			return nil, err
		}
		var grants []model.WorkspaceMemberGrant
		if err := db.Where("workspace_id = ? AND user_id = ?", workspaceID, row.UserId).Find(&grants).Error; err != nil {
			return nil, err
		}
		view := WorkspaceMemberView{UserId: row.UserId, Username: user.Username, DisplayName: user.DisplayName, Role: row.Role}
		for _, grant := range grants {
			label := grant.Source
			if grant.SourceRef != "" {
				label += ":" + grant.SourceRef
			}
			view.Sources = append(view.Sources, label)
		}
		views = append(views, view)
	}
	return views, nil
}

// ListWorkspaces returns the workspaces a person can see: all of them for
// organization owners and admins, otherwise those where they hold a role.
func ListWorkspaces(ctx context.Context, orgID, userID int, orgRole string) ([]model.Workspace, error) {
	db := model.DB.WithContext(ctx)
	query := db.Where("org_id = ?", orgID).Order("id")
	if !model.OrgRoleAtLeast(orgRole, types.OrgRoleAdmin) {
		query = query.Where("id IN (?)", db.Model(&model.WorkspaceMember{}).Select("workspace_id").
			Where("org_id = ? AND user_id = ? AND status = ?", orgID, userID, model.WorkspaceMemberStatusActive))
	}
	var workspaces []model.Workspace
	return workspaces, query.Find(&workspaces).Error
}
