package org

import (
	"context"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// CreateWorkspaceInput is what a client may choose. The slug is immutable.
type CreateWorkspaceInput struct {
	Name string
	Slug string
}

// CreateWorkspace adds a workspace. Owners and admins only. The slug "default"
// belongs to the workspace generated with the organization.
func CreateWorkspace(ctx context.Context, actorID, orgID int, in CreateWorkspaceInput) (*model.Workspace, error) {
	var created model.Workspace
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		name, err := validateName(in.Name)
		if err != nil {
			return err
		}
		if err := ValidateSlug(in.Slug); err != nil {
			return err
		}
		var taken int64
		if err := tx.Unscoped().Model(&model.Workspace{}).Where("org_id = ? AND slug = ?", orgID, in.Slug).Count(&taken).Error; err != nil {
			return err
		}
		if taken > 0 {
			return refuse(types.OrgErrSlugTaken)
		}
		now := common.GetTimestamp()
		created = model.Workspace{OrgId: orgID, Slug: in.Slug, Name: name, Status: types.WorkspaceStatusActive, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&created).Error; err != nil {
			return err
		}
		if err := model.BumpOrgPolicyVersionTx(tx, orgID); err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, WorkspaceId: created.Id, ActorUserId: actorID,
			Action: "workspace.create", TargetType: "workspace", TargetId: in.Slug})
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, refuse(types.OrgErrSlugTaken)
		}
		return nil, err
	}
	return &created, nil
}

// RequireWorkspaceRoleTx proves, inside the transaction, the actor's role in a
// workspace and that it is one of roles (any role when empty). Organization
// owners and admins are implicit workspace admins; everyone else needs an
// active projected workspace role. A suspended workspace refuses with
// workspace_suspended unless allowSuspended is set (suspend, resume and delete
// use it). It returns the workspace row and the effective role.
func RequireWorkspaceRoleTx(tx *gorm.DB, orgID, workspaceID, actorID int, allowSuspended bool, roles ...string) (*model.Workspace, string, error) {
	_, member, err := RequireOrgRoleTx(tx, orgID, actorID)
	if err != nil {
		return nil, "", err
	}
	var rows []model.Workspace
	if err := tx.Where("id = ? AND org_id = ?", workspaceID, orgID).Limit(1).Find(&rows).Error; err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return nil, "", refuse(types.OrgErrWorkspaceNotFound)
	}
	role := types.WorkspaceRoleAdmin
	if !model.OrgRoleAtLeast(member.Role, types.OrgRoleAdmin) {
		projected, err := model.GetWorkspaceMember(tx, workspaceID, actorID)
		if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && projected.Status != model.WorkspaceMemberStatusActive) {
			return nil, "", refuse(types.OrgErrWorkspaceNotFound)
		}
		if err != nil {
			return nil, "", err
		}
		role = projected.Role
	}
	if rows[0].Status != types.WorkspaceStatusActive && !allowSuspended {
		return nil, "", refuse(types.OrgErrWorkspaceSuspended)
	}
	if !roleAllowed(role, roles) {
		return nil, "", refuse(types.OrgErrWorkspaceForbidden)
	}
	return &rows[0], role, nil
}

// RequireWorkspaceAdminTx is RequireWorkspaceRoleTx for the admin role.
func RequireWorkspaceAdminTx(tx *gorm.DB, orgID, workspaceID, actorID int, allowSuspended bool) (*model.Workspace, error) {
	workspace, _, err := RequireWorkspaceRoleTx(tx, orgID, workspaceID, actorID, allowSuspended, types.WorkspaceRoleAdmin)
	return workspace, err
}

// UpdateWorkspaceName renames a workspace. Workspace admins and organization
// owners and admins may.
func UpdateWorkspaceName(ctx context.Context, actorID, orgID, workspaceID int, name string) error {
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := RequireWorkspaceAdminTx(tx, orgID, workspaceID, actorID, false); err != nil {
			return err
		}
		name, err := validateName(name)
		if err != nil {
			return err
		}
		if err := tx.Model(&model.Workspace{}).Where("id = ? AND org_id = ?", workspaceID, orgID).
			Updates(map[string]any{"name": name, "updated_at": common.GetTimestamp()}).Error; err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, WorkspaceId: workspaceID, ActorUserId: actorID,
			Action: "workspace.update", TargetType: "workspace", TargetId: itoa(workspaceID)})
	})
}

// SetWorkspaceStatus suspends or resumes a workspace. It is a parent-
// organization action (owner or admin), so a suspended workspace can always be
// resumed from above. Keys are not touched: suspension is a state check, so
// resuming never revives a key that was disabled by hand or by a revocation.
func SetWorkspaceStatus(ctx context.Context, actorID, orgID, workspaceID, status int) error {
	if status != types.WorkspaceStatusActive && status != types.WorkspaceStatusSuspended {
		return refuse(types.OrgErrInvalidInput)
	}
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		if err := model.SetWorkspaceStatusTx(tx, orgID, workspaceID, status); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return refuse(types.OrgErrWorkspaceNotFound)
			}
			return err
		}
		action := "workspace.resume"
		if status == types.WorkspaceStatusSuspended {
			action = "workspace.suspend"
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, WorkspaceId: workspaceID, ActorUserId: actorID,
			Action: action, TargetType: "workspace", TargetId: itoa(workspaceID)})
	})
}
