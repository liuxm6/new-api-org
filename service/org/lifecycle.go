package org

import (
	"context"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// lockedTarget locks the membership a write is about to change. A removed or
// missing member is "not found".
func lockedTarget(tx *gorm.DB, orgID, userID int) (*model.OrganizationMember, error) {
	target, err := model.LockOrganizationMemberTx(tx, orgID, userID)
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && target.Status == types.OrgMemberStatusRemoved) {
		return nil, refuse(types.OrgErrMemberNotFound)
	}
	return target, err
}

// SetMemberStatus suspends or reactivates a member. Suspension disables every
// member key and personal management credential the person holds in the
// organization in the same transaction; reactivation restores the membership
// but never a key, so a person who comes back creates new ones. The owner
// rules of GuardOwnerChangeTx apply: the last owner cannot be suspended.
func SetMemberStatus(ctx context.Context, actorID, orgID, userID, status int) error {
	if status != types.OrgMemberStatusActive && status != types.OrgMemberStatusSuspended {
		return refuse(types.OrgErrInvalidInput)
	}
	var revocation *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, actor, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin)
		if err != nil {
			return err
		}
		target, err := lockedTarget(tx, orgID, userID)
		if err != nil {
			return err
		}
		if target.Status == status {
			return nil
		}
		newRole := target.Role
		if status == types.OrgMemberStatusSuspended {
			newRole = "" // leaving duty, like a removal
		}
		if err := GuardOwnerChangeTx(tx, org, actor, target, newRole); err != nil {
			return err
		}
		if err := model.SetOrganizationMemberStatusTx(tx, orgID, userID, status); err != nil {
			return err
		}
		action := "member.reactivate"
		if status == types.OrgMemberStatusSuspended {
			action = "member.suspend"
			if revocation, err = ReconcileMemberKeysTx(tx, orgID, userID, "member_suspended"); err != nil {
				return err
			}
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: action,
			TargetType: "member", TargetId: itoa(userID)})
	})
	if err != nil {
		return err
	}
	revocation.Publish()
	if status == types.OrgMemberStatusSuspended {
		endOrgSessions(userID, orgID, "member_suspended")
	}
	return nil
}

// RemoveMember ends a membership: the member's keys and credentials are
// disabled, every workspace grant of every source is dropped, and the seat is
// freed. A member may always remove themselves; removing anyone else needs
// owner or admin. Owner protection applies as for role changes.
func RemoveMember(ctx context.Context, actorID, orgID, userID int) error {
	// A management credential acts as a capped administrator. Letting it end its
	// own creator's membership would sidestep the owner guard, which reads the
	// capped role of the actor.
	if _, viaCredential := managementCredentialFrom(ctx); viaCredential && actorID == userID {
		return refuse(types.OrgErrForbidden)
	}
	var revocation *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		roles := []string{types.OrgRoleOwner, types.OrgRoleAdmin}
		if actorID == userID {
			roles = nil
		}
		org, actor, err := RequireOrgRoleTx(tx, orgID, actorID, roles...)
		if err != nil {
			return err
		}
		target := actor
		if actorID != userID {
			if target, err = lockedTarget(tx, orgID, userID); err != nil {
				return err
			}
		}
		if err := GuardOwnerChangeTx(tx, org, actor, target, ""); err != nil {
			return err
		}
		if err := model.SetOrganizationMemberStatusTx(tx, orgID, userID, types.OrgMemberStatusRemoved); err != nil {
			return err
		}
		if err := model.DeleteAllWorkspaceGrantsOfUserTx(tx, orgID, userID); err != nil {
			return err
		}
		if revocation, err = ReconcileMemberKeysTx(tx, orgID, userID, "member_removed"); err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "member.remove",
			TargetType: "member", TargetId: itoa(userID)})
	})
	if err != nil {
		return err
	}
	revocation.Publish()
	endOrgSessions(userID, orgID, "member_removed")
	return nil
}

// SetOrganizationStatus suspends or resumes an organization. It is a platform
// action: there is no organization role check here, the caller must already
// have proved platform authority (Task 16 adds that route). A suspended
// organization refuses inference, tenant control-plane calls and downloads,
// while accepted tasks, settlement, refunds and payments continue. Keys are
// not touched, so resuming never revives a disabled key.
func SetOrganizationStatus(ctx context.Context, orgID, status, platformActorID int, reason string) error {
	if status != types.OrgStatusActive && status != types.OrgStatusSuspended {
		return refuse(types.OrgErrInvalidInput)
	}
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, err := model.LockOrganizationTx(tx, orgID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return refuse(types.OrgErrNotFound)
		}
		if err != nil {
			return err
		}
		if org.Status == status {
			return nil
		}
		if err := model.SetOrganizationStatusTx(tx, orgID, status); err != nil {
			return err
		}
		action := "org.resume"
		if status == types.OrgStatusSuspended {
			action = "org.suspend"
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: platformActorID, ActorKind: "platform",
			Action: action, TargetType: "organization", TargetId: org.Slug, Detail: map[string]any{"reason": reason}})
	})
}

// DeleteBlockedError is the 409 org_delete_blocked refusal with its reasons.
type DeleteBlockedError struct{ Reasons []string }

func (e *DeleteBlockedError) Error() string { return types.OrgErrDeleteBlocked }

// Unwrap lets errors.As find the structured refusal behind it.
func (e *DeleteBlockedError) Unwrap() error {
	return types.NewOrgAccessError(types.OrgErrDeleteBlocked)
}

// DeleteOrganization soft-deletes an organization. The owner must type the slug
// back, and nothing may still tie money or work to it (OrgDeleteBlockersTx):
// positive balance can only be cleared by the platform. The rows stay: the
// slug is never reused, the wallet and every financial fact remain for
// background settlement, refunds and statements. Keys and credentials are
// disabled and invitations revoked.
func DeleteOrganization(ctx context.Context, actorID, orgID int, confirmSlug string) error {
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner)
		if err != nil {
			return err
		}
		if confirmSlug == "" || confirmSlug != org.Slug {
			return refuse(types.OrgErrInvalidInput)
		}
		blockers, err := model.OrgDeleteBlockersTx(tx, org)
		if err != nil {
			return err
		}
		if len(blockers) > 0 {
			return &DeleteBlockedError{Reasons: blockers}
		}
		if _, err := model.DisableOrgKeysTx(tx, model.OrgKeyScope{OrgID: orgID}); err != nil {
			return err
		}
		if err := tx.Model(&model.OrgAccessToken{}).Where("org_id = ? AND status = ?", orgID, 1).
			Updates(map[string]any{"status": 2, "updated_at": common.GetTimestamp()}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Invite{}).Where("org_id = ? AND status = ?", orgID, types.InviteStatusPending).
			Update("status", types.InviteStatusRevoked).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Workspace{}).Where("org_id = ?", orgID).Update("status", types.WorkspaceStatusDeleted).Error; err != nil {
			return err
		}
		if err := tx.Where("org_id = ?", orgID).Delete(&model.Workspace{}).Error; err != nil {
			return err
		}
		if err := model.SetOrganizationStatusTx(tx, orgID, types.OrgStatusDeleted); err != nil {
			return err
		}
		if err := tx.Delete(&model.Organization{}, orgID).Error; err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "org.delete",
			TargetType: "organization", TargetId: org.Slug})
	})
}

// DeleteWorkspace soft-deletes a workspace: its keys are disabled, pending
// invitations revoked and the slug stays taken. The default workspace cannot
// be deleted. Work accepted earlier keeps settling.
func DeleteWorkspace(ctx context.Context, actorID, orgID, workspaceID int) error {
	var revocation *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		workspace, err := RequireWorkspaceAdminTx(tx, orgID, workspaceID, actorID, true)
		if err != nil {
			return err
		}
		if workspace.IsDefault {
			return refuse(types.OrgErrDefaultWorkspace)
		}
		if revocation, err = model.DisableOrgKeysTx(tx, model.OrgKeyScope{OrgID: orgID, WorkspaceID: workspaceID}); err != nil {
			return err
		}
		if err := tx.Model(&model.Invite{}).Where("org_id = ? AND workspace_id = ? AND status = ?", orgID, workspaceID, types.InviteStatusPending).
			Update("status", types.InviteStatusRevoked).Error; err != nil {
			return err
		}
		if err := model.SetWorkspaceStatusTx(tx, orgID, workspaceID, types.WorkspaceStatusDeleted); err != nil {
			return err
		}
		if err := tx.Delete(&model.Workspace{}, workspaceID).Error; err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, WorkspaceId: workspaceID, ActorUserId: actorID,
			Action: "workspace.delete", TargetType: "workspace", TargetId: workspace.Slug})
	})
	if err != nil {
		return err
	}
	revocation.Publish()
	return nil
}
