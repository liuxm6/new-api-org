package org

import (
	"context"
	"errors"
	"strconv"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

func itoa(n int) string { return strconv.Itoa(n) }

func validOrgRole(role string) bool {
	switch role {
	case types.OrgRoleOwner, types.OrgRoleAdmin, types.OrgRoleBilling, types.OrgRoleMember:
		return true
	}
	return false
}

// activeOwnerCountTx counts active owners other than excludeUserID.
func activeOwnerCountTx(tx *gorm.DB, orgID, excludeUserID int) (int64, error) {
	var n int64
	err := tx.Model(&model.OrganizationMember{}).
		Where("org_id = ? AND role = ? AND status = ? AND user_id <> ?",
			orgID, types.OrgRoleOwner, types.OrgMemberStatusActive, excludeUserID).Count(&n).Error
	return n, err
}

// GuardOwnerChangeTx enforces the ownership rules for any write that changes
// or removes a membership: only an owner may touch the owner role (grant it,
// take it away, or remove an owner), the last active owner can never leave or
// be demoted, and the primary owner recorded in organizations.owner_user_id
// changes only through TransferOwnership. newRole is "" for a removal. It is
// shared by role changes and by member removal (Task 7) so the rules exist
// once.
func GuardOwnerChangeTx(tx *gorm.DB, org *model.Organization, actor, target *model.OrganizationMember, newRole string) error {
	touchesOwner := target.Role == types.OrgRoleOwner || newRole == types.OrgRoleOwner
	if touchesOwner && actor.Role != types.OrgRoleOwner {
		return refuse(types.OrgErrOwnerRole)
	}
	if target.Role != types.OrgRoleOwner || newRole == types.OrgRoleOwner {
		return nil
	}
	others, err := activeOwnerCountTx(tx, org.Id, target.UserId)
	if err != nil {
		return err
	}
	if others == 0 {
		return refuse(types.OrgErrLastOwner)
	}
	if org.OwnerUserId == target.UserId {
		return refuse(types.OrgErrOwnerRole)
	}
	return nil
}

// ChangeMemberRole sets an organization role. Owners and admins may call it;
// the owner rules of GuardOwnerChangeTx apply, so an admin can neither grant
// nor remove the owner role. Disabling the keys a demotion invalidates is done
// by RevokeAfterMembershipChangeTx in the same transaction.
func ChangeMemberRole(ctx context.Context, actorID, orgID, targetUserID int, newRole string) error {
	if !validOrgRole(newRole) {
		return refuse(types.OrgErrInvalidInput)
	}
	var revocation *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, actor, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin)
		if err != nil {
			return err
		}
		target, err := model.LockOrganizationMemberTx(tx, orgID, targetUserID)
		if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && target.Status == types.OrgMemberStatusRemoved) {
			return refuse(types.OrgErrMemberNotFound)
		}
		if err != nil {
			return err
		}
		if target.Role == newRole {
			return nil
		}
		if err := GuardOwnerChangeTx(tx, org, actor, target, newRole); err != nil {
			return err
		}
		if err := model.SetOrganizationMemberRoleTx(tx, orgID, targetUserID, newRole); err != nil {
			return err
		}
		if revocation, err = ReconcileMemberKeysTx(tx, orgID, targetUserID, "role_changed"); err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "member.role_change",
			TargetType: "member", TargetId: itoa(targetUserID), Detail: map[string]any{"from": target.Role, "to": newRole}})
	})
	if err != nil {
		return err
	}
	revocation.Publish()
	return nil
}
