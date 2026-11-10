package org

import (
	"context"
	"errors"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// lockKeyForActor proves the actor may manage a key and locks it. Workspace
// admins (including organization owners and admins) manage every key of the
// workspace; members only their own; auditors none. A key outside the
// organization or workspace, or one a member does not own, is "not found".
func lockKeyForActor(tx *gorm.DB, orgID, workspaceID, keyID, actorID int) (*model.Token, error) {
	_, role, err := RequireWorkspaceRoleTx(tx, orgID, workspaceID, actorID, false, types.WorkspaceRoleAdmin, types.WorkspaceRoleMember)
	if err != nil {
		return nil, err
	}
	owner := 0
	if role != types.WorkspaceRoleAdmin {
		owner = actorID
	}
	key, err := model.LockOrgKeyTx(tx, orgID, workspaceID, keyID, owner)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, refuse(types.OrgErrKeyNotFound)
	}
	return key, err
}

// canSpendTx reports whether a person currently justifies a live member key in
// a workspace: an active organization member who is an owner or admin, or who
// holds an active admin or member workspace role. It is the rule behind
// ReconcileMemberKeysTx, read in the other direction.
func canSpendTx(tx *gorm.DB, orgID, workspaceID, userID int) (bool, error) {
	member, err := model.GetOrganizationMember(tx, orgID, userID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil || member.Status != types.OrgMemberStatusActive {
		return false, err
	}
	if model.OrgRoleAtLeast(member.Role, types.OrgRoleAdmin) {
		return true, nil
	}
	projected, err := model.GetWorkspaceMember(tx, workspaceID, userID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil || projected.Status != model.WorkspaceMemberStatusActive {
		return false, err
	}
	return projected.Role == types.WorkspaceRoleAdmin || projected.Role == types.WorkspaceRoleMember, nil
}

// UpdateKeyInput lists the only fields an update may change. A nil field stays
// as it is. Quota, ownership, workspace and principal are not editable here.
type UpdateKeyInput struct {
	Name        *string
	Status      *int
	ExpiredTime *int64
	ModelLimits *[]string
	AllowIps    *string
}

// UpdateWorkspaceKey edits a key. Turning a key back on is allowed only while
// the person it belongs to could still have been given one: a revoked member's
// key stays off even if an admin asks, because a revoked key is only ever
// replaced by a new one.
func UpdateWorkspaceKey(ctx context.Context, actorID, orgID, workspaceID, keyID int, in UpdateKeyInput) (*KeyView, error) {
	var view KeyView
	var fence *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		key, err := lockKeyForActor(tx, orgID, workspaceID, keyID, actorID)
		if err != nil {
			return err
		}
		updates := map[string]any{}
		if in.Name != nil {
			name, err := validateKeyName(*in.Name)
			if err != nil {
				return err
			}
			updates["name"] = name
		}
		if in.Status != nil {
			if *in.Status != common.TokenStatusEnabled && *in.Status != common.TokenStatusDisabled {
				return refuse(types.OrgErrInvalidInput)
			}
			if *in.Status == common.TokenStatusEnabled && key.Status != common.TokenStatusEnabled && key.OwnerType == types.TokenOwnerMember {
				ok, err := canSpendTx(tx, orgID, workspaceID, key.CreatedBy)
				if err != nil {
					return err
				}
				if !ok {
					return refuse(types.OrgErrConflict)
				}
			}
			updates["status"] = *in.Status
		}
		if in.ExpiredTime != nil {
			if *in.ExpiredTime < -1 {
				return refuse(types.OrgErrInvalidInput)
			}
			updates["expired_time"] = *in.ExpiredTime
		}
		if in.ModelLimits != nil {
			updates["model_limits_enabled"], updates["model_limits"] = len(*in.ModelLimits) > 0, strings.Join(*in.ModelLimits, ",")
		}
		if in.AllowIps != nil {
			allow := strings.TrimSpace(*in.AllowIps)
			updates["allow_ips"] = &allow
		}
		if len(updates) == 0 {
			return refuse(types.OrgErrInvalidInput)
		}
		if fence, err = model.FenceOrgKeysTx(*key); err != nil {
			return err
		}
		if err := tx.Model(&model.Token{}).Where("id = ?", key.Id).Updates(updates).Error; err != nil {
			return err
		}
		if err := tx.Where("id = ?", key.Id).Take(key).Error; err != nil {
			return err
		}
		view = NewKeyView(key)
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, WorkspaceId: workspaceID, ActorUserId: actorID,
			Action: "key.update", TargetType: "key", TargetId: itoa(keyID)})
	})
	if err != nil {
		return nil, err
	}
	fence.Publish()
	return &view, nil
}

// DeleteWorkspaceKey soft-deletes a key. The row stays, so refunds and history
// that point at its id keep working.
func DeleteWorkspaceKey(ctx context.Context, actorID, orgID, workspaceID, keyID int) error {
	var fence *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		key, err := lockKeyForActor(tx, orgID, workspaceID, keyID, actorID)
		if err != nil {
			return err
		}
		if fence, err = model.FenceOrgKeysTx(*key); err != nil {
			return err
		}
		if err := tx.Delete(&model.Token{}, key.Id).Error; err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, WorkspaceId: workspaceID, ActorUserId: actorID,
			Action: "key.delete", TargetType: "key", TargetId: itoa(keyID)})
	})
	if err != nil {
		return err
	}
	fence.Publish()
	return nil
}

// RotateWorkspaceKey replaces a key in one transaction: the old key is
// disabled and a successor with the same settings is created. A system
// key's successor inherits its access principal, so the lineage keeps reading
// its own task history; a member key's successor belongs to the same person.
// Only an enabled key can be rotated: rotating a revoked or expired key would
// turn a closed door into an open one. The old key's historical token id is
// untouched, and its remaining quota moves to the successor.
func RotateWorkspaceKey(ctx context.Context, actorID, orgID, workspaceID, keyID int) (*KeyIssued, error) {
	var issued *KeyIssued
	var fence *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		old, err := lockKeyForActor(tx, orgID, workspaceID, keyID, actorID)
		if err != nil {
			return err
		}
		if old.Status != common.TokenStatusEnabled {
			return refuse(types.OrgErrConflict)
		}
		if old.OwnerType == types.TokenOwnerMember {
			ok, err := canSpendTx(tx, orgID, workspaceID, old.CreatedBy)
			if err != nil {
				return err
			}
			if !ok {
				return refuse(types.OrgErrConflict)
			}
		}
		secret, err := common.GenerateKey()
		if err != nil {
			return err
		}
		now := common.GetTimestamp()
		successor := *old
		successor.Id, successor.Key, successor.CreatedTime, successor.AccessedTime = 0, secret, now, now
		successor.UsedQuota, successor.DeletedAt = 0, gorm.DeletedAt{}
		successor.Status = common.TokenStatusEnabled
		if fence, err = model.FenceOrgKeysTx(*old); err != nil {
			return err
		}
		if err := tx.Model(&model.Token{}).Where("id = ?", old.Id).
			Updates(map[string]any{"status": common.TokenStatusDisabled, "remain_quota": 0}).Error; err != nil {
			return err
		}
		if err := tx.Create(&successor).Error; err != nil {
			return err
		}
		issued = &KeyIssued{Key: NewKeyView(&successor), Plaintext: "sk-" + secret}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, WorkspaceId: workspaceID, ActorUserId: actorID,
			Action: "key.rotate", TargetType: "key", TargetId: itoa(successor.Id),
			Detail: map[string]any{"replaces": old.Id, "owner_type": old.OwnerType}})
	})
	if err != nil {
		return nil, err
	}
	fence.Publish()
	return issued, nil
}
