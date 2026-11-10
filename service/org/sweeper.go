package org

import (
	"context"
	"fmt"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

const (
	// OrphanSweepInterval is how often the compensation runs. It is a safety
	// net for a revocation that was missed, never the revocation itself.
	OrphanSweepInterval = 5 * time.Minute
	sweepBatch          = 500
)

// SweepOrphanKeys disables enabled organization keys that no longer have
// anyone entitled to them: member keys whose owner is gone, disabled, no longer
// an active member, or no longer holds a spending role in the key's workspace,
// and keys whose workspace or organization was deleted. System keys stay as
// long as their workspace and organization exist. It returns how many keys it
// disabled and writes one audit row per organization.
func SweepOrphanKeys(ctx context.Context) (int, error) {
	db := model.DB.WithContext(ctx)
	orphans := map[int][]int{}
	cursor := 0
	for {
		var keys []model.Token
		if err := db.Where("org_id > 0 AND status = ? AND id > ?", common.TokenStatusEnabled, cursor).
			Order("id").Limit(sweepBatch).Find(&keys).Error; err != nil {
			return 0, err
		}
		if len(keys) == 0 {
			break
		}
		for _, key := range keys {
			cursor = key.Id
			orphaned, err := keyIsOrphan(db, &key)
			if err != nil {
				return 0, err
			}
			if orphaned {
				orphans[key.OrgId] = append(orphans[key.OrgId], key.Id)
			}
		}
	}
	total := 0
	for orgID, ids := range orphans {
		var fence *model.KeyRevocation
		err := db.Transaction(func(tx *gorm.DB) error {
			var err error
			if fence, err = model.DisableOrgKeysByIDTx(tx, orgID, ids); err != nil {
				return err
			}
			if fence.Count() == 0 {
				return nil
			}
			return model.RecordOrgAuditTx(tx, model.OrgAuditEntry{OrgId: orgID, ActorKind: "system", Action: "key.orphan_disabled",
				TargetType: "key", TargetId: fmt.Sprint(fence.Count()), Detail: map[string]any{"count": fence.Count()}})
		})
		if err != nil {
			return total, err
		}
		fence.Publish()
		total += fence.Count()
	}
	return total, nil
}

// keyIsOrphan decides, from the current database state, whether nobody is
// entitled to an enabled key any more.
func keyIsOrphan(db *gorm.DB, key *model.Token) (bool, error) {
	var orgs int64
	if err := db.Model(&model.Organization{}).Where("id = ? AND status <> ?", key.OrgId, types.OrgStatusDeleted).Count(&orgs).Error; err != nil {
		return false, err
	}
	var workspaces int64
	if err := db.Model(&model.Workspace{}).Where("id = ? AND org_id = ?", key.WorkspaceId, key.OrgId).Count(&workspaces).Error; err != nil {
		return false, err
	}
	if orgs == 0 || workspaces == 0 {
		return true, nil
	}
	if key.OwnerType != types.TokenOwnerMember {
		return false, nil
	}
	var owners int64
	if err := db.Model(&model.User{}).Where("id = ? AND status = ?", key.CreatedBy, common.UserStatusEnabled).Count(&owners).Error; err != nil {
		return false, err
	}
	if owners == 0 {
		return true, nil
	}
	ok, err := canSpendTx(db, key.OrgId, key.WorkspaceId, key.CreatedBy)
	return !ok, err
}

// StartOrphanKeySweeper runs SweepOrphanKeys every OrphanSweepInterval until
// ctx ends. Start it on one node only (the master); a second runner is
// harmless, since the sweep is idempotent, but audits twice.
func StartOrphanKeySweeper(ctx context.Context) {
	ticker := time.NewTicker(OrphanSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if disabled, err := SweepOrphanKeys(ctx); err != nil {
				common.SysError(common.LogText("organization key sweep failed: %v", err))
			} else if disabled > 0 {
				common.SysLog(common.LogText("organization key sweep disabled %d orphaned keys", disabled))
			}
		}
	}
}
