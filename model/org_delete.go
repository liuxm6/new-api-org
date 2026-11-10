package model

import (
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// Reasons an organization cannot be deleted yet (design section 5.4). They are
// stable identifiers the console translates.
const (
	DeleteBlockBalance    = "balance"
	DeleteBlockLeases     = "leases"
	DeleteBlockOperations = "billing_operations"
	DeleteBlockFoldQueue  = "fold_queue"
	DeleteBlockTasks      = "tasks"
)

// OrgDeleteBlockersTx lists everything that still ties money or work to the
// organization: a non-zero wallet, leases not closed, billing operations not
// settled (or waiting for a platform decision), consumption not yet folded and
// asynchronous tasks not finished. It reads only. The wallet row is locked so
// a balance cannot change between this check and the delete.
func OrgDeleteBlockersTx(tx *gorm.DB, org *Organization) ([]string, error) {
	var blockers []string
	var wallets []User
	if err := lockForUpdate(tx.Unscoped()).Select("id", "quota").Where("id = ?", org.BillingUserId).Limit(1).Find(&wallets).Error; err != nil {
		return nil, err
	}
	if len(wallets) == 1 && wallets[0].Quota != 0 {
		blockers = append(blockers, DeleteBlockBalance)
	}
	checks := []struct {
		reason string
		query  *gorm.DB
	}{
		{DeleteBlockLeases, tx.Model(&OrgQuotaLease{}).Where("org_id = ? AND status <> ?", org.Id, types.OrgLeaseStatusClosed)},
		{DeleteBlockOperations, tx.Model(&OrgBillingOperation{}).Where("org_id = ? AND state IN ?", org.Id,
			[]string{types.OrgOpStatePrepared, types.OrgOpStateReserved, types.OrgOpStateCaptured, types.OrgOpStateRecoveryRequired})},
		{DeleteBlockFoldQueue, tx.Model(&OrgSpendFoldQueue{}).Where("org_id = ?", org.Id)},
	}
	for _, check := range checks {
		var n int64
		if err := check.query.Count(&n).Error; err != nil {
			return nil, err
		}
		if n > 0 {
			blockers = append(blockers, check.reason)
		}
	}
	var tasks, midjourneys int64
	if err := tx.Model(&Task{}).Where("org_id = ? AND status NOT IN ?", org.Id,
		[]string{string(TaskStatusSuccess), string(TaskStatusFailure)}).Count(&tasks).Error; err != nil {
		return nil, err
	}
	if err := tx.Model(&Midjourney{}).Where("org_id = ? AND status NOT IN ?", org.Id, []string{"SUCCESS", "FAILURE"}).
		Count(&midjourneys).Error; err != nil {
		return nil, err
	}
	if tasks+midjourneys > 0 {
		blockers = append(blockers, DeleteBlockTasks)
	}
	return blockers, nil
}
