package model

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// OrgDrift is one broken accounting identity (design 3.3, invariants 11 and
// 12). Reconciliation reports it and changes nothing: money is never adjusted
// to make a check pass.
type OrgDrift struct {
	Kind     string // wallet_identity, held_identity, lease, negative_wallet, negative_key
	Subject  string
	Expected int64
	Actual   int64
}

func (d OrgDrift) String() string {
	return fmt.Sprintf("%s %s: expected %d, found %d", d.Kind, d.Subject, d.Expected, d.Actual)
}

// ReconcileOrg recomputes, from the operations, leases, events and ledger, what
// the wallet and every budget's held quota must be, and returns each mismatch.
// It reads one consistent snapshot so work in flight does not look like drift.
// Operations that are closed or cancelled and leases that are closed hold
// nothing open and are not scanned.
func ReconcileOrg(ctx context.Context, orgID int) ([]OrgDrift, error) {
	var drifts []OrgDrift
	opts := &sql.TxOptions{ReadOnly: true}
	if common.MainDatabaseType() == common.DatabaseTypePostgreSQL {
		opts.Isolation = sql.LevelRepeatableRead
	}
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		drifts, err = reconcileOrgTx(tx, orgID)
		return err
	}, opts)
	return drifts, err
}

func reconcileOrgTx(tx *gorm.DB, orgID int) ([]OrgDrift, error) {
	// The first read pins the snapshot under MySQL repeatable read.
	org, err := orgFindOne[Organization](tx.Unscoped().Select("id", "billing_user_id").Where("id = ?", orgID))
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, orgNotFoundError()
	}
	var drifts []OrgDrift

	var wallet User
	if err := tx.Unscoped().Select("id", "quota").Where("id = ?", org.BillingUserId).Take(&wallet).Error; err != nil {
		return nil, err
	}
	if wallet.Quota < 0 {
		drifts = append(drifts, OrgDrift{Kind: "negative_wallet", Subject: strconv.Itoa(wallet.Id), Expected: 0, Actual: int64(wallet.Quota)})
	}
	var negativeKeys int64
	if err := tx.Unscoped().Model(&Token{}).Where("org_id = ? AND remain_quota < 0", orgID).Count(&negativeKeys).Error; err != nil {
		return nil, err
	}
	if negativeKeys > 0 {
		drifts = append(drifts, OrgDrift{Kind: "negative_key", Subject: "org " + strconv.Itoa(orgID), Expected: 0, Actual: negativeKeys})
	}

	var leases []OrgQuotaLease
	if err := tx.Where("org_id = ?", orgID).Find(&leases).Error; err != nil {
		return nil, err
	}
	var walletLeases int64
	for _, lease := range leases {
		bad := lease.Allocated < 0 || lease.Allocated+lease.Consumed > lease.Amount || lease.Folded > lease.Consumed
		if bad {
			drifts = append(drifts, OrgDrift{Kind: "lease", Subject: strconv.Itoa(lease.Id),
				Expected: lease.Amount, Actual: lease.Allocated + lease.Consumed})
		}
		if lease.TargetType == types.OrgLeaseTargetWallet && lease.Status != types.OrgLeaseStatusClosed {
			walletLeases += lease.Amount - lease.Consumed
		}
	}

	var ops []OrgBillingOperation
	if err := tx.Select("operation_id", "state", "holds").
		Where("org_id = ? AND state NOT IN ?", orgID, []string{types.OrgOpStateClosed, types.OrgOpStateCanceled}).Find(&ops).Error; err != nil {
		return nil, err
	}
	var walletDirect int64
	directBudget := map[int]int64{}
	for _, op := range ops {
		holds, err := decodeOrgHolds(op.Holds)
		if err != nil {
			return nil, err
		}
		for _, hold := range holds {
			if hold.Source != types.OrgHoldSourceDirect {
				continue
			}
			open := hold.Amount - hold.Released - hold.Captured
			switch hold.TargetType {
			case types.OrgHoldTargetWallet:
				walletDirect += open
			case types.OrgHoldTargetBudget:
				directBudget[hold.TargetId] += open
			}
		}
	}

	var credited, spent int64
	if err := tx.Model(&OrgBillingLedger{}).Where("org_id = ?", orgID).
		Select("COALESCE(SUM(amount_quota), 0)").Scan(&credited).Error; err != nil {
		return nil, err
	}
	if err := tx.Model(&OrgSpendEvent{}).Where("org_id = ?", orgID).
		Select("COALESCE(SUM(delta_quota), 0)").Scan(&spent).Error; err != nil {
		return nil, err
	}
	if want, got := credited-spent, int64(wallet.Quota)+walletLeases+walletDirect; want != got {
		drifts = append(drifts, OrgDrift{Kind: "wallet_identity", Subject: strconv.Itoa(wallet.Id), Expected: want, Actual: got})
	}

	// Spend that was captured but not folded yet still sits in held.
	var queue []OrgSpendFoldQueue
	if err := tx.Select("holds", "spend_delta").Where("org_id = ? AND kind = ?", orgID, types.OrgFoldKindCapture).
		Find(&queue).Error; err != nil {
		return nil, err
	}
	for _, row := range queue {
		holds, err := decodeOrgHolds(row.Holds)
		if err != nil {
			return nil, err
		}
		for _, hold := range holds {
			if hold.TargetType == types.OrgHoldTargetBudget && hold.Source == types.OrgHoldSourceDirect {
				directBudget[hold.TargetId] += row.SpendDelta
			}
		}
	}
	var usages []OrgBudgetUsage
	if err := tx.Where("org_id = ?", orgID).Find(&usages).Error; err != nil {
		return nil, err
	}
	for _, usage := range usages {
		var held int64
		for _, lease := range leases {
			if lease.TargetType != types.OrgLeaseTargetBudget || lease.TargetId != usage.Id {
				continue
			}
			if lease.Status == types.OrgLeaseStatusClosed {
				held += lease.Consumed - lease.Folded
			} else {
				held += lease.Amount - lease.Folded
			}
		}
		held += directBudget[usage.Id]
		if held != usage.HeldQuota {
			drifts = append(drifts, OrgDrift{Kind: "held_identity",
				Subject:  fmt.Sprintf("%s/%d/%s", usage.Scope, usage.SubjectId, usage.Period),
				Expected: held, Actual: usage.HeldQuota})
		}
	}
	return drifts, nil
}
