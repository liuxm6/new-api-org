package model

import (
	"slices"
	"strconv"

	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// topUpOrgTx raises the bound of a live operation, after the final request body
// turned out to cost more than was held (design 4.2.3). Each target takes the
// difference from its own source. When a lease cannot cover it, that target
// moves wholly to a locked-row hold for the new bound and the old lease
// allocation is returned, so every target keeps exactly one source.
func topUpOrgTx(tx *gorm.DB, cmd types.OrgBillingCommand, avoid map[string]bool) (types.OrgBillingResult, error) {
	op, err := loadOrgOperationTx(tx, cmd)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	holds, err := decodeOrgHolds(op.Holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	if op.State != types.OrgOpStateReserved && op.State != types.OrgOpStateCaptured {
		return types.OrgBillingResult{}, orgConflictError()
	}
	if cmd.Bound == op.Bound {
		return orgResult(op, holds, true, 0), nil
	}
	if cmd.Bound < op.Bound {
		return types.OrgBillingResult{}, orgConflictError()
	}
	if op.State == types.OrgOpStateReserved {
		if err := fenceOrgOperation(op, cmd); err != nil {
			return types.OrgBillingResult{}, err
		}
	}
	now, err := orgDBNow(tx)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	var leases []leaseUse
	// Locked-row changes first, in hold order; lease updates last, by lease id.
	for i := range holds {
		if err := topUpOrgHold(tx, &holds[i], op.Bound, cmd.Bound, avoid, &leases); err != nil {
			return types.OrgBillingResult{}, err
		}
	}
	slices.SortFunc(leases, func(a, b leaseUse) int { return a.id - b.id })
	for _, lease := range leases {
		if lease.release {
			err = releaseOrgLease(tx, lease)
		} else {
			err = extendOrgLease(tx, lease, now)
		}
		if err != nil {
			return types.OrgBillingResult{}, err
		}
	}
	encoded, err := encodeOrgHolds(holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	op.Bound, op.ReservedQuota, op.Holds, op.UpdatedAt = cmd.Bound, cmd.Bound, encoded, now
	err = tx.Model(&OrgBillingOperation{}).Where("id = ?", op.Id).
		Updates(map[string]any{"bound": op.Bound, "reserved_quota": op.Bound, "holds": encoded, "updated_at": now}).Error
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	return orgResult(op, holds, false, 0), nil
}

// releaseOrgLease gives allocation back to a lease after a hold moved off it.
func releaseOrgLease(tx *gorm.DB, lease leaseUse) error {
	result := tx.Model(&OrgQuotaLease{}).Where("id = ? AND allocated >= ?", lease.id, lease.amount).
		Update("allocated", gorm.Expr("allocated - ?", lease.amount))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return orgConflictError()
	}
	return nil
}

// topUpOrgHold raises one hold from oldBound to newBound.
func topUpOrgHold(tx *gorm.DB, hold *types.OrgHold, oldBound, newBound int64, avoid map[string]bool, leases *[]leaseUse) error {
	delta := newBound - oldBound
	key := orgLeaseKey(hold.TargetType, hold.TargetId)
	if hold.Source != types.OrgHoldSourceDirect {
		leaseID, err := strconv.Atoi(hold.Source)
		if err != nil {
			return err
		}
		if !avoid[key] {
			*leases = append(*leases, leaseUse{id: leaseID, key: key, amount: delta})
			hold.Amount = newBound
			return nil
		}
		// The lease cannot cover the difference: the target moves wholly to a
		// locked-row hold for the new bound and the lease gets its share back.
		if err := addDirectOrgHold(tx, hold, newBound); err != nil {
			return err
		}
		*leases = append(*leases, leaseUse{id: leaseID, key: key, amount: oldBound, release: true})
		hold.Source, hold.Amount = types.OrgHoldSourceDirect, newBound
		return nil
	}
	if err := addDirectOrgHold(tx, hold, delta); err != nil {
		return err
	}
	hold.Amount = newBound
	return nil
}

// addDirectOrgHold takes amount from the target of a hold with a locked-row
// update and refuses with the error code of that target.
func addDirectOrgHold(tx *gorm.DB, hold *types.OrgHold, amount int64) error {
	switch hold.TargetType {
	case types.OrgHoldTargetWallet:
		ok, err := DecreaseOrgWalletTx(tx, hold.TargetId, amount)
		if err != nil {
			return err
		}
		if !ok {
			return types.NewOrgAccessError(types.OrgErrQuotaExhausted)
		}
	case types.OrgHoldTargetToken:
		result := tx.Model(&Token{}).Where("id = ? AND remain_quota >= ?", hold.TargetId, amount).
			Updates(map[string]any{"remain_quota": gorm.Expr("remain_quota - ?", amount),
				"used_quota": gorm.Expr("used_quota + ?", amount)})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return types.NewOrgAccessError(types.OrgErrKeyBudget)
		}
	case types.OrgHoldTargetBudget:
		_, err := addDirectBudgetHold(tx, hold.TargetId, amount, false)
		return err
	}
	return nil
}
