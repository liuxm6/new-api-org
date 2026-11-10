package model

import (
	"context"

	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// OrgLeaseRequest asks for a slice of the wallet or of one budget row.
// RecentConsumed is what this instance spent from the target in the last ten
// seconds; it sizes the lease and an idle instance gets none.
type OrgLeaseRequest struct {
	OrgID          int
	TargetType     string
	TargetID       int
	InstanceID     string
	Shard          int
	RecentConsumed int64
}

// AcquireOrgQuotaLease grants a lease of min(a quarter of what is left, twice
// the recent consumption), good for ten seconds and, for a budget, never past
// the end of its window (design 4.2.2). It returns nil when nothing can be
// granted. A wallet lease leaves users.quota at once; a budget lease is
// counted in the usage row's held quota.
func AcquireOrgQuotaLease(ctx context.Context, req OrgLeaseRequest) (*OrgQuotaLease, error) {
	if req.Shard < 0 || req.Shard >= OrgLeaseShards || req.InstanceID == "" {
		return nil, orgInvalidError()
	}
	if req.RecentConsumed <= 0 {
		return nil, nil
	}
	var lease *OrgQuotaLease
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		switch req.TargetType {
		case types.OrgLeaseTargetWallet:
			lease, err = acquireWalletLeaseTx(tx, req)
		case types.OrgLeaseTargetBudget:
			lease, err = acquireBudgetLeaseTx(tx, req)
		default:
			err = orgInvalidError()
		}
		return err
	})
	return lease, err
}

// leaseGrantDivisor, when positive, overrides the default share of 1/(2K) that
// one grant may take of what is left. Tests pin it to keep their arithmetic.
var leaseGrantDivisor int64

// leaseAmount is a grant of at most 1/(2K) of what is left, so the K leases of
// one target together never park more than half of it, and twice the recent
// consumption, so an idle shard does not hold money it will not spend.
func leaseAmount(remaining, recent int64) int64 {
	divisor := leaseGrantDivisor
	if divisor <= 0 {
		divisor = int64(2 * OrgLeaseShards)
	}
	return min(remaining/divisor, recent*2)
}

func acquireWalletLeaseTx(tx *gorm.DB, req OrgLeaseRequest) (*OrgQuotaLease, error) {
	org, err := orgFindOne[Organization](tx.Unscoped().Select("id", "billing_user_id").Where("id = ?", req.OrgID))
	if err != nil {
		return nil, err
	}
	if org == nil || org.BillingUserId != req.TargetID {
		return nil, orgNotFoundError()
	}
	wallet, err := orgFindOne[User](lockForUpdate(tx.Unscoped().Select("id", "quota").Where("id = ?", req.TargetID)))
	if err != nil {
		return nil, err
	}
	if wallet == nil {
		return nil, orgNotFoundError()
	}
	amount := leaseAmount(int64(wallet.Quota), req.RecentConsumed)
	if amount <= 0 {
		return nil, nil
	}
	now, err := orgDBNow(tx)
	if err != nil {
		return nil, err
	}
	if ok, err := DecreaseOrgWalletTx(tx, req.TargetID, amount); err != nil || !ok {
		return nil, err
	}
	lease := OrgQuotaLease{OrgId: req.OrgID, TargetType: req.TargetType, TargetId: req.TargetID, InstanceId: req.InstanceID,
		ShardNo: req.Shard, Amount: amount, Status: types.OrgLeaseStatusActive, ExpiresAt: now + OrgLeaseTTLSeconds, CreatedAt: now}
	return &lease, tx.Create(&lease).Error
}

func acquireBudgetLeaseTx(tx *gorm.DB, req OrgLeaseRequest) (*OrgQuotaLease, error) {
	usage, err := orgFindOne[OrgBudgetUsage](lockForUpdate(tx.Where("id = ? AND org_id = ?", req.TargetID, req.OrgID)))
	if err != nil {
		return nil, err
	}
	if usage == nil {
		return nil, orgNotFoundError()
	}
	budget, err := orgFindOne[Budget](lockForUpdate(tx.Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ?",
		usage.OrgId, usage.Scope, usage.SubjectId, usage.Period)))
	if err != nil {
		return nil, err
	}
	if budget == nil || !budget.Enabled {
		return nil, nil
	}
	now, err := orgDBNow(tx)
	if err != nil {
		return nil, err
	}
	if current, _ := OrgBudgetWindow(usage.Period, now); current != usage.WindowStart {
		return nil, nil // a window that is over or not yet open grants no lease
	}
	_, windowEnd := OrgBudgetWindow(usage.Period, usage.WindowStart)
	expiresAt, ok := OrgLeaseExpiry(now, windowEnd)
	amount := leaseAmount(budget.LimitQuota-usage.SpentQuota-usage.HeldQuota, req.RecentConsumed)
	if !ok || amount <= 0 {
		return nil, nil
	}
	if err := tx.Model(&OrgBudgetUsage{}).Where("id = ?", usage.Id).
		Update("held_quota", gorm.Expr("held_quota + ?", amount)).Error; err != nil {
		return nil, err
	}
	lease := OrgQuotaLease{OrgId: req.OrgID, TargetType: req.TargetType, TargetId: req.TargetID, WindowEnd: windowEnd,
		InstanceId: req.InstanceID, ShardNo: req.Shard, Amount: amount, Status: types.OrgLeaseStatusActive,
		ExpiresAt: expiresAt, CreatedAt: now}
	return &lease, tx.Create(&lease).Error
}

// OrgSweepResult counts what one sweep did.
type OrgSweepResult struct {
	Revoked int
	Closed  int
}

// SweepOrgQuotaLeases revokes expired leases and closes revoked ones that no
// longer carry an in-flight allocation, returning the unconsumed part to its
// wallet or budget. Revoking first means a slow instance can no longer take
// from the lease; closing waits until its operations have settled or been
// recovered.
func SweepOrgQuotaLeases(ctx context.Context, limit int) (OrgSweepResult, error) {
	var result OrgSweepResult
	now, err := orgDBNow(DB.WithContext(ctx))
	if err != nil {
		return result, err
	}
	var expired []int
	if err := DB.WithContext(ctx).Model(&OrgQuotaLease{}).
		Where("status = ? AND expires_at < ?", types.OrgLeaseStatusActive, now).Order("id ASC").Limit(limit).
		Pluck("id", &expired).Error; err != nil {
		return result, err
	}
	if len(expired) > 0 {
		revoked := DB.WithContext(ctx).Model(&OrgQuotaLease{}).
			Where("id IN ? AND status = ?", expired, types.OrgLeaseStatusActive).
			Update("status", types.OrgLeaseStatusRevoked)
		if revoked.Error != nil {
			return result, revoked.Error
		}
		result.Revoked = int(revoked.RowsAffected)
	}
	var closable []int
	if err := DB.WithContext(ctx).Model(&OrgQuotaLease{}).
		Where("status = ? AND allocated = 0", types.OrgLeaseStatusRevoked).Order("id ASC").Limit(limit).
		Pluck("id", &closable).Error; err != nil {
		return result, err
	}
	for _, id := range closable {
		closed := false
		err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var err error
			closed, err = closeOrgLeaseTx(tx, id)
			return err
		})
		if err != nil {
			return result, err
		}
		if closed {
			result.Closed++
		}
	}
	return result, nil
}

// closeOrgLeaseTx returns amount - consumed of a revoked lease. The target row
// is locked before the lease row, the order every other path uses; the lease is
// then re-read under its lock, so closing twice can never refund twice.
func closeOrgLeaseTx(tx *gorm.DB, id int) (bool, error) {
	probe, err := orgFindOne[OrgQuotaLease](tx.Where("id = ?", id))
	if err != nil || probe == nil {
		return false, err
	}
	if probe.TargetType == types.OrgLeaseTargetWallet {
		_, err = orgFindOne[User](lockForUpdate(tx.Unscoped().Select("id").Where("id = ?", probe.TargetId)))
	} else {
		_, err = orgFindOne[OrgBudgetUsage](lockForUpdate(tx.Select("id").Where("id = ?", probe.TargetId)))
	}
	if err != nil {
		return false, err
	}
	lease, err := orgFindOne[OrgQuotaLease](lockForUpdate(tx.Where("id = ?", id)))
	if err != nil || lease == nil {
		return false, err
	}
	if lease.Status != types.OrgLeaseStatusRevoked || lease.Allocated != 0 {
		return false, nil
	}
	if unused := lease.Amount - lease.Consumed; unused > 0 {
		if lease.TargetType == types.OrgLeaseTargetWallet {
			err = IncreaseOrgWalletTx(tx, lease.TargetId, unused)
		} else {
			err = tx.Model(&OrgBudgetUsage{}).Where("id = ?", lease.TargetId).
				Update("held_quota", gorm.Expr("held_quota - ?", unused)).Error
		}
		if err != nil {
			return false, err
		}
	}
	return true, tx.Model(&OrgQuotaLease{}).Where("id = ?", id).Update("status", types.OrgLeaseStatusClosed).Error
}

// RevokeOrgInstanceLeases revokes every active lease of an instance that is
// shutting down; the sweeper closes them once their operations settle.
func RevokeOrgInstanceLeases(ctx context.Context, instanceID string) (int, error) {
	result := DB.WithContext(ctx).Model(&OrgQuotaLease{}).
		Where("instance_id = ? AND status = ?", instanceID, types.OrgLeaseStatusActive).
		Update("status", types.OrgLeaseStatusRevoked)
	return int(result.RowsAffected), result.Error
}

// ClaimOrgOperationForRecovery lets the recovery worker take over a reserved
// operation whose lease expired (design 4.2.6). The conditional update is the
// fence: the requesting instance writes with WHERE lease_owner = me, the
// worker with WHERE lease_until < now, so only one of them can succeed.
func ClaimOrgOperationForRecovery(ctx context.Context, operationID string, expectedRevision int64, worker string) (bool, error) {
	if operationID == "" || worker == "" {
		return false, orgInvalidError()
	}
	now, err := orgDBNow(DB.WithContext(ctx))
	if err != nil {
		return false, err
	}
	result := DB.WithContext(ctx).Model(&OrgBillingOperation{}).
		Where("operation_id = ? AND revision = ? AND state = ? AND lease_until < ?",
			operationID, expectedRevision, types.OrgOpStateReserved, now).
		Updates(map[string]any{"lease_owner": worker, "lease_until": now + OrgOperationLeaseSeconds, "updated_at": now})
	return result.RowsAffected == 1, result.Error
}

// RenewOrgOperationLease extends the lease of a live request and records how
// much output cost it has forwarded, which is what recovery settles at if the
// instance dies. Only the owner can renew.
func RenewOrgOperationLease(ctx context.Context, operationID, owner string, progress int64) (bool, error) {
	if operationID == "" || owner == "" || progress < 0 {
		return false, orgInvalidError()
	}
	now, err := orgDBNow(DB.WithContext(ctx))
	if err != nil {
		return false, err
	}
	result := DB.WithContext(ctx).Model(&OrgBillingOperation{}).
		Where("operation_id = ? AND lease_owner = ? AND state = ?", operationID, owner, types.OrgOpStateReserved).
		Updates(map[string]any{"lease_until": now + OrgOperationLeaseSeconds, "updated_at": now,
			"progress_quota": gorm.Expr("CASE WHEN progress_quota < ? THEN ? ELSE progress_quota END", progress, progress)})
	return result.RowsAffected == 1, result.Error
}

// OrgBalance splits an organization wallet into what can be spent and what
// in-flight requests are holding (design 3.3, invariant 11).
type OrgBalance struct {
	Available  int64
	LeaseHeld  int64
	DirectHeld int64
	InFlight   int64
}

// OrgBalanceView reports the wallet. Available is users.quota; in flight is the
// unconsumed part of live wallet leases plus the open locked-row holds of
// operations that have not finished.
func OrgBalanceView(ctx context.Context, orgID int) (OrgBalance, error) {
	var view OrgBalance
	db := DB.WithContext(ctx)
	org, err := orgFindOne[Organization](db.Unscoped().Select("id", "billing_user_id").Where("id = ?", orgID))
	if err != nil {
		return view, err
	}
	if org == nil {
		return view, orgNotFoundError()
	}
	if view.Available, err = OrgWalletAvailable(db, org.BillingUserId); err != nil {
		return view, err
	}
	if err := db.Model(&OrgQuotaLease{}).Where("org_id = ? AND target_type = ? AND status <> ?",
		orgID, types.OrgLeaseTargetWallet, types.OrgLeaseStatusClosed).
		Select("COALESCE(SUM(amount - consumed), 0)").Scan(&view.LeaseHeld).Error; err != nil {
		return view, err
	}
	var ops []OrgBillingOperation
	if err := db.Select("id", "holds").Where("org_id = ? AND state IN ?", orgID,
		[]string{types.OrgOpStateReserved, types.OrgOpStateCaptured}).Find(&ops).Error; err != nil {
		return view, err
	}
	for _, op := range ops {
		holds, err := decodeOrgHolds(op.Holds)
		if err != nil {
			return view, err
		}
		for _, hold := range holds {
			if hold.TargetType == types.OrgHoldTargetWallet && hold.Source == types.OrgHoldSourceDirect {
				view.DirectHeld += hold.Amount - hold.Released - hold.Captured
			}
		}
	}
	view.InFlight = view.LeaseHeld + view.DirectHeld
	return view, nil
}

// ListExpiredOrgOperations returns reserved operations whose request instance
// stopped renewing the lease, oldest first. The recovery worker settles them.
func ListExpiredOrgOperations(ctx context.Context, limit int) ([]OrgBillingOperation, error) {
	db := DB.WithContext(ctx)
	now, err := orgDBNow(db)
	if err != nil {
		return nil, err
	}
	var ops []OrgBillingOperation
	err = db.Where("state = ? AND lease_until > 0 AND lease_until < ?", types.OrgOpStateReserved, now).
		Order("id ASC").Limit(limit).Find(&ops).Error
	return ops, err
}

// MarkOrgOperationRecoveryRequired parks an asynchronous operation whose upstream
// acceptance is unknown. It keeps its holds and waits for a platform decision;
// nothing is refunded or charged on a guess. Only the worker that claimed the
// operation can park it.
func MarkOrgOperationRecoveryRequired(ctx context.Context, operationID, worker string) (bool, error) {
	now, err := orgDBNow(DB.WithContext(ctx))
	if err != nil {
		return false, err
	}
	result := DB.WithContext(ctx).Model(&OrgBillingOperation{}).
		Where("operation_id = ? AND lease_owner = ? AND state = ?", operationID, worker, types.OrgOpStateReserved).
		Updates(map[string]any{"state": types.OrgOpStateRecoveryRequired, "lease_owner": "", "lease_until": 0, "updated_at": now})
	return result.RowsAffected == 1, result.Error
}

// OrgLeaseTarget is one wallet or budget row a request of a subject can draw a
// lease from.
type OrgLeaseTarget struct {
	TargetType string
	TargetID   int
}

// OrgLeaseTargets lists the targets a request of the subject holds money on: the
// billing wallet, and the usage row of the current window of every enabled
// budget that applies. The answer is advisory; the reservation recomputes it.
func OrgLeaseTargets(ctx context.Context, subject types.OrgSubject) ([]OrgLeaseTarget, error) {
	var targets []OrgLeaseTarget
	err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, err := orgFindOne[Organization](tx.Select("id", "billing_user_id").Where("id = ?", subject.OrgID))
		if err != nil {
			return err
		}
		if org == nil {
			return orgNotFoundError()
		}
		now, err := orgDBNow(tx)
		if err != nil {
			return err
		}
		targets = append(targets, OrgLeaseTarget{TargetType: types.OrgLeaseTargetWallet, TargetID: org.BillingUserId})
		keys, err := planOrgBudgets(tx, types.OrgBillingCommand{Subject: subject}, now)
		if err != nil {
			return err
		}
		for _, key := range keys {
			usage, err := ensureOrgUsageTx(tx, subject.OrgID, key, false)
			if err != nil {
				return err
			}
			targets = append(targets, OrgLeaseTarget{TargetType: types.OrgLeaseTargetBudget, TargetID: usage.Id})
		}
		return nil
	})
	return targets, err
}
