package model

import (
	"slices"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// reserveOrgTx admits one request. It inserts the operation, then takes a hold
// on the wallet, the limited key and every enabled budget in a fixed lock
// order (design 4.2.2). Any refusal rolls the whole transaction back, so a
// refused request leaves no operation and no partial hold.
func reserveOrgTx(tx *gorm.DB, cmd types.OrgBillingCommand, avoid map[string]bool) (types.OrgBillingResult, error) {
	existing, err := orgFindOne[OrgBillingOperation](tx.Where("operation_id = ?", cmd.OperationID))
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	if existing != nil {
		return replayOrgReserve(existing, cmd)
	}
	now, err := orgDBNow(tx)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	org, err := orgFindOne[Organization](tx.Select("id", "billing_user_id", "status").Where("id = ?", cmd.Subject.OrgID))
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	if org == nil {
		return types.OrgBillingResult{}, orgNotFoundError()
	}
	if org.Status != types.OrgStatusActive {
		return types.OrgBillingResult{}, types.NewOrgAccessError(types.OrgErrSuspended)
	}
	s := cmd.Subject
	op := OrgBillingOperation{OperationId: cmd.OperationID, OrgId: s.OrgID, WorkspaceId: s.WorkspaceID,
		ActorUserId: s.ActorUserID, TokenId: s.TokenID, AccessPrincipal: s.AccessPrincipalID, OwnerType: s.OwnerType,
		BillingUserId: org.BillingUserId, BillingChannelId: cmd.BillingChannel, SourceKind: cmd.SourceKind,
		SourceId: cmd.SourceID, ModelName: cmd.ModelName, EstimatedQuota: cmd.EstimatedQuota, Bound: cmd.Bound,
		State: types.OrgOpStateReserved, ReservedQuota: cmd.Bound, EffectiveAt: now, LeaseOwner: cmd.LeaseOwner,
		LeaseUntil: now + OrgOperationLeaseSeconds, CreatedAt: now, UpdatedAt: now}
	if err := tx.Create(&op).Error; err != nil {
		if isRetryableOrgError(err) {
			return types.OrgBillingResult{}, errOrgRetry // another request inserted this operation first
		}
		return types.OrgBillingResult{}, err
	}
	holds, leases, err := takeOrgHolds(tx, cmd, org.BillingUserId, now, avoid)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	encoded, err := encodeOrgHolds(holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	if err := tx.Model(&OrgBillingOperation{}).Where("id = ?", op.Id).Update("holds", encoded).Error; err != nil {
		return types.OrgBillingResult{}, err
	}
	// The lease rows are the contended ones; they are locked last and released by
	// the commit that follows.
	for _, lease := range leases {
		if err := extendOrgLease(tx, lease, now); err != nil {
			return types.OrgBillingResult{}, err
		}
	}
	op.Holds = encoded
	return orgResult(&op, holds, false, 0), nil
}

// replayOrgReserve answers a repeated reserve: the same bound returns the
// stored result, anything else (a different bound, a finished operation) is a
// conflict.
func replayOrgReserve(op *OrgBillingOperation, cmd types.OrgBillingCommand) (types.OrgBillingResult, error) {
	if !operationBelongs(op, cmd.Subject) {
		return types.OrgBillingResult{}, orgNotFoundError()
	}
	if (op.State != types.OrgOpStateReserved && op.State != types.OrgOpStateCaptured) || op.Bound != cmd.Bound {
		return types.OrgBillingResult{}, orgConflictError()
	}
	holds, err := decodeOrgHolds(op.Holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	return orgResult(op, holds, true, 0), nil
}

// leaseUse is one lease update deferred to the end of the transaction, so a
// row lock on a lease is never held while waiting for a wallet or budget row.
type leaseUse struct {
	id     int
	key    string
	amount int64
	// release gives allocation back instead of taking it (a hold moved off the lease).
	release bool
}

func compareOrgUsageKey(a, b orgUsageKey) int {
	for _, c := range []int{orgScopeRank[a.Scope] - orgScopeRank[b.Scope], a.SubjectID - b.SubjectID,
		orgPeriodRank[a.Period] - orgPeriodRank[b.Period]} {
		if c != 0 {
			return c
		}
	}
	return int(a.WindowStart - b.WindowStart)
}

func orgLeaseKey(targetType string, targetID int) string {
	if targetType == types.OrgHoldTargetWallet {
		return "wallet"
	}
	return "budget:" + strconv.Itoa(targetID)
}

// takeOrgHolds places the holds of a new operation and returns them in lock
// order: wallet, limited key, then budgets by usage key. Locked-row holds run
// first and lease updates last, so no lease row lock is held while waiting for
// a wallet or budget row.
func takeOrgHolds(tx *gorm.DB, cmd types.OrgBillingCommand, walletUserID int, now int64, avoid map[string]bool) ([]types.OrgHold, []leaseUse, error) {
	bound := cmd.Bound
	useLeases := !cmd.ForceDirect && !types.OrgSourceForcesDirect(cmd.SourceKind)
	var holds []types.OrgHold
	var leases []leaseUse

	wallet := types.OrgHold{TargetType: types.OrgHoldTargetWallet, TargetId: walletUserID, Amount: bound, Source: types.OrgHoldSourceDirect}
	leaseID := 0
	if useLeases && !avoid["wallet"] {
		var err error
		if leaseID, err = pickOrgLease(tx, cmd, types.OrgHoldTargetWallet, walletUserID, bound, now); err != nil {
			return nil, nil, err
		}
	}
	if leaseID > 0 {
		wallet.Source = strconv.Itoa(leaseID)
		leases = append(leases, leaseUse{id: leaseID, key: "wallet", amount: bound})
	} else if ok, err := DecreaseOrgWalletTx(tx, walletUserID, bound); err != nil {
		return nil, nil, err
	} else if !ok {
		return nil, nil, types.NewOrgAccessError(types.OrgErrQuotaExhausted)
	}
	holds = append(holds, wallet)

	if cmd.Subject.TokenID > 0 {
		held, err := holdOrgToken(tx, cmd.Subject.TokenID, bound)
		if err != nil {
			return nil, nil, err
		}
		if held {
			holds = append(holds, types.OrgHold{TargetType: types.OrgHoldTargetToken, TargetId: cmd.Subject.TokenID,
				Source: types.OrgHoldSourceDirect, Amount: bound})
		}
	}

	keys, err := planOrgBudgets(tx, cmd, now)
	if err != nil {
		return nil, nil, err
	}
	for _, key := range keys {
		usage, err := ensureOrgUsageTx(tx, cmd.Subject.OrgID, key, false)
		if err != nil {
			return nil, nil, err
		}
		hold := types.OrgHold{TargetType: types.OrgHoldTargetBudget, TargetId: usage.Id, Amount: bound,
			Source: types.OrgHoldSourceDirect, Scope: key.Scope}
		leaseID := 0
		if useLeases && !avoid[orgLeaseKey(types.OrgHoldTargetBudget, usage.Id)] {
			if leaseID, err = pickOrgLease(tx, cmd, types.OrgHoldTargetBudget, usage.Id, bound, now); err != nil {
				return nil, nil, err
			}
		}
		if leaseID > 0 {
			hold.Source = strconv.Itoa(leaseID)
			leases = append(leases, leaseUse{id: leaseID, key: orgLeaseKey(types.OrgHoldTargetBudget, usage.Id), amount: bound})
			holds = append(holds, hold)
			continue
		}
		held, err := addDirectBudgetHold(tx, usage.Id, bound, true)
		if err != nil {
			return nil, nil, err
		}
		if held {
			holds = append(holds, hold)
		}
	}

	slices.SortFunc(leases, func(a, b leaseUse) int { return a.id - b.id })
	return holds, leases, nil
}

// planOrgBudgets lists the usage keys of the enabled budgets that apply to the
// request, in lock order. Budgets that are disabled or absent take no hold.
func planOrgBudgets(tx *gorm.DB, cmd types.OrgBillingCommand, now int64) ([]orgUsageKey, error) {
	var budgets []Budget
	if err := tx.Where("org_id = ? AND enabled = ?", cmd.Subject.OrgID, true).Find(&budgets).Error; err != nil {
		return nil, err
	}
	s := cmd.Subject
	subjects := orgBudgetSubjects(s.OrgID, s.WorkspaceID, s.ActorUserID, s.TokenID)
	var keys []orgUsageKey
	for _, budget := range budgets {
		if subject, ok := subjects[budget.Scope]; !ok || subject != budget.SubjectId {
			continue
		}
		start, _ := OrgBudgetWindow(budget.Period, now)
		keys = append(keys, orgUsageKey{budget.Scope, budget.SubjectId, budget.Period, start})
	}
	slices.SortFunc(keys, compareOrgUsageKey)
	return keys, nil
}

// pickOrgLease returns the hinted lease for a target when it still looks able
// to cover the amount, or 0. The check is advisory: the conditional update in
// extendOrgLease is the only authority, and failing it replays the command
// with a locked-row hold. A lease of another window, organization or target is
// never picked.
func pickOrgLease(tx *gorm.DB, cmd types.OrgBillingCommand, targetType string, targetID int, amount, now int64) (int, error) {
	for _, hint := range cmd.LeaseHints {
		if hint.TargetType != targetType || hint.TargetId != targetID || hint.LeaseId <= 0 {
			continue
		}
		lease, err := orgFindOne[OrgQuotaLease](tx.Where("id = ?", hint.LeaseId))
		if err != nil {
			return 0, err
		}
		if lease != nil && lease.OrgId == cmd.Subject.OrgID && lease.TargetType == targetType && lease.TargetId == targetID &&
			lease.Status == types.OrgLeaseStatusActive && lease.ExpiresAt > now &&
			(lease.WindowEnd == 0 || lease.WindowEnd > now) && lease.Allocated+lease.Consumed+amount <= lease.Amount {
			return lease.Id, nil
		}
	}
	return 0, nil
}

// extendOrgLease takes amount from a lease with one conditional UPDATE. Zero
// rows affected means the lease was revoked, expired, left its window or filled
// up since it was picked; the command then replays without it.
func extendOrgLease(tx *gorm.DB, lease leaseUse, now int64) error {
	result := tx.Model(&OrgQuotaLease{}).
		Where("id = ? AND status = ? AND expires_at > ? AND (window_end = 0 OR window_end > ?) AND allocated + consumed + ? <= amount",
			lease.id, types.OrgLeaseStatusActive, now, now, lease.amount).
		Update("allocated", gorm.Expr("allocated + ?", lease.amount))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return &orgLeaseRejected{key: lease.key}
	}
	return nil
}

// holdOrgToken takes a hold on a limited key. An unlimited key has nothing to
// hold and reports false.
func holdOrgToken(tx *gorm.DB, tokenID int, amount int64) (bool, error) {
	result := tx.Model(&Token{}).Where("id = ? AND unlimited_quota = ? AND remain_quota >= ?", tokenID, false, amount).
		Updates(map[string]any{"remain_quota": gorm.Expr("remain_quota - ?", amount),
			"used_quota": gorm.Expr("used_quota + ?", amount)})
	if result.Error != nil {
		return false, result.Error
	}
	if result.RowsAffected == 1 {
		return true, nil
	}
	token, err := orgFindOne[Token](tx.Select("id", "unlimited_quota").Where("id = ?", tokenID))
	if err != nil {
		return false, err
	}
	if token == nil {
		return false, orgNotFoundError()
	}
	if token.UnlimitedQuota {
		return false, nil
	}
	return false, types.NewOrgAccessError(types.OrgErrKeyBudget)
}

// addDirectBudgetHold adds amount to a usage row's held quota under the row
// lock, refusing when spent + held + amount would pass the limit. With
// onlyIfEnabled a missing or disabled budget takes no hold and reports false;
// without it the hold is always recorded so the held identity stays exact.
func addDirectBudgetHold(tx *gorm.DB, usageID int, amount int64, onlyIfEnabled bool) (bool, error) {
	usage, err := orgFindOne[OrgBudgetUsage](lockForUpdate(tx.Where("id = ?", usageID)))
	if err != nil {
		return false, err
	}
	if usage == nil {
		return false, orgNotFoundError()
	}
	budget, err := orgFindOne[Budget](lockForUpdate(tx.Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ?",
		usage.OrgId, usage.Scope, usage.SubjectId, usage.Period)))
	if err != nil {
		return false, err
	}
	enabled := budget != nil && budget.Enabled
	if onlyIfEnabled && !enabled {
		return false, nil
	}
	if enabled && usage.SpentQuota+usage.HeldQuota+amount > budget.LimitQuota {
		return false, orgBudgetError(usage.Scope)
	}
	err = tx.Model(&OrgBudgetUsage{}).Where("id = ?", usage.Id).
		Updates(map[string]any{"held_quota": gorm.Expr("held_quota + ?", amount), "updated_at": common.GetTimestamp()}).Error
	return err == nil, err
}
