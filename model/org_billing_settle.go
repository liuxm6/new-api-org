package model

import (
	"slices"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// settleOrgHoldsTx closes every hold of an operation once the final charge is
// known: what was not consumed goes back to its source, what was consumed stays
// consumed. A cancel is a settlement with charge 0. Locked-row targets are
// updated first and lease rows last, by id, matching the reserve lock order.
func settleOrgHoldsTx(tx *gorm.DB, holds []types.OrgHold, charge int64) error {
	pending, err := releaseOrgHoldsTx(tx, holds, charge)
	if err != nil {
		return err
	}
	return applyLeaseSettlementsTx(tx, pending, charge)
}

// pendingLeaseSettlement is one lease update held back to the end of the
// transaction, so its row lock is held for as few statements as possible.
type pendingLeaseSettlement struct {
	id     int
	amount int64
}

// releaseOrgHoldsTx settles the locked-row holds now and returns the lease
// updates for the caller to apply last.
func releaseOrgHoldsTx(tx *gorm.DB, holds []types.OrgHold, charge int64) ([]pendingLeaseSettlement, error) {
	var leases []pendingLeaseSettlement
	for i := range holds {
		hold := &holds[i]
		hold.Released, hold.Captured = hold.Amount-charge, charge
		if hold.Source == types.OrgHoldSourceDirect {
			if err := releaseDirectOrgHold(tx, *hold); err != nil {
				return nil, err
			}
			continue
		}
		id, err := strconv.Atoi(hold.Source)
		if err != nil {
			return nil, err
		}
		leases = append(leases, pendingLeaseSettlement{id: id, amount: hold.Amount})
	}
	slices.SortFunc(leases, func(a, b pendingLeaseSettlement) int { return a.id - b.id })
	return leases, nil
}

// applyLeaseSettlementsTx moves each lease's allocation to consumed, by id.
func applyLeaseSettlementsTx(tx *gorm.DB, leases []pendingLeaseSettlement, charge int64) error {
	for _, lease := range leases {
		result := tx.Model(&OrgQuotaLease{}).Where("id = ? AND allocated >= ?", lease.id, lease.amount).
			Updates(map[string]any{"allocated": gorm.Expr("allocated - ?", lease.amount),
				"consumed": gorm.Expr("consumed + ?", charge)})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return orgConflictError() // the lease no longer carries this allocation
		}
	}
	return nil
}

// releaseDirectOrgHold returns the unconsumed part of a locked-row hold.
func releaseDirectOrgHold(tx *gorm.DB, hold types.OrgHold) error {
	if hold.Released <= 0 {
		return nil
	}
	switch hold.TargetType {
	case types.OrgHoldTargetWallet:
		return IncreaseOrgWalletTx(tx, hold.TargetId, hold.Released)
	case types.OrgHoldTargetToken:
		// Unscoped: a key deleted while its request was in flight is still refunded.
		return restoreOrgToken(tx, hold.TargetId, hold.Released)
	case types.OrgHoldTargetBudget:
		return tx.Model(&OrgBudgetUsage{}).Where("id = ?", hold.TargetId).
			Updates(map[string]any{"held_quota": gorm.Expr("held_quota - ?", hold.Released),
				"updated_at": common.GetTimestamp()}).Error
	}
	return nil
}

// restoreOrgToken gives a limited key its quota back, deleted or not.
func restoreOrgToken(tx *gorm.DB, tokenID int, amount int64) error {
	return tx.Unscoped().Model(&Token{}).Where("id = ?", tokenID).
		Updates(map[string]any{"remain_quota": gorm.Expr("remain_quota + ?", amount),
			"used_quota": gorm.Expr("used_quota - ?", amount)}).Error
}

// orgSpendInput is one accounting fact: the event, and the fold queue row that
// carries it into budget usage, rollups and used_quota.
type orgSpendInput struct {
	kind     string
	revision int64
	delta    int64
	writeoff int64
	holds    []types.OrgHold
	snapshot string
	original int
}

// recordOrgSpendTx appends the event and its fold queue row in the caller's
// transaction, so each fact is folded exactly once.
func recordOrgSpendTx(tx *gorm.DB, op *OrgBillingOperation, in orgSpendInput, now int64) (*OrgSpendEvent, error) {
	event := OrgSpendEvent{OrgId: op.OrgId, WorkspaceId: op.WorkspaceId, ActorUserId: op.ActorUserId, TokenId: op.TokenId,
		AccessPrincipal: op.AccessPrincipal, OperationId: op.OperationId, EventKind: in.kind, Revision: in.revision,
		DeltaQuota: in.delta, EffectiveAt: op.EffectiveAt, RecordedAt: now, ModelName: op.ModelName,
		OriginalEventId: in.original, PriceSnapshot: in.snapshot}
	if err := tx.Create(&event).Error; err != nil {
		return nil, err
	}
	var budgetHolds []types.OrgHold
	for _, hold := range in.holds {
		if hold.TargetType == types.OrgHoldTargetBudget {
			budgetHolds = append(budgetHolds, hold)
		}
	}
	encoded, err := encodeOrgHolds(budgetHolds)
	if err != nil {
		return nil, err
	}
	queue := OrgSpendFoldQueue{OrgId: op.OrgId, EventId: event.Id, OperationId: op.OperationId, WorkspaceId: op.WorkspaceId,
		ActorUserId: op.ActorUserId, TokenId: op.TokenId, EffectiveAt: op.EffectiveAt, Kind: in.kind, ModelName: op.ModelName,
		SpendDelta: in.delta, WriteoffQuota: in.writeoff, Holds: encoded, RollupKey: orgRollupKey(op.ModelName, in.snapshot),
		Revision: in.revision, CreatedAt: now}
	if in.kind == types.OrgFoldKindRefund {
		queue.Revision = 0 // a refund is never a request
	}
	return &event, tx.Create(&queue).Error
}

// captureOrgTx records what a request actually cost, capped at the bound; the
// part above the bound is written off, never charged. A synchronous operation
// is terminal after one capture. An asynchronous one keeps its whole bound held
// and may revise its charge inside [0, bound] until Finalize.
func captureOrgTx(tx *gorm.DB, cmd types.OrgBillingCommand) (types.OrgBillingResult, error) {
	op, err := loadOrgOperationTx(tx, cmd)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	holds, err := decodeOrgHolds(op.Holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	charge := min(cmd.Amount, op.Bound)
	writeoff := cmd.Amount - charge
	finished := op.State == types.OrgOpStateCaptured || op.State == types.OrgOpStateClosed
	if finished && op.Revision > 0 && cmd.Revision == op.Revision && charge == op.CapturedQuota {
		return orgResult(op, holds, true, 0), nil
	}
	if (op.State != types.OrgOpStateReserved && op.State != types.OrgOpStateCaptured) || cmd.Revision != op.Revision+1 {
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
	delta := charge - op.CapturedQuota
	update := map[string]any{"revision": cmd.Revision, "captured_quota": charge, "writeoff_quota": writeoff,
		"lease_owner": "", "lease_until": 0, "updated_at": now}
	state := types.OrgOpStateCaptured
	var pendingLeases []pendingLeaseSettlement
	if types.OrgSourceIsAsync(op.SourceKind) {
		for i := range holds {
			holds[i].Captured = charge
		}
	} else {
		if pendingLeases, err = releaseOrgHoldsTx(tx, holds, charge); err != nil {
			return types.OrgBillingResult{}, err
		}
		state = types.OrgOpStateClosed
		update["settled_by"] = types.OrgSettledByRequest
		if cmd.SettledBy != "" {
			update["settled_by"] = cmd.SettledBy
		}
	}
	encoded, err := encodeOrgHolds(holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	update["state"], update["holds"] = state, encoded
	if _, err := recordOrgSpendTx(tx, op, orgSpendInput{kind: types.OrgSpendEventCapture, revision: cmd.Revision,
		delta: delta, writeoff: writeoff - op.WriteoffQuota, holds: holds, snapshot: cmd.PriceSnapshot}, now); err != nil {
		return types.OrgBillingResult{}, err
	}
	if err := tx.Model(&OrgBillingOperation{}).Where("id = ?", op.Id).Updates(update).Error; err != nil {
		return types.OrgBillingResult{}, err
	}
	if err := applyLeaseSettlementsTx(tx, pendingLeases, charge); err != nil {
		return types.OrgBillingResult{}, err
	}
	op.State, op.Revision, op.CapturedQuota, op.WriteoffQuota, op.Holds = state, cmd.Revision, charge, writeoff, encoded
	return orgResult(op, holds, false, delta), nil
}

// finalizeOrgTx closes an asynchronous operation at its last captured charge
// and releases the rest of the bound. It writes no event: the last capture
// already recorded the charge.
func finalizeOrgTx(tx *gorm.DB, cmd types.OrgBillingCommand) (types.OrgBillingResult, error) {
	op, err := loadOrgOperationTx(tx, cmd)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	holds, err := decodeOrgHolds(op.Holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	if !types.OrgSourceIsAsync(op.SourceKind) || cmd.Revision != op.Revision || min(cmd.Amount, op.Bound) != op.CapturedQuota {
		return types.OrgBillingResult{}, orgConflictError()
	}
	switch op.State {
	case types.OrgOpStateClosed:
		return orgResult(op, holds, true, 0), nil
	case types.OrgOpStateCaptured:
	default:
		return types.OrgBillingResult{}, orgConflictError()
	}
	now, err := orgDBNow(tx)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	if err := settleOrgHoldsTx(tx, holds, op.CapturedQuota); err != nil {
		return types.OrgBillingResult{}, err
	}
	encoded, err := encodeOrgHolds(holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	err = tx.Model(&OrgBillingOperation{}).Where("id = ?", op.Id).
		Updates(map[string]any{"state": types.OrgOpStateClosed, "holds": encoded, "settled_by": types.OrgSettledByRequest,
			"lease_owner": "", "lease_until": 0, "updated_at": now}).Error
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	op.State, op.Holds = types.OrgOpStateClosed, encoded
	return orgResult(op, holds, false, 0), nil
}

// cancelOrgTx gives every hold back. It writes no event and no queue row, so a
// cancelled request leaves no accounting trace and can never be a negative
// charge. An operation that already captured cannot be cancelled.
func cancelOrgTx(tx *gorm.DB, cmd types.OrgBillingCommand) (types.OrgBillingResult, error) {
	op, err := loadOrgOperationTx(tx, cmd)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	holds, err := decodeOrgHolds(op.Holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	switch op.State {
	case types.OrgOpStateCanceled:
		return orgResult(op, holds, true, 0), nil
	case types.OrgOpStateReserved:
	default:
		return types.OrgBillingResult{}, orgConflictError()
	}
	if err := fenceOrgOperation(op, cmd); err != nil {
		return types.OrgBillingResult{}, err
	}
	now, err := orgDBNow(tx)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	if err := settleOrgHoldsTx(tx, holds, 0); err != nil {
		return types.OrgBillingResult{}, err
	}
	encoded, err := encodeOrgHolds(holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	err = tx.Model(&OrgBillingOperation{}).Where("id = ?", op.Id).
		Updates(map[string]any{"state": types.OrgOpStateCanceled, "holds": encoded, "settled_by": types.OrgSettledByRequest,
			"lease_owner": "", "lease_until": 0, "updated_at": now}).Error
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	op.State, op.Holds = types.OrgOpStateCanceled, encoded
	return orgResult(op, holds, false, 0), nil
}

// refundOrgTx returns money after the operation is terminal. Refunds have their
// own revision sequence, never exceed the net charge, and only change spend and
// the wallet: they leave budget holds alone (design 4.2.4).
func refundOrgTx(tx *gorm.DB, cmd types.OrgBillingCommand) (types.OrgBillingResult, error) {
	op, err := loadOrgOperationTx(tx, cmd)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	holds, err := decodeOrgHolds(op.Holds)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	prior, err := orgFindOne[OrgSpendEvent](tx.Where("operation_id = ? AND event_kind = ? AND revision = ?",
		op.OperationId, types.OrgSpendEventRefund, cmd.Revision))
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	if prior != nil {
		if -prior.DeltaQuota != cmd.Amount {
			return types.OrgBillingResult{}, orgConflictError()
		}
		replay := orgResult(op, holds, true, 0)
		replay.Revision = cmd.Revision
		return replay, nil
	}
	if op.State != types.OrgOpStateClosed || cmd.Revision != op.RefundRevision+1 || cmd.Amount > op.CapturedQuota-op.RefundedQuota {
		return types.OrgBillingResult{}, orgConflictError()
	}
	now, err := orgDBNow(tx)
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	if err := IncreaseOrgWalletTx(tx, op.BillingUserId, cmd.Amount); err != nil {
		return types.OrgBillingResult{}, err
	}
	for _, hold := range holds {
		if hold.TargetType == types.OrgHoldTargetToken {
			if err := restoreOrgToken(tx, hold.TargetId, cmd.Amount); err != nil {
				return types.OrgBillingResult{}, err
			}
		}
	}
	origin, err := orgFindOne[OrgSpendEvent](tx.Where("operation_id = ? AND event_kind = ?", op.OperationId, types.OrgSpendEventCapture).
		Order("revision DESC"))
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	input := orgSpendInput{kind: types.OrgSpendEventRefund, revision: cmd.Revision, delta: -cmd.Amount}
	if origin != nil {
		input.original, input.snapshot = origin.Id, origin.PriceSnapshot
	}
	if _, err := recordOrgSpendTx(tx, op, input, now); err != nil {
		return types.OrgBillingResult{}, err
	}
	op.RefundedQuota += cmd.Amount
	op.RefundRevision = cmd.Revision
	err = tx.Model(&OrgBillingOperation{}).Where("id = ?", op.Id).
		Updates(map[string]any{"refunded_quota": op.RefundedQuota, "refund_revision": op.RefundRevision, "updated_at": now}).Error
	if err != nil {
		return types.OrgBillingResult{}, err
	}
	result := orgResult(op, holds, false, -cmd.Amount)
	result.Revision = cmd.Revision
	return result, nil
}
