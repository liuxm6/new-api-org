package model

import (
	"context"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

const (
	// OrgLeaseTTLSeconds is how long a quota lease may admit requests.
	OrgLeaseTTLSeconds = 10
	// OrgLeaseWindowMarginSeconds keeps a budget lease from outliving its window.
	OrgLeaseWindowMarginSeconds = 2
	orgMaxRequestBound          = math.MaxInt32
)

// OrgLeaseShards is how many leases one instance keeps per target. Each lease
// row is a counter every request on its shard must lock, so the shard count
// bounds the throughput of one target (design review 2026-11-08). It changes
// no invariant: a lease only ever holds money it took with a conditional update.
// Set ORG_LEASE_SHARDS (1-64) to match the offered rate.
var OrgLeaseShards = orgLeaseShardsFromEnv()

func orgLeaseShardsFromEnv() int {
	shards := common.GetEnvOrDefault("ORG_LEASE_SHARDS", 16)
	return min(max(shards, 1), 64)
}

// ApplyOrgBilling runs one billing command in a single database transaction
// (design 4.2.4). A lease that loses its conditional update, a deadlock, or the
// loss of a race to insert the same operation replays the whole transaction;
// a lost lease is then skipped in favour of a locked-row hold, so a revoked or
// exhausted lease can never admit anything.
func ApplyOrgBilling(ctx context.Context, cmd types.OrgBillingCommand) (types.OrgBillingResult, error) {
	if err := validateOrgCommand(cmd); err != nil {
		return types.OrgBillingResult{}, err
	}
	avoid := map[string]bool{}
	var lastErr error
	for attempt := 1; attempt <= orgBillingMaxAttempts; attempt++ {
		var result types.OrgBillingResult
		err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var err error
			result, err = applyOrgBillingTx(tx, cmd, avoid)
			return err
		})
		if err == nil {
			return result, nil
		}
		var rejected *orgLeaseRejected
		switch {
		case errors.As(err, &rejected):
			avoid[rejected.key] = true
		case isRetryableOrgError(err):
			time.Sleep(time.Duration(attempt) * 3 * time.Millisecond)
		default:
			return types.OrgBillingResult{}, err
		}
		lastErr = err
	}
	return types.OrgBillingResult{}, lastErr
}

func validateOrgCommand(cmd types.OrgBillingCommand) error {
	if cmd.OperationID == "" || len(cmd.OperationID) > 64 || cmd.Subject.OrgID <= 0 || cmd.Revision < 0 {
		return orgInvalidError()
	}
	switch cmd.Action {
	case types.OrgBillingActionReserve, types.OrgBillingActionTopUpReserve:
		if cmd.Bound <= 0 || cmd.Bound > orgMaxRequestBound {
			return orgInvalidError()
		}
	case types.OrgBillingActionCapture, types.OrgBillingActionFinalize:
		// An amount above the bound is legal: it is capped and the rest written off.
		if cmd.Amount < 0 {
			return orgInvalidError()
		}
	case types.OrgBillingActionRefund:
		if cmd.Amount <= 0 {
			return orgInvalidError()
		}
	case types.OrgBillingActionCancel:
	default:
		return orgInvalidError()
	}
	return nil
}

// isRetryableOrgError reports failures that a fresh transaction can resolve:
// deadlocks, lock timeouts, serialization failures, and a lost race to insert
// the same operation.
func isRetryableOrgError(err error) bool {
	if errors.Is(err, errOrgRetry) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"deadlock", "lock wait timeout", "could not serialize", "database is locked",
		"sqlstate 40001", "sqlstate 40p01", "error 1213", "error 1205", "duplicate entry", "duplicate key",
		"unique constraint failed", "sqlstate 23505", "error 1062"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func applyOrgBillingTx(tx *gorm.DB, cmd types.OrgBillingCommand, avoid map[string]bool) (types.OrgBillingResult, error) {
	switch cmd.Action {
	case types.OrgBillingActionReserve:
		return reserveOrgTx(tx, cmd, avoid)
	case types.OrgBillingActionTopUpReserve:
		return topUpOrgTx(tx, cmd, avoid)
	case types.OrgBillingActionCapture:
		return captureOrgTx(tx, cmd)
	case types.OrgBillingActionFinalize:
		return finalizeOrgTx(tx, cmd)
	case types.OrgBillingActionCancel:
		return cancelOrgTx(tx, cmd)
	case types.OrgBillingActionRefund:
		return refundOrgTx(tx, cmd)
	}
	return types.OrgBillingResult{}, orgInvalidError()
}

func operationBelongs(op *OrgBillingOperation, s types.OrgSubject) bool {
	return op.OrgId == s.OrgID && op.WorkspaceId == s.WorkspaceID && op.TokenId == s.TokenID &&
		op.ActorUserId == s.ActorUserID && op.AccessPrincipal == s.AccessPrincipalID && op.OwnerType == s.OwnerType
}

// loadOrgOperationTx reads an operation under a row lock. Another tenant's
// operation is reported as missing.
func loadOrgOperationTx(tx *gorm.DB, cmd types.OrgBillingCommand) (*OrgBillingOperation, error) {
	op, err := orgFindOne[OrgBillingOperation](lockForUpdate(tx.Where("operation_id = ?", cmd.OperationID)))
	if err != nil {
		return nil, err
	}
	if op == nil || !operationBelongs(op, cmd.Subject) {
		return nil, orgNotFoundError()
	}
	return op, nil
}

// fenceOrgOperation refuses a command from an instance that does not own the
// operation lease (design 4.2.6). Asynchronous operations drop the owner once
// accepted, and terminal ones never carry one.
func fenceOrgOperation(op *OrgBillingOperation, cmd types.OrgBillingCommand) error {
	if op.LeaseOwner != "" && op.LeaseOwner != cmd.LeaseOwner {
		return orgConflictError()
	}
	return nil
}

func decodeOrgHolds(raw string) ([]types.OrgHold, error) {
	var holds []types.OrgHold
	if raw == "" {
		return holds, nil
	}
	err := common.Unmarshal([]byte(raw), &holds)
	return holds, err
}

func encodeOrgHolds(holds []types.OrgHold) (string, error) {
	data, err := common.Marshal(holds)
	return string(data), err
}

// orgResult is the committed view of an operation.
func orgResult(op *OrgBillingOperation, holds []types.OrgHold, replayed bool, applied int64) types.OrgBillingResult {
	return types.OrgBillingResult{OperationID: op.OperationId, State: op.State, Revision: op.Revision, Bound: op.Bound,
		Captured: op.CapturedQuota - op.RefundedQuota, Writeoff: op.WriteoffQuota, AppliedDelta: applied,
		Replayed: replayed, Holds: holds}
}

// orgBudgetError names the scope that refused a budget hold.
func orgBudgetError(scope string) error {
	switch scope {
	case types.BudgetScopeWorkspace:
		return types.NewOrgAccessError(types.OrgErrWorkspaceBudget)
	case types.BudgetScopeMember:
		return types.NewOrgAccessError(types.OrgErrMemberBudget)
	case types.BudgetScopeKey:
		return types.NewOrgAccessError(types.OrgErrKeyBudget)
	}
	return types.NewOrgAccessError(types.OrgErrBudgetExceeded)
}
