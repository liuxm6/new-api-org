package model

import (
	"context"
	"time"

	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// SettleOrgAsyncCharge brings an asynchronous operation (task, Midjourney) to
// its final charge and closes it, in one transaction. The charge is capped at
// the bound; the part above is written off. A captured operation is revised and
// finalized, releasing the unused holds. A closed one can only go down, through
// a refund of the difference. Repeating a call with the same charge changes
// nothing. It returns the net charge left on the operation.
func SettleOrgAsyncCharge(ctx context.Context, orgID int, operationID string, charge int64) (int64, error) {
	var net int64
	var lastErr error
	for attempt := 1; attempt <= orgBillingMaxAttempts; attempt++ {
		err := DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var err error
			net, err = settleOrgAsyncTx(tx, orgID, operationID, charge)
			return err
		})
		if err == nil {
			return net, nil
		}
		if !isRetryableOrgError(err) {
			return 0, err
		}
		lastErr = err
		time.Sleep(time.Duration(attempt) * 3 * time.Millisecond)
	}
	return 0, lastErr
}

func settleOrgAsyncTx(tx *gorm.DB, orgID int, operationID string, charge int64) (int64, error) {
	if charge < 0 {
		return 0, orgInvalidError()
	}
	op, err := loadAsyncOrgOperation(tx, orgID, operationID)
	if err != nil {
		return 0, err
	}
	cmd := types.OrgBillingCommand{OperationID: operationID, Subject: types.OrgSubject{OrgID: op.OrgId,
		WorkspaceID: op.WorkspaceId, ActorUserID: op.ActorUserId, TokenID: op.TokenId,
		AccessPrincipalID: op.AccessPrincipal, OwnerType: op.OwnerType}}
	target := min(charge, op.Bound)

	switch op.State {
	case types.OrgOpStateCaptured:
		if target != op.CapturedQuota || charge-target != op.WriteoffQuota {
			origin, err := orgFindOne[OrgSpendEvent](tx.Where("operation_id = ? AND event_kind = ?", op.OperationId,
				types.OrgSpendEventCapture).Order("revision DESC"))
			if err != nil {
				return 0, err
			}
			capture := cmd
			capture.Action, capture.Amount, capture.Revision = types.OrgBillingActionCapture, charge, op.Revision+1
			if origin != nil {
				capture.PriceSnapshot = origin.PriceSnapshot
			}
			if _, err := captureOrgTx(tx, capture); err != nil {
				return 0, err
			}
			if op, err = loadAsyncOrgOperation(tx, orgID, operationID); err != nil {
				return 0, err
			}
		}
		finalize := cmd
		finalize.Action, finalize.Amount, finalize.Revision = types.OrgBillingActionFinalize, op.CapturedQuota, op.Revision
		if _, err := finalizeOrgTx(tx, finalize); err != nil {
			return 0, err
		}
		return op.CapturedQuota, nil
	case types.OrgOpStateClosed:
		net := op.CapturedQuota - op.RefundedQuota
		if target >= net {
			return net, nil
		}
		refund := cmd
		refund.Action, refund.Amount, refund.Revision = types.OrgBillingActionRefund, net-target, op.RefundRevision+1
		if _, err := refundOrgTx(tx, refund); err != nil {
			return 0, err
		}
		return target, nil
	}
	// Still reserved, cancelled, or parked for recovery: the charge is not
	// settled here, and the platform handles it from the operations list.
	return 0, orgConflictError()
}

func loadAsyncOrgOperation(tx *gorm.DB, orgID int, operationID string) (*OrgBillingOperation, error) {
	op, err := orgFindOne[OrgBillingOperation](lockForUpdate(tx.Where("operation_id = ?", operationID)))
	if err != nil {
		return nil, err
	}
	if op == nil || op.OrgId != orgID {
		return nil, orgNotFoundError()
	}
	if !types.OrgSourceIsAsync(op.SourceKind) {
		return nil, orgConflictError()
	}
	return op, nil
}

// ListStaleCapturedOrgOperations lists asynchronous operations that were
// captured but never finalized and have not changed for olderThan seconds.
func ListStaleCapturedOrgOperations(ctx context.Context, olderThan int64, limit int) ([]OrgBillingOperation, error) {
	db := DB.WithContext(ctx)
	now, err := orgDBNow(db)
	if err != nil {
		return nil, err
	}
	var ops []OrgBillingOperation
	err = db.Where("state = ? AND source_kind IN ? AND updated_at < ?", types.OrgOpStateCaptured,
		[]string{types.OrgSourceTask, types.OrgSourceMidjourney}, now-olderThan).
		Order("id ASC").Limit(limit).Find(&ops).Error
	return ops, err
}

// GetTaskByBillingOperation returns the task billed on an operation of the
// organization, or nil.
func GetTaskByBillingOperation(orgID int, operationID string) (*Task, error) {
	return orgFindOne[Task](DB.Where("org_id = ? AND billing_operation_id = ?", orgID, operationID))
}

// GetMidjourneyByBillingOperation is GetTaskByBillingOperation for Midjourney.
func GetMidjourneyByBillingOperation(orgID int, operationID string) (*Midjourney, error) {
	return orgFindOne[Midjourney](DB.Where("org_id = ? AND billing_operation_id = ?", orgID, operationID))
}
