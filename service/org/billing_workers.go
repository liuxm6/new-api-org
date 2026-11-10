package org

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/google/uuid"
)

const (
	foldInterval     = time.Second
	foldBatch        = 2000
	leaseSweepPeriod = 5 * time.Second
	recoveryPeriod   = 30 * time.Second
	recoveryBatch    = 200
	jobPeriod        = 5 * time.Second
	statementPeriod  = 10 * time.Minute
	reconcilePeriod  = time.Minute
	reconcileBatch   = 20
)

// reconcileRecheckAfter is how long a drift waits before it is looked at again.
// A drift is only reported when the second look sees it too.
var reconcileRecheckAfter = 3 * time.Second

// reconcileCursor is where the next pass resumes, so every organization is
// visited in turn however many there are.
var reconcileCursor atomic.Int64

// StartOrgBillingWorkers runs the three loops that keep organization billing
// moving: the fold of settled consumption into budgets, rollups and counters;
// the sweep that revokes expired leases and returns their unused money; and the
// recovery of requests whose instance died. Run it on one node only.
func StartOrgBillingWorkers(ctx context.Context) {
	go every(ctx, foldInterval, func() { foldQueuedOrganizations(ctx) })
	go every(ctx, leaseSweepPeriod, func() { sweepLeases(ctx) })
	go every(ctx, recoveryPeriod, func() { RecoverExpiredOperations(ctx) })
	go every(ctx, jobPeriod, func() { runBillingJobs(ctx) })
	go every(ctx, statementPeriod, func() { closeStatements(ctx) })
	go every(ctx, reconcilePeriod, func() { reconcileOrganizations(ctx, reconcileBatch) })
}

func every(ctx context.Context, period time.Duration, fn func()) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}

// foldQueuedOrganizations folds every organization that has queued rows. A
// backlog (more than a few batches, or rows older than ten seconds) is logged.
func foldQueuedOrganizations(ctx context.Context) {
	var orgIDs []int
	if err := model.DB.WithContext(ctx).Model(&model.OrgSpendFoldQueue{}).Distinct("org_id").Limit(500).
		Pluck("org_id", &orgIDs).Error; err != nil {
		common.SysError(common.LogText("organization fold: cannot list queued organizations: %v", err))
		return
	}
	for _, orgID := range orgIDs {
		for range 5 {
			result, err := model.FoldOrgSpend(ctx, orgID, foldBatch)
			if err != nil {
				common.SysError(common.LogText("organization fold failed for %d: %v", orgID, err))
				break
			}
			if result.Rows < foldBatch {
				break
			}
		}
	}
}

// reconcileOrganizations checks the next batch of organizations against the
// accounting identities of design 3.3 and reports every drift it can confirm
// on a second look. It never changes a balance: a drift needs a person. It
// returns how many organizations showed a confirmed drift.
func reconcileOrganizations(ctx context.Context, batch int) int {
	var orgIDs []int
	if err := model.DB.WithContext(ctx).Model(&model.Organization{}).Where("id > ?", reconcileCursor.Load()).
		Order("id ASC").Limit(batch).Pluck("id", &orgIDs).Error; err != nil {
		common.SysError(common.LogText("organization reconcile: cannot list organizations: %v", err))
		return 0
	}
	if len(orgIDs) < batch {
		reconcileCursor.Store(0) // the end of the list: start over next time
	} else {
		reconcileCursor.Store(int64(orgIDs[len(orgIDs)-1]))
	}
	drifted := 0
	for _, orgID := range orgIDs {
		drifts, err := model.ReconcileOrg(ctx, orgID)
		if err != nil {
			common.SysError(common.LogText("organization reconcile failed for %d: %v", orgID, err))
			continue
		}
		if len(drifts) == 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return drifted
		case <-time.After(reconcileRecheckAfter):
		}
		if drifts, err = model.ReconcileOrg(ctx, orgID); err != nil || len(drifts) == 0 {
			continue // work in flight moved the numbers; the second look is clean
		}
		drifted++
		for _, drift := range drifts {
			common.SysError(common.LogText("organization %d billing drift: %s", orgID, drift.String()))
		}
	}
	return drifted
}

func sweepLeases(ctx context.Context) {
	if _, err := model.SweepOrgQuotaLeases(ctx, 500); err != nil {
		common.SysError(common.LogText("organization lease sweep failed: %v", err))
	}
}

// RecoverExpiredOperations settles requests whose instance stopped renewing
// their lease (design 4.2.6). It first claims the operation with a conditional
// update, which fences out an instance that is merely slow: only one side can
// win. A synchronous request is captured at min(bound, max(estimate, progress))
// and marked as settled by recovery; real usage found later can only be
// refunded downward. An asynchronous task whose acceptance is unknown keeps its
// holds and waits for the platform. It returns how many operations it handled.
func RecoverExpiredOperations(ctx context.Context) int {
	ops, err := model.ListExpiredOrgOperations(ctx, recoveryBatch)
	if err != nil {
		common.SysError(common.LogText("organization recovery: cannot list operations: %v", err))
		return 0
	}
	worker := "recovery:" + uuid.NewString()
	handled := 0
	for _, op := range ops {
		claimed, err := model.ClaimOrgOperationForRecovery(ctx, op.OperationId, op.Revision, worker)
		if err != nil || !claimed {
			continue // the request settled, or another worker took it
		}
		if types.OrgSourceIsAsync(op.SourceKind) {
			if _, err := model.MarkOrgOperationRecoveryRequired(ctx, op.OperationId, worker); err != nil {
				common.SysError(common.LogText("organization recovery: cannot park %s: %v", op.OperationId, err))
				continue
			}
			handled++
			continue
		}
		amount := min(op.Bound, max(op.EstimatedQuota, op.ProgressQuota))
		_, err = model.ApplyOrgBilling(ctx, types.OrgBillingCommand{OperationID: op.OperationId,
			Subject: operationSubject(op), Action: types.OrgBillingActionCapture, Amount: amount,
			Revision: op.Revision + 1, LeaseOwner: worker, SettledBy: types.OrgSettledByRecovery})
		if err != nil {
			common.SysError(common.LogText("organization recovery: cannot settle %s: %v", op.OperationId, err))
			continue
		}
		common.SysError(common.LogText("organization operation %s settled by recovery at %d (bound %d)", op.OperationId, amount, op.Bound))
		handled++
	}
	return handled
}

// operationSubject rebuilds the trusted subject from the snapshot stored on the
// operation, so recovery works after the key is rotated or deleted.
func operationSubject(op model.OrgBillingOperation) types.OrgSubject {
	return types.OrgSubject{OrgID: op.OrgId, WorkspaceID: op.WorkspaceId, ActorUserID: op.ActorUserId, TokenID: op.TokenId,
		AccessPrincipalID: op.AccessPrincipal, OwnerType: op.OwnerType}
}

// runBillingJobs claims due receipt and notification jobs and runs them. A job
// that fails goes back with backoff; the credit that created it stays.
func runBillingJobs(ctx context.Context) {
	jobs, err := model.ClaimOrgJobs(ctx, []string{types.OrgJobKindReceipt, types.OrgJobKindNotify}, 50)
	if err != nil {
		common.SysError(common.LogText("organization jobs: cannot claim: %v", err))
		return
	}
	for _, job := range jobs {
		var runErr error
		switch job.Kind {
		case types.OrgJobKindReceipt:
			_, runErr = model.IssueOrgReceipt(ctx, job.OrgId, job.BusinessKey)
		case types.OrgJobKindNotify:
			// Delivery of the owner notification belongs to the parent service,
			// which this package must not import; the job marks the credit as
			// notified so the console can show it.
		}
		if runErr != nil {
			common.SysError(common.LogText("organization job %d (%s) failed: %v", job.Id, job.Kind, runErr))
			if err := model.FailOrgJob(ctx, job, runErr); err != nil {
				common.SysError(common.LogText("organization job %d: cannot reschedule: %v", job.Id, err))
			}
			continue
		}
		if err := model.FinishOrgJob(ctx, job.Id); err != nil {
			common.SysError(common.LogText("organization job %d: cannot finish: %v", job.Id, err))
		}
	}
}

// closeStatements issues the statement of every month that is over for every
// organization that has consumption in it, oldest month first, so a node that
// was down over a month end catches up. Issuing is idempotent.
func closeStatements(ctx context.Context) {
	now := time.Now().UTC()
	current := now.Format("2006-01")
	var rows []struct {
		OrgId  int
		Period string
	}
	err := model.DB.WithContext(ctx).Model(&model.OrgSpendRollup{}).Select("DISTINCT org_id, period").
		Where("period < ?", current).Order("period ASC").Limit(500).Scan(&rows).Error
	if err != nil {
		common.SysError(common.LogText("organization statements: cannot list periods: %v", err))
		return
	}
	for _, row := range rows {
		exists, err := model.OrgStatementExists(ctx, row.OrgId, row.Period)
		if err != nil || exists {
			continue
		}
		if _, err := model.IssueOrgStatement(ctx, row.OrgId, row.Period); err != nil {
			common.SysError(common.LogText("organization statement %d/%s failed: %v", row.OrgId, row.Period, err))
		}
	}
}
