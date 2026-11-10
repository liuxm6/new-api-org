package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	hosttypes "github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
)

// errOrgTaskWalletPath is what the personal funding functions return for a task
// that belongs to an organization: its money moves only through the operation.
var errOrgTaskWalletPath = errors.New("organization tasks are billed only through their billing operation")

// OrgBillingOperationID returns the operation of the organization billing
// session of a request, or "" when the request has none.
func OrgBillingOperationID(info *relaycommon.RelayInfo) string {
	if info == nil {
		return ""
	}
	if session, ok := info.Billing.(*OrgBillingSession); ok {
		return session.OperationID()
	}
	return ""
}

// settleOrgOperation sets the final charge of an asynchronous organization
// operation and closes it. It returns the net charge that remains.
func settleOrgOperation(ctx context.Context, orgID int, operationID, subject string, charge int) (int, error) {
	if operationID == "" {
		common.SysError(common.LogText("organization %s %s has no billing operation", subject, fmt.Sprint(orgID)))
		return 0, errors.New("organization work has no billing operation")
	}
	net, err := model.SettleOrgAsyncCharge(ctx, orgID, operationID, int64(charge))
	if err != nil {
		return 0, err
	}
	return int(net), nil
}

// CloseOrgTaskOperation closes the operation of a task that reached a terminal
// state, at the quota the task carries. It is safe to call again: a closed
// operation is left as it is.
func CloseOrgTaskOperation(ctx context.Context, task *model.Task) bool {
	if task == nil || task.OrgId <= 0 || (task.BillingOperationId == "" && task.Quota == 0) {
		return true
	}
	net, err := settleOrgOperation(ctx, task.OrgId, task.BillingOperationId, "task "+task.TaskID, task.Quota)
	if err != nil {
		logger.LogError(ctx, common.LogText("failed to close the billing operation of task %s: %s", task.TaskID, err.Error()))
		return false
	}
	if net != task.Quota {
		task.Quota = net
		if updateErr := task.UpdateQuota(); updateErr != nil {
			logger.LogError(ctx, common.LogText("closed the operation of task %s but could not write its quota back: %s", task.TaskID, updateErr.Error()))
		}
	}
	return true
}

// refundOrgTaskQuota is RefundTaskQuota for an organization task: the operation
// is brought to a zero charge and closed, which returns the wallet, the limited
// key and the budget holds in one transaction.
func refundOrgTaskQuota(ctx context.Context, task *model.Task, reason string) bool {
	if task.BillingOperationId == "" && task.Quota == 0 {
		return true // a free model never opened an operation
	}
	quota := task.Quota
	net, err := settleOrgOperation(ctx, task.OrgId, task.BillingOperationId, "task "+task.TaskID, 0)
	if err != nil {
		logger.LogWarn(ctx, common.LogText("failed to refund the organization task %s: %s", task.TaskID, err.Error()))
		return false
	}
	if refunded := quota - net; refunded > 0 {
		model.UpdateChannelUsedQuota(task.ChannelId, -refunded)
		other := taskBillingOther(task)
		other.SetPublic("task_id", task.TaskID)
		other.SetPublic("reason", reason)
		model.RecordTaskBillingLog(model.RecordTaskBillingLogParams{
			OrgId: task.OrgId, WorkspaceId: task.WorkspaceId, ActorUserId: task.ActorUserId, UserId: task.UserId,
			LogType: model.LogTypeRefund, ChannelId: task.ChannelId, ModelName: taskModelName(task),
			Quota: refunded, TokenId: task.PrivateData.TokenId, Group: task.Group, Other: other,
		})
	}
	task.Quota = net
	if err := task.UpdateQuota(); err != nil {
		logger.LogError(ctx, common.LogText("refund succeeded but clearing the task quota failed, task %s: %s", task.TaskID, err.Error()))
	}
	return true
}

// recalculateOrgTaskQuota is RecalculateTaskQuota for an organization task. The
// operation caps the charge at what was reserved, so the quota written back is
// what the organization is really charged.
func recalculateOrgTaskQuota(ctx context.Context, task *model.Task, actualQuota int, reason *common.Message, clamps ...*common.QuotaClamp) {
	preConsumed := task.Quota
	net, err := settleOrgOperation(ctx, task.OrgId, task.BillingOperationId, "task "+task.TaskID, actualQuota)
	if err != nil {
		logger.LogError(ctx, common.LogText("failed to settle the organization task %s: %s", task.TaskID, err.Error()))
		return
	}
	delta := net - preConsumed
	if net != preConsumed {
		task.Quota = net
		if err := task.UpdateQuota(); err != nil {
			logger.LogError(ctx, common.LogText("failed to write back the settled task quota, task %s: %s", task.TaskID, err.Error()))
		}
	}
	if delta == 0 {
		return
	}
	model.UpdateChannelUsedQuota(task.ChannelId, delta)
	logType, logQuota := model.LogTypeConsume, delta
	if delta < 0 {
		logType, logQuota = model.LogTypeRefund, -delta
	}
	other := taskBillingOther(task)
	other.SetPublic("task_id", task.TaskID)
	other.SetPublic("pre_consumed_quota", preConsumed)
	other.SetPublic("actual_quota", actualQuota)
	for _, clamp := range clamps {
		attachQuotaSaturationToOther(other, clamp)
	}
	model.RecordTaskBillingLog(model.RecordTaskBillingLogParams{
		OrgId: task.OrgId, WorkspaceId: task.WorkspaceId, ActorUserId: task.ActorUserId, UserId: task.UserId,
		LogType: logType, Content: []*common.Message{reason}, ChannelId: task.ChannelId, ModelName: taskModelName(task),
		Quota: logQuota, TokenId: task.PrivateData.TokenId, Group: task.Group, Other: other,
		NodeName: task.PrivateData.NodeName,
	})
}

// settleOrgMidjourneyBilling charges a persisted organization Midjourney task.
// The price is final at submit, so the operation is captured and closed here;
// a later failure refunds through the same operation.
func settleOrgMidjourneyBilling(relayInfo *relaycommon.RelayInfo, task *model.Midjourney) (bool, error) {
	session, ok := relayInfo.Billing.(*OrgBillingSession)
	if !ok {
		task.Quota, task.TokenId, task.BillingChannelId, task.BillingOperationId = 0, 0, 0, ""
		stateErr := task.UpdateBillingState()
		return false, errors.Join(errOrgLegacyBilling("SettleMidjourneyTaskBilling", relayInfo), stateErr)
	}
	if err := session.Settle(task.Quota); err != nil {
		task.Quota, task.TokenId, task.BillingChannelId, task.BillingOperationId = 0, 0, 0, ""
		return false, errors.Join(err, task.UpdateBillingState())
	}
	task.TokenId = relayInfo.TokenId
	if _, err := settleOrgOperation(context.Background(), task.OrgId, task.BillingOperationId,
		"midjourney "+task.MjId, task.Quota); err != nil {
		return true, errors.Join(err, task.UpdateBillingState())
	}
	return true, task.UpdateBillingState()
}

// refundOrgMidjourneyQuota returns the charge of a failed organization task to
// the wallet, the limited key and the budgets through its operation.
func refundOrgMidjourneyQuota(ctx context.Context, task *model.Midjourney, reason string) bool {
	quota := task.Quota
	net, err := settleOrgOperation(ctx, task.OrgId, task.BillingOperationId, "midjourney "+task.MjId, 0)
	if err != nil {
		logger.LogWarn(ctx, common.LogText("failed to refund the organization Midjourney task %s: %s", task.MjId, err.Error()))
		return false
	}
	if refunded := quota - net; refunded > 0 {
		billingChannelID := task.GetBillingChannelId()
		model.UpdateChannelUsedQuota(billingChannelID, -refunded)
		other := model.NewLogOther()
		other.SetPublic("task_id", task.MjId)
		other.SetPublic("reason", reason)
		model.RecordTaskBillingLog(model.RecordTaskBillingLogParams{
			OrgId: task.OrgId, WorkspaceId: task.WorkspaceId, ActorUserId: task.ActorUserId, UserId: task.UserId,
			LogType: model.LogTypeRefund, ChannelId: billingChannelID, ModelName: CovertMjpActionToModelName(task.Action),
			Quota: refunded, TokenId: task.TokenId, Other: other,
		})
	}
	task.Quota = net
	if err := task.UpdateBillingState(); err != nil {
		logger.LogError(ctx, common.LogText("Midjourney refund succeeded but clearing the quota failed, task %s: %s", task.MjId, err.Error()))
	}
	return true
}

const (
	staleOrgOperationAge   = 10 * 60
	staleOrgOperationBatch = 200
)

// SweepStuckOrgOperations closes asynchronous organization operations that were
// captured but never finalized: a settlement that failed after the charge, or a
// task that reached a terminal state while the database was unavailable. A task
// that is still running is left to polling. A failed task that still carries a
// charge is refunded again. An operation with no row behind it is left for the
// platform's billing-operations list.
func SweepStuckOrgOperations(ctx context.Context) int {
	ops, err := model.ListStaleCapturedOrgOperations(ctx, staleOrgOperationAge, staleOrgOperationBatch)
	if err != nil {
		logger.LogError(ctx, common.LogText("organization operation sweep cannot list: %s", err.Error()))
		return 0
	}
	handled := 0
	for _, op := range ops {
		if sweepStuckOrgOperation(ctx, op) {
			handled++
		}
	}
	return handled
}

func sweepStuckOrgOperation(ctx context.Context, op model.OrgBillingOperation) bool {
	if op.SourceKind == hosttypes.OrgSourceMidjourney {
		task, err := model.GetMidjourneyByBillingOperation(op.OrgId, op.OperationId)
		if err != nil || task == nil {
			return false
		}
		if task.Progress == "100%" && task.Status == "FAILURE" {
			return RefundMidjourneyQuota(ctx, task, "Composition failed")
		}
		_, err = settleOrgOperation(ctx, op.OrgId, op.OperationId, "midjourney "+task.MjId, task.Quota)
		return err == nil
	}
	task, err := model.GetTaskByBillingOperation(op.OrgId, op.OperationId)
	if err != nil || task == nil {
		return false
	}
	switch task.Status {
	case model.TaskStatusFailure:
		return RefundTaskQuota(ctx, task, task.FailReason)
	case model.TaskStatusSuccess:
		return CloseOrgTaskOperation(ctx, task)
	}
	return false
}

// chargeOrgViolationFee charges the fee of a failed organization request as an
// operation of its own: the request's own session was already refunded, and the
// fee is the extra the admission bound (orgViolationFeeQuota) allowed for. It
// goes through the same wallet, key and budget rules as any charge, so a fee the
// organization cannot cover is not taken rather than overdrawing it.
func chargeOrgViolationFee(ctx *gin.Context, relayInfo *relaycommon.RelayInfo, feeQuota int) bool {
	fee := *relayInfo
	fee.Billing = nil
	session, apiErr := NewOrgBillingSession(ctx, &fee, int64(feeQuota), hosttypes.OrgSourceViolationFee)
	if apiErr != nil {
		logger.LogError(ctx, common.LogText("organization violation fee not charged: %s", apiErr.Error()))
		return false
	}
	if err := session.Settle(feeQuota); err != nil {
		session.Refund(ctx)
		logger.LogError(ctx, common.LogText("failed to settle the organization violation fee: %s", err.Error()))
		return false
	}
	return true
}
