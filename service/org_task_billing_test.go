package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/setting/model_setting"
	hosttypes "github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// submitOrgTask runs the submit half of an organization task: reserve the
// price, settle it, and persist the task with the operation it was billed on.
func submitOrgTask(t *testing.T, e *orgSessionEnv, price int) *model.Task {
	t.Helper()
	require.NoError(t, e.db.AutoMigrate(&model.Task{}, &model.Log{}))
	info := e.info()
	info.TaskRelayInfo = &relaycommon.TaskRelayInfo{}
	info.ChannelMeta = &relaycommon.ChannelMeta{}
	c := testContext("")
	require.Nil(t, PreConsumeBilling(c, price, info))
	operationID := OrgBillingOperationID(info)
	require.NotEmpty(t, operationID)
	require.NoError(t, SettleBilling(c, info, price))

	task := model.InitTask("test", info)
	task.Quota = price
	task.BillingOperationId = operationID
	require.NoError(t, task.Insert())
	return task
}

func TestOrgTaskBillingFollowsTheOperation(t *testing.T) {
	ctx := context.Background()

	t.Run("a failed task gives the price back and closes the operation", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		task := submitOrgTask(t, e, 1000)
		assert.EqualValues(t, 9000, e.quota(t))

		require.True(t, RefundTaskQuota(ctx, task, "upstream failed"))
		assert.EqualValues(t, 10_000, e.quota(t))
		assert.Zero(t, task.Quota)
		assert.True(t, RefundTaskQuota(ctx, task, "again"), "a second refund is a no-op")
		assert.EqualValues(t, 10_000, e.quota(t))
	})

	t.Run("a cheaper result refunds the difference and a dearer one is capped at the price", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		task := submitOrgTask(t, e, 1000)
		RecalculateTaskQuota(ctx, task, 600, common.NewMessage("actual"))
		assert.EqualValues(t, 600, task.Quota)
		assert.EqualValues(t, 9400, e.quota(t))

		dearer := submitOrgTask(t, e, 1000)
		RecalculateTaskQuota(ctx, dearer, 5000, common.NewMessage("actual"))
		assert.EqualValues(t, 1000, dearer.Quota, "the organization is never charged above what was reserved")
		assert.EqualValues(t, 8400, e.quota(t))
	})

	t.Run("a task that succeeds at its price is closed without a refund", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		task := submitOrgTask(t, e, 1000)
		require.True(t, CloseOrgTaskOperation(ctx, task))
		assert.EqualValues(t, 9000, e.quota(t))
		assert.Equal(t, hosttypes.OrgOpStateClosed, orgOperationState(t, e, task))
		require.True(t, CloseOrgTaskOperation(ctx, task), "closing twice changes nothing")
		assert.EqualValues(t, 9000, e.quota(t))
	})

	t.Run("a zero-quota failure at submit still closes the operation", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		task := submitOrgTask(t, e, 1000)
		task.Quota = 0
		require.True(t, CloseOrgTaskOperation(ctx, task))
		assert.EqualValues(t, 10_000, e.quota(t))
		assert.Equal(t, hosttypes.OrgOpStateClosed, orgOperationState(t, e, task))
	})

	t.Run("the personal funding path refuses an organization task", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		task := submitOrgTask(t, e, 1000)
		assert.ErrorIs(t, taskAdjustFunding(task, -1000), errOrgTaskWalletPath)
		assert.ErrorIs(t, taskAdjustFunding(task, 1000), errOrgTaskWalletPath)
		assert.EqualValues(t, 9000, e.quota(t))
	})

	t.Run("a task without an operation keeps its quota for reconciliation", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		task := submitOrgTask(t, e, 1000)
		task.BillingOperationId = ""
		assert.False(t, RefundTaskQuota(ctx, task, "lost"))
		assert.EqualValues(t, 1000, task.Quota)
		assert.EqualValues(t, 9000, e.quota(t))
	})
}

func orgOperationState(t *testing.T, e *orgSessionEnv, task *model.Task) string {
	t.Helper()
	var op model.OrgBillingOperation
	require.NoError(t, e.db.Where("operation_id = ?", task.BillingOperationId).First(&op).Error)
	return op.State
}

func TestOrgMidjourneyBilling(t *testing.T) {
	ctx := context.Background()

	submit := func(t *testing.T, e *orgSessionEnv, price int) (*model.Midjourney, *relaycommon.RelayInfo) {
		t.Helper()
		require.NoError(t, e.db.AutoMigrate(&model.Midjourney{}, &model.Log{}))
		info := e.info()
		info.TaskRelayInfo = &relaycommon.TaskRelayInfo{}
		info.ChannelMeta = &relaycommon.ChannelMeta{}
		require.Nil(t, PreConsumeBilling(testContext(""), price, info))
		task := &model.Midjourney{UserId: e.wallet.Id, Code: 1, MjId: "mj-" + t.Name(), Action: "IMAGINE", ChannelId: 7}
		task.ApplyOrgSubject(e.subject)
		prepared, err := PrepareMidjourneyTaskBilling(info, task, price, true)
		require.NoError(t, err)
		require.True(t, prepared)
		require.NotEmpty(t, task.BillingOperationId)
		require.NoError(t, task.Insert())
		return task, info
	}

	t.Run("submit charges through the operation and a failure refunds it", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		task, info := submit(t, e, 800)
		assert.EqualValues(t, 9200, e.quota(t), "the price is held from the wallet")
		applied, err := SettleMidjourneyTaskBilling(info, task, true)
		require.NoError(t, err)
		require.True(t, applied)
		assert.EqualValues(t, 9200, e.quota(t))
		assert.False(t, info.Billing.NeedsRefund())

		require.True(t, RefundMidjourneyQuota(ctx, task, "Composition failed"))
		assert.EqualValues(t, 10_000, e.quota(t))
		assert.Zero(t, task.Quota)
		assert.True(t, RefundMidjourneyQuota(ctx, task, "again"))
		assert.EqualValues(t, 10_000, e.quota(t))
	})

	t.Run("a rejected submission cancels the hold and leaves no trace", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		info := e.info()
		info.TaskRelayInfo = &relaycommon.TaskRelayInfo{}
		require.Nil(t, PreConsumeBilling(testContext(""), 800, info))
		assert.EqualValues(t, 9200, e.quota(t))
		refundUnsettledForTest(info)
		assert.EqualValues(t, 10_000, e.quota(t))
	})

	t.Run("the personal funding function refuses an organization request", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		_, err := postConsumeQuotaWithResult(e.info(), 100, 0, false)
		require.Error(t, err)
		assert.EqualValues(t, 10_000, e.quota(t), "nothing was charged")
	})

	t.Run("a request without a session is never settled for free", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		require.NoError(t, e.db.AutoMigrate(&model.Midjourney{}))
		info := e.info()
		task := &model.Midjourney{UserId: e.wallet.Id, Code: 1, MjId: "mj-nosession"}
		task.ApplyOrgSubject(e.subject)
		_, err := PrepareMidjourneyTaskBilling(info, task, 500, true)
		require.Error(t, err)
		assert.Zero(t, task.Quota)
		assert.EqualValues(t, 10_000, e.quota(t))
	})
}

func refundUnsettledForTest(info *relaycommon.RelayInfo) {
	if info.Billing != nil && info.Billing.NeedsRefund() {
		info.Billing.Refund(testContext(""))
	}
}

func TestSweepStuckOrgOperations(t *testing.T) {
	ctx := context.Background()
	age := func(t *testing.T, e *orgSessionEnv, task *model.Task) {
		t.Helper()
		require.NoError(t, e.db.Model(&model.OrgBillingOperation{}).Where("operation_id = ?", task.BillingOperationId).
			Update("updated_at", 1).Error)
	}

	t.Run("a stuck operation follows its task", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		failed := submitOrgTask(t, e, 1000)
		done := submitOrgTask(t, e, 500)
		running := submitOrgTask(t, e, 200)
		require.NoError(t, e.db.Model(failed).Update("status", model.TaskStatusFailure).Error)
		require.NoError(t, e.db.Model(done).Update("status", model.TaskStatusSuccess).Error)
		assert.EqualValues(t, 8300, e.quota(t))

		assert.Zero(t, SweepStuckOrgOperations(ctx), "fresh operations are left alone")
		for _, task := range []*model.Task{failed, done, running} {
			age(t, e, task)
		}
		assert.Equal(t, 2, SweepStuckOrgOperations(ctx))
		assert.EqualValues(t, 9300, e.quota(t), "the failed task is refunded, the others keep their price")
		assert.Equal(t, hosttypes.OrgOpStateClosed, orgOperationState(t, e, failed))
		assert.Equal(t, hosttypes.OrgOpStateClosed, orgOperationState(t, e, done))
		assert.Equal(t, hosttypes.OrgOpStateCaptured, orgOperationState(t, e, running), "a running task is left to polling")
		assert.Zero(t, SweepStuckOrgOperations(ctx), "a second pass finds nothing it can settle")
	})
}

func TestOrgViolationFee(t *testing.T) {
	violation := func() *types.NewAPIError {
		return types.NewErrorWithStatusCode(errors.New("blocked"), types.ErrorCodeViolationFeeGrokCSAM, 400)
	}
	withChannel := func(info *relaycommon.RelayInfo) *relaycommon.RelayInfo {
		info.ChannelMeta = &relaycommon.ChannelMeta{}
		info.StartTime = time.Now()
		return info
	}
	feeOf := func(info *relaycommon.RelayInfo) int {
		return calcViolationFeeQuota(model_setting.GetGrokSettings().ViolationDeductionAmount, info.PriceData.GroupRatioInfo.GroupRatio)
	}

	t.Run("a failed organization request pays the fee through its own operation", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000_000)
		require.NoError(t, e.db.AutoMigrate(&model.Log{}))
		info := withChannel(e.info())
		fee := feeOf(info)
		require.Positive(t, fee)
		assert.True(t, ChargeViolationFeeIfNeeded(testContext(""), info, violation()))
		assert.EqualValues(t, 10_000_000-fee, e.quota(t))
		var op model.OrgBillingOperation
		require.NoError(t, e.db.Where("source_kind = ?", hosttypes.OrgSourceViolationFee).First(&op).Error)
		assert.Equal(t, hosttypes.OrgOpStateClosed, op.State)
		assert.EqualValues(t, fee, op.CapturedQuota)
	})

	t.Run("a fee the organization cannot cover is not taken and nothing goes negative", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10)
		require.NoError(t, e.db.AutoMigrate(&model.Log{}))
		assert.False(t, ChargeViolationFeeIfNeeded(testContext(""), withChannel(e.info()), violation()))
		assert.EqualValues(t, 10, e.quota(t))
		var open int64
		require.NoError(t, e.db.Model(&model.OrgBillingOperation{}).Where("state IN ?", []string{"prepared", "reserved"}).Count(&open).Error)
		assert.Zero(t, open)
	})

	t.Run("an ordinary error is not charged", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000_000)
		assert.False(t, ChargeViolationFeeIfNeeded(testContext(""), withChannel(e.info()),
			types.NewErrorWithStatusCode(errors.New("boom"), types.ErrorCodeBadResponseStatusCode, 500)))
		assert.EqualValues(t, 10_000_000, e.quota(t))
	})
}
