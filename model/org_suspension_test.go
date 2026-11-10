package model

import (
	"context"
	"errors"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func (e *billingEnv) setOrgStatus(t *testing.T, status int) {
	t.Helper()
	require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error { return SetOrganizationStatusTx(tx, e.f.org.Id, status) }))
}

// A suspended organization takes no new inference, but money already accepted
// still settles: captures, async finalizes, cancels and refunds all continue
// (design 5.4, Task 7).
func TestOrgLifecycleKeepsSettlement(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		key := e.f.memberKey

		t.Run("an accepted request still captures after the organization is suspended", func(t *testing.T) {
			e.reset(t, 10_000)
			_, err := e.reserve(t, key, "susp-sync", 150)
			require.NoError(t, err)
			e.setOrgStatus(t, types.OrgStatusSuspended)
			t.Cleanup(func() { e.setOrgStatus(t, types.OrgStatusActive) })

			res, err := e.capture(t, key, "susp-sync", 100, 1)
			require.NoError(t, err)
			assert.EqualValues(t, 100, res.Captured)
			assert.EqualValues(t, 9_900, e.walletQuota(t), "only the real cost is kept, the rest came back")

			refund := e.cmd(t, key, "susp-sync", types.OrgBillingActionRefund)
			refund.Amount, refund.Revision = 30, 1
			e.mustApply(t, refund)
			assert.EqualValues(t, 9_930, e.walletQuota(t), "a refund still reaches the wallet")
			e.assertInvariants(t)
		})

		t.Run("an accepted async task still revises, finalizes and cancels", func(t *testing.T) {
			e.reset(t, 10_000)
			e.setOrgStatus(t, types.OrgStatusActive)
			async := func(id string) types.OrgBillingCommand {
				cmd := e.cmd(t, key, id, types.OrgBillingActionReserve)
				cmd.Bound, cmd.SourceKind = 150, types.OrgSourceTask
				return cmd
			}
			e.mustApply(t, async("susp-async"))
			e.mustApply(t, async("susp-cancel"))
			e.setOrgStatus(t, types.OrgStatusSuspended)
			t.Cleanup(func() { e.setOrgStatus(t, types.OrgStatusActive) })

			capture := e.cmd(t, key, "susp-async", types.OrgBillingActionCapture)
			capture.Amount, capture.Revision = 100, 1
			e.mustApply(t, capture)
			capture.Amount, capture.Revision = 120, 2
			e.mustApply(t, capture) // the task is revised upward before it ends
			final := e.cmd(t, key, "susp-async", types.OrgBillingActionFinalize)
			final.Amount, final.Revision = 120, 2
			e.mustApply(t, final)
			cancel := e.cmd(t, key, "susp-cancel", types.OrgBillingActionCancel)
			e.mustApply(t, cancel)

			assert.EqualValues(t, 9_880, e.walletQuota(t), "the task is charged 120, the cancelled one costs nothing")
			e.assertInvariants(t)
		})

		t.Run("a new request is refused while suspended and accepted again after the resume", func(t *testing.T) {
			e.reset(t, 10_000)
			e.setOrgStatus(t, types.OrgStatusSuspended)
			t.Cleanup(func() { e.setOrgStatus(t, types.OrgStatusActive) })

			_, err := e.reserve(t, key, "susp-new", 50)
			requireOrgRefusal(t, err, types.OrgErrSuspended)
			assert.EqualValues(t, 10_000, e.walletQuota(t), "nothing was held")

			e.setOrgStatus(t, types.OrgStatusActive)
			_, err = e.reserve(t, key, "susp-new-2", 50)
			require.NoError(t, err)
		})
	})
}

// A payment already tied to an organization is credited to it even if the
// organization is suspended when the callback arrives, and a failing
// notification never takes the credit back (design 4.5, Task 10).
func TestOrgCreditAfterSuspension(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		e.migrateCredit(t)
		credit := int64(float64(common.QuotaPerUnit) * 3)
		for _, m := range []any{&OrgBillingLedger{}, &OrgAuditLog{}, &OrgBillingJob{}, &TopUp{}, &Redemption{}} {
			require.NoError(t, e.db.Unscoped().Where("1 = 1").Delete(m).Error)
		}
		e.reset(t, 1000)
		e.setOrgStatus(t, types.OrgStatusSuspended)
		t.Cleanup(func() { e.setOrgStatus(t, types.OrgStatusActive) })

		e.pendingTopUp(t, e.f.wallet.Id, "trade-suspended", 3)
		done, err := RechargeEpay("trade-suspended", "", "10.0.0.1")
		require.NoError(t, err)
		assert.False(t, done)
		assert.EqualValues(t, 1000+credit, e.walletQuota(t), "the order is fulfilled into the original organization")
		require.Len(t, e.ledger(t), 1)

		t.Run("the receipt and notification jobs exist, and a failing one does not undo the credit", func(t *testing.T) {
			jobs, err := ClaimOrgJobs(context.Background(), []string{types.OrgJobKindNotify, types.OrgJobKindReceipt}, 10)
			require.NoError(t, err)
			require.Len(t, jobs, 2)
			for _, job := range jobs {
				require.NoError(t, FailOrgJob(context.Background(), job, errors.New("mail server is down")))
			}
			assert.EqualValues(t, 1000+credit, e.walletQuota(t), "the money stays credited")
			require.Len(t, e.ledger(t), 1)
			var pending int64
			require.NoError(t, e.db.Model(&OrgBillingJob{}).Where("status = ?", types.OrgJobStatusPending).Count(&pending).Error)
			assert.EqualValues(t, 2, pending, "both jobs are waiting for a retry")
		})

		t.Run("a repeated callback for the same order still credits once", func(t *testing.T) {
			_, err := RechargeEpay("trade-suspended", "", "10.0.0.1")
			require.NoError(t, err)
			assert.EqualValues(t, 1000+credit, e.walletQuota(t))
			assert.Len(t, e.ledger(t), 1)
		})

		t.Run("a redemption code is credited by the platform while suspended", func(t *testing.T) {
			require.NoError(t, e.db.Create(&Redemption{Key: "SUSP-CODE", Quota: 500, Status: common.RedemptionCodeStatusEnabled,
				UserId: 1}).Error)
			quota, err := RedeemToOrganization("SUSP-CODE", e.f.wallet.Id, e.f.member.Id)
			require.NoError(t, err)
			assert.EqualValues(t, 500, quota)
			assert.EqualValues(t, 1000+credit+500, e.walletQuota(t))
		})
	})
}
