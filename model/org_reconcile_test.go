package model

import (
	"context"
	"testing"

	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (e *billingEnv) seedLedger(t *testing.T, quota int64) {
	t.Helper()
	require.NoError(t, e.db.Where("1 = 1").Delete(&OrgBillingLedger{}).Error)
	require.NoError(t, e.db.Create(&OrgBillingLedger{OrgId: e.f.org.Id, Type: types.OrgLedgerAdjust, AmountQuota: quota,
		BalanceAfter: quota, RefType: "test", RefId: "seed", IdempotencyKey: "seed"}).Error)
}

func driftKinds(drifts []OrgDrift) map[string]int {
	kinds := map[string]int{}
	for _, d := range drifts {
		kinds[d.Kind]++
	}
	return kinds
}

func TestOrgReconcile(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		ctx := context.Background()
		reconcile := func() []OrgDrift {
			drifts, err := ReconcileOrg(ctx, e.f.org.Id)
			require.NoError(t, err)
			return drifts
		}
		fresh := func() {
			e.reset(t, 10_000)
			e.seedLedger(t, 10_000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 5_000)
		}

		t.Run("a healthy organization has no drift at any stage of a request", func(t *testing.T) {
			fresh()
			assert.Empty(t, reconcile())
			_, err := e.reserve(t, e.f.memberKey, "rec-1", 150)
			require.NoError(t, err)
			assert.Empty(t, reconcile(), "reserved")
			_, err = e.capture(t, e.f.memberKey, "rec-1", 100, 1)
			require.NoError(t, err)
			assert.Empty(t, reconcile(), "captured, not yet folded")
			_, err = FoldOrgSpend(ctx, e.f.org.Id, 100)
			require.NoError(t, err)
			assert.Empty(t, reconcile(), "folded")
		})

		t.Run("leases are part of the identity", func(t *testing.T) {
			fresh()
			lease := e.walletLease(t, "inst-rec", 400)
			cmd := e.cmd(t, e.f.memberKey, "rec-lease", types.OrgBillingActionReserve)
			cmd.Bound, cmd.LeaseHints = 50, e.hint(types.OrgHoldTargetWallet, e.f.wallet.Id, lease.Id)
			e.mustApply(t, cmd)
			assert.Empty(t, reconcile())
		})

		t.Run("money that left the wallet without a record is found", func(t *testing.T) {
			fresh()
			require.NoError(t, e.db.Model(&User{}).Where("id = ?", e.f.wallet.Id).Update("quota", 9_000).Error)
			drifts := reconcile()
			require.Equal(t, map[string]int{"wallet_identity": 1}, driftKinds(drifts))
			assert.EqualValues(t, 10_000, drifts[0].Expected)
			assert.EqualValues(t, 9_000, drifts[0].Actual)
		})

		t.Run("a held quota that no hold explains is found", func(t *testing.T) {
			fresh()
			require.NoError(t, e.db.Model(&OrgBudgetUsage{}).Where("org_id = ? AND scope = ?", e.f.org.Id, types.BudgetScopeOrg).
				Update("held_quota", 77).Error)
			assert.Equal(t, map[string]int{"held_identity": 1}, driftKinds(reconcile()))
		})

		t.Run("an over-allocated lease is found", func(t *testing.T) {
			fresh()
			lease := e.walletLease(t, "inst-bad", 400)
			require.NoError(t, e.db.Model(&OrgQuotaLease{}).Where("id = ?", lease.Id).Update("allocated", lease.Amount+1).Error)
			assert.Equal(t, 1, driftKinds(reconcile())["lease"])
		})

		t.Run("a negative wallet or key balance is found", func(t *testing.T) {
			fresh()
			original := e.tokenRow(t, e.f.memberKey.Id).RemainQuota
			t.Cleanup(func() {
				require.NoError(t, e.db.Model(&Token{}).Where("id = ?", e.f.memberKey.Id).Update("remain_quota", original).Error)
			})
			require.NoError(t, e.db.Model(&User{}).Where("id = ?", e.f.wallet.Id).Update("quota", -1).Error)
			require.NoError(t, e.db.Model(&Token{}).Where("id = ?", e.f.memberKey.Id).Update("remain_quota", -5).Error)
			kinds := driftKinds(reconcile())
			assert.Equal(t, 1, kinds["negative_wallet"])
			assert.Equal(t, 1, kinds["negative_key"])
		})

		t.Run("reconciling changes nothing", func(t *testing.T) {
			fresh()
			require.NoError(t, e.db.Model(&User{}).Where("id = ?", e.f.wallet.Id).Update("quota", 9_000).Error)
			_ = reconcile()
			assert.EqualValues(t, 9_000, e.walletQuota(t), "drift is reported, never corrected")
		})

		t.Run("another organization's money is not mixed in", func(t *testing.T) {
			fresh()
			require.NoError(t, e.db.Create(&OrgBillingLedger{OrgId: e.f.org.Id + 500, Type: types.OrgLedgerAdjust,
				AmountQuota: 99_999, RefType: "test", RefId: "other", IdempotencyKey: "other"}).Error)
			assert.Empty(t, reconcile())
		})
	})
}
