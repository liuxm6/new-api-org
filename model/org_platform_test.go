package model

import (
	"context"
	"testing"

	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parkTask reserves an asynchronous task and parks it the way recovery does.
func (e *billingEnv) parkTask(t *testing.T, id string, bound int64) {
	t.Helper()
	cmd := e.cmd(t, e.f.memberKey, id, types.OrgBillingActionReserve)
	cmd.SourceKind, cmd.Bound = types.OrgSourceTask, bound
	e.mustApply(t, cmd)
	require.NoError(t, e.db.Model(&OrgBillingOperation{}).Where("operation_id = ?", id).
		Updates(map[string]any{"state": types.OrgOpStateRecoveryRequired, "lease_owner": ""}).Error)
}

func TestOrgResolveOperation(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		e.migrateInvoices(t)
		ctx := context.Background()
		resolve := func(id, action string, target, revision int64) (types.OrgBillingResult, error) {
			return ResolveOrgOperation(ctx, e.f.org.Id, OrgOperationResolution{OperationID: id, ExpectedRevision: revision,
				Action: action, TargetQuota: target, EvidenceRef: "ticket-1", Reason: "upstream confirmed", OperatorID: e.f.member.Id})
		}

		t.Run("cancel gives every hold back and leaves no accounting trace", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 500)
			e.parkTask(t, "res-1", 200)
			assert.EqualValues(t, 800, e.walletQuota(t))
			res, err := resolve("res-1", "cancel", 0, 0)
			require.NoError(t, err)
			assert.Equal(t, types.OrgOpStateCanceled, res.State)
			assert.EqualValues(t, 1000, e.walletQuota(t))
			assert.EqualValues(t, 0, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			assert.EqualValues(t, 0, e.count(t, &OrgSpendEvent{}))
			assert.Equal(t, OrgSettledByPlatform, e.operation(t, "res-1").SettledBy)
			e.assertInvariants(t)
		})

		t.Run("settle charges the evidence amount, releases the rest and enters the books once", func(t *testing.T) {
			e.reset(t, 1000)
			e.parkTask(t, "res-2", 300)
			res, err := resolve("res-2", "settle", 120, 0)
			require.NoError(t, err)
			assert.Equal(t, types.OrgOpStateClosed, res.State)
			assert.EqualValues(t, 120, res.Captured)
			assert.EqualValues(t, 880, e.walletQuota(t))
			assert.EqualValues(t, 1, e.count(t, &OrgSpendEvent{}))
			assert.EqualValues(t, 1, e.count(t, &OrgSpendFoldQueue{}))
			_, err = FoldOrgSpend(ctx, e.f.org.Id, 100)
			require.NoError(t, err)
			e.assertInvariants(t)
		})

		t.Run("a settle is capped at the bound", func(t *testing.T) {
			e.reset(t, 1000)
			e.parkTask(t, "res-3", 100)
			res, err := resolve("res-3", "settle", 9_999, 0)
			require.NoError(t, err)
			assert.EqualValues(t, 100, res.Captured)
			assert.EqualValues(t, 900, e.walletQuota(t))
		})

		t.Run("a stale revision is refused and nothing moves", func(t *testing.T) {
			e.reset(t, 1000)
			e.parkTask(t, "res-4", 100)
			_, err := resolve("res-4", "settle", 50, 7)
			requireConflict(t, err)
			assert.Equal(t, types.OrgOpStateRecoveryRequired, e.operation(t, "res-4").State)
			assert.EqualValues(t, 900, e.walletQuota(t))
		})

		t.Run("repeating a decision replays it and a different one conflicts", func(t *testing.T) {
			e.reset(t, 1000)
			e.parkTask(t, "res-5", 100)
			_, err := resolve("res-5", "settle", 40, 0)
			require.NoError(t, err)
			again, err := resolve("res-5", "settle", 40, 0)
			require.NoError(t, err)
			assert.True(t, again.Replayed)
			assert.EqualValues(t, 960, e.walletQuota(t))
			assert.EqualValues(t, 1, e.count(t, &OrgSpendEvent{}))
			_, err = resolve("res-5", "settle", 41, 0)
			requireConflict(t, err)
			_, err = resolve("res-5", "cancel", 0, 0)
			requireConflict(t, err)
		})

		t.Run("only a parked operation can be resolved, and only inside its organization", func(t *testing.T) {
			e.reset(t, 1000)
			live := e.cmd(t, e.f.memberKey, "res-6", types.OrgBillingActionReserve)
			live.Bound = 100
			e.mustApply(t, live)
			_, err := resolve("res-6", "cancel", 0, 0)
			requireConflict(t, err)
			_, err = ResolveOrgOperation(ctx, e.f.org.Id+100, OrgOperationResolution{OperationID: "res-6", Action: "cancel",
				Reason: "x", OperatorID: 1})
			requireOrgRefusal(t, err, types.OrgErrNotFound)
			_, err = resolve("no-such-op", "cancel", 0, 0)
			requireOrgRefusal(t, err, types.OrgErrNotFound)
		})

		t.Run("the decision needs a reason, an operator and a known action", func(t *testing.T) {
			e.reset(t, 1000)
			e.parkTask(t, "res-7", 100)
			for name, in := range map[string]OrgOperationResolution{
				"no reason":   {OperationID: "res-7", Action: "cancel", OperatorID: 1},
				"no operator": {OperationID: "res-7", Action: "cancel", Reason: "x"},
				"bad action":  {OperationID: "res-7", Action: "refund", Reason: "x", OperatorID: 1},
				"negative":    {OperationID: "res-7", Action: "settle", TargetQuota: -1, Reason: "x", OperatorID: 1},
			} {
				_, err := ResolveOrgOperation(ctx, e.f.org.Id, in)
				assert.Error(t, err, name)
			}
			assert.Equal(t, types.OrgOpStateRecoveryRequired, e.operation(t, "res-7").State)
		})
	})
}

func TestOrgPlatformSettings(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		ctx := context.Background()
		group, seats := "vip", 7

		require.Error(t, UpdateOrgPlatformSettings(ctx, e.f.org.Id, 1, PlatformOrgSettings{BillingGroup: &group}, ""), "a reason is mandatory")
		require.Error(t, UpdateOrgPlatformSettings(ctx, e.f.org.Id, 1, PlatformOrgSettings{}, "nothing to change"))
		version := func() int64 {
			var v int64
			require.NoError(t, e.db.Model(&Organization{}).Where("id = ?", e.f.org.Id).Select("policy_version").Scan(&v).Error)
			return v
		}
		before := version()
		require.NoError(t, UpdateOrgPlatformSettings(ctx, e.f.org.Id, 1, PlatformOrgSettings{BillingGroup: &group, SeatLimit: &seats}, "plan upgrade"))
		var org Organization
		require.NoError(t, e.db.First(&org, e.f.org.Id).Error)
		assert.Equal(t, "vip", org.BillingGroup)
		assert.Equal(t, 7, org.SeatLimit)
		var wallet User
		require.NoError(t, e.db.First(&wallet, e.f.wallet.Id).Error)
		assert.Equal(t, "vip", wallet.Group, "the wallet follows the billing group, never a person's")
		assert.Greater(t, version(), before)

		tooFew := 0
		require.Error(t, UpdateOrgPlatformSettings(ctx, e.f.org.Id, 1, PlatformOrgSettings{SeatLimit: &tooFew}, "x"), "below one seat")
		// Three people hold seats: a limit of two is above the floor of one but
		// below what is already taken, and must be refused.
		for i := range 2 {
			extra := User{Username: "seat-" + string(rune('a'+i)), Password: "x", Role: 1, Status: 1, AffCode: "sc" + string(rune('a'+i))}
			require.NoError(t, e.db.Create(&extra).Error)
			require.NoError(t, e.db.Create(&OrganizationMember{OrgId: e.f.org.Id, UserId: extra.Id, Role: types.OrgRoleMember,
				Status: types.OrgMemberStatusActive}).Error)
		}
		var taken int64
		require.NoError(t, e.db.Model(&OrganizationMember{}).Where("org_id = ? AND status <> ?", e.f.org.Id, types.OrgMemberStatusRemoved).Count(&taken).Error)
		require.GreaterOrEqual(t, taken, int64(2))
		below := int(taken) - 1
		require.Error(t, UpdateOrgPlatformSettings(ctx, e.f.org.Id, 1, PlatformOrgSettings{SeatLimit: &below}, "x"), "below the seats taken")
		exact := int(taken)
		require.NoError(t, UpdateOrgPlatformSettings(ctx, e.f.org.Id, 1, PlatformOrgSettings{SeatLimit: &exact}, "fits exactly"))
		empty := ""
		require.Error(t, UpdateOrgPlatformSettings(ctx, e.f.org.Id, 1, PlatformOrgSettings{BillingGroup: &empty}, "x"))
		var audits int64
		require.NoError(t, e.db.Model(&OrgAuditLog{}).Where("action = ?", "platform.settings").Count(&audits).Error)
		assert.EqualValues(t, 2, audits, "only the two successful changes are audited")
	})
}
