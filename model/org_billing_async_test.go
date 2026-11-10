package model

import (
	"context"
	"testing"

	"github.com/QuantumNous/new-api/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSettleOrgAsyncCharge(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		ctx := context.Background()
		key := e.f.memberKey

		// submit reserves the bound and captures the price; polling settles later
		submit := func(id string, bound, price int64) {
			cmd := e.cmd(t, key, id, types.OrgBillingActionReserve)
			cmd.SourceKind, cmd.Bound = types.OrgSourceTask, bound
			e.mustApply(t, cmd)
			capture := cmd
			capture.Action, capture.Amount, capture.Revision, capture.Bound = types.OrgBillingActionCapture, price, 1, 0
			e.mustApply(t, capture)
		}

		t.Run("a failed task gives the whole price back", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 500)
			submit("fail-1", 100, 100)
			assert.EqualValues(t, 900, e.walletQuota(t))

			net, err := SettleOrgAsyncCharge(ctx, e.f.org.Id, "fail-1", 0)
			require.NoError(t, err)
			assert.EqualValues(t, 0, net)
			assert.EqualValues(t, 1000, e.walletQuota(t))
			op := e.operation(t, "fail-1")
			assert.Equal(t, types.OrgOpStateClosed, op.State)
			assert.EqualValues(t, 0, op.CapturedQuota)

			again, err := SettleOrgAsyncCharge(ctx, e.f.org.Id, "fail-1", 0)
			require.NoError(t, err)
			assert.EqualValues(t, 0, again, "repeating changes nothing")
			assert.EqualValues(t, 1000, e.walletQuota(t))
			e.assertInvariants(t)
		})

		t.Run("an actual cost below the price refunds the difference and an equal one just closes", func(t *testing.T) {
			e.reset(t, 1000)
			submit("down-1", 100, 100)
			net, err := SettleOrgAsyncCharge(ctx, e.f.org.Id, "down-1", 70)
			require.NoError(t, err)
			assert.EqualValues(t, 70, net)
			assert.EqualValues(t, 930, e.walletQuota(t))
			assert.Equal(t, types.OrgOpStateClosed, e.operation(t, "down-1").State)

			submit("same-1", 100, 100)
			net, err = SettleOrgAsyncCharge(ctx, e.f.org.Id, "same-1", 100)
			require.NoError(t, err)
			assert.EqualValues(t, 100, net)
			assert.Equal(t, types.OrgOpStateClosed, e.operation(t, "same-1").State)
			assert.EqualValues(t, 830, e.walletQuota(t))
			e.assertInvariants(t)
		})

		t.Run("an actual cost above the bound is capped and the rest written off", func(t *testing.T) {
			e.reset(t, 1000)
			submit("over-1", 100, 80)
			net, err := SettleOrgAsyncCharge(ctx, e.f.org.Id, "over-1", 400)
			require.NoError(t, err)
			assert.EqualValues(t, 100, net)
			op := e.operation(t, "over-1")
			assert.EqualValues(t, 300, op.WriteoffQuota)
			assert.EqualValues(t, 900, e.walletQuota(t))
			e.assertInvariants(t)
		})

		t.Run("a closed operation can only go down", func(t *testing.T) {
			e.reset(t, 1000)
			submit("closed-1", 100, 100)
			_, err := SettleOrgAsyncCharge(ctx, e.f.org.Id, "closed-1", 100)
			require.NoError(t, err)

			net, err := SettleOrgAsyncCharge(ctx, e.f.org.Id, "closed-1", 500)
			require.NoError(t, err)
			assert.EqualValues(t, 100, net, "a later higher figure never charges more")
			assert.EqualValues(t, 900, e.walletQuota(t))

			net, err = SettleOrgAsyncCharge(ctx, e.f.org.Id, "closed-1", 30)
			require.NoError(t, err)
			assert.EqualValues(t, 30, net)
			assert.EqualValues(t, 970, e.walletQuota(t))
			net, err = SettleOrgAsyncCharge(ctx, e.f.org.Id, "closed-1", 0)
			require.NoError(t, err)
			assert.EqualValues(t, 0, net)
			assert.EqualValues(t, 1000, e.walletQuota(t))
			e.assertInvariants(t)
		})

		t.Run("a limited key gets its quota back with the wallet", func(t *testing.T) {
			e.reset(t, 1000)
			limited := e.limitedKey(t, "async-limited", 500)
			cmd := e.cmd(t, limited, "key-1", types.OrgBillingActionReserve)
			cmd.SourceKind, cmd.Bound = types.OrgSourceTask, 100
			e.mustApply(t, cmd)
			capture := cmd
			capture.Action, capture.Amount, capture.Revision, capture.Bound = types.OrgBillingActionCapture, 100, 1, 0
			e.mustApply(t, capture)
			assert.EqualValues(t, 400, e.tokenRow(t, limited.Id).RemainQuota)

			_, err := SettleOrgAsyncCharge(ctx, e.f.org.Id, "key-1", 0)
			require.NoError(t, err)
			assert.EqualValues(t, 500, e.tokenRow(t, limited.Id).RemainQuota)
			assert.EqualValues(t, 1000, e.walletQuota(t))
			e.assertInvariants(t)
		})

		t.Run("refusals", func(t *testing.T) {
			e.reset(t, 1000)
			reserved := e.cmd(t, key, "reserved-1", types.OrgBillingActionReserve)
			reserved.SourceKind, reserved.Bound = types.OrgSourceTask, 100
			e.mustApply(t, reserved)
			_, err := SettleOrgAsyncCharge(ctx, e.f.org.Id, "reserved-1", 0)
			requireConflict(t, err)

			submit("belongs-1", 100, 100)
			_, err = SettleOrgAsyncCharge(ctx, e.f.org.Id+999, "belongs-1", 0)
			requireOrgRefusal(t, err, types.OrgErrNotFound)
			_, err = SettleOrgAsyncCharge(ctx, e.f.org.Id, "missing", 0)
			requireOrgRefusal(t, err, types.OrgErrNotFound)

			_, err = e.reserve(t, key, "sync-1", 50)
			require.NoError(t, err)
			_, err = e.capture(t, key, "sync-1", 50, 1)
			require.NoError(t, err)
			_, err = SettleOrgAsyncCharge(ctx, e.f.org.Id, "sync-1", 0)
			requireConflict(t, err)

			_, err = SettleOrgAsyncCharge(ctx, e.f.org.Id, "belongs-1", -1)
			require.Error(t, err)
			assert.Equal(t, types.OrgOpStateCaptured, e.operation(t, "belongs-1").State, "a refused call changes nothing")
		})
	})
}
