package model

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// billingEnv is one dialect's database with a single organization fixture. A
// scenario calls reset to get a clean billing state with a known wallet balance.
type billingEnv struct {
	db       *gorm.DB
	f        orgFixture
	dialect  string
	credited int64
	baseKeys []int
}

// openOrgBillingDB opens a database whose connections are real and concurrent.
// SQLite and MySQL reuse the migration opener; PostgreSQL gets its own schema
// on a pool because the migration opener pins one transaction, which would hide
// every locking behavior these tests exist to prove.
func openOrgBillingDB(t *testing.T, dialect string) *gorm.DB {
	t.Helper()
	if dialect == "postgres" {
		return openOrgPostgresPool(t)
	}
	db := openOrgMigrationDB(t, dialect)
	if dialect == "mysql" {
		sqlDB, err := db.DB()
		require.NoError(t, err)
		sqlDB.SetMaxOpenConns(loadParam("TEST_ORG_DB_CONNS", 32))
		require.NoError(t, db.Migrator().DropTable(&Token{}))
		t.Cleanup(func() { assert.NoError(t, db.Migrator().DropTable(&Token{})) })
	}
	return db
}

func openOrgPostgresPool(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not configured")
	}
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	adminSQL, err := admin.DB()
	require.NoError(t, err)
	schema := fmt.Sprintf("org_billing_test_%d", time.Now().UnixNano())
	require.NoError(t, admin.Exec("CREATE SCHEMA ?", clause.Table{Name: schema}).Error)

	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := gorm.Open(postgres.Open(parsed.String()), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(loadParam("TEST_ORG_DB_CONNS", 32))

	previousDB, previousType := DB, common.MainDatabaseType()
	DB = db
	common.SetMainDatabaseType(common.DatabaseTypePostgreSQL)
	initCol()
	t.Cleanup(func() {
		DB = previousDB
		common.SetMainDatabaseType(previousType)
		initCol()
		assert.NoError(t, sqlDB.Close())
		assert.NoError(t, admin.Exec("DROP SCHEMA ? CASCADE", clause.Table{Name: schema}).Error)
		assert.NoError(t, adminSQL.Close())
	})
	return db
}

func forEachBillingDialect(t *testing.T, run func(t *testing.T, e *billingEnv)) {
	t.Helper()
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			// The lease tests below were written for four shards and a grant of a
			// quarter of what is left. TestOrgBillingLoad runs with the production
			// defaults.
			previousShards, previousDivisor := OrgLeaseShards, leaseGrantDivisor
			OrgLeaseShards, leaseGrantDivisor = 4, 4
			t.Cleanup(func() { OrgLeaseShards, leaseGrantDivisor = previousShards, previousDivisor })
			db := openOrgBillingDB(t, dialect)
			e := &billingEnv{db: db, dialect: dialect}
			e.f = newOrgFixture(t, db)
			e.baseKeys = []int{e.f.memberKey.Id, e.f.systemKey.Id}
			run(t, e)
		})
	}
}

// reset empties every billing table and gives the wallet a known balance.
func (e *billingEnv) reset(t *testing.T, quota int64) {
	t.Helper()
	for _, m := range []any{&OrgSpendFoldQueue{}, &OrgSpendEvent{}, &OrgFoldBatch{}, &OrgSpendRollup{},
		&OrgWriteoffDaily{}, &OrgQuotaLease{}, &OrgBillingOperation{}, &OrgBudgetUsage{}, &Budget{}} {
		require.NoError(t, e.db.Where("1 = 1").Delete(m).Error)
	}
	require.NoError(t, e.db.Unscoped().Where("id NOT IN ?", e.baseKeys).Delete(&Token{}).Error)
	require.NoError(t, e.db.Model(&Token{}).Where("id IN ?", e.baseKeys).Update("used_quota", 0).Error)
	require.NoError(t, e.db.Model(&User{}).Where("id = ?", e.f.wallet.Id).
		Updates(map[string]any{"quota": quota, "used_quota": 0, "request_count": 0}).Error)
	require.NoError(t, e.db.Model(&Organization{}).Where("id = ?", e.f.org.Id).Update("policy_version", 3).Error)
	e.credited = quota
}

func (e *billingEnv) walletQuota(t *testing.T) int64 {
	t.Helper()
	var quota int64
	require.NoError(t, e.db.Model(&User{}).Where("id = ?", e.f.wallet.Id).Select("quota").Scan(&quota).Error)
	return quota
}

func (e *billingEnv) limitedKey(t *testing.T, name string, remain int) Token {
	t.Helper()
	key := Token{UserId: e.f.wallet.Id, Key: "org-" + name, Name: name, Status: common.TokenStatusEnabled,
		ExpiredTime: -1, RemainQuota: remain, OrgId: e.f.org.Id, WorkspaceId: e.f.workspace.Id,
		CreatedBy: e.f.member.Id, OwnerType: types.TokenOwnerMember, AccessPrincipalId: "prn-" + name}
	require.NoError(t, e.db.Create(&key).Error)
	return key
}

func (e *billingEnv) tokenRow(t *testing.T, id int) Token {
	t.Helper()
	var token Token
	require.NoError(t, e.db.Unscoped().First(&token, id).Error)
	return token
}

func (e *billingEnv) setBudget(t *testing.T, scope string, subject int, period string, limit int64) OrgBudgetStatus {
	t.Helper()
	status, err := ChangeBudgetLimit(context.Background(), OrgBudgetChange{OrgID: e.f.org.Id, Scope: scope,
		SubjectID: subject, Period: period, LimitQuota: limit, Enabled: true})
	require.NoError(t, err)
	return status
}

func (e *billingEnv) usage(t *testing.T, scope string, subject int, period string) OrgBudgetUsage {
	t.Helper()
	var row OrgBudgetUsage
	require.NoError(t, e.db.Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ?",
		e.f.org.Id, scope, subject, period).Order("window_start desc").First(&row).Error)
	return row
}

func (e *billingEnv) lease(t *testing.T, id int) OrgQuotaLease {
	t.Helper()
	var lease OrgQuotaLease
	require.NoError(t, e.db.First(&lease, id).Error)
	return lease
}

func (e *billingEnv) operation(t *testing.T, id string) OrgBillingOperation {
	t.Helper()
	var op OrgBillingOperation
	require.NoError(t, e.db.Where("operation_id = ?", id).First(&op).Error)
	return op
}

func (e *billingEnv) count(t *testing.T, model any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(model).Count(&n).Error)
	return n
}

func (e *billingEnv) cmd(t *testing.T, key Token, id, action string) types.OrgBillingCommand {
	t.Helper()
	return types.OrgBillingCommand{OperationID: id, Subject: subjectOf(t, key), Action: action,
		ModelName: "gpt-x", SourceKind: types.OrgSourceRelay, LeaseOwner: "inst-a"}
}

func (e *billingEnv) reserve(t *testing.T, key Token, id string, bound int64) (types.OrgBillingResult, error) {
	t.Helper()
	cmd := e.cmd(t, key, id, types.OrgBillingActionReserve)
	cmd.Bound = bound
	return ApplyOrgBilling(context.Background(), cmd)
}

func (e *billingEnv) capture(t *testing.T, key Token, id string, amount, revision int64) (types.OrgBillingResult, error) {
	t.Helper()
	cmd := e.cmd(t, key, id, types.OrgBillingActionCapture)
	cmd.Amount, cmd.Revision = amount, revision
	return ApplyOrgBilling(context.Background(), cmd)
}

func (e *billingEnv) mustApply(t *testing.T, cmd types.OrgBillingCommand) types.OrgBillingResult {
	t.Helper()
	res, err := ApplyOrgBilling(context.Background(), cmd)
	require.NoError(t, err)
	return res
}

func requireConflict(t *testing.T, err error) {
	t.Helper()
	requireOrgRefusal(t, err, types.OrgErrConflict)
	var accessErr *types.OrgAccessError
	require.ErrorAs(t, err, &accessErr)
	assert.Equal(t, 409, accessErr.Status)
}

func parseHolds(t *testing.T, raw string) []types.OrgHold {
	t.Helper()
	var holds []types.OrgHold
	if raw == "" {
		return holds
	}
	require.NoError(t, common.Unmarshal([]byte(raw), &holds))
	return holds
}

func holdOf(holds []types.OrgHold, targetType string) *types.OrgHold {
	for i := range holds {
		if holds[i].TargetType == targetType {
			return &holds[i]
		}
	}
	return nil
}

// assertInvariants checks design 3.3 invariants 11 and 12 against the whole
// organization. overOK lists usage rows that a lowered limit may have left above
// their limit; every other enabled budget must still satisfy spent + held <= limit.
func (e *billingEnv) assertInvariants(t *testing.T, overOK ...bool) {
	t.Helper()
	allowOver := len(overOK) > 0 && overOK[0]
	db := e.db

	// Invariant 11: wallet identity and non-negative balances.
	var wallet User
	require.NoError(t, db.First(&wallet, e.f.wallet.Id).Error)
	require.GreaterOrEqual(t, wallet.Quota, 0, "users.quota must never be negative")
	var negativeKeys int64
	require.NoError(t, db.Model(&Token{}).Unscoped().Where("remain_quota < 0").Count(&negativeKeys).Error)
	require.Zero(t, negativeKeys, "limited key remain_quota must never be negative")

	var eventSum int64
	require.NoError(t, db.Model(&OrgSpendEvent{}).Select("COALESCE(SUM(delta_quota), 0)").Scan(&eventSum).Error)
	var leases []OrgQuotaLease
	require.NoError(t, db.Find(&leases).Error)
	var ops []OrgBillingOperation
	require.NoError(t, db.Find(&ops).Error)

	var walletLeases int64
	for _, lease := range leases {
		require.GreaterOrEqual(t, lease.Allocated, int64(0), "lease %d allocated", lease.Id)
		require.LessOrEqual(t, lease.Allocated+lease.Consumed, lease.Amount, "lease %d capacity", lease.Id)
		require.LessOrEqual(t, lease.Folded, lease.Consumed, "lease %d folded", lease.Id)
		if lease.TargetType == types.OrgLeaseTargetWallet && lease.Status != types.OrgLeaseStatusClosed {
			walletLeases += lease.Amount - lease.Consumed
		}
	}
	var walletDirect int64
	directBudget := map[int]int64{}
	for _, op := range ops {
		for _, hold := range parseHolds(t, op.Holds) {
			if hold.Source != types.OrgHoldSourceDirect {
				continue
			}
			open := hold.Amount - hold.Released - hold.Captured
			if hold.TargetType == types.OrgHoldTargetWallet && op.State != types.OrgOpStateClosed && op.State != types.OrgOpStateCanceled {
				walletDirect += open
			}
			if hold.TargetType == types.OrgHoldTargetBudget {
				directBudget[hold.TargetId] += open
			}
		}
	}
	assert.Equal(t, e.credited-eventSum, int64(wallet.Quota)+walletLeases+walletDirect,
		"wallet identity: credited - events = quota + open leases + open direct holds")

	// Invariant 12: held equals leases plus direct holds, spent + held <= limit.
	var queue []OrgSpendFoldQueue
	require.NoError(t, db.Where("kind = ?", types.OrgFoldKindCapture).Find(&queue).Error)
	for _, row := range queue {
		for _, hold := range parseHolds(t, row.Holds) {
			if hold.TargetType == types.OrgHoldTargetBudget && hold.Source == types.OrgHoldSourceDirect {
				directBudget[hold.TargetId] += row.SpendDelta
			}
		}
	}
	var usages []OrgBudgetUsage
	require.NoError(t, db.Find(&usages).Error)
	for _, usage := range usages {
		var held int64
		for _, lease := range leases {
			if lease.TargetType != types.OrgLeaseTargetBudget || lease.TargetId != usage.Id {
				continue
			}
			if lease.Status == types.OrgLeaseStatusClosed {
				held += lease.Consumed - lease.Folded
			} else {
				held += lease.Amount - lease.Folded
			}
		}
		held += directBudget[usage.Id]
		require.GreaterOrEqual(t, usage.HeldQuota, int64(0), "usage %d held", usage.Id)
		assert.Equal(t, held, usage.HeldQuota, "held identity for %s/%d/%s", usage.Scope, usage.SubjectId, usage.Period)

		var budget Budget
		err := db.Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ?",
			usage.OrgId, usage.Scope, usage.SubjectId, usage.Period).Take(&budget).Error
		if err != nil || !budget.Enabled || allowOver {
			continue
		}
		assert.LessOrEqual(t, usage.SpentQuota+usage.HeldQuota, budget.LimitQuota,
			"spent + held <= limit for %s/%d/%s", usage.Scope, usage.SubjectId, usage.Period)
	}
}

func TestOrgBillingStateMachine(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		ctx := context.Background()
		fold := func() {
			_, err := FoldOrgSpend(ctx, e.f.org.Id, 2000)
			require.NoError(t, err)
			e.assertInvariants(t)
		}

		t.Run("sync capture is terminal and can only be refunded downward", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 500)
			key := e.f.memberKey

			res, err := e.reserve(t, key, "sync-1", 150)
			require.NoError(t, err)
			assert.Equal(t, types.OrgOpStateReserved, res.State)
			assert.EqualValues(t, 850, e.walletQuota(t))
			assert.EqualValues(t, 150, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			require.NotNil(t, holdOf(res.Holds, types.OrgHoldTargetWallet))
			assert.Equal(t, types.OrgHoldSourceDirect, holdOf(res.Holds, types.OrgHoldTargetBudget).Source)
			e.assertInvariants(t)

			again, err := e.reserve(t, key, "sync-1", 150)
			require.NoError(t, err)
			assert.True(t, again.Replayed)
			assert.EqualValues(t, 850, e.walletQuota(t), "replayed reserve must not hold twice")
			_, err = e.reserve(t, key, "sync-1", 151)
			requireConflict(t, err)

			res, err = e.capture(t, key, "sync-1", 100, 1)
			require.NoError(t, err)
			assert.Equal(t, types.OrgOpStateClosed, res.State)
			assert.EqualValues(t, 100, res.Captured)
			assert.EqualValues(t, 100, res.AppliedDelta)
			assert.EqualValues(t, 900, e.walletQuota(t), "50 released, 100 consumed")
			assert.EqualValues(t, 100, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			assert.EqualValues(t, 1, e.count(t, &OrgSpendEvent{}))
			assert.EqualValues(t, 1, e.count(t, &OrgSpendFoldQueue{}))
			e.assertInvariants(t)

			fold()
			usage := e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
			assert.EqualValues(t, 100, usage.SpentQuota)
			assert.EqualValues(t, 0, usage.HeldQuota)

			_, err = e.capture(t, key, "sync-1", 150, 2)
			requireConflict(t, err)
			_, err = e.capture(t, key, "sync-1", 120, 1)
			requireConflict(t, err)
			replay, err := e.capture(t, key, "sync-1", 100, 1)
			require.NoError(t, err)
			assert.True(t, replay.Replayed)
			assert.EqualValues(t, 1, e.count(t, &OrgSpendEvent{}))
			e.assertInvariants(t)

			refund := e.cmd(t, key, "sync-1", types.OrgBillingActionRefund)
			refund.Amount, refund.Revision = 30, 1
			res = e.mustApply(t, refund)
			assert.EqualValues(t, 70, res.Captured)
			assert.EqualValues(t, -30, res.AppliedDelta)
			assert.EqualValues(t, 930, e.walletQuota(t))
			var refundEvent OrgSpendEvent
			require.NoError(t, e.db.Where("event_kind = ?", types.OrgSpendEventRefund).First(&refundEvent).Error)
			assert.EqualValues(t, -30, refundEvent.DeltaQuota)
			assert.NotZero(t, refundEvent.OriginalEventId)
			e.assertInvariants(t)

			refund.Amount, refund.Revision = 80, 2
			_, err = ApplyOrgBilling(ctx, refund)
			requireConflict(t, err)
			refund.Amount, refund.Revision = 30, 1
			assert.True(t, e.mustApply(t, refund).Replayed)
			refund.Amount = 31
			_, err = ApplyOrgBilling(ctx, refund)
			requireConflict(t, err)
			assert.EqualValues(t, 930, e.walletQuota(t))

			refund.Amount, refund.Revision = 70, 2
			res = e.mustApply(t, refund)
			assert.EqualValues(t, 0, res.Captured)
			assert.EqualValues(t, 1000, e.walletQuota(t))
			refund.Amount, refund.Revision = 1, 3
			_, err = ApplyOrgBilling(ctx, refund)
			requireConflict(t, err)
			fold()
			assert.EqualValues(t, 0, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).SpentQuota)
			assert.EqualValues(t, 0, e.count(t, &OrgSpendFoldQueue{}))
		})

		t.Run("async revisions stay inside zero to bound until finalize", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 500)
			key := e.f.memberKey
			base := e.cmd(t, key, "async-1", types.OrgBillingActionReserve)
			base.SourceKind = types.OrgSourceTask
			base.Bound = 150
			res := e.mustApply(t, base)
			assert.Equal(t, types.OrgHoldSourceDirect, holdOf(res.Holds, types.OrgHoldTargetWallet).Source)
			assert.EqualValues(t, 850, e.walletQuota(t))

			revise := func(amount, revision int64) (types.OrgBillingResult, error) {
				cmd := base
				cmd.Action, cmd.Amount, cmd.Revision, cmd.Bound = types.OrgBillingActionCapture, amount, revision, 0
				return ApplyOrgBilling(ctx, cmd)
			}
			orgUsage := func() OrgBudgetUsage {
				return e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
			}

			res, err := revise(100, 1)
			require.NoError(t, err)
			assert.Equal(t, types.OrgOpStateCaptured, res.State)
			assert.EqualValues(t, 100, res.AppliedDelta)
			assert.EqualValues(t, 850, e.walletQuota(t), "async keeps the whole bound until finalize")
			assert.EqualValues(t, 150, orgUsage().HeldQuota)
			e.assertInvariants(t)
			fold()
			assert.EqualValues(t, 100, orgUsage().SpentQuota)
			assert.EqualValues(t, 50, orgUsage().HeldQuota)

			res, err = revise(150, 2)
			require.NoError(t, err)
			assert.EqualValues(t, 50, res.AppliedDelta)
			fold()
			assert.EqualValues(t, 150, orgUsage().SpentQuota)
			assert.EqualValues(t, 0, orgUsage().HeldQuota)

			res, err = revise(120, 3)
			require.NoError(t, err)
			assert.EqualValues(t, -30, res.AppliedDelta)
			assert.EqualValues(t, 120, res.Captured)
			fold()
			assert.EqualValues(t, 120, orgUsage().SpentQuota)
			assert.EqualValues(t, 30, orgUsage().HeldQuota)

			_, err = revise(120, 5)
			requireConflict(t, err)
			_, err = revise(110, 3)
			requireConflict(t, err)
			replay, err := revise(120, 3)
			require.NoError(t, err)
			assert.True(t, replay.Replayed)
			_, err = revise(-1, 4)
			require.Error(t, err)

			over, err := revise(400, 4)
			require.NoError(t, err)
			assert.EqualValues(t, 150, over.Captured, "charge is capped at the bound")
			assert.EqualValues(t, 250, over.Writeoff)
			back, err := revise(120, 5)
			require.NoError(t, err)
			assert.EqualValues(t, 120, back.Captured)
			assert.EqualValues(t, 0, back.Writeoff)

			final := base
			final.Action, final.Amount, final.Revision, final.Bound = types.OrgBillingActionFinalize, 119, 5, 0
			_, err = ApplyOrgBilling(ctx, final)
			requireConflict(t, err)
			final.Amount = 120
			res = e.mustApply(t, final)
			assert.Equal(t, types.OrgOpStateClosed, res.State)
			assert.EqualValues(t, 120, res.Captured)
			assert.EqualValues(t, 0, res.AppliedDelta)
			assert.EqualValues(t, 880, e.walletQuota(t))
			assert.True(t, e.mustApply(t, final).Replayed)
			fold()
			assert.EqualValues(t, 120, orgUsage().SpentQuota)
			assert.EqualValues(t, 0, orgUsage().HeldQuota, "held returns to zero after finalize")

			var eventSum int64
			require.NoError(t, e.db.Model(&OrgSpendEvent{}).Select("COALESCE(SUM(delta_quota), 0)").Scan(&eventSum).Error)
			assert.EqualValues(t, 120, eventSum)

			late := e.cmd(t, key, "async-1", types.OrgBillingActionRefund)
			late.Amount, late.Revision = 20, 1
			assert.EqualValues(t, 100, e.mustApply(t, late).Captured)
			assert.EqualValues(t, 900, e.walletQuota(t))
		})

		t.Run("cancel is synchronous and leaves no accounting trace", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 500)
			key := e.f.memberKey
			_, err := e.reserve(t, key, "cancel-1", 150)
			require.NoError(t, err)
			cancel := e.cmd(t, key, "cancel-1", types.OrgBillingActionCancel)
			res := e.mustApply(t, cancel)
			assert.Equal(t, types.OrgOpStateCanceled, res.State)
			assert.EqualValues(t, 1000, e.walletQuota(t))
			assert.EqualValues(t, 0, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			assert.EqualValues(t, 0, e.count(t, &OrgSpendEvent{}))
			assert.EqualValues(t, 0, e.count(t, &OrgSpendFoldQueue{}))
			assert.True(t, e.mustApply(t, cancel).Replayed)
			_, err = e.capture(t, key, "cancel-1", 10, 1)
			requireConflict(t, err)
			_, err = e.reserve(t, key, "cancel-1", 150)
			requireConflict(t, err)
			e.assertInvariants(t)

			task := e.cmd(t, key, "cancel-2", types.OrgBillingActionReserve)
			task.SourceKind, task.Bound = types.OrgSourceTask, 100
			e.mustApply(t, task)
			capture := task
			capture.Action, capture.Amount, capture.Revision, capture.Bound = types.OrgBillingActionCapture, 40, 1, 0
			e.mustApply(t, capture)
			cancel = e.cmd(t, key, "cancel-2", types.OrgBillingActionCancel)
			_, err = ApplyOrgBilling(ctx, cancel)
			requireConflict(t, err)
			e.assertInvariants(t)
		})

		t.Run("topup reserve raises the bound once", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 500)
			key := e.f.memberKey
			_, err := e.reserve(t, key, "topup-1", 100)
			require.NoError(t, err)
			top := e.cmd(t, key, "topup-1", types.OrgBillingActionTopUpReserve)
			top.Bound = 150
			res := e.mustApply(t, top)
			assert.EqualValues(t, 150, res.Bound)
			assert.EqualValues(t, 850, e.walletQuota(t))
			assert.EqualValues(t, 150, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			assert.True(t, e.mustApply(t, top).Replayed)
			top.Bound = 120
			_, err = ApplyOrgBilling(ctx, top)
			requireConflict(t, err)
			top.Bound = 5000
			_, err = ApplyOrgBilling(ctx, top)
			requireOrgRefusal(t, err, types.OrgErrQuotaExhausted)
			assert.EqualValues(t, 850, e.walletQuota(t), "failed top-up changes nothing")
			e.assertInvariants(t)

			res, err = e.capture(t, key, "topup-1", 140, 1)
			require.NoError(t, err)
			assert.EqualValues(t, 860, e.walletQuota(t))
			assert.EqualValues(t, 140, res.Captured)
			e.assertInvariants(t)
		})

		t.Run("other tenants cannot see or settle the operation", func(t *testing.T) {
			e.reset(t, 1000)
			_, err := e.reserve(t, e.f.memberKey, "tenant-1", 10)
			require.NoError(t, err)
			foreign := e.cmd(t, e.f.memberKey, "tenant-1", types.OrgBillingActionCancel)
			foreign.Subject.OrgID += 100
			_, err = ApplyOrgBilling(ctx, foreign)
			requireOrgRefusal(t, err, types.OrgErrNotFound)
			_, err = e.reserve(t, e.f.memberKey, "tenant-bad", 0)
			require.Error(t, err)
			_, err = e.reserve(t, e.f.memberKey, "", 5)
			require.Error(t, err)
			e.assertInvariants(t)
		})
	})
}

// admit runs n concurrent reservations of bound 1 and returns how many were
// admitted and the refusal codes of the rest.
func (e *billingEnv) admit(t *testing.T, n int, prefix string, keyFor func(i int) Token, hintFor func(i int) []types.OrgLeaseHint) (int, map[string]int) {
	t.Helper()
	var admitted atomic.Int64
	var mu sync.Mutex
	refusals := map[string]int{}
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			cmd := e.cmd(t, keyFor(i), fmt.Sprintf("%s-%d", prefix, i), types.OrgBillingActionReserve)
			cmd.Bound = 1
			if hintFor != nil {
				cmd.LeaseHints = hintFor(i)
			}
			_, err := ApplyOrgBilling(context.Background(), cmd)
			if err == nil {
				admitted.Add(1)
				return
			}
			var accessErr *types.OrgAccessError
			code := "unexpected: " + err.Error()
			if errors.As(err, &accessErr) {
				code = accessErr.Code
			}
			mu.Lock()
			refusals[code]++
			mu.Unlock()
		})
	}
	wg.Wait()
	return int(admitted.Load()), refusals
}

// watchNeverNegative samples the wallet and every limited key while work runs.
func (e *billingEnv) watchNeverNegative(t *testing.T) (stop func()) {
	t.Helper()
	done := make(chan struct{})
	var wg sync.WaitGroup
	var bad atomic.Int64
	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			var users, tokens int64
			e.db.Model(&User{}).Where("quota < 0").Count(&users)
			e.db.Unscoped().Model(&Token{}).Where("remain_quota < 0").Count(&tokens)
			if users+tokens > 0 {
				bad.Add(1)
			}
			// A capacity run samples gently; a tight loop would compete with the load itself.
			if ms := loadParam("TEST_ORG_WATCH_MS", 0); ms > 0 {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
		}
	})
	return func() {
		close(done)
		wg.Wait()
		assert.Zero(t, bad.Load(), "balance went negative at some committed instant")
	}
}

func TestOrgQuotaNeverNegative(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		sameKey := func(key Token) func(int) Token { return func(int) Token { return key } }

		t.Run("wallet of 10 admits exactly 10 of 100 concurrent requests", func(t *testing.T) {
			e.reset(t, 10)
			stop := e.watchNeverNegative(t)
			admitted, refusals := e.admit(t, 100, "w", sameKey(e.f.memberKey), nil)
			stop()
			assert.Equal(t, 10, admitted)
			assert.Equal(t, map[string]int{types.OrgErrQuotaExhausted: 90}, refusals)
			assert.EqualValues(t, 0, e.walletQuota(t))
			assert.EqualValues(t, 10, e.count(t, &OrgBillingOperation{}), "refused requests leave no operation")
			e.assertInvariants(t)
		})

		t.Run("three instances mixing leases and direct holds still admit exactly 10", func(t *testing.T) {
			e.reset(t, 10)
			ctx := context.Background()
			var granted []*OrgQuotaLease
			for i, recent := range []int64{4, 3, 2} {
				lease, err := AcquireOrgQuotaLease(ctx, OrgLeaseRequest{OrgID: e.f.org.Id, TargetType: types.OrgLeaseTargetWallet,
					TargetID: e.f.wallet.Id, InstanceID: fmt.Sprintf("inst-%d", i), Shard: i, RecentConsumed: recent})
				require.NoError(t, err)
				require.NotNil(t, lease)
				granted = append(granted, lease)
			}
			assert.EqualValues(t, 2, granted[0].Amount)
			assert.EqualValues(t, 2, granted[1].Amount)
			assert.EqualValues(t, 1, granted[2].Amount)
			e.assertInvariants(t)

			hints := func(i int) []types.OrgLeaseHint {
				lease := granted[i%3]
				return []types.OrgLeaseHint{{TargetType: types.OrgHoldTargetWallet, TargetId: e.f.wallet.Id, LeaseId: lease.Id}}
			}
			stop := e.watchNeverNegative(t)
			admitted, refusals := e.admit(t, 100, "l", sameKey(e.f.memberKey), hints)
			stop()
			assert.Equal(t, 10, admitted)
			assert.Equal(t, map[string]int{types.OrgErrQuotaExhausted: 90}, refusals)
			assert.EqualValues(t, 0, e.walletQuota(t))
			for _, lease := range granted {
				row := e.lease(t, lease.Id)
				assert.LessOrEqual(t, row.Allocated+row.Consumed, row.Amount)
			}
			e.assertInvariants(t)
		})

		t.Run("limited key remain never goes below zero", func(t *testing.T) {
			e.reset(t, 1000)
			key := e.limitedKey(t, "limited", 7)
			stop := e.watchNeverNegative(t)
			admitted, refusals := e.admit(t, 60, "k", sameKey(key), nil)
			stop()
			assert.Equal(t, 7, admitted)
			assert.Equal(t, map[string]int{types.OrgErrKeyBudget: 53}, refusals)
			assert.EqualValues(t, 0, e.tokenRow(t, key.Id).RemainQuota)
			assert.EqualValues(t, 993, e.walletQuota(t), "refused requests roll the wallet hold back")
			e.assertInvariants(t)
		})

		t.Run("org month, member day and key lifetime budgets are all-or-nothing", func(t *testing.T) {
			e.reset(t, 1000)
			key := e.limitedKey(t, "stacked", 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 40)
			e.setBudget(t, types.BudgetScopeMember, e.f.member.Id, types.BudgetPeriodDaily, 25)
			e.setBudget(t, types.BudgetScopeKey, key.Id, types.BudgetPeriodLifetime, 9)
			stop := e.watchNeverNegative(t)
			admitted, refusals := e.admit(t, 100, "s", sameKey(key), nil)
			stop()
			assert.Equal(t, 9, admitted, "the tightest budget decides")
			assert.Equal(t, map[string]int{types.OrgErrKeyBudget: 91}, refusals)
			for scope, subject := range map[string]int{types.BudgetScopeOrg: e.f.org.Id, types.BudgetScopeMember: e.f.member.Id, types.BudgetScopeKey: key.Id} {
				period := map[string]string{types.BudgetScopeOrg: types.BudgetPeriodMonthly, types.BudgetScopeMember: types.BudgetPeriodDaily, types.BudgetScopeKey: types.BudgetPeriodLifetime}[scope]
				assert.EqualValues(t, 9, e.usage(t, scope, subject, period).HeldQuota, scope)
			}
			assert.EqualValues(t, 991, e.walletQuota(t))
			assert.EqualValues(t, 991, e.tokenRow(t, key.Id).RemainQuota)
			e.assertInvariants(t)
		})

		t.Run("a failure on any target rolls every other target back", func(t *testing.T) {
			e.reset(t, 1000)
			key := e.limitedKey(t, "rollback", 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 1000)
			e.setBudget(t, types.BudgetScopeMember, e.f.member.Id, types.BudgetPeriodDaily, 3)
			_, err := e.reserve(t, key, "rb-1", 2)
			require.NoError(t, err)
			_, err = e.reserve(t, key, "rb-2", 2)
			requireOrgRefusal(t, err, types.OrgErrMemberBudget)
			assert.EqualValues(t, 998, e.walletQuota(t))
			assert.EqualValues(t, 998, e.tokenRow(t, key.Id).RemainQuota)
			assert.EqualValues(t, 2, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			assert.EqualValues(t, 1, e.count(t, &OrgBillingOperation{}))
			e.assertInvariants(t)

			e.reset(t, 1)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 1000)
			_, err = e.reserve(t, e.f.memberKey, "rb-3", 2)
			requireOrgRefusal(t, err, types.OrgErrQuotaExhausted)
			assert.EqualValues(t, 0, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			assert.EqualValues(t, 1, e.walletQuota(t))
			e.assertInvariants(t)
		})

		t.Run("workspace and org budget codes name the scope that refused", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeWorkspace, e.f.workspace.Id, types.BudgetPeriodDaily, 1)
			_, err := e.reserve(t, e.f.memberKey, "sc-1", 2)
			requireOrgRefusal(t, err, types.OrgErrWorkspaceBudget)
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodWeekly, 1)
			_, err = e.reserve(t, e.f.systemKey, "sc-2", 2)
			requireOrgRefusal(t, err, types.OrgErrBudgetExceeded)
			e.assertInvariants(t)
		})
	})
}

func (e *billingEnv) walletLease(t *testing.T, instance string, recent int64) *OrgQuotaLease {
	t.Helper()
	lease, err := AcquireOrgQuotaLease(context.Background(), OrgLeaseRequest{OrgID: e.f.org.Id,
		TargetType: types.OrgLeaseTargetWallet, TargetID: e.f.wallet.Id, InstanceID: instance, RecentConsumed: recent})
	require.NoError(t, err)
	require.NotNil(t, lease)
	return lease
}

func (e *billingEnv) hint(targetType string, targetID, leaseID int) []types.OrgLeaseHint {
	return []types.OrgLeaseHint{{TargetType: targetType, TargetId: targetID, LeaseId: leaseID}}
}

func (e *billingEnv) expireLease(t *testing.T, id int) {
	t.Helper()
	require.NoError(t, e.db.Model(&OrgQuotaLease{}).Where("id = ?", id).Update("expires_at", time.Now().Unix()-5).Error)
}

func TestOrgLeaseFencing(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		ctx := context.Background()

		t.Run("a swept lease never admits another request", func(t *testing.T) {
			e.reset(t, 100)
			lease := e.walletLease(t, "inst-a", 40)
			assert.EqualValues(t, 25, lease.Amount)
			assert.EqualValues(t, 75, e.walletQuota(t))
			e.assertInvariants(t)

			cmd := e.cmd(t, e.f.memberKey, "lf-1", types.OrgBillingActionReserve)
			cmd.Bound, cmd.LeaseHints = 10, e.hint(types.OrgHoldTargetWallet, e.f.wallet.Id, lease.Id)
			res := e.mustApply(t, cmd)
			assert.Equal(t, strconv.Itoa(lease.Id), holdOf(res.Holds, types.OrgHoldTargetWallet).Source)
			assert.EqualValues(t, 75, e.walletQuota(t), "lease reservations do not touch users.quota")
			assert.EqualValues(t, 10, e.lease(t, lease.Id).Allocated)
			e.assertInvariants(t)

			cmd.OperationID, cmd.Bound = "lf-big", 20
			res = e.mustApply(t, cmd)
			assert.Equal(t, types.OrgHoldSourceDirect, holdOf(res.Holds, types.OrgHoldTargetWallet).Source, "lease cannot cover 20 more")
			assert.EqualValues(t, 55, e.walletQuota(t))
			e.assertInvariants(t)

			e.expireLease(t, lease.Id)
			swept, err := SweepOrgQuotaLeases(ctx, 100)
			require.NoError(t, err)
			assert.Zero(t, swept.Closed, "a lease with allocation cannot close yet")
			assert.Equal(t, 1, swept.Revoked)
			assert.Equal(t, types.OrgLeaseStatusRevoked, e.lease(t, lease.Id).Status)
			e.assertInvariants(t)

			cmd.OperationID, cmd.Bound = "lf-2", 1
			res = e.mustApply(t, cmd)
			assert.Equal(t, types.OrgHoldSourceDirect, holdOf(res.Holds, types.OrgHoldTargetWallet).Source, "revoked lease is bypassed")
			assert.EqualValues(t, 10, e.lease(t, lease.Id).Allocated, "revoked lease took nothing new")
			assert.EqualValues(t, 54, e.walletQuota(t))
			e.assertInvariants(t)

			captured, err := e.capture(t, e.f.memberKey, "lf-1", 6, 1)
			require.NoError(t, err)
			assert.EqualValues(t, 6, captured.Captured)
			row := e.lease(t, lease.Id)
			assert.EqualValues(t, 0, row.Allocated)
			assert.EqualValues(t, 6, row.Consumed)
			assert.EqualValues(t, 54, e.walletQuota(t))
			e.assertInvariants(t)

			swept, err = SweepOrgQuotaLeases(ctx, 100)
			require.NoError(t, err)
			assert.Equal(t, 1, swept.Closed)
			assert.Equal(t, types.OrgLeaseStatusClosed, e.lease(t, lease.Id).Status)
			assert.EqualValues(t, 54+19, e.walletQuota(t), "amount - consumed returns to the wallet")
			e.assertInvariants(t)

			again, err := SweepOrgQuotaLeases(ctx, 100)
			require.NoError(t, err)
			assert.Zero(t, again.Closed)
			assert.EqualValues(t, 73, e.walletQuota(t), "closing twice cannot refund twice")
		})

		t.Run("an expired but unswept lease is not used", func(t *testing.T) {
			e.reset(t, 100)
			lease := e.walletLease(t, "inst-a", 40)
			e.expireLease(t, lease.Id)
			cmd := e.cmd(t, e.f.memberKey, "lf-exp", types.OrgBillingActionReserve)
			cmd.Bound, cmd.LeaseHints = 5, e.hint(types.OrgHoldTargetWallet, e.f.wallet.Id, lease.Id)
			res := e.mustApply(t, cmd)
			assert.Equal(t, types.OrgHoldSourceDirect, holdOf(res.Holds, types.OrgHoldTargetWallet).Source)
			assert.EqualValues(t, 0, e.lease(t, lease.Id).Allocated)
			e.assertInvariants(t)
		})

		t.Run("lowering a budget fences leases and instances move to direct holds", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 400)
			usage := e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
			lease, err := AcquireOrgQuotaLease(ctx, OrgLeaseRequest{OrgID: e.f.org.Id, TargetType: types.OrgLeaseTargetBudget,
				TargetID: usage.Id, InstanceID: "inst-a", RecentConsumed: 500})
			require.NoError(t, err)
			require.NotNil(t, lease)
			assert.EqualValues(t, 100, lease.Amount)
			assert.EqualValues(t, 100, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			e.assertInvariants(t)

			cmd := e.cmd(t, e.f.memberKey, "bl-1", types.OrgBillingActionReserve)
			cmd.Bound, cmd.LeaseHints = 30, e.hint(types.OrgHoldTargetBudget, usage.Id, lease.Id)
			res := e.mustApply(t, cmd)
			assert.Equal(t, strconv.Itoa(lease.Id), holdOf(res.Holds, types.OrgHoldTargetBudget).Source)
			assert.EqualValues(t, 30, e.lease(t, lease.Id).Allocated)
			assert.EqualValues(t, 100, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota, "lease holds were counted at grant time")
			e.assertInvariants(t)

			status, err := ChangeBudgetLimit(ctx, OrgBudgetChange{OrgID: e.f.org.Id, Scope: types.BudgetScopeOrg,
				SubjectID: e.f.org.Id, Period: types.BudgetPeriodMonthly, LimitQuota: 200, Enabled: true})
			require.NoError(t, err)
			assert.EqualValues(t, 30, status.Held, "unused 70 returned, 30 in flight stays")
			row := e.lease(t, lease.Id)
			assert.Equal(t, types.OrgLeaseStatusRevoked, row.Status)
			assert.EqualValues(t, 30, row.Amount)
			assert.EqualValues(t, 30, row.Allocated)
			e.assertInvariants(t)

			cmd.OperationID, cmd.Bound = "bl-2", 1
			res = e.mustApply(t, cmd)
			assert.Equal(t, types.OrgHoldSourceDirect, holdOf(res.Holds, types.OrgHoldTargetBudget).Source)
			assert.EqualValues(t, 30, e.lease(t, lease.Id).Allocated, "revoked lease admits nothing")
			_, err = e.capture(t, e.f.memberKey, "bl-1", 30, 1)
			require.NoError(t, err)
			e.assertInvariants(t)
		})

		t.Run("a lease from the previous window is never used for the current one", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodDaily, 400)
			current := e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodDaily)
			yesterday := OrgBudgetUsage{OrgId: e.f.org.Id, Scope: types.BudgetScopeOrg, SubjectId: e.f.org.Id,
				Period: types.BudgetPeriodDaily, WindowStart: current.WindowStart - 86400, HeldQuota: 50}
			require.NoError(t, e.db.Create(&yesterday).Error)
			stale := OrgQuotaLease{OrgId: e.f.org.Id, TargetType: types.OrgLeaseTargetBudget, TargetId: yesterday.Id,
				WindowEnd: current.WindowStart, InstanceId: "inst-a", Amount: 50, Status: types.OrgLeaseStatusActive,
				ExpiresAt: time.Now().Unix() + 600, CreatedAt: time.Now().Unix()}
			require.NoError(t, e.db.Create(&stale).Error)

			cmd := e.cmd(t, e.f.memberKey, "xm-1", types.OrgBillingActionReserve)
			cmd.Bound, cmd.LeaseHints = 10, e.hint(types.OrgHoldTargetBudget, yesterday.Id, stale.Id)
			res := e.mustApply(t, cmd)
			hold := holdOf(res.Holds, types.OrgHoldTargetBudget)
			assert.Equal(t, types.OrgHoldSourceDirect, hold.Source)
			assert.Equal(t, current.Id, hold.TargetId)
			assert.EqualValues(t, 0, e.lease(t, stale.Id).Allocated)
			assert.EqualValues(t, 10, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodDaily).HeldQuota)
		})

		t.Run("operation lease owner is fenced against the recovery worker", func(t *testing.T) {
			e.reset(t, 1000)
			key := e.f.memberKey
			_, err := e.reserve(t, key, "fence-1", 100)
			require.NoError(t, err)

			stranger := e.cmd(t, key, "fence-1", types.OrgBillingActionCapture)
			stranger.Amount, stranger.Revision, stranger.LeaseOwner = 50, 1, "inst-z"
			_, err = ApplyOrgBilling(ctx, stranger)
			requireConflict(t, err)
			assert.EqualValues(t, 900, e.walletQuota(t))

			claimed, err := ClaimOrgOperationForRecovery(ctx, "fence-1", 0, "recovery-1")
			require.NoError(t, err)
			assert.False(t, claimed, "a live lease cannot be claimed")
			ok, err := RenewOrgOperationLease(ctx, "fence-1", "inst-a", 33)
			require.NoError(t, err)
			require.True(t, ok)
			ok, err = RenewOrgOperationLease(ctx, "fence-1", "inst-z", 99)
			require.NoError(t, err)
			assert.False(t, ok, "only the owner renews")
			op := e.operation(t, "fence-1")
			assert.EqualValues(t, 33, op.ProgressQuota)
			assert.Greater(t, op.LeaseUntil, time.Now().Unix()+60)

			require.NoError(t, e.db.Model(&OrgBillingOperation{}).Where("operation_id = ?", "fence-1").Update("lease_until", time.Now().Unix()-5).Error)
			claimed, err = ClaimOrgOperationForRecovery(ctx, "fence-1", 99, "recovery-1")
			require.NoError(t, err)
			assert.False(t, claimed, "stale revision loses")
			claimed, err = ClaimOrgOperationForRecovery(ctx, "fence-1", 0, "recovery-1")
			require.NoError(t, err)
			require.True(t, claimed)
			claimed, err = ClaimOrgOperationForRecovery(ctx, "fence-1", 0, "recovery-2")
			require.NoError(t, err)
			assert.False(t, claimed, "only one worker wins")

			late := e.cmd(t, key, "fence-1", types.OrgBillingActionCapture)
			late.Amount, late.Revision, late.LeaseOwner = 80, 1, "inst-a"
			_, err = ApplyOrgBilling(ctx, late)
			requireConflict(t, err)
			assert.EqualValues(t, 900, e.walletQuota(t), "the original owner lost the race and wrote nothing")
			assert.EqualValues(t, 0, e.count(t, &OrgSpendEvent{}))

			recovery := e.cmd(t, key, "fence-1", types.OrgBillingActionCapture)
			recovery.Amount, recovery.Revision, recovery.LeaseOwner, recovery.SettledBy = 33, 1, "recovery-1", types.OrgSettledByRecovery
			res := e.mustApply(t, recovery)
			assert.Equal(t, types.OrgOpStateClosed, res.State)
			assert.Equal(t, types.OrgSettledByRecovery, e.operation(t, "fence-1").SettledBy)
			assert.EqualValues(t, 967, e.walletQuota(t))
			e.assertInvariants(t)
		})

		t.Run("crashed instance funds return after recovery settles and the lease closes", func(t *testing.T) {
			e.reset(t, 100)
			lease := e.walletLease(t, "inst-a", 40)
			cmd := e.cmd(t, e.f.memberKey, "crash-1", types.OrgBillingActionReserve)
			cmd.Bound, cmd.LeaseHints = 10, e.hint(types.OrgHoldTargetWallet, e.f.wallet.Id, lease.Id)
			e.mustApply(t, cmd)
			e.expireLease(t, lease.Id)
			require.NoError(t, e.db.Model(&OrgBillingOperation{}).Where("operation_id = ?", "crash-1").Update("lease_until", time.Now().Unix()-1).Error)

			swept, err := SweepOrgQuotaLeases(ctx, 100)
			require.NoError(t, err)
			assert.Zero(t, swept.Closed)
			claimed, err := ClaimOrgOperationForRecovery(ctx, "crash-1", 0, "recovery-1")
			require.NoError(t, err)
			require.True(t, claimed)
			settle := e.cmd(t, e.f.memberKey, "crash-1", types.OrgBillingActionCapture)
			settle.Amount, settle.Revision, settle.LeaseOwner, settle.SettledBy = 7, 1, "recovery-1", types.OrgSettledByRecovery
			e.mustApply(t, settle)
			swept, err = SweepOrgQuotaLeases(ctx, 100)
			require.NoError(t, err)
			assert.Equal(t, 1, swept.Closed)
			assert.EqualValues(t, 93, e.walletQuota(t), "everything but the 7 consumed is available again")
			e.assertInvariants(t)
		})
	})
}

func TestOrgQuotaLeases(t *testing.T) {
	t.Run("lease expiry is ten seconds and ends two seconds before the window", func(t *testing.T) {
		now := int64(1_700_000_000)
		for name, tc := range map[string]struct {
			windowEnd int64
			want      int64
			ok        bool
		}{
			"wallet has no window":      {0, now + 10, true},
			"far window end":            {now + 86400, now + 10, true},
			"window ends in 5 seconds":  {now + 5, now + 3, true},
			"window ends in 12 seconds": {now + 12, now + 10, true},
			"window ends in 2 seconds":  {now + 2, 0, false},
			"window already over":       {now - 1, 0, false},
		} {
			got, ok := OrgLeaseExpiry(now, tc.windowEnd)
			assert.Equal(t, tc.ok, ok, name)
			assert.Equal(t, tc.want, got, name)
		}
	})

	t.Run("budget windows are fixed to UTC", func(t *testing.T) {
		at := time.Date(2026, time.March, 18, 15, 4, 5, 0, time.UTC).Unix() // a Wednesday
		for period, want := range map[string][2]time.Time{
			types.BudgetPeriodDaily:   {time.Date(2026, 3, 18, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 19, 0, 0, 0, 0, time.UTC)},
			types.BudgetPeriodWeekly:  {time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 23, 0, 0, 0, 0, time.UTC)},
			types.BudgetPeriodMonthly: {time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)},
		} {
			start, end := OrgBudgetWindow(period, at)
			assert.Equal(t, want[0].Unix(), start, period)
			assert.Equal(t, want[1].Unix(), end, period)
		}
		start, end := OrgBudgetWindow(types.BudgetPeriodLifetime, at)
		assert.Zero(t, start)
		assert.Zero(t, end)
		sunday := time.Date(2026, time.March, 22, 23, 59, 59, 0, time.UTC).Unix()
		start, _ = OrgBudgetWindow(types.BudgetPeriodWeekly, sunday)
		assert.Equal(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC).Unix(), start)
	})

	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		ctx := context.Background()
		request := func(target string, id int, shard int, recent int64) OrgLeaseRequest {
			return OrgLeaseRequest{OrgID: e.f.org.Id, TargetType: target, TargetID: id, InstanceID: "inst-a", Shard: shard, RecentConsumed: recent}
		}

		t.Run("amount is min of a quarter of the remainder and twice recent consumption", func(t *testing.T) {
			e.reset(t, 1000)
			lease, err := AcquireOrgQuotaLease(ctx, request(types.OrgLeaseTargetWallet, e.f.wallet.Id, 0, 30))
			require.NoError(t, err)
			assert.EqualValues(t, 60, lease.Amount, "2x recent wins")
			assert.EqualValues(t, 940, e.walletQuota(t))
			assert.Equal(t, types.OrgLeaseStatusActive, lease.Status)
			assert.InDelta(t, time.Now().Unix()+10, lease.ExpiresAt, 3)
			e.assertInvariants(t)

			lease, err = AcquireOrgQuotaLease(ctx, request(types.OrgLeaseTargetWallet, e.f.wallet.Id, 1, 5000))
			require.NoError(t, err)
			assert.EqualValues(t, 235, lease.Amount, "a quarter of 940 wins")
			none, err := AcquireOrgQuotaLease(ctx, request(types.OrgLeaseTargetWallet, e.f.wallet.Id, 2, 0))
			require.NoError(t, err)
			assert.Nil(t, none, "no recent consumption means no lease")
			_, err = AcquireOrgQuotaLease(ctx, request(types.OrgLeaseTargetWallet, e.f.wallet.Id, OrgLeaseShards, 10))
			require.Error(t, err)
			_, err = AcquireOrgQuotaLease(ctx, request(types.OrgLeaseTargetWallet, e.f.wallet.Id+100, 0, 10))
			requireOrgRefusal(t, err, types.OrgErrNotFound)
			e.assertInvariants(t)
		})

		t.Run("budget lease counts against held and stops at the limit", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 100)
			usage := e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
			lease, err := AcquireOrgQuotaLease(ctx, request(types.OrgLeaseTargetBudget, usage.Id, 0, 1000))
			require.NoError(t, err)
			assert.EqualValues(t, 25, lease.Amount)
			assert.EqualValues(t, usage.WindowStart+monthSeconds(t, usage.WindowStart), lease.WindowEnd)
			assert.LessOrEqual(t, lease.ExpiresAt, lease.WindowEnd-2)
			assert.EqualValues(t, 25, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			assert.EqualValues(t, 1000, e.walletQuota(t), "a budget lease never touches the wallet")
			e.assertInvariants(t)

			for range 6 {
				_, err = AcquireOrgQuotaLease(ctx, request(types.OrgLeaseTargetBudget, usage.Id, 1, 1000))
				require.NoError(t, err)
			}
			final := e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
			assert.LessOrEqual(t, final.SpentQuota+final.HeldQuota, int64(100))
			e.assertInvariants(t)

			_, err = ChangeBudgetLimit(ctx, OrgBudgetChange{OrgID: e.f.org.Id, Scope: types.BudgetScopeOrg, SubjectID: e.f.org.Id,
				Period: types.BudgetPeriodMonthly, LimitQuota: 100, Enabled: false})
			require.NoError(t, err)
			none, err := AcquireOrgQuotaLease(ctx, request(types.OrgLeaseTargetBudget, usage.Id, 2, 1000))
			require.NoError(t, err)
			assert.Nil(t, none, "a disabled budget grants no lease")
		})

		t.Run("shutdown revokes the instance's own leases and the sweeper closes them", func(t *testing.T) {
			e.reset(t, 100)
			mine := e.walletLease(t, "inst-a", 40)
			other, err := AcquireOrgQuotaLease(ctx, OrgLeaseRequest{OrgID: e.f.org.Id, TargetType: types.OrgLeaseTargetWallet,
				TargetID: e.f.wallet.Id, InstanceID: "inst-b", RecentConsumed: 40})
			require.NoError(t, err)
			revoked, err := RevokeOrgInstanceLeases(ctx, "inst-a")
			require.NoError(t, err)
			assert.Equal(t, 1, revoked)
			assert.Equal(t, types.OrgLeaseStatusRevoked, e.lease(t, mine.Id).Status)
			assert.Equal(t, types.OrgLeaseStatusActive, e.lease(t, other.Id).Status)
			swept, err := SweepOrgQuotaLeases(ctx, 100)
			require.NoError(t, err)
			assert.Equal(t, 1, swept.Closed)
			assert.EqualValues(t, 100-other.Amount, e.walletQuota(t))
			e.assertInvariants(t)
		})

		t.Run("balance view splits available from in-flight holds", func(t *testing.T) {
			e.reset(t, 1000)
			lease := e.walletLease(t, "inst-a", 100)
			cmd := e.cmd(t, e.f.memberKey, "bv-1", types.OrgBillingActionReserve)
			cmd.Bound, cmd.LeaseHints = 20, e.hint(types.OrgHoldTargetWallet, e.f.wallet.Id, lease.Id)
			e.mustApply(t, cmd)
			_, err := e.reserve(t, e.f.systemKey, "bv-2", 30)
			require.NoError(t, err)
			view, err := OrgBalanceView(ctx, e.f.org.Id)
			require.NoError(t, err)
			assert.EqualValues(t, e.walletQuota(t), view.Available)
			assert.EqualValues(t, lease.Amount, view.LeaseHeld)
			assert.EqualValues(t, 30, view.DirectHeld)
			assert.EqualValues(t, lease.Amount+30, view.InFlight)
			available, err := OrgWalletAvailable(e.db, e.f.wallet.Id)
			require.NoError(t, err)
			assert.EqualValues(t, view.Available, available)
			_, err = OrgBalanceView(ctx, e.f.org.Id+100)
			requireOrgRefusal(t, err, types.OrgErrNotFound)

			_, err = e.capture(t, e.f.systemKey, "bv-2", 30, 1)
			require.NoError(t, err)
			view, err = OrgBalanceView(ctx, e.f.org.Id)
			require.NoError(t, err)
			assert.EqualValues(t, 0, view.DirectHeld, "closed operations hold nothing")
			e.assertInvariants(t)
		})

		t.Run("negative platform adjustment cannot dip into leased money", func(t *testing.T) {
			e.reset(t, 100)
			lease := e.walletLease(t, "inst-a", 100)
			require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
				ok, err := DecreaseOrgWalletTx(tx, e.f.wallet.Id, 100)
				require.NoError(t, err)
				assert.False(t, ok, "only 75 is unleased")
				ok, err = DecreaseOrgWalletTx(tx, e.f.wallet.Id, 75)
				require.NoError(t, err)
				assert.True(t, ok)
				return nil
			}))
			assert.EqualValues(t, 0, e.walletQuota(t))
			assert.EqualValues(t, 25, lease.Amount)
		})
	})
}

func monthSeconds(t *testing.T, start int64) int64 {
	t.Helper()
	begin := time.Unix(start, 0).UTC()
	return begin.AddDate(0, 1, 0).Unix() - start
}

func TestOrgBudgetChangeSemantics(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		ctx := context.Background()
		orgUsage := func() OrgBudgetUsage {
			return e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
		}
		change := func(limit int64, enabled bool, expected int64) (OrgBudgetStatus, error) {
			return ChangeBudgetLimit(ctx, OrgBudgetChange{OrgID: e.f.org.Id, Scope: types.BudgetScopeOrg, SubjectID: e.f.org.Id,
				Period: types.BudgetPeriodMonthly, LimitQuota: limit, Enabled: enabled, ExpectedVersion: expected})
		}

		t.Run("lowering revokes leases, refunds the unused part and applies to later admissions", func(t *testing.T) {
			e.reset(t, 1000)
			status := e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 1000)
			assert.EqualValues(t, 1000, status.Limit)
			assert.EqualValues(t, 1000, status.Available)

			usage := orgUsage()
			lease, err := AcquireOrgQuotaLease(ctx, OrgLeaseRequest{OrgID: e.f.org.Id, TargetType: types.OrgLeaseTargetBudget,
				TargetID: usage.Id, InstanceID: "inst-a", RecentConsumed: 10000})
			require.NoError(t, err)
			assert.EqualValues(t, 250, lease.Amount)
			cmd := e.cmd(t, e.f.memberKey, "bc-1", types.OrgBillingActionReserve)
			cmd.Bound, cmd.LeaseHints = 100, e.hint(types.OrgHoldTargetBudget, usage.Id, lease.Id)
			e.mustApply(t, cmd)
			cmd.OperationID, cmd.Bound = "bc-2", 20
			e.mustApply(t, cmd)
			_, err = e.capture(t, e.f.memberKey, "bc-1", 100, 1)
			require.NoError(t, err)
			_, err = FoldOrgSpend(ctx, e.f.org.Id, 100)
			require.NoError(t, err)
			e.assertInvariants(t)
			assert.EqualValues(t, 100, orgUsage().SpentQuota)
			assert.EqualValues(t, 150, orgUsage().HeldQuota)

			status, err = change(180, true, 0)
			require.NoError(t, err)
			assert.EqualValues(t, 180, status.Limit)
			assert.EqualValues(t, 100, status.Spent)
			assert.EqualValues(t, 20, status.Held, "unused = amount - allocated - consumed = 130 returned")
			assert.EqualValues(t, 0, status.OverBy)
			row := e.lease(t, lease.Id)
			assert.Equal(t, types.OrgLeaseStatusRevoked, row.Status)
			assert.EqualValues(t, row.Allocated+row.Consumed, row.Amount)
			assert.EqualValues(t, 20, row.Allocated)
			assert.EqualValues(t, 100, row.Consumed)
			e.assertInvariants(t)

			_, err = e.reserve(t, e.f.memberKey, "bc-3", 61)
			requireOrgRefusal(t, err, types.OrgErrBudgetExceeded)
			_, err = e.reserve(t, e.f.memberKey, "bc-4", 60)
			require.NoError(t, err)
			e.assertInvariants(t)
			var version int64
			require.NoError(t, e.db.Model(&Organization{}).Where("id = ?", e.f.org.Id).Select("policy_version").Scan(&version).Error)
			assert.EqualValues(t, 3+2, version, "each budget change bumps policy_version")
		})

		t.Run("lowering below what is already admitted reports over_by and keeps settling", func(t *testing.T) {
			e.reset(t, 1000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 500)
			_, err := e.reserve(t, e.f.memberKey, "ob-1", 100)
			require.NoError(t, err)
			_, err = e.reserve(t, e.f.memberKey, "ob-2", 100)
			require.NoError(t, err)
			status, err := change(50, true, 0)
			require.NoError(t, err)
			assert.EqualValues(t, 200, status.Held)
			assert.EqualValues(t, 150, status.OverBy)
			assert.EqualValues(t, 0, status.Available)
			_, err = e.reserve(t, e.f.memberKey, "ob-3", 1)
			requireOrgRefusal(t, err, types.OrgErrBudgetExceeded)

			_, err = e.capture(t, e.f.memberKey, "ob-1", 100, 1)
			require.NoError(t, err)
			_, err = FoldOrgSpend(ctx, e.f.org.Id, 100)
			require.NoError(t, err)
			status, err = GetOrgBudgetStatus(ctx, e.f.org.Id, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
			require.NoError(t, err)
			assert.EqualValues(t, 100, status.Spent)
			assert.EqualValues(t, 100, status.Held)
			assert.EqualValues(t, 150, status.OverBy, "spent + held - limit")
			e.assertInvariants(t, true)

			status, err = change(400, true, 0)
			require.NoError(t, err)
			assert.EqualValues(t, 0, status.OverBy)
			_, err = e.reserve(t, e.f.memberKey, "ob-4", 100)
			require.NoError(t, err)
			e.assertInvariants(t)
		})

		t.Run("enabling uses the spend already projected and disabling stops holding", func(t *testing.T) {
			e.reset(t, 1000)
			for _, id := range []string{"en-1", "en-2"} {
				_, err := e.reserve(t, e.f.memberKey, id, 30)
				require.NoError(t, err)
				_, err = e.capture(t, e.f.memberKey, id, 30, 1)
				require.NoError(t, err)
			}
			_, err := FoldOrgSpend(ctx, e.f.org.Id, 100)
			require.NoError(t, err)
			assert.EqualValues(t, 60, orgUsage().SpentQuota, "spend is projected before any budget exists")

			status, err := change(100, true, 0)
			require.NoError(t, err)
			assert.EqualValues(t, 60, status.Spent, "enabling starts from existing spend, not zero")
			assert.EqualValues(t, 40, status.Available)
			_, err = e.reserve(t, e.f.memberKey, "en-3", 41)
			requireOrgRefusal(t, err, types.OrgErrBudgetExceeded)
			_, err = e.reserve(t, e.f.memberKey, "en-4", 40)
			require.NoError(t, err)

			status, err = change(100, false, 0)
			require.NoError(t, err)
			assert.EqualValues(t, 40, status.Held, "an in-flight hold survives disabling")
			res, err := e.reserve(t, e.f.memberKey, "en-5", 500)
			require.NoError(t, err)
			assert.Nil(t, holdOf(res.Holds, types.OrgHoldTargetBudget), "disabled budgets take no hold")
			e.assertInvariants(t)
		})

		t.Run("raising applies at once and a stale version is refused", func(t *testing.T) {
			e.reset(t, 1000)
			status := e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 10)
			assert.EqualValues(t, 1, status.Version)
			_, err := e.reserve(t, e.f.memberKey, "up-1", 11)
			requireOrgRefusal(t, err, types.OrgErrBudgetExceeded)
			status, err = change(100, true, 1)
			require.NoError(t, err)
			assert.EqualValues(t, 2, status.Version)
			_, err = e.reserve(t, e.f.memberKey, "up-2", 11)
			require.NoError(t, err)
			_, err = change(5, true, 1)
			requireConflict(t, err)
			assert.EqualValues(t, 100, mustStatus(t, e).Limit, "a refused change writes nothing")
			_, err = ChangeBudgetLimit(ctx, OrgBudgetChange{OrgID: e.f.org.Id, Scope: "team", SubjectID: 1, Period: types.BudgetPeriodMonthly, LimitQuota: 1})
			require.Error(t, err)
			_, err = ChangeBudgetLimit(ctx, OrgBudgetChange{OrgID: e.f.org.Id, Scope: types.BudgetScopeOrg, SubjectID: e.f.org.Id, Period: types.BudgetPeriodMonthly, LimitQuota: -1})
			require.Error(t, err)
			e.assertInvariants(t)
		})
	})
}

func mustStatus(t *testing.T, e *billingEnv) OrgBudgetStatus {
	t.Helper()
	status, err := GetOrgBudgetStatus(context.Background(), e.f.org.Id, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
	require.NoError(t, err)
	return status
}

func TestOrgSpendFolder(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		ctx := context.Background()

		t.Run("folds every projection, rollup and counter in one batch", func(t *testing.T) {
			e.reset(t, 10000)
			memberKey := e.limitedKey(t, "folder-limited", 5000)
			unlimited := e.f.memberKey
			system := e.f.systemKey
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 1000)
			e.setBudget(t, types.BudgetScopeWorkspace, e.f.workspace.Id, types.BudgetPeriodDaily, 1000)
			e.setBudget(t, types.BudgetScopeMember, e.f.member.Id, types.BudgetPeriodDaily, 1000)
			e.setBudget(t, types.BudgetScopeKey, memberKey.Id, types.BudgetPeriodLifetime, 1000)
			orgUsage := e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)

			// 1: direct sync, limited member key, charge 60 of bound 80.
			_, err := e.reserve(t, memberKey, "f-1", 80)
			require.NoError(t, err)
			_, err = e.capture(t, memberKey, "f-1", 60, 1)
			require.NoError(t, err)
			// 2: lease-sourced org budget hold, unlimited key, charge 40 of 100.
			lease, err := AcquireOrgQuotaLease(ctx, OrgLeaseRequest{OrgID: e.f.org.Id, TargetType: types.OrgLeaseTargetBudget,
				TargetID: orgUsage.Id, InstanceID: "inst-a", RecentConsumed: 1000})
			require.NoError(t, err)
			cmd := e.cmd(t, unlimited, "f-2", types.OrgBillingActionReserve)
			cmd.Bound, cmd.ModelName = 100, "gpt-y"
			cmd.LeaseHints = e.hint(types.OrgHoldTargetBudget, orgUsage.Id, lease.Id)
			e.mustApply(t, cmd)
			_, err = e.capture(t, unlimited, "f-2", 40, 1)
			require.NoError(t, err)
			// 3: system key (actor 0), charge 25 of bound 10 -> 10 charged, 15 written off.
			sys := e.cmd(t, system, "f-3", types.OrgBillingActionReserve)
			sys.Bound = 10
			e.mustApply(t, sys)
			res, err := e.capture(t, system, "f-3", 25, 1)
			require.NoError(t, err)
			assert.EqualValues(t, 10, res.Captured)
			assert.EqualValues(t, 15, res.Writeoff)
			// 4: refund 20 of operation 1, after its capture.
			refund := e.cmd(t, memberKey, "f-1", types.OrgBillingActionRefund)
			refund.Amount, refund.Revision = 20, 1
			e.mustApply(t, refund)
			quotaBefore := e.walletQuota(t)
			e.assertInvariants(t)

			folded, err := FoldOrgSpend(ctx, e.f.org.Id, 2000)
			require.NoError(t, err)
			assert.Equal(t, 4, folded.Rows)
			assert.EqualValues(t, 60+40+10-20, folded.SpendSum)
			assert.EqualValues(t, 15, folded.WriteoffSum)
			assert.Equal(t, quotaBefore, e.walletQuota(t), "the folder never touches users.quota")
			assert.EqualValues(t, 0, e.count(t, &OrgSpendFoldQueue{}))
			e.assertInvariants(t)

			orgMonth := e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
			assert.EqualValues(t, 90, orgMonth.SpentQuota)
			assert.Equal(t, lease.Amount-40, orgMonth.HeldQuota, "the lease keeps its unconsumed remainder")
			assert.EqualValues(t, 40, e.lease(t, lease.Id).Folded, "folded follows the spend taken from the lease")
			orgLife := e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodLifetime)
			assert.EqualValues(t, 90, orgLife.SpentQuota, "periods without a budget still accumulate spend")
			assert.EqualValues(t, 0, orgLife.HeldQuota)
			assert.EqualValues(t, 90, e.usage(t, types.BudgetScopeWorkspace, e.f.workspace.Id, types.BudgetPeriodDaily).SpentQuota)
			assert.EqualValues(t, 80, e.usage(t, types.BudgetScopeMember, e.f.member.Id, types.BudgetPeriodDaily).SpentQuota,
				"member scope carries member keys only, and the refund")
			assert.EqualValues(t, 40, e.usage(t, types.BudgetScopeKey, memberKey.Id, types.BudgetPeriodLifetime).SpentQuota)
			assert.EqualValues(t, 40, e.usage(t, types.BudgetScopeKey, unlimited.Id, types.BudgetPeriodMonthly).SpentQuota)
			assert.EqualValues(t, 10, e.usage(t, types.BudgetScopeKey, system.Id, types.BudgetPeriodMonthly).SpentQuota)
			assert.EqualValues(t, 24, e.count(t, &OrgBudgetUsage{}), "org, workspace, member and three keys, four periods each")
			var systemMember int64
			require.NoError(t, e.db.Model(&OrgBudgetUsage{}).Where("scope = ? AND subject_id = ?", types.BudgetScopeMember, 0).Count(&systemMember).Error)
			assert.Zero(t, systemMember, "actor 0 produces no member projection")

			var wallet User
			require.NoError(t, e.db.First(&wallet, e.f.wallet.Id).Error)
			assert.EqualValues(t, 90, wallet.UsedQuota)
			assert.EqualValues(t, 3, wallet.RequestCount, "refunds are not requests")
			limited := e.tokenRow(t, memberKey.Id)
			assert.EqualValues(t, 40, limited.UsedQuota, "limited key used_quota moves at reserve, settle and refund, not in the folder")
			assert.EqualValues(t, 4960, limited.RemainQuota)
			assert.EqualValues(t, 40, e.tokenRow(t, unlimited.Id).UsedQuota)
			assert.EqualValues(t, 10, e.tokenRow(t, system.Id).UsedQuota)

			var batches []OrgFoldBatch
			require.NoError(t, e.db.Find(&batches).Error)
			require.Len(t, batches, 1)
			assert.Equal(t, 4, batches[0].RowCount)
			assert.EqualValues(t, 90, batches[0].SpendSum)
			assert.Equal(t, time.Now().UTC().Format("2006-01"), batches[0].Period)
			assert.InDelta(t, time.Now().Unix(), batches[0].FoldedAt, 5)

			var rollups []OrgSpendRollup
			require.NoError(t, e.db.Find(&rollups).Error)
			var rollupSum int64
			keys := map[string]bool{}
			for _, row := range rollups {
				rollupSum += row.SpendQuota
				keys[row.RollupKey] = true
				assert.Equal(t, batches[0].Period, row.Period)
				assert.Equal(t, batches[0].Period, row.EffectivePeriod)
				assert.Equal(t, e.f.workspace.Id, row.WorkspaceId)
			}
			assert.EqualValues(t, batches[0].SpendSum, rollupSum, "rollups sum to the batch")
			assert.Len(t, keys, 2, "gpt-x and gpt-y roll up separately")

			var writeoffs []OrgWriteoffDaily
			require.NoError(t, e.db.Find(&writeoffs).Error)
			require.Len(t, writeoffs, 1)
			assert.Equal(t, unixDay(time.Now().Unix()), writeoffs[0].Day)
			assert.Equal(t, "gpt-x", writeoffs[0].ModelName)
			assert.EqualValues(t, 15, writeoffs[0].WriteoffQuota)
			today, err := OrgWriteoffToday(ctx, e.f.org.Id, "gpt-x")
			require.NoError(t, err)
			assert.EqualValues(t, 15, today)

			empty, err := FoldOrgSpend(ctx, e.f.org.Id, 2000)
			require.NoError(t, err)
			assert.Zero(t, empty.Rows)
			assert.EqualValues(t, 1, e.count(t, &OrgFoldBatch{}), "an empty fold writes no batch")
		})

		t.Run("a failed write rolls the whole batch back and a rerun folds it once", func(t *testing.T) {
			e.reset(t, 10000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 1000)
			for i := range 3 {
				id := fmt.Sprintf("rb-%d", i)
				_, err := e.reserve(t, e.f.memberKey, id, 50)
				require.NoError(t, err)
				_, err = e.capture(t, e.f.memberKey, id, 30, 1)
				require.NoError(t, err)
			}
			fail := true
			require.NoError(t, e.db.Callback().Create().Before("gorm:create").Register("test:fail_fold_batch", func(tx *gorm.DB) {
				if fail && tx.Statement.Table == "org_fold_batches" {
					_ = tx.AddError(errors.New("injected fold batch failure"))
				}
			}))
			t.Cleanup(func() { e.db.Callback().Create().Remove("test:fail_fold_batch") })

			_, err := FoldOrgSpend(ctx, e.f.org.Id, 2000)
			require.ErrorContains(t, err, "injected")
			assert.EqualValues(t, 3, e.count(t, &OrgSpendFoldQueue{}), "queue rows survive")
			assert.EqualValues(t, 0, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).SpentQuota)
			// Each of the 3 requests held 50 and settled at 30: the 20 released
			// already left held, the 30 consumed stays until the fold.
			assert.EqualValues(t, 90, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			assert.EqualValues(t, 0, e.count(t, &OrgSpendRollup{}))
			var wallet User
			require.NoError(t, e.db.First(&wallet, e.f.wallet.Id).Error)
			assert.EqualValues(t, 0, wallet.UsedQuota)
			e.assertInvariants(t)

			fail = false
			res, err := FoldOrgSpend(ctx, e.f.org.Id, 2000)
			require.NoError(t, err)
			assert.Equal(t, 3, res.Rows)
			assert.EqualValues(t, 90, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).SpentQuota)
			assert.EqualValues(t, 0, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			e.assertInvariants(t)
		})

		t.Run("a failure on the last write, the lease row, rolls back everything written before it", func(t *testing.T) {
			e.reset(t, 10000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 1000)
			// Only budget leases reach the fold; a wallet lease is settled at capture.
			usage := e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly)
			lease, err := AcquireOrgQuotaLease(ctx, OrgLeaseRequest{OrgID: e.f.org.Id, TargetType: types.OrgLeaseTargetBudget,
				TargetID: usage.Id, InstanceID: "inst-fold", RecentConsumed: 500})
			require.NoError(t, err)
			require.NotNil(t, lease)
			cmd := e.cmd(t, e.f.memberKey, "lf-fail", types.OrgBillingActionReserve)
			cmd.Bound, cmd.LeaseHints = 50, e.hint(types.OrgHoldTargetBudget, usage.Id, lease.Id)
			e.mustApply(t, cmd)
			_, err = e.capture(t, e.f.memberKey, "lf-fail", 30, 1)
			require.NoError(t, err)

			fail := true
			require.NoError(t, e.db.Callback().Update().Before("gorm:update").Register("test:fail_fold_lease", func(tx *gorm.DB) {
				if fail && tx.Statement.Table == "org_quota_leases" {
					_ = tx.AddError(errors.New("injected lease write failure"))
				}
			}))
			t.Cleanup(func() { e.db.Callback().Update().Remove("test:fail_fold_lease") })

			_, err = FoldOrgSpend(ctx, e.f.org.Id, 2000)
			require.ErrorContains(t, err, "injected")
			assert.EqualValues(t, 1, e.count(t, &OrgSpendFoldQueue{}), "the queue row survives")
			assert.EqualValues(t, 0, e.count(t, &OrgFoldBatch{}), "no batch is recorded")
			assert.EqualValues(t, 0, e.count(t, &OrgSpendRollup{}), "the rollup written earlier is rolled back")
			assert.EqualValues(t, 0, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).SpentQuota,
				"the usage row written just before the lease is rolled back")
			assert.EqualValues(t, 0, e.lease(t, lease.Id).Folded)
			var wallet User
			require.NoError(t, e.db.First(&wallet, e.f.wallet.Id).Error)
			assert.EqualValues(t, 0, wallet.UsedQuota, "the wallet counter is rolled back")
			e.assertInvariants(t)

			fail = false
			res, err := FoldOrgSpend(ctx, e.f.org.Id, 2000)
			require.NoError(t, err)
			assert.Equal(t, 1, res.Rows)
			assert.EqualValues(t, 30, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).SpentQuota)
			assert.EqualValues(t, 30, e.lease(t, lease.Id).Folded, "the rerun folds the lease once")
			e.assertInvariants(t)
		})

		t.Run("small batches fold each row exactly once", func(t *testing.T) {
			e.reset(t, 10000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 5000)
			for i := range 7 {
				id := fmt.Sprintf("sb-%d", i)
				_, err := e.reserve(t, e.f.memberKey, id, 10)
				require.NoError(t, err)
				_, err = e.capture(t, e.f.memberKey, id, 4, 1)
				require.NoError(t, err)
			}
			var rows int
			for {
				res, err := FoldOrgSpend(ctx, e.f.org.Id, 3)
				require.NoError(t, err)
				if res.Rows == 0 {
					break
				}
				rows += res.Rows
				e.assertInvariants(t)
			}
			assert.Equal(t, 7, rows)
			assert.EqualValues(t, 3, e.count(t, &OrgFoldBatch{}))
			assert.EqualValues(t, 28, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).SpentQuota)
		})

		t.Run("racing workers fold every row exactly once", func(t *testing.T) {
			e.reset(t, 100000)
			e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 50000)
			for i := range 24 {
				id := fmt.Sprintf("rw-%d", i)
				_, err := e.reserve(t, e.f.memberKey, id, 10)
				require.NoError(t, err)
				_, err = e.capture(t, e.f.memberKey, id, 5, 1)
				require.NoError(t, err)
			}
			var total atomic.Int64
			var wg sync.WaitGroup
			for range 6 {
				wg.Go(func() {
					for {
						res, err := FoldOrgSpend(ctx, e.f.org.Id, 2)
						if !assert.NoError(t, err) || res.Rows == 0 {
							return
						}
						total.Add(int64(res.Rows))
					}
				})
			}
			wg.Wait()
			assert.EqualValues(t, 24, total.Load())
			assert.EqualValues(t, 120, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).SpentQuota)
			assert.EqualValues(t, 0, e.usage(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly).HeldQuota)
			var wallet User
			require.NoError(t, e.db.First(&wallet, e.f.wallet.Id).Error)
			assert.EqualValues(t, 120, wallet.UsedQuota)
			assert.EqualValues(t, 24, wallet.RequestCount)
			e.assertInvariants(t)
		})

		t.Run("folded_at is read after the wallet row lock is granted", func(t *testing.T) {
			if e.dialect == "sqlite" {
				t.Skip("SQLite has no row locks to wait on")
			}
			e.reset(t, 1000)
			_, err := e.reserve(t, e.f.memberKey, "lk-1", 10)
			require.NoError(t, err)
			_, err = e.capture(t, e.f.memberKey, "lk-1", 5, 1)
			require.NoError(t, err)

			locked := make(chan struct{})
			release := make(chan struct{})
			var releasedAt atomic.Int64
			holder := make(chan error, 1)
			go func() {
				holder <- e.db.Transaction(func(tx *gorm.DB) error {
					var wallet User
					if err := lockForUpdate(tx).Where("id = ?", e.f.wallet.Id).Take(&wallet).Error; err != nil {
						return err
					}
					close(locked)
					<-release
					unix, err := orgDBNow(tx)
					releasedAt.Store(unix)
					return err
				})
			}()
			<-locked
			result := make(chan error, 1)
			go func() {
				_, err := FoldOrgSpend(ctx, e.f.org.Id, 100)
				result <- err
			}()
			time.Sleep(1200 * time.Millisecond) // the fold has started and is parked on the lock
			close(release)
			require.NoError(t, <-holder)
			require.NoError(t, <-result)
			var batch OrgFoldBatch
			require.NoError(t, e.db.First(&batch).Error)
			assert.GreaterOrEqual(t, batch.FoldedAt, releasedAt.Load(), "clock was read after the lock, not before")
		})
	})
}

func TestOrgLegacyBillingSealed(t *testing.T) {
	db := openOrgMigrationDB(t, "sqlite")
	f := newOrgFixture(t, db)
	require.NoError(t, db.Model(&User{}).Where("id = ?", f.wallet.Id).Update("quota", 500).Error)
	require.NoError(t, db.Model(&User{}).Where("id = ?", f.member.Id).Update("quota", 500).Error)
	quotaOf := func(id int) int {
		var quota int
		require.NoError(t, db.Model(&User{}).Where("id = ?", id).Select("quota").Scan(&quota).Error)
		return quota
	}

	t.Run("non-transactional wallet writes refuse an organization wallet", func(t *testing.T) {
		require.ErrorIs(t, IncreaseUserQuota(f.wallet.Id, 10, true), ErrBillingAccount)
		require.ErrorIs(t, DecreaseUserQuota(f.wallet.Id, 10, true), ErrBillingAccount)
		ok, err := TryReserveUserQuota(f.wallet.Id, 10)
		require.ErrorIs(t, err, ErrBillingAccount)
		assert.False(t, ok)
		assert.Equal(t, 500, quotaOf(f.wallet.Id))
	})

	t.Run("batch mode rejects before anything is queued", func(t *testing.T) {
		resetBatchUpdateTestState(t)
		common.BatchUpdateEnabled = true
		require.ErrorIs(t, IncreaseUserQuota(f.wallet.Id, 10, false), ErrBillingAccount)
		require.ErrorIs(t, DecreaseUserQuota(f.wallet.Id, 10, false), ErrBillingAccount)
		assert.Empty(t, batchUpdateStores[BatchUpdateTypeUserQuota], "nothing was queued for the flush")
		batchUpdate()
		assert.Equal(t, 500, quotaOf(f.wallet.Id))
	})

	t.Run("ordinary users are unaffected", func(t *testing.T) {
		resetBatchUpdateTestState(t)
		require.NoError(t, IncreaseUserQuota(f.member.Id, 10, true))
		require.NoError(t, DecreaseUserQuota(f.member.Id, 4, true))
		ok, err := TryReserveUserQuota(f.member.Id, 6)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, 500, quotaOf(f.member.Id))
		ok, err = TryReserveUserQuota(f.member.Id, 10_000)
		require.NoError(t, err)
		assert.False(t, ok, "insufficient quota is not a billing-account refusal")
	})

	t.Run("the transactional primitives are the only way in", func(t *testing.T) {
		require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
			require.NoError(t, IncreaseOrgWalletTx(tx, f.wallet.Id, 25))
			ok, err := DecreaseOrgWalletTx(tx, f.wallet.Id, 5)
			require.NoError(t, err)
			assert.True(t, ok)
			ok, err = DecreaseOrgWalletTx(tx, f.wallet.Id, 10_000)
			require.NoError(t, err)
			assert.False(t, ok, "conditional update refuses an overdraft")
			assert.ErrorIs(t, IncreaseOrgWalletTx(tx, f.wallet.Id, common.MaxWalletQuota), ErrWalletQuotaLimitExceeded)
			return nil
		}))
		assert.Equal(t, 520, quotaOf(f.wallet.Id))
	})
}

func unixDay(unix int64) string { return time.Unix(unix, 0).UTC().Format("2006-01-02") }

var _ = errors.New
var _ = strconv.Itoa
var _ sync.Mutex
var _ atomic.Int64
var _ = os.Getenv
