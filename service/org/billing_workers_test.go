package org

import (
	"context"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// billingWorkerFixture is an organization with a funded wallet and one key.
type billingWorkerFixture struct {
	db      *gorm.DB
	org     *model.Organization
	wallet  int
	subject types.OrgSubject
}

func newBillingWorkerFixture(t *testing.T, db *gorm.DB, quota int) billingWorkerFixture {
	t.Helper()
	owner := newUser(t, db, "w-owner", "w-owner@example.com")
	created, err := CreateOrganization(context.Background(), owner.Id, CreateOrganizationInput{Name: "W", Slug: "wrk"})
	require.NoError(t, err)
	org := created.Org
	require.NoError(t, db.Model(&model.User{}).Where("id = ?", org.BillingUserId).Update("quota", quota).Error)
	var ws model.Workspace
	require.NoError(t, db.Where("org_id = ?", org.Id).First(&ws).Error)
	key := model.Token{UserId: org.BillingUserId, Key: "wrkkey", Name: "k", Status: common.TokenStatusEnabled, ExpiredTime: -1,
		UnlimitedQuota: true, OrgId: org.Id, WorkspaceId: ws.Id, CreatedBy: owner.Id, OwnerType: types.TokenOwnerMember, AccessPrincipalId: "prn"}
	require.NoError(t, db.Create(&key).Error)
	return billingWorkerFixture{db: db, org: &org, wallet: org.BillingUserId, subject: types.OrgSubject{OrgID: org.Id,
		WorkspaceID: ws.Id, ActorUserID: owner.Id, TokenID: key.Id, AccessPrincipalID: "prn", OwnerType: types.TokenOwnerMember}}
}

func (f billingWorkerFixture) quota(t *testing.T) int {
	t.Helper()
	var quota int
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.wallet).Select("quota").Scan(&quota).Error)
	return quota
}

func (f billingWorkerFixture) reserve(t *testing.T, id, source string, bound int64) {
	t.Helper()
	_, err := model.ApplyOrgBilling(context.Background(), types.OrgBillingCommand{OperationID: id, Subject: f.subject,
		Action: types.OrgBillingActionReserve, Bound: bound, ModelName: "m", SourceKind: source, LeaseOwner: "dead-instance"})
	require.NoError(t, err)
}

func (f billingWorkerFixture) expire(t *testing.T, id string) {
	t.Helper()
	require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("operation_id = ?", id).
		Update("lease_until", time.Now().Unix()-5).Error)
}

func (f billingWorkerFixture) operation(t *testing.T, id string) model.OrgBillingOperation {
	t.Helper()
	var op model.OrgBillingOperation
	require.NoError(t, f.db.Where("operation_id = ?", id).First(&op).Error)
	return op
}

func TestOrgRecoverExpiredOperations(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newBillingWorkerFixture(t, db, 10_000)

		t.Run("a live request is left alone", func(t *testing.T) {
			f.reserve(t, "live-1", types.OrgSourceRelay, 500)
			assert.Zero(t, RecoverExpiredOperations(ctx))
			assert.Equal(t, types.OrgOpStateReserved, f.operation(t, "live-1").State)
		})

		t.Run("a dead synchronous request settles at the estimate, never above the bound", func(t *testing.T) {
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", f.wallet).Update("quota", 10_000).Error)
			f.reserve(t, "dead-1", types.OrgSourceRelay, 500)
			require.NoError(t, db.Model(&model.OrgBillingOperation{}).Where("operation_id = ?", "dead-1").
				Updates(map[string]any{"estimated_quota": 120, "progress_quota": 180}).Error)
			f.expire(t, "dead-1")
			before := f.quota(t)
			assert.Equal(t, 1, RecoverExpiredOperations(ctx))
			op := f.operation(t, "dead-1")
			assert.Equal(t, types.OrgOpStateClosed, op.State)
			assert.Equal(t, types.OrgSettledByRecovery, op.SettledBy)
			assert.EqualValues(t, 180, op.CapturedQuota, "max(estimate, progress), under the bound")
			assert.Equal(t, before+500-180, f.quota(t), "the rest of the hold returns")
			assert.Zero(t, RecoverExpiredOperations(ctx), "settling twice is impossible")
		})

		t.Run("the estimate is capped at the bound", func(t *testing.T) {
			f.reserve(t, "dead-2", types.OrgSourceRelay, 100)
			require.NoError(t, db.Model(&model.OrgBillingOperation{}).Where("operation_id = ?", "dead-2").
				Update("progress_quota", 9_999).Error)
			f.expire(t, "dead-2")
			assert.Equal(t, 1, RecoverExpiredOperations(ctx))
			op := f.operation(t, "dead-2")
			assert.EqualValues(t, 100, op.CapturedQuota)
			assert.Zero(t, op.WriteoffQuota, "a recovery estimate is never an overrun the platform has to absorb")
		})

		t.Run("an asynchronous task with unknown acceptance is parked, not guessed", func(t *testing.T) {
			before := f.quota(t)
			f.reserve(t, "task-1", types.OrgSourceTask, 300)
			f.expire(t, "task-1")
			assert.Equal(t, 1, RecoverExpiredOperations(ctx))
			op := f.operation(t, "task-1")
			assert.Equal(t, types.OrgOpStateRecoveryRequired, op.State)
			assert.Equal(t, before-300, f.quota(t), "nothing is refunded or charged on a guess")
			var events int64
			require.NoError(t, db.Model(&model.OrgSpendEvent{}).Where("operation_id = ?", "task-1").Count(&events).Error)
			assert.Zero(t, events)
			assert.Zero(t, RecoverExpiredOperations(ctx), "a parked operation is not picked up again")
		})

		t.Run("the original instance loses the race once recovery claimed the operation", func(t *testing.T) {
			f.reserve(t, "race-1", types.OrgSourceRelay, 200)
			f.expire(t, "race-1")
			claimed, err := model.ClaimOrgOperationForRecovery(ctx, "race-1", 0, "recovery-x")
			require.NoError(t, err)
			require.True(t, claimed)
			_, err = model.ApplyOrgBilling(ctx, types.OrgBillingCommand{OperationID: "race-1", Subject: f.subject,
				Action: types.OrgBillingActionCapture, Amount: 150, Revision: 1, LeaseOwner: "dead-instance"})
			require.Error(t, err, "the slow instance must not be able to settle after recovery claimed it")
			assert.Equal(t, types.OrgOpStateReserved, f.operation(t, "race-1").State)
		})

		t.Run("recovery works after the key was deleted", func(t *testing.T) {
			f.reserve(t, "gone-1", types.OrgSourceRelay, 250)
			require.NoError(t, db.Delete(&model.Token{}, f.subject.TokenID).Error)
			f.expire(t, "gone-1")
			require.Equal(t, 1, RecoverExpiredOperations(ctx))
			assert.Equal(t, types.OrgOpStateClosed, f.operation(t, "gone-1").State)
		})
	})
}

func TestOrgFoldWorker(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newBillingWorkerFixture(t, db, 10_000)
		for _, id := range []string{"fw-1", "fw-2", "fw-3"} {
			f.reserve(t, id, types.OrgSourceRelay, 100)
			_, err := model.ApplyOrgBilling(ctx, types.OrgBillingCommand{OperationID: id, Subject: f.subject,
				Action: types.OrgBillingActionCapture, Amount: 40, Revision: 1, LeaseOwner: "dead-instance"})
			require.NoError(t, err)
		}
		var queued int64
		require.NoError(t, db.Model(&model.OrgSpendFoldQueue{}).Count(&queued).Error)
		require.EqualValues(t, 3, queued)

		foldQueuedOrganizations(ctx)

		require.NoError(t, db.Model(&model.OrgSpendFoldQueue{}).Count(&queued).Error)
		assert.Zero(t, queued, "the worker drained the queue")
		var wallet model.User
		require.NoError(t, db.First(&wallet, f.wallet).Error)
		assert.EqualValues(t, 120, wallet.UsedQuota)
		assert.EqualValues(t, 3, wallet.RequestCount)
		foldQueuedOrganizations(ctx) // an empty pass is harmless
		require.NoError(t, db.First(&wallet, f.wallet).Error)
		assert.EqualValues(t, 120, wallet.UsedQuota)
	})
}

func TestOrgReconcileWorker(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		previous := reconcileRecheckAfter
		reconcileRecheckAfter = time.Millisecond
		t.Cleanup(func() { reconcileRecheckAfter = previous; reconcileCursor.Store(0) })
		reconcileCursor.Store(0)

		f := newBillingWorkerFixture(t, db, 10_000)
		require.NoError(t, db.AutoMigrate(&model.OrgBillingLedger{}))
		require.NoError(t, db.Create(&model.OrgBillingLedger{OrgId: f.org.Id, Type: types.OrgLedgerAdjust, AmountQuota: 10_000,
			BalanceAfter: 10_000, RefType: "test", RefId: "seed", IdempotencyKey: "seed"}).Error)

		assert.Zero(t, reconcileOrganizations(ctx, 10), "a funded, quiet organization is clean")

		f.reserve(t, "rw-1", types.OrgSourceRelay, 100)
		assert.Zero(t, reconcileOrganizations(ctx, 10), "a held reservation is accounted for")

		require.NoError(t, db.Model(&model.User{}).Where("id = ?", f.wallet).Update("quota", 9_000).Error)
		assert.Equal(t, 1, reconcileOrganizations(ctx, 10), "money that left without a record is reported")
		assert.EqualValues(t, 9_000, f.quota(t), "and nothing is corrected")

		reconcileCursor.Store(0)
		assert.Equal(t, 1, reconcileOrganizations(ctx, 1), "a batch smaller than the list still visits it")
		assert.Equal(t, int64(f.org.Id), reconcileCursor.Load(), "the cursor remembers where it stopped")
	})
}
