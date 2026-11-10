package model

import (
	"errors"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupBillingAccountDB(t *testing.T) *gorm.DB {
	t.Helper()
	db := openOrgMigrationDB(t, "sqlite")
	require.NoError(t, db.AutoMigrate(&User{}, &UserSession{}, &Checkin{}, &SubscriptionPlan{}, &UserSubscription{}))
	return db
}

func createBillingAccount(t *testing.T, db *gorm.DB, group string) *User {
	t.Helper()
	var wallet *User
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		var err error
		wallet, err = CreateBillingAccountTx(tx, group)
		return err
	}))
	return wallet
}

func TestOrgBillingAccountIsolation(t *testing.T) {
	db := setupBillingAccountDB(t)
	wallet := createBillingAccount(t, db, "default")
	require.True(t, wallet.IsBillingAccount())
	require.NotZero(t, wallet.Id)
	assert.Empty(t, wallet.Email)
	assert.Zero(t, wallet.Quota)

	t.Run("password login", func(t *testing.T) {
		// Even a guessed username with any password must not authenticate.
		attempt := &User{Username: wallet.Username, Password: "anything-at-all"}
		assert.ErrorIs(t, attempt.ValidateAndFill(), ErrInvalidCredentials)
	})

	t.Run("password reset", func(t *testing.T) {
		require.NoError(t, db.Model(&User{}).Where("id = ?", wallet.Id).Update("email", "wallet@example.com").Error)
		t.Cleanup(func() { db.Model(&User{}).Where("id = ?", wallet.Id).Update("email", "") })
		assert.ErrorIs(t, ResetUserPasswordByEmail("wallet@example.com", "new-password-123"), ErrEmailNotFound)
	})

	t.Run("session", func(t *testing.T) {
		session := &UserSession{
			SID: "wallet-session", UserID: wallet.Id, UserAuthVersion: 1,
			RefreshHash: "hash", ExpiresAt: time.Now().Add(time.Hour).Unix(),
		}
		assert.ErrorIs(t, createUserSessionWithTx(db, session), ErrBillingAccount)
	})

	t.Run("check-in", func(t *testing.T) {
		setting := operation_setting.GetCheckinSetting()
		previous := *setting
		*setting = operation_setting.CheckinSetting{Enabled: true, MinQuota: 100, MaxQuota: 100}
		t.Cleanup(func() { *setting = previous })
		_, err := UserCheckin(wallet.Id)
		assert.ErrorIs(t, err, ErrBillingAccount)
		var granted int64
		require.NoError(t, db.Model(&Checkin{}).Where("user_id = ?", wallet.Id).Count(&granted).Error)
		assert.Zero(t, granted)
	})

	t.Run("affiliate transfer", func(t *testing.T) {
		require.NoError(t, db.Model(&User{}).Where("id = ?", wallet.Id).Update("aff_quota", 10_000_000).Error)
		target := &User{Id: wallet.Id}
		err := target.TransferAffQuotaToQuota(10_000_000)
		assert.ErrorIs(t, err, ErrBillingAccount)
		var after User
		require.NoError(t, db.First(&after, wallet.Id).Error)
		assert.Zero(t, after.Quota)
	})

	t.Run("subscription grant", func(t *testing.T) {
		plan := &SubscriptionPlan{Title: "pro", Enabled: true}
		require.NoError(t, db.Create(plan).Error)
		err := db.Transaction(func(tx *gorm.DB) error {
			_, err := CreateUserSubscriptionFromPlanTx(tx, wallet.Id, plan, "admin")
			return err
		})
		assert.ErrorIs(t, err, ErrBillingAccount)
		var count int64
		require.NoError(t, db.Model(&UserSubscription{}).Where("user_id = ?", wallet.Id).Count(&count).Error)
		assert.Zero(t, count)
	})

	t.Run("hidden from default listing", func(t *testing.T) {
		human := &User{Username: "alice", Password: "password-123", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AffCode: "aff1"}
		require.NoError(t, db.Create(human).Error)
		page := &common.PageInfo{Page: 1, PageSize: 50}
		users, total, err := GetAllUsers(page)
		require.NoError(t, err)
		assert.EqualValues(t, 1, total)
		require.Len(t, users, 1)
		assert.Equal(t, "alice", users[0].Username)

		found, foundTotal, err := SearchUsers(wallet.Username, "", nil, nil, 0, 20)
		require.NoError(t, err)
		assert.Zero(t, foundTotal)
		assert.Empty(t, found)
	})
}

func TestOrgBillingAccountFactory(t *testing.T) {
	db := setupBillingAccountDB(t)

	t.Run("no sign-up or invitation bonus", func(t *testing.T) {
		previousNew, previousInvitee := common.QuotaForNewUser, common.QuotaForInvitee
		common.QuotaForNewUser, common.QuotaForInvitee = 5_000_000, 5_000_000
		t.Cleanup(func() { common.QuotaForNewUser, common.QuotaForInvitee = previousNew, previousInvitee })
		wallet := createBillingAccount(t, db, "default")
		assert.Zero(t, wallet.Quota)
		var stored User
		require.NoError(t, db.First(&stored, wallet.Id).Error)
		assert.Zero(t, stored.Quota)
		assert.Equal(t, types.UserKindBilling, stored.Kind)
	})

	t.Run("uses only the given group", func(t *testing.T) {
		wallet := createBillingAccount(t, db, "team")
		assert.Equal(t, "team", wallet.Group)
		assert.Equal(t, "default", createBillingAccount(t, db, "").Group)
	})

	t.Run("generates unique usernames and codes", func(t *testing.T) {
		first, second := createBillingAccount(t, db, "default"), createBillingAccount(t, db, "default")
		assert.NotEqual(t, first.Username, second.Username)
		assert.NotEqual(t, first.AffCode, second.AffCode)
	})

	t.Run("rolls back with the caller transaction", func(t *testing.T) {
		var before int64
		require.NoError(t, db.Model(&User{}).Where("kind = ?", types.UserKindBilling).Count(&before).Error)
		sentinel := errors.New("outer failure")
		err := db.Transaction(func(tx *gorm.DB) error {
			if _, err := CreateBillingAccountTx(tx, "default"); err != nil {
				return err
			}
			return sentinel
		})
		require.ErrorIs(t, err, sentinel)
		var after int64
		require.NoError(t, db.Model(&User{}).Where("kind = ?", types.UserKindBilling).Count(&after).Error)
		assert.Equal(t, before, after, "a rolled-back organization must not leave an orphan wallet")
	})

	t.Run("requires a transaction", func(t *testing.T) {
		_, err := CreateBillingAccountTx(nil, "default")
		assert.Error(t, err)
	})
}
