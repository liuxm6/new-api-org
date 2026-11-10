package model

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type orgFixture struct {
	org       Organization
	workspace Workspace
	wallet    *User
	member    User
	memberKey Token
	systemKey Token
}

func newOrgFixture(t *testing.T, db *gorm.DB) orgFixture {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&User{}, &Token{}))
	require.NoError(t, migrateOrgTables())
	f := orgFixture{wallet: createBillingAccount(t, db, "default")}
	f.member = User{Username: "member-a", Password: "password-123", Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, AffCode: "mem-a"}
	require.NoError(t, db.Create(&f.member).Error)
	f.org = Organization{Slug: "acme", Name: "Acme", OwnerUserId: f.member.Id, BillingUserId: f.wallet.Id,
		Status: types.OrgStatusActive, PolicyVersion: 3}
	require.NoError(t, db.Create(&f.org).Error)
	f.workspace = Workspace{OrgId: f.org.Id, Slug: "default", Name: "Default", IsDefault: true, Status: types.WorkspaceStatusActive}
	require.NoError(t, db.Create(&f.workspace).Error)
	f.memberKey = Token{UserId: f.wallet.Id, Key: "org-member-key", Name: "member", Status: common.TokenStatusEnabled,
		ExpiredTime: -1, UnlimitedQuota: true, OrgId: f.org.Id, WorkspaceId: f.workspace.Id,
		CreatedBy: f.member.Id, OwnerType: types.TokenOwnerMember, AccessPrincipalId: "prn-member"}
	require.NoError(t, db.Create(&f.memberKey).Error)
	f.systemKey = Token{UserId: f.wallet.Id, Key: "org-system-key", Name: "system", Status: common.TokenStatusEnabled,
		ExpiredTime: -1, UnlimitedQuota: true, OrgId: f.org.Id, WorkspaceId: f.workspace.Id,
		CreatedBy: 0, OwnerType: types.TokenOwnerWorkspace, AccessPrincipalId: "prn-system"}
	require.NoError(t, db.Create(&f.systemKey).Error)
	return f
}

func subjectOf(t *testing.T, token Token) types.OrgSubject {
	t.Helper()
	subject, ok := OrgSubjectFromToken(&token)
	require.True(t, ok)
	return subject
}

func requireOrgRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var accessErr *types.OrgAccessError
	require.ErrorAs(t, err, &accessErr)
	assert.Equal(t, code, accessErr.Code)
}

func TestOrgRequestStateFailClosed(t *testing.T) {
	db := openOrgMigrationDB(t, "sqlite")
	f := newOrgFixture(t, db)
	ctx := context.Background()

	t.Run("live member and system keys are admitted", func(t *testing.T) {
		state, err := LoadOrgRequestState(ctx, subjectOf(t, f.memberKey))
		require.NoError(t, err)
		assert.EqualValues(t, 3, state.PolicyVersion)
		assert.Equal(t, f.wallet.Id, state.BillingUserId)
		_, err = LoadOrgRequestState(ctx, subjectOf(t, f.systemKey))
		require.NoError(t, err)
	})

	t.Run("personal key is never an organization subject", func(t *testing.T) {
		_, ok := OrgSubjectFromToken(&Token{Id: 1, UserId: 9})
		assert.False(t, ok)
		_, ok = OrgSubjectFromToken(nil)
		assert.False(t, ok)
	})

	t.Run("forged subject fields are refused", func(t *testing.T) {
		for name, mutate := range map[string]func(*types.OrgSubject){
			"other org":       func(s *types.OrgSubject) { s.OrgID += 100 },
			"other workspace": func(s *types.OrgSubject) { s.WorkspaceID += 100 },
			"other actor":     func(s *types.OrgSubject) { s.ActorUserID += 100 },
			"other principal": func(s *types.OrgSubject) { s.AccessPrincipalID = "prn-forged" },
			"other owner":     func(s *types.OrgSubject) { s.OwnerType = types.TokenOwnerWorkspace },
		} {
			subject := subjectOf(t, f.memberKey)
			mutate(&subject)
			_, err := LoadOrgRequestState(ctx, subject)
			require.Error(t, err, name)
			var accessErr *types.OrgAccessError
			require.ErrorAs(t, err, &accessErr, name)
			assert.Equal(t, 404, accessErr.Status, name)
		}
	})

	t.Run("incomplete subject is refused", func(t *testing.T) {
		_, err := LoadOrgRequestState(ctx, types.OrgSubject{OrgID: f.org.Id})
		requireOrgRefusal(t, err, types.OrgErrNotFound)
	})

	t.Run("key that lies about its wallet is refused", func(t *testing.T) {
		require.NoError(t, db.Model(&Token{}).Where("id = ?", f.memberKey.Id).Update("user_id", f.member.Id).Error)
		t.Cleanup(func() { db.Model(&Token{}).Where("id = ?", f.memberKey.Id).Update("user_id", f.wallet.Id) })
		_, err := LoadOrgRequestState(ctx, subjectOf(t, f.memberKey))
		requireOrgRefusal(t, err, types.OrgErrNotFound)
	})

	cases := []struct {
		name   string
		break_ func()
		fix    func()
		key    Token
		code   string
		http   int
	}{
		{"disabled key", func() {
			db.Model(&Token{}).Where("id = ?", f.memberKey.Id).Update("status", common.TokenStatusDisabled)
		},
			func() { db.Model(&Token{}).Where("id = ?", f.memberKey.Id).Update("status", common.TokenStatusEnabled) },
			f.memberKey, types.OrgErrForbidden, 403},
		{"suspended organization", func() { db.Model(&Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusSuspended) },
			func() { db.Model(&Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusActive) },
			f.systemKey, types.OrgErrSuspended, 403},
		{"suspended workspace", func() {
			db.Model(&Workspace{}).Where("id = ?", f.workspace.Id).Update("status", types.WorkspaceStatusSuspended)
		},
			func() {
				db.Model(&Workspace{}).Where("id = ?", f.workspace.Id).Update("status", types.WorkspaceStatusActive)
			},
			f.systemKey, types.OrgErrWorkspaceSuspended, 403},
		{"disabled member", func() { db.Model(&User{}).Where("id = ?", f.member.Id).Update("status", common.UserStatusDisabled) },
			func() { db.Model(&User{}).Where("id = ?", f.member.Id).Update("status", common.UserStatusEnabled) },
			f.memberKey, types.OrgErrMemberSuspended, 403},
		{"disabled wallet", func() { db.Model(&User{}).Where("id = ?", f.wallet.Id).Update("status", common.UserStatusDisabled) },
			func() { db.Model(&User{}).Where("id = ?", f.wallet.Id).Update("status", common.UserStatusEnabled) },
			f.systemKey, types.OrgErrSuspended, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.break_()
			t.Cleanup(tc.fix)
			_, err := LoadOrgRequestState(ctx, subjectOf(t, tc.key))
			var accessErr *types.OrgAccessError
			require.ErrorAs(t, err, &accessErr)
			assert.Equal(t, tc.code, accessErr.Code)
			assert.Equal(t, tc.http, accessErr.Status)
		})
	}

	t.Run("an unsuspended member does not revive a disabled system path", func(t *testing.T) {
		// A system key has no human owner, so a disabled member must not block it.
		require.NoError(t, db.Model(&User{}).Where("id = ?", f.member.Id).Update("status", common.UserStatusDisabled).Error)
		t.Cleanup(func() { db.Model(&User{}).Where("id = ?", f.member.Id).Update("status", common.UserStatusEnabled) })
		_, err := LoadOrgRequestState(ctx, subjectOf(t, f.systemKey))
		require.NoError(t, err)
	})

	t.Run("recovery-required operations are counted per organization", func(t *testing.T) {
		require.NoError(t, db.Create(&OrgBillingOperation{OperationId: "op-r1", OrgId: f.org.Id, State: types.OrgOpStateRecoveryRequired}).Error)
		require.NoError(t, db.Create(&OrgBillingOperation{OperationId: "op-r2", OrgId: f.org.Id + 7, State: types.OrgOpStateRecoveryRequired}).Error)
		state, err := LoadOrgRequestState(ctx, subjectOf(t, f.systemKey))
		require.NoError(t, err)
		assert.EqualValues(t, 1, state.RecoveryRequired)
	})

	t.Run("database failure refuses with 503, never admits", func(t *testing.T) {
		sqlDB, err := db.DB()
		require.NoError(t, err)
		require.NoError(t, sqlDB.Close())
		_, err = LoadOrgRequestState(ctx, subjectOf(t, f.systemKey))
		requireOrgRefusal(t, err, types.OrgErrStateUnavailable)
		var accessErr *types.OrgAccessError
		require.ErrorAs(t, err, &accessErr)
		assert.Equal(t, 503, accessErr.Status)
	})
}

func TestOrgTokenCacheCompatibility(t *testing.T) {
	db := openOrgMigrationDB(t, "sqlite")
	f := newOrgFixture(t, db)
	useUserCacheMiniRedis(t)

	cacheKey := getTokenCacheKey(f.memberKey.Key)

	t.Run("organization fields round-trip through the cache", func(t *testing.T) {
		loaded, err := GetTokenByKey(f.memberKey.Key, false)
		require.NoError(t, err)
		assert.Equal(t, f.org.Id, loaded.OrgId)
		cached, err := cacheGetTokenByKey(f.memberKey.Key)
		require.NoError(t, err)
		assert.Equal(t, f.org.Id, cached.OrgId)
		assert.Equal(t, f.workspace.Id, cached.WorkspaceId)
		assert.Equal(t, f.member.Id, cached.CreatedBy)
		assert.Equal(t, types.TokenOwnerMember, cached.OwnerType)
		assert.Equal(t, "prn-member", cached.AccessPrincipalId)
	})

	t.Run("tampered organization fields fail the MAC and reload from the database", func(t *testing.T) {
		for _, fields := range []map[string]any{
			{"OrgId": 0},
			{"OrgId": f.org.Id + 1},
			{"WorkspaceId": f.workspace.Id + 1},
			{"CreatedBy": f.member.Id + 1},
			{"OwnerType": types.TokenOwnerWorkspace},
			{"AccessPrincipalId": "prn-forged"},
		} {
			require.NoError(t, common.RDB.HSet(t.Context(), cacheKey, fields).Err())
			_, err := cacheGetTokenByKey(f.memberKey.Key)
			require.Error(t, err, "%v must not verify", fields)
			reloaded, err := GetTokenByKey(f.memberKey.Key, false)
			require.NoError(t, err)
			assert.Equal(t, f.org.Id, reloaded.OrgId, "database value wins after %v", fields)
			assert.Equal(t, "prn-member", reloaded.AccessPrincipalId)
			cached, err := cacheGetTokenByKey(f.memberKey.Key)
			require.NoError(t, err, "cache is repaired after %v", fields)
			assert.Equal(t, f.org.Id, cached.OrgId)
		}
	})

	t.Run("an entry written before organization fields existed is never read as a personal key", func(t *testing.T) {
		require.NoError(t, common.RDB.HDel(t.Context(), cacheKey,
			"OrgId", "WorkspaceId", "CreatedBy", "OwnerType", "AccessPrincipalId").Err())
		_, err := cacheGetTokenByKey(f.memberKey.Key)
		require.Error(t, err, "legacy entry must fail integrity")
		reloaded, err := GetTokenByKey(f.memberKey.Key, false)
		require.NoError(t, err)
		assert.Equal(t, f.org.Id, reloaded.OrgId)
		assert.Equal(t, types.TokenOwnerMember, reloaded.OwnerType)
	})

	t.Run("a personal key still verifies without organization fields", func(t *testing.T) {
		personal := Token{UserId: f.member.Id, Key: "personal-key", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true}
		require.NoError(t, db.Create(&personal).Error)
		_, err := GetTokenByKey(personal.Key, false)
		require.NoError(t, err)
		cached, err := cacheGetTokenByKey(personal.Key)
		require.NoError(t, err)
		assert.Zero(t, cached.OrgId)
		assert.Empty(t, cached.OwnerType)
	})

	t.Run("generic token update cannot change ownership", func(t *testing.T) {
		attempt := f.memberKey
		attempt.OrgId, attempt.WorkspaceId, attempt.AccessPrincipalId = 0, 0, "prn-hijack"
		attempt.Name = "renamed"
		require.NoError(t, attempt.Update())
		var stored Token
		require.NoError(t, db.First(&stored, f.memberKey.Id).Error)
		assert.Equal(t, "renamed", stored.Name)
		assert.Equal(t, f.org.Id, stored.OrgId)
		assert.Equal(t, f.workspace.Id, stored.WorkspaceId)
		assert.Equal(t, "prn-member", stored.AccessPrincipalId)
	})
}

func TestOrgPolicyVersionBumps(t *testing.T) {
	db := openOrgMigrationDB(t, "sqlite")
	f := newOrgFixture(t, db)
	require.NoError(t, db.Create(&OrganizationMember{OrgId: f.org.Id, UserId: f.member.Id, Role: types.OrgRoleOwner,
		Status: types.OrgMemberStatusActive}).Error)
	version := func() int64 {
		var v int64
		require.NoError(t, db.Model(&Organization{}).Where("id = ?", f.org.Id).Select("policy_version").Scan(&v).Error)
		return v
	}
	writers := map[string]func(tx *gorm.DB) error{
		"member role": func(tx *gorm.DB) error {
			return SetOrganizationMemberRoleTx(tx, f.org.Id, f.member.Id, types.OrgRoleAdmin)
		},
		"member status": func(tx *gorm.DB) error {
			return SetOrganizationMemberStatusTx(tx, f.org.Id, f.member.Id, types.OrgMemberStatusSuspended)
		},
		"organization": func(tx *gorm.DB) error { return SetOrganizationStatusTx(tx, f.org.Id, types.OrgStatusSuspended) },
		"workspace status": func(tx *gorm.DB) error {
			return SetWorkspaceStatusTx(tx, f.org.Id, f.workspace.Id, types.WorkspaceStatusSuspended)
		},
	}
	for name, write := range writers {
		before := version()
		require.NoError(t, db.Transaction(write), name)
		assert.Equal(t, before+1, version(), name+" must advance policy_version by one")
		before = version()
		assert.Error(t, db.Transaction(func(tx *gorm.DB) error {
			if err := write(tx); err != nil {
				return err
			}
			return errors.New("force rollback")
		}), name)
		assert.Equal(t, before, version(), name+" rolled back with its version bump")
	}
	t.Run("writes to a missing target fail instead of bumping", func(t *testing.T) {
		before := version()
		err := db.Transaction(func(tx *gorm.DB) error { return SetOrganizationMemberRoleTx(tx, f.org.Id, 9999, types.OrgRoleMember) })
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
		assert.Equal(t, before, version())
	})
	t.Run("workspace refs resolve only inside their organization", func(t *testing.T) {
		got, err := GetWorkspaceByRef(db, f.org.Id, "default")
		require.NoError(t, err)
		assert.Equal(t, f.workspace.Id, got.Id)
		_, err = GetWorkspaceByRef(db, f.org.Id+1, "default")
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})
}

func TestOrgSessionScopeSurvivesCache(t *testing.T) {
	db := openOrgMigrationDB(t, "sqlite")
	require.NoError(t, db.AutoMigrate(&User{}, &UserSession{}))
	redisServer := useUserCacheMiniRedis(t)
	_ = redisServer
	user := User{Username: "scoped", Password: "x", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AffCode: "scoped", AuthVersion: 1}
	require.NoError(t, db.Create(&user).Error)
	now := time.Now().Unix()
	session := &UserSession{SID: "org-scoped-sid", UserID: user.Id, Version: 1, UserAuthVersion: 1, Status: UserSessionStatusActive,
		RefreshHash: "refresh-1", LoginMethod: "oidc", LastActiveAt: now, ExpiresAt: now + 3600,
		AuthScope: types.AuthScopeOrg, OrgID: 41, ProviderID: 7}
	require.NoError(t, CreateUserSession(session))

	t.Run("a cache hit keeps scope, organization and provider", func(t *testing.T) {
		cached, err := getUserSessionCache(session.SID)
		require.NoError(t, err)
		assert.Equal(t, types.AuthScopeOrg, cached.AuthScope)
		got, err := GetUserSessionCached(session.SID)
		require.NoError(t, err)
		assert.Equal(t, types.AuthScopeOrg, got.EffectiveAuthScope())
		assert.Equal(t, 41, got.OrgID)
		assert.Equal(t, 7, got.ProviderID)
	})

	t.Run("refresh rotation cannot widen the scope", func(t *testing.T) {
		rotated, err := RotateUserSessionRefresh(user.Id, session.SID, "refresh-1", "refresh-2", now+1, time.Second)
		require.NoError(t, err)
		assert.Equal(t, types.AuthScopeOrg, rotated.EffectiveAuthScope())
		got, err := GetUserSessionCached(session.SID)
		require.NoError(t, err)
		assert.Equal(t, types.AuthScopeOrg, got.EffectiveAuthScope())
		assert.Equal(t, 41, got.OrgID)
	})

	t.Run("a tampered scope fails the cache MAC and reloads from the database", func(t *testing.T) {
		require.NoError(t, common.RDB.HSet(context.Background(), userSessionCacheKey(session.SID), "AuthScope", types.AuthScopeGlobal).Err())
		_, err := getUserSessionCache(session.SID)
		assert.Error(t, err, "the MAC covers the scope")
		got, err := GetUserSessionCached(session.SID)
		require.NoError(t, err)
		assert.Equal(t, types.AuthScopeOrg, got.EffectiveAuthScope(), "the database row is authoritative")
	})

	t.Run("a schema 1 entry written before this change is not trusted", func(t *testing.T) {
		require.NoError(t, common.RDB.HSet(context.Background(), userSessionCacheKey(session.SID), "CacheSchema", 1).Err())
		_, err := getUserSessionCache(session.SID)
		assert.Error(t, err)
	})

	t.Run("blank scope rows from before the column are global", func(t *testing.T) {
		assert.Equal(t, types.AuthScopeGlobal, (&UserSession{}).EffectiveAuthScope())
	})
}
