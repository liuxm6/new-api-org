package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type orgAuthFixture struct {
	org       model.Organization
	workspace model.Workspace
	wallet    model.User
	member    model.User
	memberKey model.Token
	systemKey model.Token
	personal  model.Token
}

func setupOrgAuthTest(t *testing.T) orgAuthFixture {
	t.Helper()
	require.NoError(t, i18n.Init())
	previousDB, previousLogDB := model.DB, model.LOG_DB
	previousType, previousRedis := common.MainDatabaseType(), common.RedisEnabled
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Token{}, &model.Organization{},
		&model.Workspace{}, &model.OrgBillingOperation{}, &model.OrganizationMember{},
		&model.WorkspaceMember{}, &model.UserSession{}, &model.UserAccessToken{}, &model.Option{}))
	model.DB, model.LOG_DB = db, db
	common.SetMainDatabaseType(common.DatabaseTypeSQLite)
	common.RedisEnabled = false
	model.InitColumnNames()
	orgsvc.ResetAccessCache()
	t.Cleanup(func() {
		model.DB, model.LOG_DB = previousDB, previousLogDB
		common.SetMainDatabaseType(previousType)
		common.RedisEnabled = previousRedis
		model.InitColumnNames()
		_ = sqlDB.Close()
	})

	f := orgAuthFixture{
		wallet: model.User{Username: "org_wallet", Password: "x", Role: common.RoleCommonUser,
			Status: common.UserStatusEnabled, Group: "default", AffCode: "w1", Kind: types.UserKindBilling},
		member: model.User{Username: "member", Password: "x", Role: common.RoleCommonUser,
			Status: common.UserStatusEnabled, Group: "default", AffCode: "m1"},
	}
	require.NoError(t, db.Create(&f.wallet).Error)
	require.NoError(t, db.Create(&f.member).Error)
	f.org = model.Organization{Slug: "acme", Name: "Acme", OwnerUserId: f.member.Id,
		BillingUserId: f.wallet.Id, Status: types.OrgStatusActive, PolicyVersion: 1}
	require.NoError(t, db.Create(&f.org).Error)
	f.workspace = model.Workspace{OrgId: f.org.Id, Slug: "default", Name: "Default", IsDefault: true, Status: types.WorkspaceStatusActive}
	require.NoError(t, db.Create(&f.workspace).Error)
	newKey := func(key string, userID, createdBy int, ownerType, principal string, orgID, wsID int) model.Token {
		token := model.Token{UserId: userID, Key: key, Name: key, Status: common.TokenStatusEnabled, ExpiredTime: -1,
			UnlimitedQuota: true, OrgId: orgID, WorkspaceId: wsID, CreatedBy: createdBy,
			OwnerType: ownerType, AccessPrincipalId: principal}
		require.NoError(t, db.Create(&token).Error)
		return token
	}
	f.memberKey = newKey("orgmemberkey", f.wallet.Id, f.member.Id, types.TokenOwnerMember, "prn-m", f.org.Id, f.workspace.Id)
	f.systemKey = newKey("orgsystemkey", f.wallet.Id, 0, types.TokenOwnerWorkspace, "prn-s", f.org.Id, f.workspace.Id)
	f.personal = newKey("personalkey", f.member.Id, 0, "", "", 0, 0)
	return f
}

// callTokenAuth runs a request through TokenAuth. The handler records what the
// middleware put on the context.
func callTokenAuth(t *testing.T, key string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	seen := map[string]any{}
	router := gin.New()
	router.GET("/v1/ping", TokenAuth(), func(c *gin.Context) {
		subject, isOrg := OrgSubjectFromContext(c)
		seen["is_org"] = isOrg
		seen["subject"] = subject
		seen["rate_subject"] = RateLimitSubject(c)
		seen["policy_version"] = c.GetInt64(string(constant.ContextKeyOrgPolicyVersion))
		c.Status(http.StatusOK)
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/ping", nil)
	request.Header.Set("Authorization", "Bearer sk-"+key)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder, seen
}

func TestOrgContextAttribution(t *testing.T) {
	f := setupOrgAuthTest(t)

	t.Run("member key attributes to its member", func(t *testing.T) {
		recorder, seen := callTokenAuth(t, "orgmemberkey")
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		assert.Equal(t, true, seen["is_org"])
		subject := seen["subject"].(types.OrgSubject)
		assert.Equal(t, f.org.Id, subject.OrgID)
		assert.Equal(t, f.workspace.Id, subject.WorkspaceID)
		assert.Equal(t, f.member.Id, subject.ActorUserID)
		assert.Equal(t, f.memberKey.Id, subject.TokenID)
		assert.Equal(t, "prn-m", subject.AccessPrincipalID)
		assert.Equal(t, types.TokenOwnerMember, subject.OwnerType)
		assert.Equal(t, "org:"+itoa(f.org.Id)+":user:"+itoa(f.member.Id), seen["rate_subject"])
		assert.EqualValues(t, 1, seen["policy_version"])
	})

	t.Run("system key has actor 0 and rate limits per workspace", func(t *testing.T) {
		recorder, seen := callTokenAuth(t, "orgsystemkey")
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		subject := seen["subject"].(types.OrgSubject)
		assert.Zero(t, subject.ActorUserID)
		assert.Equal(t, types.TokenOwnerWorkspace, subject.OwnerType)
		assert.Equal(t, "org:"+itoa(f.org.Id)+":ws:"+itoa(f.workspace.Id), seen["rate_subject"])
	})

	t.Run("personal key keeps the legacy path and user rate subject", func(t *testing.T) {
		recorder, seen := callTokenAuth(t, "personalkey")
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
		assert.Equal(t, false, seen["is_org"])
		assert.Equal(t, itoa(f.member.Id), seen["rate_subject"])
	})

	t.Run("two organizations never share a rate bucket", func(t *testing.T) {
		other := &gin.Context{}
		other.Set(string(constant.ContextKeyOrgSubject), types.OrgSubject{OrgID: f.org.Id + 1, WorkspaceID: 1, ActorUserID: f.member.Id})
		mine := &gin.Context{}
		mine.Set(string(constant.ContextKeyOrgSubject), types.OrgSubject{OrgID: f.org.Id, WorkspaceID: 1, ActorUserID: f.member.Id})
		assert.NotEqual(t, RateLimitSubject(mine), RateLimitSubject(other))
	})

	t.Run("a client cannot supply the subject through headers or query", func(t *testing.T) {
		router := gin.New()
		var got types.OrgSubject
		router.GET("/v1/ping", TokenAuth(), func(c *gin.Context) {
			got, _ = OrgSubjectFromContext(c)
			c.Status(http.StatusOK)
		})
		request := httptest.NewRequest(http.MethodGet, "/v1/ping?org_id=999&workspace_id=999&actor_user_id=999", nil)
		request.Header.Set("Authorization", "Bearer sk-orgmemberkey")
		request.Header.Set("X-Org-Id", "999")
		request.Header.Set("X-Workspace-Id", "999")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		require.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, f.org.Id, got.OrgID)
		assert.Equal(t, f.workspace.Id, got.WorkspaceID)
		assert.Equal(t, f.member.Id, got.ActorUserID)
	})
}

func TestOrgTokenAuthRefusals(t *testing.T) {
	f := setupOrgAuthTest(t)
	db := model.DB
	cases := []struct {
		name   string
		break_ func()
		fix    func()
		key    string
		status int
		code   string
	}{
		{"suspended organization",
			func() {
				db.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusSuspended)
			},
			func() {
				db.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusActive)
			},
			"orgsystemkey", http.StatusForbidden, types.OrgErrSuspended},
		{"suspended workspace",
			func() {
				db.Model(&model.Workspace{}).Where("id = ?", f.workspace.Id).Update("status", types.WorkspaceStatusSuspended)
			},
			func() {
				db.Model(&model.Workspace{}).Where("id = ?", f.workspace.Id).Update("status", types.WorkspaceStatusActive)
			},
			"orgsystemkey", http.StatusForbidden, types.OrgErrWorkspaceSuspended},
		{"disabled member",
			func() {
				db.Model(&model.User{}).Where("id = ?", f.member.Id).Update("status", common.UserStatusDisabled)
			},
			func() {
				db.Model(&model.User{}).Where("id = ?", f.member.Id).Update("status", common.UserStatusEnabled)
			},
			"orgmemberkey", http.StatusForbidden, types.OrgErrMemberSuspended},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.break_()
			t.Cleanup(tc.fix)
			recorder, seen := callTokenAuth(t, tc.key)
			assert.Equal(t, tc.status, recorder.Code)
			assert.Contains(t, recorder.Body.String(), `"code":"`+tc.code+`"`)
			assert.Empty(t, seen, "the handler must not run")
			assert.NotContains(t, recorder.Body.String(), "wallet", "no wallet identifiers in client errors")
		})
	}

	t.Run("a missing organization row is refused and never treated as personal", func(t *testing.T) {
		// Prime the happy path first, then break the database under the middleware.
		recorder, _ := callTokenAuth(t, "orgsystemkey")
		require.Equal(t, http.StatusOK, recorder.Code)
		// A vanished organization row is the state that cannot be proven.
		require.NoError(t, db.Exec("DELETE FROM organizations").Error)
		recorder, seen := callTokenAuth(t, "orgsystemkey")
		assert.Equal(t, http.StatusNotFound, recorder.Code)
		assert.Empty(t, seen)
	})
}

func itoa(n int) string { return strconv.Itoa(n) }

// db returns the fixture database for tests that change state between calls.
func (orgAuthFixture) db() *gorm.DB { return model.DB }
