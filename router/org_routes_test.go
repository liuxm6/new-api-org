package router

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// orgRoutesFixture drives the real /api router: the whole middleware chain,
// rate limits and declared route rules are the production ones.
type orgRoutesFixture struct {
	engine *gin.Engine
	db     *gorm.DB
	users  map[string]*model.User
	tokens map[string]string // global-session JWTs by user name
}

func setupOrgRoutes(t *testing.T) *orgRoutesFixture {
	t.Helper()
	require.NoError(t, i18n.Init())
	previousDB, previousLog, previousType := model.DB, model.LOG_DB, common.MainDatabaseType()
	previousRedis, previousSecret := common.RedisEnabled, common.SessionSecret
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.UserSession{}, &model.Token{}, &model.Option{},
		&model.AuditLog{}, &model.UserAccessToken{}, &model.Task{}, &model.Midjourney{},
		&model.TwoFA{}, &model.TwoFABackupCode{}, &model.PasskeyCredential{}, &model.AuthFlow{}, &model.CustomOAuthProvider{}))
	model.DB, model.LOG_DB = db, db
	common.SetDatabaseTypes(common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	common.RedisEnabled = false
	common.SessionSecret = "org-routes-test-secret"
	model.InitColumnNames()
	require.NoError(t, model.MigrateOrgTables())
	orgsvc.ResetAccessCache()
	require.NoError(t, model.EnsureLegacyAccessTokenRetireAt(time.Now().Unix()))
	t.Cleanup(func() {
		model.DB, model.LOG_DB = previousDB, previousLog
		common.SetMainDatabaseType(previousType)
		common.RedisEnabled, common.SessionSecret = previousRedis, previousSecret
		_ = sqlDB.Close()
	})

	// Tests that assert exact wallet figures run without leases; a lease moves money first.
	service.SetOrgQuotaLeasesEnabled(false)
	service.ResetOrgQuotaLeases()
	t.Cleanup(func() { service.SetOrgQuotaLeasesEnabled(true); service.ResetOrgQuotaLeases() })

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	SetApiRouter(engine)
	f := &orgRoutesFixture{engine: engine, db: db, users: map[string]*model.User{}, tokens: map[string]string{}}
	return f
}

func (f *orgRoutesFixture) user(t *testing.T, name, email string) *model.User {
	t.Helper()
	user := &model.User{Username: name, Password: "password-123", Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
		Group: "default", AffCode: "aff-" + name, Email: email, AuthVersion: 1}
	require.NoError(t, f.db.Create(user).Error)
	f.users[name] = user
	f.tokens[name] = f.session(t, user, types.AuthScopeGlobal, 0)
	return user
}

func (f *orgRoutesFixture) session(t *testing.T, user *model.User, scope string, orgID int) string {
	t.Helper()
	now := time.Now().Unix()
	sid := uuid.NewString()
	require.NoError(t, model.CreateUserSession(&model.UserSession{SID: sid, UserID: user.Id, Version: 1, UserAuthVersion: 1,
		Status: model.UserSessionStatusActive, RefreshHash: "r-" + sid, LoginMethod: "password", LastActiveAt: now,
		ExpiresAt: now + 3600, AuthScope: scope, OrgID: orgID}))
	jwt, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: user.Id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1})
	require.NoError(t, err)
	return jwt
}

type routeReply struct {
	Status int
	Body   map[string]any
	Raw    string
}

func (r routeReply) code() string { s, _ := r.Body["code"].(string); return s }
func (r routeReply) data() map[string]any {
	d, _ := r.Body["data"].(map[string]any)
	return d
}

func (f *orgRoutesFixture) do(t *testing.T, bearer, method, path, body string) routeReply {
	t.Helper()
	return f.doHeaders(t, bearer, nil, method, path, body)
}

// doHeaders is do with extra request headers (a security proof, for one).
func (f *orgRoutesFixture) doHeaders(t *testing.T, bearer string, headers map[string]string, method, path, body string) routeReply {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.10:1234"
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	reply := routeReply{Status: recorder.Code, Raw: recorder.Body.String(), Body: map[string]any{}}
	_ = common.Unmarshal(recorder.Body.Bytes(), &reply.Body)
	return reply
}

func TestOrgRoutePermissions(t *testing.T) {
	f := setupOrgRoutes(t)
	f.user(t, "owner", "owner@example.com")
	f.user(t, "admin", "admin@example.com")
	f.user(t, "member", "member@example.com")
	f.user(t, "outsider", "outsider@example.com")
	f.user(t, "noemail", "")

	created := f.do(t, f.tokens["owner"], http.MethodPost, "/api/orgs", `{"name":"Acme","slug":"acme"}`)
	require.Equal(t, 200, created.Status, created.Raw)
	orgID := int(created.data()["organization"].(map[string]any)["id"].(float64))
	require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: orgID, UserId: f.users["admin"].Id, Role: types.OrgRoleAdmin,
		Status: types.OrgMemberStatusActive}).Error)
	require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: orgID, UserId: f.users["member"].Id, Role: types.OrgRoleMember,
		Status: types.OrgMemberStatusActive}).Error)
	org := "/api/orgs/acme"

	t.Run("creation hides platform fields and never echoes the wallet", func(t *testing.T) {
		assert.NotContains(t, created.Raw, "billing_user_id")
		assert.NotContains(t, created.Raw, "invoice_sequence")
		for _, body := range []string{
			`{"name":"X","slug":"xcorp","seat_limit":999}`,
			`{"name":"X","slug":"xcorp","billing_group":"vip"}`,
			`{"name":"X","slug":"xcorp","status":1}`,
			`{"name":"X","slug":"xcorp","owner_user_id":1}`,
			`not json`, `[]`, `null`,
		} {
			reply := f.do(t, f.tokens["owner"], http.MethodPost, "/api/orgs", body)
			assert.Equal(t, 400, reply.Status, body)
			assert.Equal(t, types.OrgErrInvalidInput, reply.code(), body)
		}
		assert.Zero(t, func() int64 {
			var n int64
			f.db.Model(&model.Organization{}).Where("slug = ?", "xcorp").Count(&n)
			return n
		}())
	})

	t.Run("unverified email, reserved and duplicate slugs", func(t *testing.T) {
		previous := common.EmailVerificationEnabled
		common.EmailVerificationEnabled = true
		t.Cleanup(func() { common.EmailVerificationEnabled = previous })
		assert.Equal(t, types.OrgErrEmailNotVerified, f.do(t, f.tokens["noemail"], http.MethodPost, "/api/orgs", `{"name":"N","slug":"noemailco"}`).code())
		assert.Equal(t, types.OrgErrSlugReserved, f.do(t, f.tokens["owner"], http.MethodPost, "/api/orgs", `{"name":"N","slug":"admin"}`).code())
		duplicate := f.do(t, f.tokens["owner"], http.MethodPost, "/api/orgs", `{"name":"N","slug":"acme"}`)
		assert.Equal(t, 409, duplicate.Status)
		assert.Equal(t, types.OrgErrSlugTaken, duplicate.code())
	})

	t.Run("anonymous callers are refused everywhere", func(t *testing.T) {
		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/api/orgs"}, {http.MethodPost, "/api/orgs"}, {http.MethodGet, org},
			{http.MethodPatch, org}, {http.MethodGet, org + "/members"}, {http.MethodPost, org + "/invites"},
			{http.MethodPost, "/api/invites/anything/accept"},
		} {
			assert.Equal(t, 401, f.do(t, "", route.method, route.path, `{}`).Status, route.method+" "+route.path)
		}
	})

	t.Run("role matrix on the real routes", func(t *testing.T) {
		for _, tc := range []struct {
			who, method, path, body string
			status                  int
			code                    string
		}{
			{"owner", "GET", org, "", 200, ""},
			{"member", "GET", org, "", 200, ""},
			{"outsider", "GET", org, "", 404, types.OrgErrNotFound},
			{"outsider", "PATCH", org, `{"name":"Hijack"}`, 404, types.OrgErrNotFound},
			{"member", "PATCH", org, `{"name":"Nope"}`, 403, types.OrgErrForbidden},
			{"admin", "PATCH", org, `{"name":"Nope"}`, 403, types.OrgErrForbidden},
			{"owner", "PATCH", org, `{"name":"Acme Corp"}`, 200, ""},
			{"owner", "PATCH", org, `{"name":"Acme","seat_limit":500}`, 400, types.OrgErrInvalidInput},
			{"owner", "PATCH", org, `{"slug":"stolen"}`, 400, types.OrgErrInvalidInput},
			{"owner", "PATCH", org, `{}`, 400, types.OrgErrInvalidInput},
			{"member", "GET", org + "/members", "", 403, types.OrgErrForbidden},
			{"admin", "GET", org + "/members", "", 200, ""},
			{"member", "POST", org + "/invites", `{"email":"x@example.com"}`, 403, types.OrgErrForbidden},
			{"admin", "POST", org + "/transfer-ownership", `{"user_id":3}`, 403, types.OrgErrForbidden},
			{"member", "GET", org + "/invites", "", 403, types.OrgErrForbidden},
		} {
			reply := f.do(t, f.tokens[tc.who], tc.method, tc.path, tc.body)
			assert.Equal(t, tc.status, reply.Status, "%s %s %s: %s", tc.who, tc.method, tc.path, reply.Raw)
			assert.Equal(t, tc.code, reply.code(), "%s %s %s", tc.who, tc.method, tc.path)
		}
	})

	t.Run("my organizations list is per caller", func(t *testing.T) {
		mine := f.do(t, f.tokens["member"], http.MethodGet, "/api/orgs", "")
		list, _ := mine.Body["data"].([]any)
		require.Len(t, list, 1)
		assert.Equal(t, "member", list[0].(map[string]any)["role"])
		none := f.do(t, f.tokens["outsider"], http.MethodGet, "/api/orgs", "")
		assert.Empty(t, none.Body["data"])
	})

	t.Run("a personal access token is never accepted on control routes", func(t *testing.T) {
		raw, err := common.GenerateRandomCharsKey(43)
		require.NoError(t, err)
		pat := model.AccessTokenPrefix + raw
		token := &model.UserAccessToken{Name: "pat", TokenHash: model.AccessTokenFingerprint(pat), TokenHint: model.AccessTokenHint(pat)}
		require.NoError(t, token.SetScopes([]string{"profile:read", "api_key:read", "wallet:read"}))
		require.NoError(t, model.CreateUserAccessToken(f.users["owner"].Id, token, service.AccessTokenMaxPerUser))
		for _, route := range []struct{ method, path string }{{"GET", "/api/orgs"}, {"GET", org}, {"PATCH", org}, {"POST", "/api/orgs"}} {
			reply := f.do(t, pat, route.method, route.path, `{"name":"x","slug":"patcorp"}`)
			assert.Equal(t, 403, reply.Status, route.method+" "+route.path)
			assert.Equal(t, "AUTH_SESSION_REQUIRED", reply.code())
		}
	})
}

func TestOrgRouteSessionScope(t *testing.T) {
	f := setupOrgRoutes(t)
	owner := f.user(t, "owner", "owner@example.com")
	for _, name := range []string{"acme", "globex"} {
		reply := f.do(t, f.tokens["owner"], http.MethodPost, "/api/orgs", `{"name":"`+name+`","slug":"`+name+`"}`)
		require.Equal(t, 200, reply.Status, reply.Raw)
	}
	var acme model.Organization
	require.NoError(t, f.db.Where("slug = ?", "acme").First(&acme).Error)
	scoped := f.session(t, owner, types.AuthScopeOrg, acme.Id)

	for _, tc := range []struct {
		name, method, path, body string
		status                   int
		code                     string
	}{
		{"its own organization", "GET", "/api/orgs/acme", "", 200, ""},
		{"its own organization by id", "GET", "/api/orgs/" + strconv.Itoa(acme.Id), "", 200, ""},
		{"its own members", "GET", "/api/orgs/acme/members", "", 200, ""},
		{"another organization it owns", "GET", "/api/orgs/globex", "", 404, types.OrgErrNotFound},
		{"another organization's members", "GET", "/api/orgs/globex/members", "", 404, types.OrgErrNotFound},
		{"the list of all its organizations", "GET", "/api/orgs", "", 403, types.OrgErrSessionScope},
		{"creating a new organization", "POST", "/api/orgs", `{"name":"N","slug":"newcorp"}`, 403, types.OrgErrSessionScope},
		{"redeeming an invitation", "POST", "/api/invites/whatever/accept", "", 403, types.OrgErrSessionScope},
		// Reachable by an org session now, but only with a single-use proof.
		{"transferring ownership", "POST", "/api/orgs/acme/transfer-ownership", `{"user_id":2}`, 403, "SECURITY_PROOF_REQUIRED"},
		{"deleting the organization", "DELETE", "/api/orgs/acme", `{"confirm_slug":"acme"}`, 403, "SECURITY_PROOF_REQUIRED"},
		{"the personal profile", "GET", "/api/user/self", "", 403, types.OrgErrSessionScope},
		{"personal keys", "GET", "/api/token/", "", 403, types.OrgErrSessionScope},
		{"personal top-up", "POST", "/api/user/topup", `{"key":"x"}`, 403, types.OrgErrSessionScope},
		{"the generic verification endpoint", "GET", "/api/verify/methods", "", 403, types.OrgErrSessionScope},
		{"platform administration", "GET", "/api/user/", "", 403, types.OrgErrSessionScope},
		{"platform options", "GET", "/api/option/", "", 403, types.OrgErrSessionScope},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := f.do(t, scoped, tc.method, tc.path, tc.body)
			assert.Equal(t, tc.status, reply.Status, reply.Raw)
			assert.Equal(t, tc.code, reply.code())
		})
	}

	t.Run("the same person with a global session is unaffected", func(t *testing.T) {
		assert.Equal(t, 200, f.do(t, f.tokens["owner"], "GET", "/api/orgs/globex", "").Status)
		assert.Equal(t, 200, f.do(t, f.tokens["owner"], "GET", "/api/user/self", "").Status)
	})

	t.Run("every allowlisted route is a registered organization route", func(t *testing.T) {
		registered := map[string]bool{}
		for _, route := range f.engine.Routes() {
			registered[route.Method+" "+route.Path] = true
		}
		allowlisted := middleware.OrgSessionRouteKeys()
		require.NotEmpty(t, allowlisted)
		for _, key := range allowlisted {
			assert.True(t, registered[key], "allowlisted but not registered: %s", key)
		}
		for key := range registered {
			if strings.Contains(key, "/api/orgs") || strings.Contains(key, "/api/invites") {
				assert.Contains(t, middleware.AccessTokenRouteRuleKeys(), key, "organization route without a declared rule: %s", key)
			}
		}
	})
}

func TestOrgRouteInviteFlow(t *testing.T) {
	f := setupOrgRoutes(t)
	f.user(t, "owner", "owner@example.com")
	f.user(t, "invitee", "invitee@example.com")
	f.user(t, "other", "other@example.com")
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)

	// No mail provider is configured in tests, so the link comes back to the admin.
	issued := f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/invites", `{"email":"Invitee@Example.com","org_role":"member"}`)
	require.Equal(t, 200, issued.Status, issued.Raw)
	assert.Equal(t, false, issued.data()["email_sent"])
	link, _ := issued.data()["invite_url"].(string)
	require.Contains(t, link, "/#/invite/", "the token travels in the fragment")
	token := link[strings.LastIndex(link, "/")+1:]
	assert.Len(t, token, 43, "256 bits, unpadded base64url")

	t.Run("the list shows state but no token", func(t *testing.T) {
		list := f.do(t, f.tokens["owner"], "GET", "/api/orgs/acme/invites", "")
		assert.Equal(t, 200, list.Status)
		assert.NotContains(t, list.Raw, token)
		assert.Contains(t, list.Raw, `"state":"pending"`)
	})

	t.Run("the wrong account cannot redeem, and that does not burn the invitation", func(t *testing.T) {
		previous := common.EmailVerificationEnabled
		common.EmailVerificationEnabled = true
		t.Cleanup(func() { common.EmailVerificationEnabled = previous })
		reply := f.do(t, f.tokens["other"], "POST", "/api/invites/"+token+"/accept", "")
		assert.Equal(t, 409, reply.Status)
		assert.Equal(t, types.OrgErrInviteEmailMismatch, reply.code())
	})

	t.Run("redemption joins once and responses are not cacheable", func(t *testing.T) {
		request := httptest.NewRequest("POST", "/api/invites/"+token+"/accept", nil)
		request.Header.Set("Authorization", "Bearer "+f.tokens["invitee"])
		recorder := httptest.NewRecorder()
		f.engine.ServeHTTP(recorder, request)
		assert.Equal(t, 200, recorder.Code, recorder.Body.String())
		assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
		assert.Equal(t, "no-referrer", recorder.Header().Get("Referrer-Policy"))
		replay := f.do(t, f.tokens["invitee"], "POST", "/api/invites/"+token+"/accept", "")
		assert.Equal(t, 410, replay.Status)
		assert.Equal(t, types.OrgErrInviteUsed, replay.code())
		assert.Equal(t, 200, f.do(t, f.tokens["invitee"], "GET", "/api/orgs/acme", "").Status)
	})

	t.Run("unknown tokens are a uniform 404", func(t *testing.T) {
		for _, bad := range []string{"nope", strings.Repeat("A", 43)} {
			reply := f.do(t, f.tokens["invitee"], "POST", "/api/invites/"+bad+"/accept", "")
			assert.Equal(t, 404, reply.Status)
			assert.Equal(t, types.OrgErrInviteNotFound, reply.code())
		}
	})

	t.Run("revoking and listing are admin-only", func(t *testing.T) {
		again := f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/invites", `{"email":"later@example.com"}`)
		require.Equal(t, 200, again.Status)
		id := strconv.Itoa(int(again.data()["id"].(float64)))
		assert.Equal(t, 403, f.do(t, f.tokens["invitee"], "DELETE", "/api/orgs/acme/invites/"+id, "").Status)
		assert.Equal(t, 200, f.do(t, f.tokens["owner"], "DELETE", "/api/orgs/acme/invites/"+id, "").Status)
		assert.Equal(t, 400, f.do(t, f.tokens["owner"], "DELETE", "/api/orgs/acme/invites/abc", "").Status)
	})

	t.Run("an invite body cannot choose the owner role or carry extra fields", func(t *testing.T) {
		assert.Equal(t, types.OrgErrOwnerRole, f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/invites", `{"email":"o@example.com","org_role":"owner"}`).code())
		assert.Equal(t, 400, f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/invites", `{"email":"o@example.com","token_hash":"x"}`).Status)
	})
}

func TestOrgRouteWorkspacesAndMembers(t *testing.T) {
	f := setupOrgRoutes(t)
	owner := f.user(t, "owner", "owner@example.com")
	f.user(t, "admin", "admin@example.com")
	f.user(t, "dev", "dev@example.com")
	f.user(t, "stranger", "stranger@example.com")
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)
	var acme model.Organization
	require.NoError(t, f.db.Where("slug = ?", "acme").First(&acme).Error)
	for name, role := range map[string]string{"admin": types.OrgRoleAdmin, "dev": types.OrgRoleMember} {
		require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: acme.Id, UserId: f.users[name].Id, Role: role,
			Status: types.OrgMemberStatusActive}).Error)
	}
	base := "/api/orgs/acme"

	t.Run("workspace creation, listing and role gates", func(t *testing.T) {
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "POST", base+"/workspaces", `{"name":"Prod","slug":"prod"}`).Status)
		assert.Equal(t, 409, f.do(t, f.tokens["admin"], "POST", base+"/workspaces", `{"name":"D","slug":"default"}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["admin"], "POST", base+"/workspaces", `{"name":"D","slug":"zzz","org_id":9}`).Status)
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "POST", base+"/workspaces", `{"name":"Prod","slug":"prod"}`).Status)
		all := f.do(t, f.tokens["admin"], "GET", base+"/workspaces", "")
		assert.Len(t, all.Body["data"], 2)
		mine := f.do(t, f.tokens["dev"], "GET", base+"/workspaces", "")
		assert.Empty(t, mine.Body["data"], "a member without grants sees no workspace")
		assert.Equal(t, 404, f.do(t, f.tokens["dev"], "GET", base+"/workspaces/prod", "").Status)
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "GET", base+"/workspaces/prod", "").Status)
	})

	t.Run("workspace members are managed through grants", func(t *testing.T) {
		uid := strconv.Itoa(f.users["dev"].Id)
		assert.Equal(t, 404, f.do(t, f.tokens["dev"], "PUT", base+"/workspaces/prod/members/"+uid, `{"role":"admin"}`).Status, "no self-promotion")
		assert.Equal(t, 400, f.do(t, f.tokens["admin"], "PUT", base+"/workspaces/prod/members/"+uid, `{"role":"owner"}`).Status)
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "PUT", base+"/workspaces/prod/members/"+uid, `{"role":"member"}`).Status)
		assert.Equal(t, 404, f.do(t, f.tokens["admin"], "PUT", base+"/workspaces/prod/members/"+strconv.Itoa(f.users["stranger"].Id), `{"role":"member"}`).Status,
			"only organization members can be workspace members")
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "GET", base+"/workspaces/prod/members", "").Status, "members cannot list members")
		list := f.do(t, f.tokens["admin"], "GET", base+"/workspaces/prod/members", "")
		assert.Contains(t, list.Raw, `"manual"`)
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "DELETE", base+"/workspaces/prod/members/"+uid, "").Status)
		assert.Equal(t, 404, f.do(t, f.tokens["dev"], "GET", base+"/workspaces/prod", "").Status)
	})

	t.Run("suspend and resume are parent routes; the default workspace cannot be deleted", func(t *testing.T) {
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "POST", base+"/workspaces/prod/suspend", "").Status)
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "POST", base+"/workspaces/prod/suspend", "").Status)
		suspended := f.do(t, f.tokens["admin"], "GET", base+"/workspaces/prod", "")
		assert.Equal(t, 403, suspended.Status)
		assert.Equal(t, types.OrgErrWorkspaceSuspended, suspended.code())
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "POST", base+"/workspaces/prod/resume", "").Status, "resume works while suspended")
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "GET", base+"/workspaces/prod", "").Status)
		assert.Equal(t, 404, f.do(t, f.tokens["admin"], "POST", base+"/workspaces/ghost/suspend", "").Status)
		del := f.do(t, f.tokens["admin"], "DELETE", base+"/workspaces/default", "")
		assert.Equal(t, 409, del.Status)
		assert.Equal(t, types.OrgErrDefaultWorkspace, del.code())
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "DELETE", base+"/workspaces/prod", "").Status)
		assert.Equal(t, 404, f.do(t, f.tokens["admin"], "GET", base+"/workspaces/prod", "").Status)
	})

	t.Run("member changes follow the owner rules", func(t *testing.T) {
		dev, ownerID := strconv.Itoa(f.users["dev"].Id), strconv.Itoa(owner.Id)
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "PATCH", base+"/members/"+dev, `{"role":"admin"}`).Status)
		assert.Equal(t, types.OrgErrOwnerRole, f.do(t, f.tokens["admin"], "PATCH", base+"/members/"+dev, `{"role":"owner"}`).code())
		assert.Equal(t, types.OrgErrOwnerRole, f.do(t, f.tokens["admin"], "PATCH", base+"/members/"+ownerID, `{"role":"member"}`).code())
		assert.Equal(t, 400, f.do(t, f.tokens["admin"], "PATCH", base+"/members/"+dev, `{}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["admin"], "PATCH", base+"/members/"+dev, `{"role":"billing","org_id":2}`).Status)
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "PATCH", base+"/members/"+dev, `{"role":"billing"}`).Status)
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "PATCH", base+"/members/"+dev, `{"status":2}`).Status)
		assert.Equal(t, types.OrgErrMemberSuspended, f.do(t, f.tokens["dev"], "GET", base, "").code(), "a suspended member is locked out at once")
		assert.Equal(t, 200, f.do(t, f.tokens["admin"], "PATCH", base+"/members/"+dev, `{"status":1}`).Status)
		assert.Equal(t, types.OrgErrLastOwner, f.do(t, f.tokens["owner"], "DELETE", base+"/members/"+ownerID, "").code())
		assert.Equal(t, 200, f.do(t, f.tokens["dev"], "DELETE", base+"/members/"+dev, "").Status, "a member may leave")
		assert.Equal(t, 404, f.do(t, f.tokens["dev"], "GET", base, "").Status)
		assert.Equal(t, 404, f.do(t, f.tokens["admin"], "DELETE", base+"/members/"+dev, "").Status)
	})

	t.Run("irreversible owner actions need a proof, whatever the session scope", func(t *testing.T) {
		scoped := f.session(t, owner, types.AuthScopeOrg, acme.Id)
		for _, bearer := range []string{scoped, f.tokens["owner"]} {
			for _, route := range []struct{ method, path, body string }{
				{"POST", base + "/transfer-ownership", `{"user_id":2}`},
				{"DELETE", base, `{"confirm_slug":"acme"}`},
			} {
				reply := f.do(t, bearer, route.method, route.path, route.body)
				assert.Equal(t, 403, reply.Status, route.method)
				assert.Equal(t, "SECURITY_PROOF_REQUIRED", reply.code(), route.method)
			}
		}
	})

	t.Run("delete needs the slug, the owner and a proof", func(t *testing.T) {
		assert.Equal(t, 403, f.do(t, f.tokens["admin"], "DELETE", base, `{"confirm_slug":"acme"}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["owner"], "DELETE", base, `{"confirm_slug":"nope"}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["owner"], "DELETE", base, `{}`).Status)
		proof := f.proof(t, f.tokens["owner"], types.SensitiveOrgDelete, acme.Id, "slug:acme")
		reply := f.doHeaders(t, f.tokens["owner"], map[string]string{"X-Security-Proof": proof}, "DELETE", base, `{"confirm_slug":"acme"}`)
		assert.Equal(t, 200, reply.Status, reply.Raw)
		assert.Equal(t, 404, f.do(t, f.tokens["owner"], "GET", base, "").Status)
	})
}
