package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// orgControlFixture adds control-plane principals on top of the inference
// fixture: one user per organization role plus a second organization.
type orgControlFixture struct {
	orgAuthFixture
	users    map[string]model.User
	otherOrg model.Organization
	otherWs  model.Workspace
	engine   *gin.Engine
}

func orgControlRoutes() *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ok := func(c *gin.Context) {
		access, _ := OrgAccessFromContext(c)
		body := gin.H{"success": true, "org_role": access.Member.Role}
		if ws, found := WorkspaceAccessFromContext(c); found {
			body["ws_role"], body["implicit"] = ws.Role, ws.Implicit
		}
		c.JSON(http.StatusOK, body)
	}
	declare := func(method, path string) { DeclareOrgControlRoute(method, path, true) }
	for _, route := range []struct {
		path     string
		handlers []gin.HandlerFunc
	}{
		{"/api/orgs/:org/ping", []gin.HandlerFunc{OrgAuth()}},
		{"/api/orgs/:org/members", []gin.HandlerFunc{OrgAuth(types.OrgRoleOwner, types.OrgRoleAdmin)}},
		{"/api/orgs/:org/billing", []gin.HandlerFunc{OrgAuth(types.OrgRoleOwner, types.OrgRoleBilling)}},
		{"/api/orgs/:org/workspaces/:ws/suspend", []gin.HandlerFunc{OrgAuth(types.OrgRoleOwner, types.OrgRoleAdmin)}},
		{"/api/orgs/:org/workspaces/:ws/keys", []gin.HandlerFunc{OrgAuth(), WorkspaceAuth(types.WorkspaceRoleAdmin, types.WorkspaceRoleMember)}},
		{"/api/orgs/:org/workspaces/:ws/audit", []gin.HandlerFunc{OrgAuth(), WorkspaceAuth(types.WorkspaceRoleAdmin, types.WorkspaceRoleAuditor)}},
	} {
		declare(http.MethodGet, route.path)
		engine.GET(route.path, append([]gin.HandlerFunc{UserAuth()}, append(route.handlers, ok)...)...)
	}
	engine.GET("/api/user/self", UserAuth(), func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"success": true}) })
	return engine
}

func setupOrgControlTest(t *testing.T) orgControlFixture {
	t.Helper()
	base := setupOrgAuthTest(t)
	previousSecret := common.SessionSecret
	common.SessionSecret = "org-control-test-secret"
	t.Cleanup(func() { common.SessionSecret = previousSecret })
	db := model.DB
	f := orgControlFixture{orgAuthFixture: base, users: map[string]model.User{}, engine: orgControlRoutes()}
	now := common.GetTimestamp()
	addMember := func(name, role string, status int) {
		user := model.User{Username: name, Password: "x", Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
			Group: "default", AffCode: "aff-" + name, AuthVersion: 1}
		require.NoError(t, db.Create(&user).Error)
		f.users[name] = user
		require.NoError(t, db.Create(&model.OrganizationMember{OrgId: f.org.Id, UserId: user.Id, Role: role, Status: status, JoinedAt: now}).Error)
	}
	addMember("owner", types.OrgRoleOwner, types.OrgMemberStatusActive)
	addMember("admin", types.OrgRoleAdmin, types.OrgMemberStatusActive)
	addMember("billing", types.OrgRoleBilling, types.OrgMemberStatusActive)
	addMember("wsadmin", types.OrgRoleMember, types.OrgMemberStatusActive)
	addMember("wsmember", types.OrgRoleMember, types.OrgMemberStatusActive)
	addMember("wsauditor", types.OrgRoleMember, types.OrgMemberStatusActive)
	addMember("plain", types.OrgRoleMember, types.OrgMemberStatusActive)
	addMember("suspended", types.OrgRoleMember, types.OrgMemberStatusSuspended)
	addMember("removed", types.OrgRoleMember, types.OrgMemberStatusRemoved)
	for name, role := range map[string]string{"wsadmin": types.WorkspaceRoleAdmin, "wsmember": types.WorkspaceRoleMember, "wsauditor": types.WorkspaceRoleAuditor} {
		require.NoError(t, db.Create(&model.WorkspaceMember{WorkspaceId: f.workspace.Id, OrgId: f.org.Id,
			UserId: f.users[name].Id, Role: role, Status: 1}).Error)
	}
	outsider := model.User{Username: "outsider", Password: "x", Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
		Group: "default", AffCode: "aff-outsider", AuthVersion: 1}
	require.NoError(t, db.Create(&outsider).Error)
	f.users["outsider"] = outsider

	otherWallet := model.User{Username: "org_wallet_b", Password: "x", Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
		Group: "default", AffCode: "wb", Kind: types.UserKindBilling}
	require.NoError(t, db.Create(&otherWallet).Error)
	f.otherOrg = model.Organization{Slug: "globex", Name: "Globex", OwnerUserId: f.users["owner"].Id,
		BillingUserId: otherWallet.Id, Status: types.OrgStatusActive, PolicyVersion: 1}
	require.NoError(t, db.Create(&f.otherOrg).Error)
	f.otherWs = model.Workspace{OrgId: f.otherOrg.Id, Slug: "default", Name: "Default", IsDefault: true, Status: types.WorkspaceStatusActive}
	require.NoError(t, db.Create(&f.otherWs).Error)
	require.NoError(t, db.Create(&model.OrganizationMember{OrgId: f.otherOrg.Id, UserId: f.users["owner"].Id,
		Role: types.OrgRoleOwner, Status: types.OrgMemberStatusActive, JoinedAt: now}).Error)
	return f
}

// sessionToken creates a real login session row and returns its dashboard JWT.
func sessionToken(t *testing.T, user model.User, scope string, orgID int) string {
	t.Helper()
	now := time.Now().Unix()
	sid := uuid.NewString()
	require.NoError(t, model.CreateUserSession(&model.UserSession{SID: sid, UserID: user.Id, Version: 1, UserAuthVersion: 1,
		Status: model.UserSessionStatusActive, RefreshHash: "refresh-" + sid, LoginMethod: "password",
		LastActiveAt: now, ExpiresAt: now + 3600, AuthScope: scope, OrgID: orgID}))
	jwt, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: user.Id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1})
	require.NoError(t, err)
	return jwt
}

type orgControlResult struct {
	Status int
	Code   string
	Body   map[string]any
}

func (f orgControlFixture) call(t *testing.T, bearer, path string) orgControlResult {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	result := orgControlResult{Status: recorder.Code, Body: map[string]any{}}
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &result.Body), recorder.Body.String())
	result.Code, _ = result.Body["code"].(string)
	return result
}

func TestOrgAuthorization(t *testing.T) {
	f := setupOrgControlTest(t)
	org, ws := strconv.Itoa(f.org.Id), strconv.Itoa(f.workspace.Id)
	token := map[string]string{}
	for name, user := range f.users {
		token[name] = sessionToken(t, user, types.AuthScopeGlobal, 0)
	}
	orgPath := func(suffix string) string { return "/api/orgs/" + org + suffix }
	wsPath := func(suffix string) string { return orgPath("/workspaces/" + ws + suffix) }

	cases := []struct {
		name   string
		user   string
		path   string
		status int
		code   string
	}{
		{"owner reaches an any-role route", "owner", orgPath("/ping"), 200, ""},
		{"billing is a member for any-role routes", "billing", orgPath("/ping"), 200, ""},
		{"non member is 404 not 403", "outsider", orgPath("/ping"), 404, types.OrgErrNotFound},
		{"removed member is 404", "removed", orgPath("/ping"), 404, types.OrgErrNotFound},
		{"suspended member is refused", "suspended", orgPath("/ping"), 403, types.OrgErrMemberSuspended},
		{"insufficient role is 403", "plain", orgPath("/members"), 403, types.OrgErrForbidden},
		{"billing cannot manage members", "billing", orgPath("/members"), 403, types.OrgErrForbidden},
		{"admin manages members", "admin", orgPath("/members"), 200, ""},
		{"billing role reaches billing", "billing", orgPath("/billing"), 200, ""},
		{"admin is not billing", "admin", orgPath("/billing"), 403, types.OrgErrForbidden},
		{"org owner is implicit workspace admin", "owner", wsPath("/keys"), 200, ""},
		{"org admin is implicit workspace admin", "admin", wsPath("/audit"), 200, ""},
		{"explicit workspace admin", "wsadmin", wsPath("/keys"), 200, ""},
		{"workspace member may use keys", "wsmember", wsPath("/keys"), 200, ""},
		{"workspace member is not auditor", "wsmember", wsPath("/audit"), 403, types.OrgErrWorkspaceForbidden},
		{"auditor reads audit", "wsauditor", wsPath("/audit"), 200, ""},
		{"auditor may not manage keys", "wsauditor", wsPath("/keys"), 403, types.OrgErrWorkspaceForbidden},
		{"billing role grants no workspace access", "billing", wsPath("/keys"), 404, types.OrgErrWorkspaceNotFound},
		{"org member without grant is 404", "plain", wsPath("/keys"), 404, types.OrgErrWorkspaceNotFound},
		{"workspace of another org is 404", "owner", orgPath("/workspaces/" + strconv.Itoa(f.otherWs.Id) + "/keys"), 404, types.OrgErrWorkspaceNotFound},
		{"unknown workspace is 404", "owner", orgPath("/workspaces/9999/keys"), 404, types.OrgErrWorkspaceNotFound},
		{"slug reference resolves", "owner", "/api/orgs/acme/workspaces/default/keys", 200, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := f.call(t, token[tc.user], tc.path)
			assert.Equal(t, tc.status, got.Status, "%v", got.Body)
			assert.Equal(t, tc.code, got.Code)
		})
	}

	t.Run("implicit admin is reported as implicit", func(t *testing.T) {
		got := f.call(t, token["owner"], wsPath("/keys"))
		assert.Equal(t, "admin", got.Body["ws_role"])
		assert.Equal(t, true, got.Body["implicit"])
		got = f.call(t, token["wsadmin"], wsPath("/keys"))
		assert.Equal(t, false, got.Body["implicit"])
	})

	t.Run("a role change is visible to the next request", func(t *testing.T) {
		require.Equal(t, 200, f.call(t, token["admin"], orgPath("/members")).Status)
		require.NoError(t, model.DB.Transaction(func(tx *gorm.DB) error {
			return model.SetOrganizationMemberRoleTx(tx, f.org.Id, f.users["admin"].Id, types.OrgRoleMember)
		}))
		assert.Equal(t, 403, f.call(t, token["admin"], orgPath("/members")).Status)
		assert.Equal(t, 404, f.call(t, token["admin"], wsPath("/keys")).Status, "implicit admin access must end with the role")
	})

	t.Run("suspended organization refuses members but hides itself from outsiders", func(t *testing.T) {
		require.NoError(t, model.DB.Transaction(func(tx *gorm.DB) error {
			return model.SetOrganizationStatusTx(tx, f.org.Id, types.OrgStatusSuspended)
		}))
		t.Cleanup(func() {
			model.DB.Transaction(func(tx *gorm.DB) error {
				return model.SetOrganizationStatusTx(tx, f.org.Id, types.OrgStatusActive)
			})
		})
		assert.Equal(t, types.OrgErrSuspended, f.call(t, token["owner"], orgPath("/ping")).Code)
		assert.Equal(t, 403, f.call(t, token["owner"], orgPath("/ping")).Status)
		assert.Equal(t, 404, f.call(t, token["outsider"], orgPath("/ping")).Status)
	})

	t.Run("suspended workspace refuses members and is parent-resumable", func(t *testing.T) {
		require.NoError(t, model.DB.Transaction(func(tx *gorm.DB) error {
			return model.SetWorkspaceStatusTx(tx, f.org.Id, f.workspace.Id, types.WorkspaceStatusSuspended)
		}))
		for _, user := range []string{"owner", "wsadmin", "wsmember"} {
			got := f.call(t, token[user], wsPath("/keys"))
			assert.Equal(t, 403, got.Status, user)
			assert.Equal(t, types.OrgErrWorkspaceSuspended, got.Code, user)
		}
		assert.Equal(t, 404, f.call(t, token["plain"], wsPath("/keys")).Status, "non members still see 404")
		// The parent route only needs OrgAuth, so it stays reachable for resume.
		assert.Equal(t, 200, f.call(t, token["owner"], wsPath("/suspend")).Status)
	})

	t.Run("personal access tokens are refused on control routes", func(t *testing.T) {
		rule, declared := AccessTokenRouteRule("GET /api/orgs/:org/ping")
		require.True(t, declared)
		assert.Equal(t, "session", rule.Kind())
	})
}

func TestOrgSessionScope(t *testing.T) {
	f := setupOrgControlTest(t)
	owner := f.users["owner"] // owner of both organizations
	orgA, orgB := strconv.Itoa(f.org.Id), strconv.Itoa(f.otherOrg.Id)
	global := sessionToken(t, owner, types.AuthScopeGlobal, 0)
	scopedToA := sessionToken(t, owner, types.AuthScopeOrg, f.org.Id)

	cases := []struct {
		name   string
		bearer string
		path   string
		status int
		code   string
	}{
		{"global session reaches personal routes", global, "/api/user/self", 200, ""},
		{"global session reaches organization A", global, "/api/orgs/" + orgA + "/ping", 200, ""},
		{"global session reaches organization B", global, "/api/orgs/" + orgB + "/ping", 200, ""},
		{"org session reaches its own organization", scopedToA, "/api/orgs/" + orgA + "/ping", 200, ""},
		{"org session by slug", scopedToA, "/api/orgs/acme/ping", 200, ""},
		{"org session cannot reach another organization it belongs to", scopedToA, "/api/orgs/" + orgB + "/ping", 404, types.OrgErrNotFound},
		{"org session cannot reach another organization by slug", scopedToA, "/api/orgs/globex/ping", 404, types.OrgErrNotFound},
		{"org session cannot read the personal profile", scopedToA, "/api/user/self", 403, types.OrgErrSessionScope},
		{"org session keeps its role on its own organization", scopedToA, "/api/orgs/" + orgA + "/billing", 200, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := f.call(t, tc.bearer, tc.path)
			assert.Equal(t, tc.status, got.Status, "%v", got.Body)
			assert.Equal(t, tc.code, got.Code)
		})
	}

	t.Run("an unknown scope value fails closed", func(t *testing.T) {
		weird := sessionToken(t, owner, "tenant", f.org.Id)
		assert.Equal(t, 403, f.call(t, weird, "/api/orgs/"+orgA+"/ping").Status)
		assert.Equal(t, 403, f.call(t, weird, "/api/user/self").Status)
	})

	t.Run("an org session without an organization id fails closed", func(t *testing.T) {
		unbound := sessionToken(t, owner, types.AuthScopeOrg, 0)
		assert.Equal(t, 403, f.call(t, unbound, "/api/orgs/"+orgA+"/ping").Status)
	})

	t.Run("undeclared routes are denied to org sessions by default", func(t *testing.T) {
		engine := gin.New()
		engine.GET("/api/orgs/:org/forgotten", UserAuth(), OrgAuth(), func(c *gin.Context) { c.Status(http.StatusOK) })
		request := httptest.NewRequest(http.MethodGet, "/api/orgs/"+orgA+"/forgotten", nil)
		request.Header.Set("Authorization", "Bearer "+scopedToA)
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusForbidden, recorder.Code)
		request = httptest.NewRequest(http.MethodGet, "/api/orgs/"+orgA+"/forgotten", nil)
		request.Header.Set("Authorization", "Bearer "+global)
		recorder = httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusOK, recorder.Code, "a global session is unaffected")
	})

	t.Run("optional authentication degrades an org session to anonymous", func(t *testing.T) {
		engine := gin.New()
		var userID int
		engine.GET("/api/maybe", TryUserAuth(), func(c *gin.Context) { userID = c.GetInt("id"); c.Status(http.StatusOK) })
		request := httptest.NewRequest(http.MethodGet, "/api/maybe", nil)
		request.Header.Set("Authorization", "Bearer "+scopedToA)
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Zero(t, userID, "an org session must not be identified on undeclared routes")
	})
}

func TestOrgInviteTokenNeverReachesAccessLog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	previous := common.LogWriter
	var output bytes.Buffer
	common.LogWriter = &output
	t.Cleanup(func() { common.LogWriter = previous })
	engine := gin.New()
	SetUpLogger(engine)
	engine.POST("/api/invites/:token/accept", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	const secret = "q9Zk2-bearer-credential-in-the-path"
	engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/invites/"+secret+"/accept", nil))
	assert.Contains(t, output.String(), "/api/invites/:token/accept")
	assert.NotContains(t, output.String(), secret)
}
