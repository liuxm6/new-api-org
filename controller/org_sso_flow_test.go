package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/oauth"
	"github.com/QuantumNous/new-api/service"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// orgFlow drives the real org-SSO handlers and the real authentication and
// organization middleware against the fake IdP of Task 12 (setupOrgSSO), with a
// cookie jar standing in for the browser.
type orgFlow struct {
	*orgSSO
	t        *testing.T
	db       *gorm.DB
	engine   *gin.Engine
	org      model.Organization
	provider model.CustomOAuthProvider
	owner    model.User
	jar      map[string]string
}

var orgFlowRoutesOnce = func() func() {
	declared := false
	return func() {
		if declared {
			return
		}
		declared = true
		for _, route := range []struct{ method, path string }{
			{"GET", "/api/orgs/:org"}, {"POST", "/api/orgs/:org/sensitive/begin"}, {"POST", "/api/orgs/:org/sensitive/callback"},
			{"POST", "/api/orgs/:org/management-keys"}, {"DELETE", "/api/orgs/:org/management-keys/:mkid"},
		} {
			middleware.DeclareOrgControlRoute(route.method, route.path, true)
		}
		middleware.DeclareOrgControlRoute("POST", "/api/org-sso/:org/link/begin", false)
		middleware.DeclareOrgControlRoute("POST", "/api/org-sso/:org/link/callback", false)
	}
}()

func setupOrgFlow(t *testing.T) *orgFlow {
	t.Helper()
	f := setupOrgSSO(t)
	db := model.DB
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.Token{}, &model.Task{}, &model.Midjourney{}, &model.Option{}, &model.UserAccessToken{},
		&model.TwoFA{}, &model.TwoFABackupCode{}, &model.PasskeyCredential{}, &model.CustomOAuthProvider{}))
	require.NoError(t, model.MigrateOrgTables())
	common.RedisEnabled = false
	model.InitColumnNames()
	orgsvc.ResetAccessCache()
	previousSecret, previousAddress := common.SessionSecret, system_setting.ServerAddress
	common.SessionSecret, system_setting.ServerAddress = "org-flow-test-secret", "https://console.example.org"
	previousFactory := newOrgOIDCProvider
	t.Cleanup(func() {
		common.SessionSecret, system_setting.ServerAddress, newOrgOIDCProvider = previousSecret, previousAddress, previousFactory
	})
	newOrgOIDCProvider = func(provider *model.CustomOAuthProvider, redirectURI string) (*oauth.OrgOIDCProvider, error) {
		cfg, err := oauth.NewOrgOIDCConfig(provider, redirectURI)
		if err != nil {
			return nil, err
		}
		return oauth.NewOrgOIDCProvider(cfg, f.client, oauth.WithOrgOIDCJWKSCooldown(0))
	}

	owner := model.User{Username: "flow-owner", Password: "password-123", Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
		Group: "default", AffCode: "aff-flow-owner", Email: "owner@corp.example", AuthVersion: 1}
	require.NoError(t, db.Create(&owner).Error)
	created, err := orgsvc.CreateOrganization(context.Background(), owner.Id, orgsvc.CreateOrganizationInput{Name: "Acme", Slug: "acme"})
	require.NoError(t, err)
	require.NoError(t, db.Model(&model.Organization{}).Where("id = ?", created.Org.Id).Update("seat_limit", 100).Error)
	issuer, clientID, secret, on := f.idp.issuer, orgSSOClientID, orgSSOSecret, true
	_, err = orgsvc.UpdateSSOConfig(context.Background(), owner.Id, created.Org.Id, orgsvc.SSOConfigInput{
		Issuer: &issuer, ClientID: &clientID, ClientSecret: &secret, Enabled: &on, JITEnabled: &on})
	require.NoError(t, err)
	flow := &orgFlow{orgSSO: f, t: t, db: db, owner: owner, jar: map[string]string{}}
	require.NoError(t, db.First(&flow.org, created.Org.Id).Error)
	require.NoError(t, db.Where("org_id = ?", flow.org.Id).First(&flow.provider).Error)
	f.row = &flow.provider

	orgFlowRoutesOnce()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.POST("/api/org-sso/:org/begin", OrgSSOBegin)
	engine.POST("/api/org-sso/:org/callback", OrgSSOCallback)
	engine.POST("/api/org-sso/:org/link/begin", middleware.UserAuth(), OrgLinkBegin)
	engine.POST("/api/org-sso/:org/link/callback", middleware.UserAuth(), OrgLinkCallback)
	admins := middleware.OrgAuth(types.OrgRoleOwner, types.OrgRoleAdmin)
	engine.GET("/api/orgs/:org", middleware.UserAuth(), middleware.OrgAuth(), GetOrganization)
	engine.POST("/api/orgs/:org/sensitive/begin", middleware.UserAuth(), admins, OrgSensitiveBegin)
	engine.POST("/api/orgs/:org/sensitive/callback", middleware.UserAuth(), admins, OrgSensitiveCallback)
	engine.POST("/api/orgs/:org/management-keys", middleware.UserAuth(), admins, CreateManagementKey)
	engine.DELETE("/api/orgs/:org/management-keys/:mkid", middleware.UserAuth(), admins, RevokeManagementKey)
	engine.GET("/api/user/self", middleware.UserAuth(), func(c *gin.Context) { c.JSON(200, gin.H{"success": true}) })
	engine.POST("/api/user/auth/refresh", RefreshAuth)
	flow.engine = engine
	return flow
}

type flowReply struct {
	Status int
	Body   map[string]any
	Raw    string
	Header http.Header
}

func (r flowReply) code() string { s, _ := r.Body["code"].(string); return s }
func (r flowReply) data() map[string]any {
	d, _ := r.Body["data"].(map[string]any)
	return d
}

// do sends a request with the jar's cookies, then stores what the response sets.
func (f *orgFlow) do(bearer, method, path, body string, headers ...string) flowReply {
	f.t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.20:1234"
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		request.Header.Set(headers[i], headers[i+1])
	}
	for name, value := range f.jar {
		request.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(f.jar, cookie.Name)
		} else {
			f.jar[cookie.Name] = cookie.Value
		}
	}
	reply := flowReply{Status: recorder.Code, Raw: recorder.Body.String(), Header: recorder.Header(), Body: map[string]any{}}
	_ = common.Unmarshal(recorder.Body.Bytes(), &reply.Body)
	return reply
}

// setIdentity makes the next ID Token (and UserInfo) describe this person.
func (f *orgFlow) setIdentity(sub, email string, verified bool, authTime func(time.Time) *time.Time) {
	f.idp.with(func() {
		f.idp.claims = func(c jwt.MapClaims) { c["sub"], c["email"], c["email_verified"] = sub, email, verified }
		f.idp.userinfo = func(w http.ResponseWriter) {
			orgIDPWrite(w, http.StatusOK, map[string]any{"sub": sub, "email": email, "name": "Person"})
		}
		if authTime != nil {
			f.idp.authTime = authTime
		}
	})
}

// authorize plays the browser to the IdP and back, returning the callback body.
func (f *orgFlow) authorize(reply flowReply, extra map[string]any) string {
	f.t.Helper()
	require.Equal(f.t, 200, reply.Status, reply.Raw)
	authURL, _ := reply.data()["authorization_url"].(string)
	require.NotEmpty(f.t, authURL, reply.Raw)
	code, state, _ := f.idp.authorize(authURL, orgSSOClientConfig{clientID: orgSSOClientID})
	body := map[string]any{"state": state, "code": code}
	for key, value := range extra {
		body[key] = value
	}
	encoded, err := common.Marshal(body)
	require.NoError(f.t, err)
	return string(encoded)
}

// login runs one whole organization sign-in and returns the callback reply.
func (f *orgFlow) login() flowReply {
	f.t.Helper()
	begin := f.do("", "POST", "/api/org-sso/acme/begin", "{}")
	return f.do("", "POST", "/api/org-sso/acme/callback", f.authorize(begin, nil))
}

func (f *orgFlow) loginToken() string {
	f.t.Helper()
	reply := f.login()
	require.Equal(f.t, 200, reply.Status, reply.Raw)
	token, _ := reply.data()["access_token"].(string)
	require.NotEmpty(f.t, token)
	return token
}

func (f *orgFlow) globalSession(user model.User) string {
	f.t.Helper()
	bundle, err := service.CreateLoginSession(user.Id, "password", "192.0.2.30", "test")
	require.NoError(f.t, err)
	return bundle.AccessToken
}

func (f *orgFlow) identityOf(sub string) *model.OrgIdentity {
	f.t.Helper()
	identity, err := model.GetOrgIdentityBySubject(f.db, f.org.Id, f.provider.Id, sub)
	require.NoError(f.t, err)
	return identity
}

func (f *orgFlow) audit(action string) []model.OrgAuditLog {
	var rows []model.OrgAuditLog
	require.NoError(f.t, f.db.Where("org_id = ? AND action = ?", f.org.Id, action).Find(&rows).Error)
	return rows
}

func TestOrgOIDCIdentityBinding(t *testing.T) {
	f := setupOrgFlow(t)
	ctx := context.Background()

	t.Run("the provider's organization and issuer cannot be changed in place", func(t *testing.T) {
		stored := f.provider
		moved := stored
		moved.OrgId++
		assert.ErrorIs(t, model.UpdateCustomOAuthProvider(&moved), model.ErrOrgProviderImmutable)
		reissued := stored
		reissued.Issuer = "https://evil.example.com"
		assert.ErrorIs(t, model.UpdateCustomOAuthProvider(&reissued), model.ErrOrgProviderImmutable)
		issuer := "https://evil.example.com"
		_, err := orgsvc.UpdateSSOConfig(ctx, f.owner.Id, f.org.Id, orgsvc.SSOConfigInput{Issuer: &issuer})
		var refusal *types.OrgAccessError
		require.ErrorAs(t, err, &refusal, "the owner API refuses a different issuer")
		assert.Equal(t, types.OrgErrConflict, refusal.Code)
		edited := stored
		edited.Scopes = "openid email"
		require.NoError(t, model.UpdateCustomOAuthProvider(&edited), "other fields stay editable")
		assert.NoError(t, model.UpdateCustomOAuthProvider(&stored))

		platform := model.CustomOAuthProvider{Name: "Plat", Slug: "plat", ClientId: "c", AuthorizationEndpoint: "https://a/b", TokenEndpoint: "https://a/t", UserInfoEndpoint: "https://a/u"}
		require.NoError(t, model.CreateCustomOAuthProvider(&platform))
		platform.OrgId = f.org.Id
		platform.Issuer, platform.ClientSecret = "https://idp.example.com", "s"
		assert.ErrorIs(t, model.UpdateCustomOAuthProvider(&platform), model.ErrOrgProviderImmutable, "a platform provider cannot be turned into a tenant one")
	})

	t.Run("a tenant IdP never joins the platform login registry", func(t *testing.T) {
		require.NoError(t, oauth.LoadCustomProviders())
		assert.Nil(t, oauth.GetProvider(f.provider.Slug))
		oauth.RegisterOrUpdateCustomProvider(&f.provider)
		assert.Nil(t, oauth.GetProvider(f.provider.Slug))
		assert.NotNil(t, oauth.GetProvider("plat"), "platform providers load as before")
	})

	t.Run("the first sign-in creates a bonus-free placeholder and one org session", func(t *testing.T) {
		previousBonus, previousInvitee := common.QuotaForNewUser, common.QuotaForInvitee
		common.QuotaForNewUser, common.QuotaForInvitee = 5000, 5000
		t.Cleanup(func() { common.QuotaForNewUser, common.QuotaForInvitee = previousBonus, previousInvitee })
		f.setIdentity("sub-alice", "alice@corp.example", true, nil)
		reply := f.login()
		require.Equal(t, 200, reply.Status, reply.Raw)
		assert.Equal(t, true, reply.data()["joined"])
		identity := f.identityOf("sub-alice")
		assert.Equal(t, f.idp.issuer, identity.Issuer)
		assert.Equal(t, "alice@corp.example", identity.ClaimEmail)
		assert.Equal(t, types.OrgIdentitySourceSSO, identity.Source)
		var user model.User
		require.NoError(t, f.db.First(&user, identity.UserId).Error)
		assert.Equal(t, types.UserKindHuman, user.Kind)
		assert.Empty(t, user.Email, "the claim email is not a global address")
		assert.Zero(t, user.Quota, "no sign-up bonus")
		assert.Zero(t, user.InviterId)
		assert.NotEmpty(t, user.Password)
		assert.False(t, common.ValidatePasswordAndHash("alice@corp.example", user.Password))
		member, err := model.GetOrganizationMember(f.db, f.org.Id, user.Id)
		require.NoError(t, err)
		assert.Equal(t, types.OrgMemberStatusActive, member.Status)
		assert.Equal(t, types.OrgMemberSourceSSO, member.Source)
		assert.Equal(t, types.OrgRoleMember, member.Role)
		assert.Zero(t, countOf(f.db, &model.Checkin{}), "no check-in or bonus rows")

		var sessions []model.UserSession
		require.NoError(t, f.db.Where("user_id = ?", user.Id).Find(&sessions).Error)
		require.Len(t, sessions, 1)
		assert.Equal(t, types.AuthScopeOrg, sessions[0].AuthScope)
		assert.Equal(t, f.org.Id, sessions[0].OrgID)
		assert.Equal(t, f.provider.Id, sessions[0].ProviderID)
		assert.Equal(t, "org_sso", sessions[0].LoginMethod)
		ws, err := model.GetWorkspaceMember(f.db, 1, user.Id)
		require.NoError(t, err)
		assert.Equal(t, types.WorkspaceRoleMember, ws.Role, "joined the default workspace")
		require.Len(t, f.audit("sso.jit_join"), 1)
	})

	t.Run("a second sign-in is the same person and takes no new seat", func(t *testing.T) {
		before := countOf(f.db, &model.User{})
		seats, err := orgsvc.SeatsInUse(f.db, f.org.Id)
		require.NoError(t, err)
		reply := f.login()
		require.Equal(t, 200, reply.Status, reply.Raw)
		assert.Equal(t, false, reply.data()["joined"])
		assert.Equal(t, before, countOf(f.db, &model.User{}))
		after, _ := orgsvc.SeatsInUse(f.db, f.org.Id)
		assert.Equal(t, seats, after)
	})

	t.Run("matching email never merges: a global account with that address is untouched", func(t *testing.T) {
		victim := model.User{Username: "victim", Password: "password-123", Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
			Group: "default", AffCode: "aff-victim", Email: "bob@corp.example", AuthVersion: 1}
		require.NoError(t, f.db.Create(&victim).Error)
		f.setIdentity("sub-bob", "bob@corp.example", true, nil)
		require.Equal(t, 200, f.login().Status)
		identity := f.identityOf("sub-bob")
		assert.NotEqual(t, victim.Id, identity.UserId)
		_, err := model.GetOrganizationMember(f.db, f.org.Id, victim.Id)
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound, "the victim is not a member")
		var sessions int64
		f.db.Model(&model.UserSession{}).Where("user_id = ?", victim.Id).Count(&sessions)
		assert.Zero(t, sessions, "no session of any scope for the global account")
	})

	t.Run("an unverified or missing email claim does not join", func(t *testing.T) {
		f.setIdentity("sub-carl", "carl@corp.example", false, nil)
		reply := f.login()
		assert.Equal(t, 403, reply.Status, reply.Raw)
		assert.Equal(t, types.OrgErrEmailNotVerified, reply.code())
		f.setIdentity("sub-dana", "", true, nil)
		assert.Equal(t, types.OrgErrEmailNotVerified, f.login().code())
		for _, sub := range []string{"sub-carl", "sub-dana"} {
			_, err := model.GetOrgIdentityBySubject(f.db, f.org.Id, f.provider.Id, sub)
			assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
		}
		assert.NotEmpty(t, f.audit("sso.login_denied"), "refusals are audited with a reason code")
	})

	t.Run("JIT off, a full org and a suspended org all refuse a new person", func(t *testing.T) {
		off := false
		_, err := orgsvc.UpdateSSOConfig(ctx, f.owner.Id, f.org.Id, orgsvc.SSOConfigInput{JITEnabled: &off})
		require.NoError(t, err)
		f.setIdentity("sub-eve", "eve@corp.example", true, nil)
		assert.Equal(t, types.OrgErrJITDisabled, f.login().code())
		on := true
		_, err = orgsvc.UpdateSSOConfig(ctx, f.owner.Id, f.org.Id, orgsvc.SSOConfigInput{JITEnabled: &on})
		require.NoError(t, err)

		require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("seat_limit", 1).Error)
		assert.Equal(t, types.OrgErrSeatLimitReached, f.login().code())
		require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("seat_limit", 100).Error)

		require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusSuspended).Error)
		refused := f.do("", "POST", "/api/org-sso/acme/begin", "{}")
		assert.Equal(t, 403, refused.Status)
		assert.Equal(t, types.OrgErrSSONotConfigured, refused.code(), "a suspended organization looks like no SSO at all")
		require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusActive).Error)
		_, err = model.GetOrgIdentityBySubject(f.db, f.org.Id, f.provider.Id, "sub-eve")
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})

	t.Run("a suspended or SCIM-removed member is not revived by signing in", func(t *testing.T) {
		f.setIdentity("sub-fay", "fay@corp.example", true, nil)
		require.Equal(t, 200, f.login().Status)
		fay := f.identityOf("sub-fay")
		require.NoError(t, orgsvc.SetMemberStatus(ctx, f.owner.Id, f.org.Id, fay.UserId, types.OrgMemberStatusSuspended))
		assert.Equal(t, types.OrgErrMemberSuspended, f.login().code())
		require.NoError(t, orgsvc.SetMemberStatus(ctx, f.owner.Id, f.org.Id, fay.UserId, types.OrgMemberStatusActive))
		require.NoError(t, orgsvc.RemoveMember(ctx, f.owner.Id, f.org.Id, fay.UserId))
		assert.Equal(t, types.OrgErrMemberSuspended, f.login().code(), "a removed member is invited back, not signed back in")
	})

	t.Run("state is single use and bound to this browser", func(t *testing.T) {
		f.setIdentity("sub-alice", "alice@corp.example", true, nil)
		begin := f.do("", "POST", "/api/org-sso/acme/begin", "{}")
		body := f.authorize(begin, nil)
		cookie := f.jar["new_api_org_oidc_login"]
		require.NotEmpty(t, cookie)
		delete(f.jar, "new_api_org_oidc_login")
		other := f.do("", "POST", "/api/org-sso/acme/callback", body)
		assert.Equal(t, 400, other.Status)
		assert.Equal(t, "SSO_FLOW_INVALID", other.code(), "a callback without the binding cookie fails")
		f.jar["new_api_org_oidc_login"] = cookie
		replay := f.do("", "POST", "/api/org-sso/acme/callback", body)
		assert.Equal(t, "SSO_FLOW_INVALID", replay.code(), "the failed attempt spent the state")
		assert.NotContains(t, replay.Raw, orgSSOSecret)
	})
}

func countOf(db *gorm.DB, model any) int64 {
	var n int64
	db.Model(model).Count(&n)
	return n
}
