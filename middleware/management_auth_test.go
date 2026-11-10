package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mgmtFixture struct {
	orgControlFixture
	engine *gin.Engine
}

func setupMgmtTest(t *testing.T) mgmtFixture {
	t.Helper()
	base := setupOrgControlTest(t)
	require.NoError(t, model.DB.AutoMigrate(&model.OrgAccessToken{}, &model.OrgAuditLog{}, &model.WorkspaceMemberGrant{}))
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	ok := func(c *gin.Context) {
		body := gin.H{"success": true}
		if principal, found := ManagementPrincipalFromContext(c); found {
			body["role"], body["scopes"], body["actor"] = principal.Role, principal.Scopes, principal.ActorUserID
		}
		if org := ScimOrgID(c); org > 0 {
			body["scim_org"] = org
		}
		c.JSON(http.StatusOK, body)
	}
	engine.GET("/api/mgmt/orgs/:org/members", ManagementAuth(types.MgmtScopeMembersRead), ok)
	engine.GET("/api/mgmt/orgs/:org/keys", ManagementAuth(types.MgmtScopeKeysRead), ok)
	engine.GET("/scim/v2/Users", ScimAuth(), ok)
	engine.GET("/api/not-scim", ScimAuth(), ok)
	engine.GET("/v1/models", TokenAuth(), ok)
	return mgmtFixture{orgControlFixture: base, engine: engine}
}

func (f mgmtFixture) call(t *testing.T, bearer, path string) (int, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	body := map[string]any{}
	_ = common.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder.Code, body
}

func (f mgmtFixture) issue(t *testing.T, creator, kind string, scopes ...string) string {
	t.Helper()
	created, err := orgsvc.CreateCredential(context.Background(), f.users[creator].Id, f.org.Id, orgsvc.CreateCredentialInput{
		Name: "ci", Kind: kind, Scopes: scopes, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	return created.Plaintext
}

func (f mgmtFixture) setRole(t *testing.T, user, role string, status int) {
	t.Helper()
	require.NoError(t, model.DB.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", f.org.Id, f.users[user].Id).
		Updates(map[string]any{"role": role, "status": status}).Error)
}

func TestOrgManagementCredential(t *testing.T) {
	f := setupMgmtTest(t)
	members := "/api/mgmt/orgs/acme/members"
	read := types.MgmtScopeMembersRead

	t.Run("hash, prefix and a single failure answer", func(t *testing.T) {
		token := f.issue(t, "admin", types.OrgAccessTokenPersonalManagement, read)
		status, body := f.call(t, token, members)
		assert.Equal(t, 200, status, body)
		assert.Equal(t, types.OrgRoleAdmin, body["role"])
		var stored model.OrgAccessToken
		require.NoError(t, model.DB.Where("token_hash = ?", model.HashOrgAccessToken(token)).First(&stored).Error)
		assert.NotEqual(t, token, stored.TokenHash)
		assert.Len(t, stored.TokenHash, 64)

		tampered := token[:len(token)-1] + "0"
		if tampered == token {
			tampered = token[:len(token)-1] + "1"
		}
		answers := map[string]bool{}
		for _, bearer := range []string{tampered, "omk-", "", "sk-" + token[4:], strings.ToUpper(token), token + "x"} {
			status, body := f.call(t, bearer, members)
			assert.Equal(t, 401, status, bearer)
			answers[body["code"].(string)] = true
		}
		assert.Len(t, answers, 1, "an unknown, malformed or wrong-prefix credential must not be distinguishable: %v", answers)
	})

	t.Run("scopes: missing, unknown and not in the vocabulary", func(t *testing.T) {
		token := f.issue(t, "admin", types.OrgAccessTokenPersonalManagement, read)
		status, _ := f.call(t, token, "/api/mgmt/orgs/acme/keys")
		assert.Equal(t, 403, status, "keys:read was never granted")

		_, err := orgsvc.CreateCredential(context.Background(), f.users["admin"].Id, f.org.Id, orgsvc.CreateCredentialInput{
			Name: "bad", Kind: types.OrgAccessTokenPersonalManagement, Scopes: []string{"members:read", "owner:write"}, ExpiresAt: time.Now().Add(time.Hour).Unix()})
		requireRefusal(t, err, types.OrgErrInvalidInput)

		// A row written around the service with an unknown scope fails closed.
		require.NoError(t, model.DB.Model(&model.OrgAccessToken{}).Where("token_hash = ?", model.HashOrgAccessToken(token)).
			Update("scopes", `["members:read","root:all"]`).Error)
		status, _ = f.call(t, token, members)
		assert.Equal(t, 401, status)
	})

	t.Run("scim cannot be mixed with other scopes, in either direction", func(t *testing.T) {
		for _, tc := range []struct {
			kind   string
			scopes []string
		}{
			{types.OrgAccessTokenSCIMService, []string{types.MgmtScopeSCIM, read}},
			{types.OrgAccessTokenPersonalManagement, []string{types.MgmtScopeSCIM}},
			{types.OrgAccessTokenPersonalManagement, []string{types.MgmtScopeSCIM, read}},
			{types.OrgAccessTokenSCIMService, []string{read}},
		} {
			_, err := orgsvc.CreateCredential(context.Background(), f.users["admin"].Id, f.org.Id, orgsvc.CreateCredentialInput{
				Name: "mix", Kind: tc.kind, Scopes: tc.scopes, ExpiresAt: time.Now().Add(time.Hour).Unix()})
			requireRefusal(t, err, types.OrgErrInvalidInput)
		}
		// Even a row forged straight into the table cannot authenticate.
		forged := model.OrgAccessToken{OrgId: f.org.Id, Name: "forged", TokenHash: model.HashOrgAccessToken("osc-forged"), Kind: types.OrgAccessTokenSCIMService,
			Scopes: `["scim","members:read"]`, CreatedBy: f.users["admin"].Id, ExpiresAt: time.Now().Add(time.Hour).Unix(), Status: types.OrgAccessTokenActive}
		require.NoError(t, model.DB.Create(&forged).Error)
		status, _ := f.call(t, "osc-forged", "/scim/v2/Users")
		assert.Equal(t, 401, status)
	})

	t.Run("expiry, revocation and the organization", func(t *testing.T) {
		token := f.issue(t, "admin", types.OrgAccessTokenPersonalManagement, read)
		hash := model.HashOrgAccessToken(token)
		status, _ := f.call(t, token, members)
		require.Equal(t, 200, status)
		require.NoError(t, model.DB.Model(&model.OrgAccessToken{}).Where("token_hash = ?", hash).Update("expires_at", time.Now().Add(-time.Second).Unix()).Error)
		status, _ = f.call(t, token, members)
		assert.Equal(t, 401, status, "expired")
		require.NoError(t, model.DB.Model(&model.OrgAccessToken{}).Where("token_hash = ?", hash).
			Updates(map[string]any{"expires_at": time.Now().Add(time.Hour).Unix(), "status": types.OrgAccessTokenRevoked}).Error)
		status, _ = f.call(t, token, members)
		assert.Equal(t, 401, status, "revoked")
		require.NoError(t, model.DB.Model(&model.OrgAccessToken{}).Where("token_hash = ?", hash).Update("status", types.OrgAccessTokenActive).Error)

		status, body := f.call(t, token, "/api/mgmt/orgs/globex/members")
		assert.Equal(t, 404, status, "another organization: %v", body)
		assert.Equal(t, types.OrgErrNotFound, body["code"])

		require.NoError(t, model.DB.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusSuspended).Error)
		status, body = f.call(t, token, members)
		assert.Equal(t, 403, status)
		assert.Equal(t, types.OrgErrSuspended, body["code"])
		require.NoError(t, model.DB.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusActive).Error)
	})

	t.Run("a personal credential follows its creator's live standing", func(t *testing.T) {
		token := f.issue(t, "admin", types.OrgAccessTokenPersonalManagement, read)
		status, _ := f.call(t, token, members)
		require.Equal(t, 200, status)

		f.setRole(t, "admin", types.OrgRoleMember, types.OrgMemberStatusActive)
		status, _ = f.call(t, token, members)
		assert.Equal(t, 401, status, "demoted: a stale scope keeps no power")
		f.setRole(t, "admin", types.OrgRoleBilling, types.OrgMemberStatusActive)
		status, _ = f.call(t, token, members)
		assert.Equal(t, 401, status, "billing is not owner or admin")
		f.setRole(t, "admin", types.OrgRoleAdmin, types.OrgMemberStatusSuspended)
		status, _ = f.call(t, token, members)
		assert.Equal(t, 401, status, "suspended member")
		f.setRole(t, "admin", types.OrgRoleAdmin, types.OrgMemberStatusRemoved)
		status, _ = f.call(t, token, members)
		assert.Equal(t, 401, status, "removed member")
		f.setRole(t, "admin", types.OrgRoleAdmin, types.OrgMemberStatusActive)
		status, _ = f.call(t, token, members)
		assert.Equal(t, 200, status)
		require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", f.users["admin"].Id).Update("status", common.UserStatusDisabled).Error)
		status, _ = f.call(t, token, members)
		assert.Equal(t, 401, status, "globally disabled creator")
		require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", f.users["admin"].Id).Update("status", common.UserStatusEnabled).Error)
	})

	t.Run("the real revocation path ends it for good", func(t *testing.T) {
		token := f.issue(t, "admin", types.OrgAccessTokenPersonalManagement, read)
		require.NoError(t, orgsvc.ChangeMemberRole(context.Background(), f.users["owner"].Id, f.org.Id, f.users["admin"].Id, types.OrgRoleMember))
		require.NoError(t, orgsvc.ChangeMemberRole(context.Background(), f.users["owner"].Id, f.org.Id, f.users["admin"].Id, types.OrgRoleAdmin))
		status, _ := f.call(t, token, members)
		assert.Equal(t, 401, status, "demotion disabled the credential; restoring the role does not bring it back")
	})

	t.Run("an owner's credential still acts as an administrator", func(t *testing.T) {
		token := f.issue(t, "owner", types.OrgAccessTokenPersonalManagement, read)
		status, body := f.call(t, token, members)
		require.Equal(t, 200, status)
		assert.Equal(t, types.OrgRoleAdmin, body["role"])
		principal, err := orgsvc.AuthenticateCredential(context.Background(), token, types.OrgAccessTokenPersonalManagement)
		require.NoError(t, err)
		assert.Equal(t, types.OrgRoleAdmin, principal.Access.Member.Role)
	})

	t.Run("a credential cannot mint, rename or revoke credentials", func(t *testing.T) {
		ctx := orgsvc.WithManagementCredential(context.Background(), 1)
		_, err := orgsvc.CreateCredential(ctx, f.users["owner"].Id, f.org.Id, orgsvc.CreateCredentialInput{
			Name: "child", Kind: types.OrgAccessTokenPersonalManagement, Scopes: []string{read}, ExpiresAt: time.Now().Add(time.Hour).Unix()})
		requireRefusal(t, err, types.OrgErrForbidden)
		requireRefusal(t, orgsvc.RevokeCredential(ctx, f.users["owner"].Id, f.org.Id, 1), types.OrgErrForbidden)
		requireRefusal(t, orgsvc.RenameCredential(ctx, f.users["owner"].Id, f.org.Id, 1, "x"), types.OrgErrForbidden)
		requireRefusal(t, orgsvc.RemoveMember(ctx, f.users["owner"].Id, f.org.Id, f.users["owner"].Id), types.OrgErrForbidden)
		// And it cannot grant the owner role even to a member it can see.
		requireRefusal(t, orgsvc.ChangeMemberRole(ctx, f.users["owner"].Id, f.org.Id, f.users["plain"].Id, types.OrgRoleOwner), types.OrgErrOwnerRole)
	})

	t.Run("it is not an inference key", func(t *testing.T) {
		token := f.issue(t, "admin", types.OrgAccessTokenPersonalManagement, read)
		scim := f.issue(t, "admin", types.OrgAccessTokenSCIMService, types.MgmtScopeSCIM)
		for _, bearer := range []string{token, scim} {
			status, _ := f.call(t, bearer, "/v1/models")
			assert.Equal(t, 401, status)
		}
	})

	t.Run("the credential kind, not only its prefix, decides where it works", func(t *testing.T) {
		now := time.Now().Add(time.Hour).Unix()
		rows := []model.OrgAccessToken{
			{OrgId: f.org.Id, Name: "x1", TokenHash: model.HashOrgAccessToken("osc-wrong-kind"), Kind: types.OrgAccessTokenPersonalManagement,
				Scopes: `["scim"]`, CreatedBy: f.users["admin"].Id, ExpiresAt: now, Status: types.OrgAccessTokenActive},
			{OrgId: f.org.Id, Name: "x2", TokenHash: model.HashOrgAccessToken("omk-wrong-kind"), Kind: types.OrgAccessTokenSCIMService,
				Scopes: `["members:read"]`, CreatedBy: f.users["admin"].Id, ExpiresAt: now, Status: types.OrgAccessTokenActive},
		}
		require.NoError(t, model.DB.Create(&rows).Error)
		status, _ := f.call(t, "osc-wrong-kind", "/scim/v2/Users")
		assert.Equal(t, 401, status, "a personal credential row is not a SCIM credential whatever its plaintext starts with")
		status, _ = f.call(t, "omk-wrong-kind", members)
		assert.Equal(t, 401, status, "a SCIM credential row is not a management credential")
	})

	t.Run("a SCIM credential: only SCIM routes, and not tied to its creator", func(t *testing.T) {
		scim := f.issue(t, "admin", types.OrgAccessTokenSCIMService, types.MgmtScopeSCIM)
		status, body := f.call(t, scim, "/scim/v2/Users")
		assert.Equal(t, 200, status, body)
		assert.EqualValues(t, f.org.Id, body["scim_org"])
		status, _ = f.call(t, scim, "/api/not-scim")
		assert.Equal(t, 403, status, "outside the /scim/v2 tree")
		status, _ = f.call(t, scim, members)
		assert.Equal(t, 401, status, "not a management credential")
		personal := f.issue(t, "admin", types.OrgAccessTokenPersonalManagement, read)
		status, _ = f.call(t, personal, "/scim/v2/Users")
		assert.Equal(t, 401, status, "a management credential is not a SCIM credential")

		// The creator leaves: the SCIM credential keeps working.
		f.setRole(t, "admin", types.OrgRoleAdmin, types.OrgMemberStatusRemoved)
		require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", f.users["admin"].Id).Update("status", common.UserStatusDisabled).Error)
		status, _ = f.call(t, scim, "/scim/v2/Users")
		assert.Equal(t, 200, status, "scim_service does not depend on its creator")
		require.NoError(t, model.DB.Model(&model.User{}).Where("id = ?", f.users["admin"].Id).Update("status", common.UserStatusEnabled).Error)

		// But organization state, expiry and revocation apply.
		require.NoError(t, model.DB.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusSuspended).Error)
		status, _ = f.call(t, scim, "/scim/v2/Users")
		assert.Equal(t, 403, status, "suspended organization")
		require.NoError(t, model.DB.Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusActive).Error)
		require.NoError(t, model.DB.Model(&model.OrgAccessToken{}).Where("token_hash = ?", model.HashOrgAccessToken(scim)).
			Update("status", types.OrgAccessTokenRevoked).Error)
		status, _ = f.call(t, scim, "/scim/v2/Users")
		assert.Equal(t, 401, status, "revoked")
	})
}

func requireRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var access *types.OrgAccessError
	require.ErrorAs(t, err, &access, "expected %s, got %v", code, err)
	assert.Equal(t, code, access.Code)
}
