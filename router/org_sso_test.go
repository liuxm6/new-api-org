package router

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// proof mints the single-use proof a global session would get by verifying
// with its password, for one org action on one resource.
func (f *orgRoutesFixture) proof(t *testing.T, bearer, action string, orgID int, resource string) string {
	t.Helper()
	return f.proofFor(t, bearer, action, orgID, types.AuthScopeGlobal, resource, "password")
}

func (f *orgRoutesFixture) proofFor(t *testing.T, bearer, action string, orgID int, authScope, resource, method string) string {
	t.Helper()
	identity, err := service.ParseAccessToken(bearer)
	require.NoError(t, err)
	context, err := service.OrgSensitiveContextJSON(orgID, authScope, resource)
	require.NoError(t, err)
	binding, err := service.BindVerificationOperation(service.VerificationOperation{Scope: action, Context: context})
	require.NoError(t, err)
	proof, err := service.CompleteSecurityVerification(identity, binding, method)
	require.NoError(t, err)
	return proof.ProofToken
}

func proofHeader(proof string) map[string]string { return map[string]string{"X-Security-Proof": proof} }

func grantResource(kind string, scopes []string, expiresAt int64) string {
	return "grant:" + kind + ":" + strconv.FormatInt(expiresAt, 10) + ":" + strings.Join(scopes, ",")
}

type orgWithAdmins struct {
	org   model.Organization
	owner string
	admin string
}

func (f *orgRoutesFixture) acme(t *testing.T) orgWithAdmins {
	t.Helper()
	f.user(t, "owner", "owner@example.com")
	f.user(t, "admin", "admin@example.com")
	f.user(t, "dev", "dev@example.com")
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)
	var org model.Organization
	require.NoError(t, f.db.Where("slug = ?", "acme").First(&org).Error)
	for name, role := range map[string]string{"admin": types.OrgRoleAdmin, "dev": types.OrgRoleMember} {
		require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: org.Id, UserId: f.users[name].Id, Role: role,
			Status: types.OrgMemberStatusActive, Source: types.OrgMemberSourceManual}).Error)
	}
	return orgWithAdmins{org: org, owner: f.tokens["owner"], admin: f.tokens["admin"]}
}

// mintKey creates a credential through the real route with a valid proof and
// returns its plaintext and id.
func (f *orgRoutesFixture) mintKey(t *testing.T, bearer string, orgID int, kind string, scopes []string) (string, int) {
	t.Helper()
	expires := time.Now().Add(24 * time.Hour).Unix()
	body := `{"name":"ci","kind":"` + kind + `","scopes":["` + strings.Join(scopes, `","`) + `"],"expires_at":` + strconv.FormatInt(expires, 10) + `}`
	proof := f.proof(t, bearer, types.SensitiveManagementKeyCreate, orgID, grantResource(kind, scopes, expires))
	reply := f.doHeaders(t, bearer, proofHeader(proof), "POST", "/api/orgs/acme/management-keys", body)
	require.Equal(t, 200, reply.Status, reply.Raw)
	token, _ := reply.data()["token"].(string)
	credential, _ := reply.data()["credential"].(map[string]any)
	require.NotEmpty(t, token)
	return token, int(credential["id"].(float64))
}

func TestOrgRouteManagementKeys(t *testing.T) {
	f := setupOrgRoutes(t)
	a := f.acme(t)
	scopes := []string{types.MgmtScopeMembersRead, types.MgmtScopeMembersWrite}

	t.Run("creation needs a human session and a proof bound to the exact grant", func(t *testing.T) {
		expires := time.Now().Add(24 * time.Hour).Unix()
		body := `{"name":"ci","kind":"personal_management","scopes":["members:read","members:write"],"expires_at":` + strconv.FormatInt(expires, 10) + `}`
		assert.Equal(t, "SECURITY_PROOF_REQUIRED", f.do(t, a.owner, "POST", "/api/orgs/acme/management-keys", body).code())
		wide := f.proof(t, a.owner, types.SensitiveManagementKeyCreate, a.org.Id,
			grantResource("personal_management", []string{"keys:write", "members:read", "members:write"}, expires))
		assert.Equal(t, "SECURITY_PROOF_CONTEXT_MISMATCH", f.doHeaders(t, a.owner, proofHeader(wide), "POST", "/api/orgs/acme/management-keys", body).code(),
			"a proof for a wider grant does not authorize a narrower or different one")
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "POST", "/api/orgs/acme/management-keys", body).Status)
		assert.Equal(t, 401, f.do(t, "", "POST", "/api/orgs/acme/management-keys", body).Status)

		token, id := f.mintKey(t, a.owner, a.org.Id, "personal_management", scopes)
		assert.True(t, strings.HasPrefix(token, types.ManagementKeyPrefix))
		var stored model.OrgAccessToken
		require.NoError(t, f.db.First(&stored, id).Error)
		assert.Equal(t, model.HashOrgAccessToken(token), stored.TokenHash, "only the SHA-256 is stored")
		assert.NotContains(t, stored.TokenHash, token)
		assert.Equal(t, token[len(token)-4:], stored.TokenHint)
		list := f.do(t, a.owner, "GET", "/api/orgs/acme/management-keys", "")
		assert.Equal(t, 200, list.Status)
		assert.NotContains(t, list.Raw, token, "the plaintext is shown once")
		assert.NotContains(t, list.Raw, stored.TokenHash)
	})

	t.Run("a proof works once", func(t *testing.T) {
		expires := time.Now().Add(24 * time.Hour).Unix()
		body := `{"name":"once","kind":"personal_management","scopes":["members:read"],"expires_at":` + strconv.FormatInt(expires, 10) + `}`
		proof := f.proof(t, a.owner, types.SensitiveManagementKeyCreate, a.org.Id, grantResource("personal_management", []string{"members:read"}, expires))
		assert.Equal(t, 200, f.doHeaders(t, a.owner, proofHeader(proof), "POST", "/api/orgs/acme/management-keys", body).Status)
		assert.Equal(t, "SECURITY_PROOF_CONSUMED", f.doHeaders(t, a.owner, proofHeader(proof), "POST", "/api/orgs/acme/management-keys", body).code())
	})

	t.Run("a proof does not cross sessions or organizations", func(t *testing.T) {
		expires := time.Now().Add(24 * time.Hour).Unix()
		body := `{"name":"x","kind":"personal_management","scopes":["members:read"],"expires_at":` + strconv.FormatInt(expires, 10) + `}`
		mine := f.proof(t, a.owner, types.SensitiveManagementKeyCreate, a.org.Id, grantResource("personal_management", []string{"members:read"}, expires))
		other := f.session(t, f.users["owner"], types.AuthScopeGlobal, 0)
		assert.NotEqual(t, 200, f.doHeaders(t, other, proofHeader(mine), "POST", "/api/orgs/acme/management-keys", body).Status, "another session")
		foreign := f.proof(t, a.owner, types.SensitiveManagementKeyCreate, a.org.Id+99, grantResource("personal_management", []string{"members:read"}, expires))
		assert.Equal(t, "SECURITY_PROOF_CONTEXT_MISMATCH", f.doHeaders(t, a.owner, proofHeader(foreign), "POST", "/api/orgs/acme/management-keys", body).code())
		asOrgSession := f.proofFor(t, a.owner, types.SensitiveManagementKeyCreate, a.org.Id, types.AuthScopeOrg,
			grantResource("personal_management", []string{"members:read"}, expires), "password")
		assert.Equal(t, "SECURITY_PROOF_CONTEXT_MISMATCH", f.doHeaders(t, a.owner, proofHeader(asOrgSession), "POST", "/api/orgs/acme/management-keys", body).code(),
			"a proof issued for the org scope is not good for a global session")
	})

	t.Run("revocation needs a proof and ends the credential", func(t *testing.T) {
		token, id := f.mintKey(t, a.owner, a.org.Id, "personal_management", scopes)
		assert.Equal(t, 401, f.do(t, "", "GET", "/api/mgmt/orgs/acme/members", "").Status, "anonymous is refused")
		call := func() routeReply { return f.do(t, token, "GET", "/api/mgmt/orgs/acme/members", "") }
		assert.Equal(t, 200, call().Status)
		assert.Equal(t, "SECURITY_PROOF_REQUIRED", f.do(t, a.owner, "DELETE", "/api/orgs/acme/management-keys/"+strconv.Itoa(id), "").code())
		proof := f.proof(t, a.owner, types.SensitiveManagementKeyRevoke, a.org.Id, "credential:"+strconv.Itoa(id))
		assert.Equal(t, 200, f.doHeaders(t, a.owner, proofHeader(proof), "DELETE", "/api/orgs/acme/management-keys/"+strconv.Itoa(id), "").Status)
		assert.Equal(t, 401, call().Status, "a revoked credential stops at once")
		assert.Equal(t, types.OrgErrCredentialInvalid, call().code())
	})
}

func TestOrgRouteManagementReach(t *testing.T) {
	f := setupOrgRoutes(t)
	a := f.acme(t)
	token, _ := f.mintKey(t, a.owner, a.org.Id, "personal_management", []string{types.MgmtScopeMembersRead})
	writer, _ := f.mintKey(t, a.owner, a.org.Id, "personal_management", []string{types.MgmtScopeMembersRead, types.MgmtScopeMembersWrite})
	scim, _ := f.mintKey(t, a.owner, a.org.Id, "scim_service", []string{types.MgmtScopeSCIM})
	devID := strconv.Itoa(f.users["dev"].Id)
	ownerID := strconv.Itoa(f.users["owner"].Id)

	t.Run("it reaches only the management tree, within its scopes", func(t *testing.T) {
		assert.Equal(t, 200, f.do(t, token, "GET", "/api/mgmt/orgs/acme/members", "").Status)
		assert.Equal(t, 403, f.do(t, token, "PATCH", "/api/mgmt/orgs/acme/members/"+devID, `{"role":"billing"}`).Status, "write needs the write scope")
		assert.Equal(t, 403, f.do(t, token, "GET", "/api/mgmt/orgs/acme/workspaces", "").Status, "keys:read is not granted")
		assert.Equal(t, 200, f.do(t, writer, "PATCH", "/api/mgmt/orgs/acme/members/"+devID, `{"role":"billing"}`).Status)
	})

	t.Run("it is not an inference key, a session or a SCIM credential", func(t *testing.T) {
		for _, tc := range []struct{ method, path string }{
			{"GET", "/v1/models"}, {"POST", "/v1/chat/completions"}, {"GET", "/api/orgs/acme"}, {"GET", "/api/user/self"},
			{"GET", "/api/orgs/acme/management-keys"}, {"POST", "/api/orgs/acme/transfer-ownership"}, {"PUT", "/api/orgs/acme/sso"},
			{"GET", "/scim/v2/Users"},
		} {
			reply := f.do(t, writer, tc.method, tc.path, `{}`)
			assert.Contains(t, []int{401, 403, 404}, reply.Status, tc.method+" "+tc.path)
			assert.NotEqual(t, 200, reply.Status, tc.method+" "+tc.path)
		}
		assert.Equal(t, 401, f.do(t, scim, "GET", "/api/mgmt/orgs/acme/members", "").Status, "a SCIM token is not a management key")
	})

	t.Run("it cannot change an owner, whoever created it", func(t *testing.T) {
		assert.Equal(t, 409, f.do(t, writer, "PATCH", "/api/mgmt/orgs/acme/members/"+ownerID, `{"role":"member"}`).Status)
		assert.Equal(t, 409, f.do(t, writer, "PATCH", "/api/mgmt/orgs/acme/members/"+devID, `{"role":"owner"}`).Status)
		assert.Equal(t, 403, f.do(t, writer, "DELETE", "/api/mgmt/orgs/acme/members/"+ownerID, "").Status, "not even its own creator")
	})

	t.Run("another organization sees it as unknown", func(t *testing.T) {
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Globex","slug":"globex"}`).Status)
		reply := f.do(t, writer, "GET", "/api/mgmt/orgs/globex/members", "")
		assert.Equal(t, 404, reply.Status)
	})

	t.Run("the live role limits it: demotion, removal and disablement end it", func(t *testing.T) {
		admin, _ := f.mintKey(t, a.admin, a.org.Id, "personal_management", []string{types.MgmtScopeMembersRead})
		assert.Equal(t, 200, f.do(t, admin, "GET", "/api/mgmt/orgs/acme/members", "").Status)
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", a.org.Id, f.users["admin"].Id).
			Update("role", types.OrgRoleMember).Error)
		assert.Equal(t, 401, f.do(t, admin, "GET", "/api/mgmt/orgs/acme/members", "").Status, "demoted creator")
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", a.org.Id, f.users["admin"].Id).
			Update("role", types.OrgRoleAdmin).Error)
		assert.Equal(t, 200, f.do(t, admin, "GET", "/api/mgmt/orgs/acme/members", "").Status, "role restored: the credential works again only because it was never revoked")
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["admin"].Id).Update("status", common.UserStatusDisabled).Error)
		assert.Equal(t, 401, f.do(t, admin, "GET", "/api/mgmt/orgs/acme/members", "").Status, "globally disabled creator")
	})

	t.Run("a suspended organization and an expired credential are refused", func(t *testing.T) {
		require.NoError(t, f.db.Model(&model.OrgAccessToken{}).Where("token_hash = ?", model.HashOrgAccessToken(token)).
			Update("expires_at", time.Now().Add(-time.Minute).Unix()).Error)
		assert.Equal(t, 401, f.do(t, token, "GET", "/api/mgmt/orgs/acme/members", "").Status, "expired")
		require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", a.org.Id).Update("status", types.OrgStatusSuspended).Error)
		assert.Equal(t, 403, f.do(t, writer, "GET", "/api/mgmt/orgs/acme/members", "").Status, "suspended organization")
	})
}

// orgSession issues a session restricted to the organization and bound to a
// provider, and gives the person the active identity such a session implies.
func (f *orgRoutesFixture) orgSession(t *testing.T, user *model.User, orgID int) string {
	t.Helper()
	provider := model.CustomOAuthProvider{Name: "SSO", Slug: "sso-" + strconv.Itoa(user.Id), OrgId: orgID, Issuer: "https://idp.example.com",
		ClientId: "c", ClientSecret: "s", Enabled: true}
	require.NoError(t, f.db.Create(&provider).Error)
	require.NoError(t, f.db.Create(&model.OrgIdentity{OrgId: orgID, ProviderId: provider.Id, Issuer: provider.Issuer, Subject: "sub-" + strconv.Itoa(user.Id),
		UserId: user.Id, Source: types.OrgIdentitySourceSSO, Status: types.OrgIdentityActive}).Error)
	now := time.Now().Unix()
	sid := "org-sess-" + strconv.Itoa(user.Id)
	require.NoError(t, model.CreateUserSession(&model.UserSession{SID: sid, UserID: user.Id, Version: 1, UserAuthVersion: 1,
		Status: model.UserSessionStatusActive, RefreshHash: "r-" + sid, LoginMethod: "org_sso", LastActiveAt: now, ExpiresAt: now + 3600,
		AuthScope: types.AuthScopeOrg, OrgID: orgID, ProviderID: provider.Id}))
	jwt, _, err := service.IssueAccessToken(service.AuthIdentity{UserID: user.Id, SessionID: sid, UserAuthVersion: 1, SessionVersion: 1})
	require.NoError(t, err)
	return jwt
}

func TestOrgRouteOrgSessionProof(t *testing.T) {
	f := setupOrgRoutes(t)
	a := f.acme(t)
	orgToken := f.orgSession(t, f.users["owner"], a.org.Id)
	devID := strconv.Itoa(f.users["dev"].Id)
	transfer := `{"user_id":` + devID + `}`

	t.Run("an org session can reach the action only through its own proof", func(t *testing.T) {
		reply := f.do(t, orgToken, "POST", "/api/orgs/acme/transfer-ownership", transfer)
		assert.Equal(t, "SECURITY_PROOF_REQUIRED", reply.code())
		_, err := service.CompleteSecurityVerification(mustIdentity(t, orgToken), mustBinding(t, types.SensitiveOwnershipTransfer, a.org.Id, types.AuthScopeOrg, "user:"+devID), "password")
		assert.Error(t, err, "an org session can only answer with org_oidc, never a password")
	})

	t.Run("a proof for a different resource, scope or session is refused", func(t *testing.T) {
		other := f.proofFor(t, orgToken, types.SensitiveOwnershipTransfer, a.org.Id, types.AuthScopeOrg, "user:999", "org_oidc")
		assert.Equal(t, "SECURITY_PROOF_CONTEXT_MISMATCH", f.doHeaders(t, orgToken, proofHeader(other), "POST", "/api/orgs/acme/transfer-ownership", transfer).code(),
			"another target user")
		wrongAction := f.proofFor(t, orgToken, types.SensitiveSSOUpdate, a.org.Id, types.AuthScopeOrg, "sso:"+strconv.Itoa(a.org.Id), "org_oidc")
		assert.Equal(t, "SECURITY_PROOF_SCOPE_MISMATCH", f.doHeaders(t, orgToken, proofHeader(wrongAction), "POST", "/api/orgs/acme/transfer-ownership", transfer).code(),
			"another action")
		asGlobal := f.proofFor(t, orgToken, types.SensitiveOwnershipTransfer, a.org.Id, types.AuthScopeGlobal, "user:"+devID, "org_oidc")
		assert.Equal(t, "SECURITY_PROOF_CONTEXT_MISMATCH", f.doHeaders(t, orgToken, proofHeader(asGlobal), "POST", "/api/orgs/acme/transfer-ownership", transfer).code(),
			"the proof claims the global scope but the session is org-restricted")
	})

	t.Run("a valid org proof authorizes once", func(t *testing.T) {
		proof := f.proofFor(t, orgToken, types.SensitiveOwnershipTransfer, a.org.Id, types.AuthScopeOrg, "user:"+devID, "org_oidc")
		ok := f.doHeaders(t, orgToken, proofHeader(proof), "POST", "/api/orgs/acme/transfer-ownership", transfer)
		assert.Equal(t, 200, ok.Status, ok.Raw)
		replay := f.doHeaders(t, orgToken, proofHeader(proof), "POST", "/api/orgs/acme/transfer-ownership", transfer)
		assert.NotEqual(t, 200, replay.Status)
	})

	t.Run("an org session has no way to mint a proof for anything global", func(t *testing.T) {
		identity, err := service.ParseAccessToken(orgToken)
		require.NoError(t, err)
		for _, scope := range []string{service.VerificationScopeAccountDelete, service.VerificationScopePasswordChange, service.VerificationScopeChannelKeyRead} {
			binding, err := service.BindVerificationOperation(service.VerificationOperation{Scope: scope})
			if err != nil {
				continue
			}
			_, err = service.CompleteSecurityVerification(identity, binding, service.VerificationMethodOrgOIDC)
			assert.Error(t, err, scope)
			_, err = service.CompleteSecurityVerification(identity, binding, "password")
			assert.Error(t, err, scope)
		}
		for _, route := range []struct{ method, path string }{
			{"POST", "/api/verify"}, {"GET", "/api/verify/methods"}, {"GET", "/api/user/self"}, {"POST", "/api/user/topup"},
		} {
			reply := f.do(t, orgToken, route.method, route.path, `{"method":"password","scope":"account.delete"}`)
			assert.Equal(t, 403, reply.Status, route.path)
			assert.Equal(t, types.OrgErrSessionScope, reply.code(), route.path)
		}
	})
}

func TestOrgRouteMemberDemotionEndsCredential(t *testing.T) {
	f := setupOrgRoutes(t)
	a := f.acme(t)
	token, _ := f.mintKey(t, a.admin, a.org.Id, "personal_management", []string{types.MgmtScopeMembersRead})
	require.Equal(t, 200, f.do(t, token, "GET", "/api/mgmt/orgs/acme/members", "").Status)
	adminID := strconv.Itoa(f.users["admin"].Id)
	require.Equal(t, 200, f.do(t, a.owner, "PATCH", "/api/orgs/acme/members/"+adminID, `{"role":"member"}`).Status)
	assert.Equal(t, 401, f.do(t, token, "GET", "/api/mgmt/orgs/acme/members", "").Status, "demoted through the real route")
	require.Equal(t, 200, f.do(t, a.owner, "PATCH", "/api/orgs/acme/members/"+adminID, `{"role":"admin"}`).Status)
	assert.Equal(t, 401, f.do(t, token, "GET", "/api/mgmt/orgs/acme/members", "").Status, "restoring the role does not revive the credential")
}

func (f *orgRoutesFixture) scim(t *testing.T, token, method, path, body string) routeReply {
	t.Helper()
	reply := f.do(t, token, method, path, body)
	return reply
}

func TestOrgSCIMRoutes(t *testing.T) {
	f := setupOrgRoutes(t)
	a := f.acme(t)
	issuer, clientID, secret, on := "https://idp.example.com", "client", "secret", true
	_, err := orgsvcUpdateSSO(t, f, a.org.Id, issuer, clientID, secret, on)
	require.NoError(t, err)
	scim, _ := f.mintKey(t, a.owner, a.org.Id, "scim_service", []string{types.MgmtScopeSCIM})
	mgmt, _ := f.mintKey(t, a.owner, a.org.Id, "personal_management", []string{types.MgmtScopeMembersRead})

	t.Run("only a SCIM credential gets in", func(t *testing.T) {
		for name, bearer := range map[string]string{"none": "", "session": a.owner, "management key": mgmt, "inference key": "sk-abcdefghijklmnopqrstuvwxyz"} {
			reply := f.scim(t, bearer, "GET", "/scim/v2/Users", "")
			assert.Equal(t, 401, reply.Status, name)
			assert.Contains(t, reply.Raw, "urn:ietf:params:scim:api:messages:2.0:Error", name)
		}
		assert.Equal(t, 200, f.scim(t, scim, "GET", "/scim/v2/Users", "").Status)
		assert.Equal(t, 200, f.scim(t, scim, "GET", "/scim/v2/ServiceProviderConfig", "").Status)
	})

	t.Run("create, get, filter, patch and delete speak SCIM", func(t *testing.T) {
		created := f.scim(t, scim, "POST", "/scim/v2/Users",
			`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"zed@corp.example","externalId":"ext-zed","displayName":"Zed",`+
				`"active":true,"urn:ietf:params:scim:schemas:extension:newapi:2.0:Identity":{"oidcSub":"sub-zed"}}`)
		require.Equal(t, 201, created.Status, created.Raw)
		id, _ := created.Body["id"].(string)
		require.NotEmpty(t, id)
		assert.Equal(t, "zed@corp.example", created.Body["userName"])
		assert.Equal(t, true, created.Body["active"])
		assert.Equal(t, 200, f.scim(t, scim, "POST", "/scim/v2/Users",
			`{"userName":"zed@corp.example","externalId":"ext-zed","urn:ietf:params:scim:schemas:extension:newapi:2.0:Identity":{"oidcSub":"sub-zed"}}`).Status, "replay returns the same user")
		noSub := f.scim(t, scim, "POST", "/scim/v2/Users", `{"userName":"nosub@corp.example","externalId":"ext-nosub"}`)
		assert.Equal(t, 400, noSub.Status)
		assert.Equal(t, "invalidValue", noSub.Body["scimType"])
		conflict := f.scim(t, scim, "POST", "/scim/v2/Users",
			`{"userName":"zed2@corp.example","externalId":"ext-zed","urn:ietf:params:scim:schemas:extension:newapi:2.0:Identity":{"oidcSub":"sub-other"}}`)
		assert.Equal(t, 409, conflict.Status)
		assert.Equal(t, "uniqueness", conflict.Body["scimType"])

		list := f.scim(t, scim, "GET", "/scim/v2/Users?filter="+`userName%20eq%20%22zed@corp.example%22`, "")
		assert.EqualValues(t, 1, list.Body["totalResults"])
		assert.Equal(t, 400, f.scim(t, scim, "GET", "/scim/v2/Users?filter=active%20eq%20true", "").Status)
		assert.Equal(t, 400, f.scim(t, scim, "GET", "/scim/v2/Users?startIndex=x", "").Status)

		patched := f.scim(t, scim, "PATCH", "/scim/v2/Users/"+id,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
		assert.Equal(t, 200, patched.Status, patched.Raw)
		assert.Equal(t, false, patched.Body["active"])
		assert.Equal(t, 400, f.scim(t, scim, "PATCH", "/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","path":"roles","value":"owner"}]}`).Status)

		assert.Equal(t, 204, f.scim(t, scim, "DELETE", "/scim/v2/Users/"+id, "").Status)
		assert.Equal(t, 404, f.scim(t, scim, "GET", "/scim/v2/Users/"+id, "").Status)
		assert.Equal(t, 404, f.scim(t, scim, "DELETE", "/scim/v2/Users/"+id, "").Status)
		assert.Equal(t, 404, f.scim(t, scim, "GET", "/scim/v2/Users/abc", "").Status)
	})

	t.Run("groups: a mapping grants, an unmapped group does not, and the org role is out of reach", func(t *testing.T) {
		user := f.scim(t, scim, "POST", "/scim/v2/Users",
			`{"userName":"grp@corp.example","urn:ietf:params:scim:schemas:extension:newapi:2.0:Identity":{"oidcSub":"sub-grp"}}`)
		require.Equal(t, 201, user.Status, user.Raw)
		uid, _ := user.Body["id"].(string)
		group := f.scim(t, scim, "POST", "/scim/v2/Groups", `{"displayName":"devs","members":[{"value":"`+uid+`"}]}`)
		require.Equal(t, 201, group.Status, group.Raw)
		assert.Empty(t, group.Body["members"], "no mapping, no grant")
		gid, _ := group.Body["id"].(string)

		for _, role := range []string{"owner", "admin_org", "billing"} {
			assert.Equal(t, 400, f.do(t, a.owner, "POST", "/api/orgs/acme/scim/mappings", `{"idp_group":"devs","workspace_id":1,"ws_role":"`+role+`"}`).Status, role)
		}
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "POST", "/api/orgs/acme/scim/mappings", `{"idp_group":"devs","workspace_id":1,"ws_role":"member"}`).Status)
		mapped := f.do(t, a.owner, "POST", "/api/orgs/acme/scim/mappings", `{"idp_group":"devs","workspace_id":1,"ws_role":"member"}`)
		require.Equal(t, 200, mapped.Status, mapped.Raw)
		patch := f.scim(t, scim, "PATCH", "/scim/v2/Groups/"+gid,
			`{"Operations":[{"op":"add","path":"members","value":[{"value":"`+uid+`"}]}]}`)
		assert.Equal(t, 200, patch.Status, patch.Raw)
		members, _ := patch.Body["members"].([]any)
		assert.Len(t, members, 1)
		var role string
		require.NoError(t, f.db.Model(&model.WorkspaceMember{}).Where("workspace_id = 1 AND status = 1").Where("role = ?", types.WorkspaceRoleMember).Select("role").Limit(1).Scan(&role).Error)
		assert.Equal(t, types.WorkspaceRoleMember, role)
		assert.Equal(t, 204, f.scim(t, scim, "DELETE", "/scim/v2/Groups/"+gid, "").Status)
		assert.Equal(t, 404, f.scim(t, scim, "GET", "/scim/v2/Groups/"+gid, "").Status)
	})

	t.Run("every write is audited with the credential and the SCIM actor, never a secret", func(t *testing.T) {
		var rows []model.OrgAuditLog
		require.NoError(t, f.db.Where("org_id = ? AND action LIKE ? AND action NOT LIKE ?", a.org.Id, "scim.%", "scim.mapping_%").Find(&rows).Error)
		require.NotEmpty(t, rows)
		for _, row := range rows {
			assert.Equal(t, "scim", row.ActorKind, row.Action)
			assert.True(t, strings.HasPrefix(row.CredentialRef, "mk_"), row.Action)
			assert.NotContains(t, row.Detail+row.CredentialRef+row.TargetId, types.SCIMTokenPrefix, row.Action)
			assert.NotContains(t, row.Detail, scim, row.Action)
		}
		var mapping model.OrgAuditLog
		require.NoError(t, f.db.Where("org_id = ? AND action = ?", a.org.Id, "scim.mapping_save").First(&mapping).Error)
		assert.Equal(t, "user", mapping.ActorKind, "a mapping an owner saves in the console is a person's action")
		var human []model.OrgAuditLog
		require.NoError(t, f.db.Where("org_id = ? AND action = ?", a.org.Id, "management_key.create").Find(&human).Error)
		require.NotEmpty(t, human)
		for _, row := range human {
			assert.NotContains(t, row.Detail, "omk-")
			assert.NotContains(t, row.Detail, scim)
		}
	})

	t.Run("a suspended organization stops the credential; a revoked one is gone", func(t *testing.T) {
		require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", a.org.Id).Update("status", types.OrgStatusSuspended).Error)
		assert.Equal(t, 403, f.scim(t, scim, "GET", "/scim/v2/Users", "").Status)
		require.NoError(t, f.db.Model(&model.Organization{}).Where("id = ?", a.org.Id).Update("status", types.OrgStatusActive).Error)
		assert.Equal(t, 200, f.scim(t, scim, "GET", "/scim/v2/Users", "").Status)
		require.NoError(t, f.db.Model(&model.OrgAccessToken{}).Where("token_hash = ?", model.HashOrgAccessToken(scim)).Update("status", types.OrgAccessTokenRevoked).Error)
		assert.Equal(t, 401, f.scim(t, scim, "GET", "/scim/v2/Users", "").Status)
	})
}

func orgsvcUpdateSSO(t *testing.T, f *orgRoutesFixture, orgID int, issuer, clientID, secret string, on bool) (any, error) {
	t.Helper()
	owner := f.users["owner"]
	view, err := orgsvc.UpdateSSOConfig(context.Background(), owner.Id, orgID, orgsvc.SSOConfigInput{
		Issuer: &issuer, ClientID: &clientID, ClientSecret: &secret, Enabled: &on})
	return view, err
}

func mustIdentity(t *testing.T, bearer string) service.AuthIdentity {
	t.Helper()
	identity, err := service.ParseAccessToken(bearer)
	require.NoError(t, err)
	return identity
}

func mustBinding(t *testing.T, action string, orgID int, authScope, resource string) service.VerificationBinding {
	t.Helper()
	context, err := service.OrgSensitiveContextJSON(orgID, authScope, resource)
	require.NoError(t, err)
	binding, err := service.BindVerificationOperation(service.VerificationOperation{Scope: action, Context: context})
	require.NoError(t, err)
	return binding
}
