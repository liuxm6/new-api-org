package controller

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

func defaultAuthTime(now time.Time) *time.Time { v := now.Add(-time.Minute); return &v }

// admin signs a new person in through the IdP, promotes them to administrator
// and returns their org-restricted access token.
func (f *orgFlow) admin(sub string) (token string, userID int) {
	f.t.Helper()
	f.setIdentity(sub, sub+"@corp.example", true, defaultAuthTime)
	token = f.loginToken()
	userID = f.identityOf(sub).UserId
	require.NoError(f.t, orgsvc.ChangeMemberRole(context.Background(), f.owner.Id, f.org.Id, userID, types.OrgRoleAdmin))
	return token, userID
}

func (f *orgFlow) global(name, email string) (model.User, string) {
	f.t.Helper()
	user := model.User{Username: name, Password: "password-123", Role: common.RoleCommonUser, Status: common.UserStatusEnabled,
		Group: "default", AffCode: "aff-" + name, Email: email, AuthVersion: 1}
	require.NoError(f.t, f.db.Create(&user).Error)
	return user, f.globalSession(user)
}

func TestOrgOIDCSessionScope(t *testing.T) {
	f := setupOrgFlow(t)
	ctx := context.Background()
	f.setIdentity("sub-sam", "sam@corp.example", true, defaultAuthTime)
	token := f.loginToken()
	identity, err := service.ParseAccessToken(token)
	require.NoError(t, err)
	sam := f.identityOf("sub-sam")
	require.NoError(t, f.db.Create(&model.Organization{Slug: "globex", Name: "Globex", OwnerUserId: f.owner.Id, BillingUserId: 999, Status: types.OrgStatusActive, PolicyVersion: 1}).Error)

	t.Run("the issued session carries the scope and nothing wider", func(t *testing.T) {
		session, err := model.GetUserSessionCached(identity.SessionID)
		require.NoError(t, err)
		assert.Equal(t, types.AuthScopeOrg, session.EffectiveAuthScope())
		assert.Equal(t, f.org.Id, session.OrgID)
		assert.Equal(t, f.provider.Id, session.ProviderID)
		assert.Equal(t, 200, f.do(token, "GET", "/api/orgs/acme", "").Status)
	})

	t.Run("it refuses personal, other-organization and platform routes", func(t *testing.T) {
		self := f.do(token, "GET", "/api/user/self", "")
		assert.Equal(t, 403, self.Status)
		assert.Equal(t, types.OrgErrSessionScope, self.code())
		other := f.do(token, "GET", "/api/orgs/globex", "")
		assert.Equal(t, 404, other.Status, "another organization does not exist for this session")
		link := f.do(token, "POST", "/api/org-sso/acme/link/begin", "{}")
		assert.Equal(t, 403, link.Status)
		assert.Equal(t, types.OrgErrSessionScope, link.code(), "linking a global account is for a global session only")
	})

	t.Run("refresh rotates the credential and keeps the session's scope", func(t *testing.T) {
		refresh := f.jar[service.RefreshCookieName]
		require.NotEmpty(t, refresh)
		reply := f.do("", "POST", "/api/user/auth/refresh", "")
		require.Equal(t, 200, reply.Status, reply.Raw)
		next, _ := reply.data()["access_token"].(string)
		require.NotEmpty(t, next)
		assert.NotEqual(t, refresh, f.jar[service.RefreshCookieName], "the refresh credential rotated")
		refreshed, err := service.ParseAccessToken(next)
		require.NoError(t, err)
		assert.Equal(t, identity.SessionID, refreshed.SessionID, "same session row")
		session, err := model.GetUserSessionCached(refreshed.SessionID)
		require.NoError(t, err)
		assert.Equal(t, types.AuthScopeOrg, session.EffectiveAuthScope())
		assert.Equal(t, f.org.Id, session.OrgID)
		assert.Equal(t, 200, f.do(next, "GET", "/api/orgs/acme", "").Status)
		assert.Equal(t, types.OrgErrSessionScope, f.do(next, "GET", "/api/user/self", "").code(), "refresh did not widen it")
		token = next
	})

	t.Run("a different person's global session on the same user id is unaffected", func(t *testing.T) {
		_, global := f.global("globaluser", "global@corp.example")
		assert.Equal(t, 200, f.do(global, "GET", "/api/user/self", "").Status)
		assert.Equal(t, 404, f.do(global, "GET", "/api/orgs/acme", "").Status, "a non-member has no org")
	})

	t.Run("losing the membership ends the session at the next request and the next refresh", func(t *testing.T) {
		assert.Equal(t, 200, f.do(token, "GET", "/api/orgs/acme", "").Status)
		// Bypass the revocation hook to prove the refresh check by itself.
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", f.org.Id, sam.UserId).
			Update("status", types.OrgMemberStatusSuspended).Error)
		orgsvc.ResetAccessCache()
		suspended := f.do(token, "GET", "/api/orgs/acme", "")
		assert.Equal(t, 403, suspended.Status)
		assert.Equal(t, types.OrgErrMemberSuspended, suspended.code())
		refresh := f.do("", "POST", "/api/user/auth/refresh", "")
		assert.Equal(t, 401, refresh.Status, "no new access token from a person who lost their standing")
		assert.Equal(t, "AUTH_SESSION_REVOKED", refresh.code())
		session, err := model.GetUserSessionCached(identity.SessionID)
		if err == nil {
			assert.NotEqual(t, model.UserSessionStatusActive, session.Status)
		}
	})

	t.Run("the service paths end org sessions too", func(t *testing.T) {
		require.NoError(t, f.db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", f.org.Id, sam.UserId).
			Update("status", types.OrgMemberStatusActive).Error)
		orgsvc.ResetAccessCache()
		f.jar = map[string]string{}
		again := f.loginToken()
		againIdentity, _ := service.ParseAccessToken(again)
		require.NoError(t, orgsvc.SetMemberStatus(ctx, f.owner.Id, f.org.Id, sam.UserId, types.OrgMemberStatusSuspended))
		session, err := model.GetUserSessionCached(againIdentity.SessionID)
		require.Error(t, err, "the session is already revoked: %v", session)
		assert.Equal(t, 401, f.do(again, "GET", "/api/orgs/acme", "").Status)
		require.NoError(t, orgsvc.SetMemberStatus(ctx, f.owner.Id, f.org.Id, sam.UserId, types.OrgMemberStatusActive))
	})

	t.Run("a deprovisioned identity cannot sign in or refresh", func(t *testing.T) {
		f.jar = map[string]string{}
		live := f.loginToken()
		off := false
		_, err := orgsvc.PatchScimUser(ctx, f.org.Id, sam.Id, orgsvc.ScimUserChanges{Active: &off})
		require.NoError(t, err)
		assert.Equal(t, 401, f.do(live, "GET", "/api/orgs/acme", "").Status, "the SCIM deactivation revoked the session")
		denied := f.login()
		assert.Equal(t, 403, denied.Status)
		assert.Equal(t, types.OrgErrIdentityDisabled, denied.code())
	})

	t.Run("org verification offers only org.* operations by org_oidc", func(t *testing.T) {
		f.jar = map[string]string{}
		on := true
		_, err := orgsvc.PatchScimUser(ctx, f.org.Id, sam.Id, orgsvc.ScimUserChanges{Active: &on})
		require.NoError(t, err)
		fresh := f.loginToken()
		freshIdentity, _ := service.ParseAccessToken(fresh)
		for _, scope := range []string{service.VerificationScopeChannelKeyRead, service.VerificationScopeAccountDelete, service.VerificationScopePasswordChange,
			service.VerificationScopeAccessTokenGenerate, service.VerificationScopeAdminUserDelete, service.VerificationScopeTwoFADisable,
			service.VerificationScopePasskeyRegister, types.SensitiveIdentityLink, "billing.transfer_personal_funds"} {
			_, err := service.GetVerificationRequirements(freshIdentity, scope)
			assert.Error(t, err, "%s must not be verifiable from an org session", scope)
			_, err = service.RequireVerificationMethod(freshIdentity, scope, service.VerificationMethodPassword)
			assert.Error(t, err, scope)
		}
		for _, scope := range service.OrgSessionSensitiveScopes() {
			requirements, err := service.GetVerificationRequirements(freshIdentity, scope)
			require.NoError(t, err, scope)
			require.Len(t, requirements.Methods, 1)
			assert.Equal(t, service.VerificationMethodOrgOIDC, requirements.Methods[0].Method)
		}
	})
}

func TestOrgSensitiveOperationProof(t *testing.T) {
	f := setupOrgFlow(t)
	token, adminID := f.admin("sub-ivy")
	identity, err := service.ParseAccessToken(token)
	require.NoError(t, err)
	expires := time.Now().Add(24 * time.Hour).Unix()
	grant := map[string]any{"action": types.SensitiveManagementKeyCreate, "kind": "personal_management", "scopes": []string{"members:read"}, "expires_at": expires}
	create := `{"name":"ci","kind":"personal_management","scopes":["members:read"],"expires_at":` + strconv.FormatInt(expires, 10) + `}`
	createWith := func(proof string) flowReply {
		return f.do(token, "POST", "/api/orgs/acme/management-keys", create, "X-Security-Proof", proof)
	}
	// begin starts the fresh ceremony for the grant; the callback body carries
	// the same parameters, which the server recomputes.
	begin := func(body map[string]any) flowReply {
		encoded, _ := common.Marshal(body)
		return f.do(token, "POST", "/api/orgs/acme/sensitive/begin", string(encoded))
	}
	callback := func(started flowReply, body map[string]any) flowReply {
		encoded, _ := common.Marshal(body)
		return f.do(token, "POST", "/api/orgs/acme/sensitive/callback", mergeBody(t, f.authorize(started, nil), string(encoded)))
	}
	proofFor := func(body map[string]any) string {
		reply := callback(begin(body), body)
		require.Equal(t, 200, reply.Status, reply.Raw)
		proof, _ := reply.data()["proof_token"].(string)
		require.NotEmpty(t, proof)
		return proof
	}

	t.Run("no proof, no credential", func(t *testing.T) {
		reply := f.do(token, "POST", "/api/orgs/acme/management-keys", create)
		assert.Equal(t, 403, reply.Status)
		assert.Equal(t, "SECURITY_PROOF_REQUIRED", reply.code())
	})

	t.Run("fresh IdP authentication yields a proof that works exactly once", func(t *testing.T) {
		proof := proofFor(grant)
		first := createWith(proof)
		require.Equal(t, 200, first.Status, first.Raw)
		assert.NotEmpty(t, first.data()["token"])
		replay := createWith(proof)
		assert.Equal(t, 403, replay.Status)
		assert.Equal(t, "SECURITY_PROOF_CONSUMED", replay.code())
		var stored model.OrgAccessToken
		require.NoError(t, f.db.Where("org_id = ?", f.org.Id).Order("id DESC").First(&stored).Error)
		assert.Equal(t, adminID, stored.CreatedBy)
		assert.Equal(t, types.OrgAccessTokenPersonalManagement, stored.Kind)
	})

	t.Run("the proof is bound to the exact grant and the exact action", func(t *testing.T) {
		narrow := proofFor(grant)
		wide := strings.Replace(create, `"members:read"`, `"members:read","members:write"`, 1)
		reply := f.do(token, "POST", "/api/orgs/acme/management-keys", wide, "X-Security-Proof", narrow)
		assert.Equal(t, "SECURITY_PROOF_CONTEXT_MISMATCH", reply.code(), "a proof for fewer scopes does not authorize more")
		revoke := f.do(token, "DELETE", "/api/orgs/acme/management-keys/1", "", "X-Security-Proof", proofFor(grant))
		assert.Equal(t, "SECURITY_PROOF_SCOPE_MISMATCH", revoke.code(), "a create proof does not revoke")
	})

	t.Run("it is bound to the session", func(t *testing.T) {
		proof := proofFor(grant)
		f.jar = map[string]string{}
		otherToken := f.loginToken()
		require.NotEqual(t, token, otherToken)
		reply := f.do(otherToken, "POST", "/api/orgs/acme/management-keys", create, "X-Security-Proof", proof)
		assert.Equal(t, 403, reply.Status)
		assert.Equal(t, "SECURITY_PROOF_INVALID", reply.code(), "another session of the same person cannot spend it")
		assert.Equal(t, 200, createWith(proof).Status, "the session it was issued to still can")
	})

	t.Run("it expires", func(t *testing.T) {
		proof := proofFor(grant)
		require.NoError(t, f.db.Model(&model.AuthFlow{}).Where("purpose = ? AND consumed_at IS NULL", model.AuthFlowPurposeSecurityProof).
			Update("expires_at", time.Now().Add(-time.Second)).Error)
		reply := createWith(proof)
		assert.Equal(t, 403, reply.Status)
		assert.Equal(t, "SECURITY_PROOF_EXPIRED", reply.code())
	})

	t.Run("only the allowlisted operations can be started from an org session", func(t *testing.T) {
		for _, action := range []string{types.SensitiveIdentityLink, service.VerificationScopeAccountDelete, service.VerificationScopeChannelKeyRead, "", "org.billing.transfer"} {
			reply := begin(map[string]any{"action": action})
			assert.Equal(t, 400, reply.Status, action)
		}
		assert.Equal(t, 200, begin(map[string]any{"action": types.SensitiveSSOUpdate}).Status)
		delete(f.jar, "new_api_org_oidc_proof")
	})

	t.Run("the callback must repeat the same action", func(t *testing.T) {
		started := begin(grant)
		swapped := map[string]any{"action": types.SensitiveManagementKeyCreate, "kind": "personal_management", "scopes": []string{"members:read", "keys:write"}, "expires_at": expires}
		reply := callback(started, swapped)
		assert.Equal(t, 400, reply.Status, reply.Raw)
		assert.Equal(t, "SSO_FLOW_INVALID", reply.code())
	})

	t.Run("a stale or unreported sign-in is not fresh", func(t *testing.T) {
		f.setIdentity("sub-ivy", "sub-ivy@corp.example", true, func(now time.Time) *time.Time { v := now.Add(-20 * time.Minute); return &v })
		stale := callback(begin(grant), grant)
		assert.Equal(t, 403, stale.Status)
		assert.Equal(t, "SECURITY_FRESH_AUTH_STALE", stale.code())
		f.setIdentity("sub-ivy", "sub-ivy@corp.example", true, func(time.Time) *time.Time { return nil })
		unsupported := callback(begin(grant), grant)
		assert.Equal(t, 403, unsupported.Status)
		assert.Equal(t, "SECURITY_FRESH_AUTH_UNSUPPORTED", unsupported.code(),
			"an IdP that cannot say when the user signed in cannot approve this; the person starts again from a separate global sign-in")
		f.setIdentity("sub-ivy", "sub-ivy@corp.example", true, defaultAuthTime)
	})

	t.Run("another person at the IdP cannot approve for this session", func(t *testing.T) {
		started := begin(grant)
		f.setIdentity("sub-someone-else", "else@corp.example", true, defaultAuthTime)
		reply := callback(started, grant)
		assert.Equal(t, 403, reply.Status)
		assert.Equal(t, "SSO_IDENTITY_MISMATCH", reply.code())
		f.setIdentity("sub-ivy", "sub-ivy@corp.example", true, defaultAuthTime)
	})

	t.Run("a global session cannot use an org_oidc proof, and an org proof does not cross scopes", func(t *testing.T) {
		proof := proofFor(grant)
		global := f.globalSession(f.owner)
		globalIdentity, _ := service.ParseAccessToken(global)
		_, err := service.RequireVerificationMethod(globalIdentity, types.SensitiveOrgDelete, service.VerificationMethodOrgOIDC)
		assert.Error(t, err, "org_oidc is not a global method")
		for _, scope := range []string{service.VerificationScopeAccountDelete, service.VerificationScopePasswordChange, service.VerificationScopeAccessTokenGenerate} {
			operation := service.VerificationOperation{Scope: scope}
			if scope == service.VerificationScopeAccessTokenGenerate {
				operation.Context = []byte(`{"scopes":["a"],"expires_at":0}`)
			}
			_, err := service.ConsumeOperationProof(proof, identity, operation)
			assert.Error(t, err, "an org proof cannot authorize %s", scope)
		}
		assert.Equal(t, 200, createWith(proof).Status, "none of that spent it")
	})

	t.Run("audit rows and responses hold no proof, code, state or cookie", func(t *testing.T) {
		var rows []model.OrgAuditLog
		require.NoError(t, f.db.Where("org_id = ?", f.org.Id).Find(&rows).Error)
		require.NotEmpty(t, rows)
		var created []model.OrgAccessToken
		require.NoError(t, f.db.Where("org_id = ?", f.org.Id).Find(&created).Error)
		for _, row := range rows {
			for _, secret := range []string{orgSSOSecret, orgSSOAccessToken, "code-", "proof_token", "omk-", "Bearer"} {
				assert.NotContains(t, row.Detail, secret, row.Action)
			}
			assert.NotContains(t, row.CredentialRef+row.TargetId, "omk-")
		}
		for _, token := range created {
			assert.NotContains(t, token.TokenHash, "omk-")
		}
	})
}

// mergeBody overlays the parameters of the action onto the IdP's callback body.
func mergeBody(t *testing.T, idpBody, actionBody string) string {
	t.Helper()
	merged := map[string]any{}
	require.NoError(t, common.Unmarshal([]byte(idpBody), &merged))
	extra := map[string]any{}
	require.NoError(t, common.Unmarshal([]byte(actionBody), &extra))
	for key, value := range extra {
		merged[key] = value
	}
	encoded, err := common.Marshal(merged)
	require.NoError(t, err)
	return string(encoded)
}

func TestOrgGlobalIdentityLink(t *testing.T) {
	f := setupOrgFlow(t)
	ctx := context.Background()
	gina, ginaToken := f.global("gina", "gina@home.example")
	linkProof := func(bearer string) string {
		identity, err := service.ParseAccessToken(bearer)
		require.NoError(t, err)
		context, err := service.OrgSensitiveContextJSON(f.org.Id, types.AuthScopeGlobal, "sso:"+strconv.Itoa(f.org.Id))
		require.NoError(t, err)
		binding, err := service.BindVerificationOperation(service.VerificationOperation{Scope: types.SensitiveIdentityLink, Context: context})
		require.NoError(t, err)
		proof, err := service.CompleteSecurityVerification(identity, binding, service.VerificationMethodPassword)
		require.NoError(t, err)
		return proof.ProofToken
	}
	startLink := func(bearer string) flowReply {
		return f.do(bearer, "POST", "/api/org-sso/acme/link/begin", "{}", "X-Security-Proof", linkProof(bearer))
	}
	finish := func(bearer string, started flowReply) flowReply {
		return f.do(bearer, "POST", "/api/org-sso/acme/link/callback", f.authorize(started, nil))
	}
	membership := func(userID int) *model.OrganizationMember {
		member, err := model.GetOrganizationMember(f.db, f.org.Id, userID)
		if err != nil {
			return nil
		}
		return member
	}

	// The IdP person has already been in the organization as a placeholder.
	f.setIdentity("sub-gina", "gina@corp.example", true, defaultAuthTime)
	require.Equal(t, 200, f.login().Status)
	placeholder := f.identityOf("sub-gina").UserId

	t.Run("both proofs are required: the global account and the organization identity", func(t *testing.T) {
		noProof := f.do(ginaToken, "POST", "/api/org-sso/acme/link/begin", "{}")
		assert.Equal(t, 403, noProof.Status)
		assert.Equal(t, "SECURITY_PROOF_REQUIRED", noProof.code(), "the global account's own verification comes first")
		anonymous := f.do("", "POST", "/api/org-sso/acme/link/begin", "{}", "X-Security-Proof", "x")
		assert.Equal(t, 401, anonymous.Status)

		stale := f.do(ginaToken, "POST", "/api/org-sso/acme/link/begin", "{}", "X-Security-Proof", linkProof(ginaToken))
		require.Equal(t, 200, stale.Status, stale.Raw)
		f.setIdentity("sub-gina", "gina@corp.example", true, func(time.Time) *time.Time { return nil })
		unsupported := finish(ginaToken, stale)
		assert.Equal(t, 403, unsupported.Status)
		assert.Equal(t, "SECURITY_FRESH_AUTH_UNSUPPORTED", unsupported.code())
		f.setIdentity("sub-gina", "gina@corp.example", true, defaultAuthTime)
		assert.NotNil(t, membership(placeholder), "nothing changed")
		assert.Nil(t, membership(gina.Id))
	})

	t.Run("an org session or another global session cannot complete a link", func(t *testing.T) {
		orgToken := f.loginToken()
		assert.Equal(t, types.OrgErrSessionScope, f.do(orgToken, "POST", "/api/org-sso/acme/link/callback", "{}").code())
		started := startLink(ginaToken)
		require.Equal(t, 200, started.Status, started.Raw)
		_, otherSession := f.global("gina-twin", "twin@home.example")
		body := f.authorize(started, nil)
		cookie := f.jar["new_api_org_oidc_link"]
		hijack := f.do(otherSession, "POST", "/api/org-sso/acme/link/callback", body)
		assert.Equal(t, 400, hijack.Status, "the ceremony belongs to the session that started it")
		f.jar["new_api_org_oidc_link"] = cookie
		assert.Equal(t, 200, f.do(ginaToken, "POST", "/api/org-sso/acme/link/callback", body).Status, "and that session can still finish it")
		assert.Equal(t, types.OrgMemberStatusRemoved, membership(placeholder).Status, "linked: the placeholder left")
	})

	t.Run("the global account replaced the empty placeholder", func(t *testing.T) {
		member := membership(gina.Id)
		require.NotNil(t, member)
		assert.Equal(t, types.OrgMemberStatusActive, member.Status)
		assert.Equal(t, types.OrgRoleMember, member.Role)
		identity := f.identityOf("sub-gina")
		assert.Equal(t, gina.Id, identity.UserId)
		assert.NotZero(t, identity.GlobalLinkVerifiedAt)
		var old model.User
		require.NoError(t, f.db.First(&old, placeholder).Error)
		assert.Equal(t, common.UserStatusDisabled, old.Status, "the emptied placeholder is shut off")
		var reloaded model.User
		require.NoError(t, f.db.First(&reloaded, gina.Id).Error)
		assert.Equal(t, "gina@home.example", reloaded.Email, "the claim email did not touch the global account")
		ws, err := model.GetWorkspaceMember(f.db, 1, gina.Id)
		require.NoError(t, err)
		assert.Equal(t, types.WorkspaceRoleMember, ws.Role, "workspace access moved with the person")
		require.Len(t, f.audit("identity.link"), 1)
		var sessions int64
		f.db.Model(&model.UserSession{}).Where("user_id = ? AND auth_scope = ? AND status = ?", placeholder, types.AuthScopeOrg, model.UserSessionStatusActive).Count(&sessions)
		assert.Zero(t, sessions, "the placeholder's org sessions ended")
		assert.Equal(t, 200, f.do(ginaToken, "GET", "/api/user/self", "").Status, "the global session is still global")
		assert.Equal(t, 200, f.do(ginaToken, "GET", "/api/orgs/acme", "").Status, "a global session of a member reads the organization as before")
	})

	t.Run("a replayed callback does nothing", func(t *testing.T) {
		started := startLink(ginaToken)
		body := f.authorize(started, nil)
		require.Equal(t, 200, f.do(ginaToken, "POST", "/api/org-sso/acme/link/callback", body).Status)
		replay := f.do(ginaToken, "POST", "/api/org-sso/acme/link/callback", body)
		assert.Equal(t, 400, replay.Status)
	})

	t.Run("business facts, another standing and a missing JIT gate are 409s or refusals", func(t *testing.T) {
		// A placeholder that already spent: keys block the swap.
		f.setIdentity("sub-hal", "hal@corp.example", true, defaultAuthTime)
		require.Equal(t, 200, f.login().Status)
		hal := f.identityOf("sub-hal").UserId
		require.NoError(t, f.db.Create(&model.Token{UserId: f.org.BillingUserId, Key: "hal-key-0123456789", Name: "hal", Status: common.TokenStatusEnabled,
			ExpiredTime: -1, UnlimitedQuota: true, OrgId: f.org.Id, WorkspaceId: 1, CreatedBy: hal, OwnerType: types.TokenOwnerMember, AccessPrincipalId: "prn-hal"}).Error)
		ida, idaToken := f.global("ida", "ida@home.example")
		started := startLink(idaToken)
		require.Equal(t, 200, started.Status, started.Raw)
		conflict := finish(idaToken, started)
		assert.Equal(t, 409, conflict.Status, conflict.Raw)
		assert.Equal(t, types.OrgErrConflict, conflict.code())
		assert.NotNil(t, membership(hal), "both principals are kept")
		assert.Equal(t, types.OrgMemberStatusActive, membership(hal).Status)
		assert.Nil(t, membership(ida.Id))
		var halUser model.User
		require.NoError(t, f.db.First(&halUser, hal).Error)
		assert.Equal(t, common.UserStatusEnabled, halUser.Status, "the placeholder with history is untouched")

		// An account that is already a member through another path.
		f.setIdentity("sub-jo", "jo@corp.example", true, defaultAuthTime)
		jo, joToken := f.global("jo", "jo@home.example")
		require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: f.org.Id, UserId: jo.Id, Role: types.OrgRoleMember,
			Status: types.OrgMemberStatusActive, Source: types.OrgMemberSourceManual}).Error)
		already := finish(joToken, startLink(joToken))
		assert.Equal(t, 409, already.Status, "no second identity merges into an existing member silently")

		// An unknown identity needs the same gates as signing in: JIT and a verified email.
		kim, kimToken := f.global("kim", "kim@home.example")
		f.setIdentity("sub-kim", "kim@corp.example", false, defaultAuthTime)
		unverified := finish(kimToken, startLink(kimToken))
		assert.Equal(t, 403, unverified.Status)
		assert.Equal(t, types.OrgErrEmailNotVerified, unverified.code())
		off := false
		_, err := orgsvc.UpdateSSOConfig(ctx, f.owner.Id, f.org.Id, orgsvc.SSOConfigInput{JITEnabled: &off})
		require.NoError(t, err)
		f.setIdentity("sub-kim", "kim@corp.example", true, defaultAuthTime)
		assert.Equal(t, types.OrgErrJITDisabled, finish(kimToken, startLink(kimToken)).code())
		assert.Nil(t, membership(kim.Id))
		on := true
		_, err = orgsvc.UpdateSSOConfig(ctx, f.owner.Id, f.org.Id, orgsvc.SSOConfigInput{JITEnabled: &on})
		require.NoError(t, err)
		joined := finish(kimToken, startLink(kimToken))
		assert.Equal(t, 200, joined.Status, joined.Raw)
		assert.Equal(t, true, joined.data()["joined"])
		assert.Equal(t, false, joined.data()["replaced"])
		assert.Equal(t, kim.Id, f.identityOf("sub-kim").UserId)
	})

	t.Run("an identity that is already linked elsewhere cannot be taken by a second account", func(t *testing.T) {
		f.setIdentity("sub-gina", "gina@corp.example", true, defaultAuthTime)
		_, thiefToken := f.global("thief", "thief@home.example")
		reply := finish(thiefToken, startLink(thiefToken))
		assert.Equal(t, 409, reply.Status, "gina's real account is the active member of that identity")
		assert.Equal(t, gina.Id, f.identityOf("sub-gina").UserId)
	})
}
