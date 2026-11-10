package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/oauth"
	"github.com/QuantumNous/new-api/service"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Organization SSO entry points (design section 8.1). They sit next to the
// platform OAuth handlers in oauth.go but share none of their state: a tenant
// IdP never joins the platform provider registry, signs in only into its own
// organization, and issues only org-restricted sessions.
//
// Browser flow: the SPA calls begin, redirects the browser to the returned
// authorization URL, and the IdP sends it to the console's /org-sso/callback
// page, which posts state, code and iss back to the matching callback endpoint.
// The page that initiated the flow is the only one holding the HttpOnly binding
// cookie, which is what ties the callback to this browser (ASVS 5.0.0 10.1.2).

const (
	orgSSOCallbackPath = "/org-sso/callback"

	orgSSOCookieLogin = "new_api_org_oidc_login"
	orgSSOCookieProof = "new_api_org_oidc_proof"
	orgSSOCookieLink  = "new_api_org_oidc_link"
)

// newOrgOIDCProvider builds the relying party of a stored tenant provider.
// Tests replace it with a provider over the fake IdP's client.
var newOrgOIDCProvider = service.GetOrgOIDCProvider

func orgSSOCallbackURL() string {
	return strings.TrimRight(system_setting.ServerAddress, "/") + orgSSOCallbackPath
}

func setOrgSSOCookie(c *gin.Context, name, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{Name: name, Value: value, Path: "/api", MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

// takeOrgSSOCookie reads and clears the binding cookie: it is single use
// whatever happens next.
func takeOrgSSOCookie(c *gin.Context, name string) string {
	value, _ := c.Cookie(name)
	setOrgSSOCookie(c, name, "", -1)
	return value
}

func orgSSOFail(c *gin.Context, status int, code, message string) {
	common.ApiErrorStatus(c, status, common.NewMessage(message), gin.H{"code": code})
}

// orgSSOError maps a relying-party failure to a fixed public answer. The
// cause (which can quote the IdP) goes to the operator log only.
func orgSSOError(c *gin.Context, orgID int, err error) {
	var failure *oauth.OrgOIDCError
	if errors.As(err, &failure) && failure.Cause != nil {
		common.SysLog(common.LogText("organization sso failure (org %d): %s: %v", orgID, failure.Kind, failure.Cause))
	}
	orgsvc.AuditSSOEvent(c.Request.Context(), orgID, 0, "sso.login_failed", map[string]any{"reason": oauth.OrgOIDCAuditCode(err)})
	switch {
	case errors.Is(err, oauth.ErrOrgOIDCFreshUnsupported):
		orgSSOFail(c, http.StatusForbidden, "SECURITY_FRESH_AUTH_UNSUPPORTED",
			"Your identity provider cannot confirm a recent sign-in. Sign in with your own account and repeat this action")
	case errors.Is(err, oauth.ErrOrgOIDCFreshStale):
		orgSSOFail(c, http.StatusForbidden, "SECURITY_FRESH_AUTH_STALE", "The sign-in is not recent enough. Try again")
	case errors.Is(err, oauth.ErrOrgOIDCFlowInvalid), errors.Is(err, oauth.ErrOrgOIDCFlowExpired), errors.Is(err, oauth.ErrOrgOIDCFlowReplayed),
		errors.Is(err, oauth.ErrOrgOIDCFlowMismatch), errors.Is(err, oauth.ErrOrgOIDCBindingMismatch):
		orgSSOFail(c, http.StatusBadRequest, "SSO_FLOW_INVALID", "The sign-in flow is invalid or has expired. Start again")
	case errors.Is(err, oauth.ErrOrgOIDCIdentityMismatch):
		orgSSOFail(c, http.StatusForbidden, "SSO_IDENTITY_MISMATCH", "The sign-in does not match your account in this organization")
	default:
		orgSSOFail(c, http.StatusUnauthorized, "SSO_FAILED", "Single sign-on failed")
	}
}

// orgSSOTarget resolves the organization and its enabled IdP for a public
// endpoint. Unknown, suspended or unconfigured all answer the same, so the
// endpoint does not reveal which organizations exist.
func orgSSOTarget(c *gin.Context) (*model.Organization, *model.CustomOAuthProvider, bool) {
	org, err := model.GetOrganizationByRef(model.DB, c.Param("org"))
	if err == nil && org.Status == types.OrgStatusActive {
		provider, perr := orgsvc.OrgSSOProvider(model.DB, org.Id)
		if perr == nil && provider.Enabled {
			return org, provider, true
		}
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		common.SysError(common.LogText("organization sso lookup failed: %v", err))
	}
	respondOrgError(c, types.NewOrgAccessError(types.OrgErrSSONotConfigured))
	return nil, nil, false
}

func orgOIDCFor(c *gin.Context, provider *model.CustomOAuthProvider) (*oauth.OrgOIDCProvider, bool) {
	oidcProvider, err := newOrgOIDCProvider(provider, orgSSOCallbackURL())
	if err != nil {
		common.SysLog(common.LogText("organization sso provider rejected (org %d): %v", provider.OrgId, err))
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrSSONotConfigured))
		return nil, false
	}
	return oidcProvider, true
}

type orgSSOCallbackBody struct {
	State  string `json:"state"`
	Code   string `json:"code"`
	Iss    string `json:"iss"`
	Error  string `json:"error"`
	Action string `json:"action"`
	// Parameters of the sensitive action, to recompute its resource.
	Kind         string   `json:"kind"`
	Scopes       []string `json:"scopes"`
	ExpiresAt    int64    `json:"expires_at"`
	CredentialID int      `json:"credential_id"`
	UserID       int      `json:"user_id"`
}

func decodeSSOBody(c *gin.Context) (orgSSOCallbackBody, bool) {
	var body orgSSOCallbackBody
	if err := common.DecodeJson(http.MaxBytesReader(c.Writer, c.Request.Body, orgBodyLimit), &body); err != nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return body, false
	}
	return body, true
}

func writeBegin(c *gin.Context, cookie string, begin *oauth.OrgOIDCBegin) {
	setOrgSSOCookie(c, cookie, begin.BrowserBinding, int(oauth.OrgOIDCFlowTTL.Seconds()))
	c.Header("Cache-Control", "no-store")
	common.ApiSuccess(c, gin.H{"authorization_url": begin.AuthorizationURL, "expires_at": begin.ExpiresAt.Unix()})
}

// OrgSSOBegin starts a sign-in to an organization through its IdP.
func OrgSSOBegin(c *gin.Context) {
	_, provider, ok := orgSSOTarget(c)
	if !ok {
		return
	}
	oidcProvider, ok := orgOIDCFor(c, provider)
	if !ok {
		return
	}
	begin, err := oidcProvider.Begin(c.Request.Context(), oauth.OrgOIDCBeginRequest{})
	if err != nil {
		orgSSOError(c, provider.OrgId, err)
		return
	}
	writeBegin(c, orgSSOCookieLogin, begin)
}

// OrgSSOCallback finishes the sign-in and issues an org-restricted session.
// The session is bound to this organization and provider for life: refresh
// rotation keeps the same row, and nothing here reads or creates a global
// session.
func OrgSSOCallback(c *gin.Context) {
	org, provider, ok := orgSSOTarget(c)
	if !ok {
		return
	}
	body, ok := decodeSSOBody(c)
	if !ok {
		return
	}
	binding := takeOrgSSOCookie(c, orgSSOCookieLogin)
	oidcProvider, ok := orgOIDCFor(c, provider)
	if !ok {
		return
	}
	identity, err := oidcProvider.Complete(c.Request.Context(), oauth.OrgOIDCCallback{State: body.State, Code: body.Code,
		Issuer: body.Iss, Error: body.Error, BrowserBinding: binding})
	if err != nil {
		orgSSOError(c, org.Id, err)
		return
	}
	result, err := orgsvc.ResolveSSOLogin(orgContext(c), org.Id, provider.Id, ssoClaims(identity))
	if err != nil {
		respondOrgError(c, err)
		return
	}
	bundle, err := service.CreateOrgLoginSession(result.UserID, service.OrgSessionScope{OrgID: org.Id, ProviderID: provider.Id},
		c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		writeAuthSessionError(c, err)
		return
	}
	service.WriteRefreshCookie(c, bundle.RefreshToken)
	orgsvc.AuditSSOEvent(orgContext(c), org.Id, result.UserID, "sso.login", map[string]any{"provider_id": provider.Id, "joined": result.Joined})
	c.Header("Cache-Control", "no-store")
	common.ApiSuccess(c, gin.H{
		"access_token": bundle.AccessToken, "token_type": bundle.TokenType, "access_expires_at": bundle.AccessExpiresAt,
		"session": bundle.Session, "organization": gin.H{"id": org.Id, "slug": org.Slug}, "joined": result.Joined,
	})
}

func ssoClaims(identity *oauth.OrgOIDCIdentity) orgsvc.SSOClaims {
	return orgsvc.SSOClaims{Issuer: identity.Issuer, Subject: identity.Subject, Email: identity.Email,
		EmailVerified: identity.EmailVerified, Name: identity.Name}
}

// sensitiveResource recomputes, from the request and the server's own state,
// the exact resource a sensitive proof is for.
func sensitiveResource(org *model.Organization, body orgSSOCallbackBody) (string, bool) {
	switch body.Action {
	case types.SensitiveManagementKeyCreate:
		return credentialGrantResource(body.Kind, body.Scopes, body.ExpiresAt), true
	case types.SensitiveManagementKeyRevoke:
		return credentialResource(body.CredentialID), body.CredentialID > 0
	case types.SensitiveOwnershipTransfer:
		return ownershipResource(body.UserID), body.UserID > 0
	case types.SensitiveOrgDelete:
		return orgDeleteResource(org.Slug), true
	case types.SensitiveSSOUpdate:
		return ssoResource(org.Id), true
	}
	return "", false
}

// sensitiveFlowContext is the server-side string the fresh ceremony carries.
// It is short because it travels through the flow store; the resource enters
// as a digest, and the callback recomputes both sides.
func sensitiveFlowContext(action string, orgID int, resource string) string {
	sum := sha256.Sum256([]byte(resource))
	return "proof|" + action + "|" + strconv.Itoa(orgID) + "|" + hex.EncodeToString(sum[:8])
}

type orgSessionStanding struct {
	identity service.AuthIdentity
	org      *model.Organization
	provider *model.CustomOAuthProvider
	subject  string
}

// orgSessionStandingFor proves the caller is an org-restricted session of this
// organization that still has an active identity at the session's provider.
func orgSessionStandingFor(c *gin.Context) (*orgSessionStanding, bool) {
	access, ok := requestedOrg(c)
	if !ok {
		return nil, false
	}
	identity, ok := middleware.GetSessionAuthIdentity(c)
	if !ok || middleware.SessionAuthScope(c) != types.AuthScopeOrg {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrSessionScope))
		return nil, false
	}
	session, err := model.GetUserSessionCached(identity.SessionID)
	if err != nil {
		writeAuthSessionError(c, err)
		return nil, false
	}
	orgIdentity, err := model.GetOrgIdentityByUser(model.DB, access.Org.Id, identity.UserID)
	if err != nil || orgIdentity.Status != types.OrgIdentityActive || orgIdentity.ProviderId != session.ProviderID {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrForbidden))
		return nil, false
	}
	provider, err := orgsvc.OrgSSOProvider(model.DB, access.Org.Id)
	if err != nil || !provider.Enabled || provider.Id != session.ProviderID {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrSSONotConfigured))
		return nil, false
	}
	return &orgSessionStanding{identity: identity, org: access.Org, provider: provider, subject: orgIdentity.Subject}, true
}

// OrgSensitiveBegin starts the fresh re-authentication an org-restricted
// session needs before one irreversible organization action. The ceremony is
// bound to this session, this person's subject and this exact action.
func OrgSensitiveBegin(c *gin.Context) {
	standing, ok := orgSessionStandingFor(c)
	if !ok {
		return
	}
	body, ok := decodeSSOBody(c)
	if !ok {
		return
	}
	resource, ok := sensitiveResource(standing.org, body)
	if !ok || !slicesContains(service.OrgSessionSensitiveScopes(), body.Action) {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	if _, err := service.RequireVerificationMethod(standing.identity, body.Action, service.VerificationMethodOrgOIDC); err != nil {
		writeSecurityOperationError(c, err)
		return
	}
	oidcProvider, ok := orgOIDCFor(c, standing.provider)
	if !ok {
		return
	}
	begin, err := oidcProvider.Begin(c.Request.Context(), oauth.OrgOIDCBeginRequest{Fresh: true, UserID: standing.identity.UserID,
		SessionID: standing.identity.SessionID, ExpectedSubject: standing.subject,
		Context: sensitiveFlowContext(body.Action, standing.org.Id, resource)})
	if err != nil {
		orgSSOError(c, standing.org.Id, err)
		return
	}
	writeBegin(c, orgSSOCookieProof, begin)
}

func slicesContains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// OrgSensitiveCallback completes the fresh ceremony and returns the proof. An
// IdP that does not report auth_time is answered with
// SECURITY_FRESH_AUTH_UNSUPPORTED: the action must then be started again from
// an independent global sign-in.
func OrgSensitiveCallback(c *gin.Context) {
	standing, ok := orgSessionStandingFor(c)
	if !ok {
		return
	}
	body, ok := decodeSSOBody(c)
	if !ok {
		return
	}
	resource, ok := sensitiveResource(standing.org, body)
	if !ok || !slicesContains(service.OrgSessionSensitiveScopes(), body.Action) {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	binding := takeOrgSSOCookie(c, orgSSOCookieProof)
	oidcProvider, ok := orgOIDCFor(c, standing.provider)
	if !ok {
		return
	}
	identity, err := oidcProvider.Complete(c.Request.Context(), oauth.OrgOIDCCallback{State: body.State, Code: body.Code,
		Issuer: body.Iss, Error: body.Error, BrowserBinding: binding,
		UserID: standing.identity.UserID, SessionID: standing.identity.SessionID})
	if err != nil {
		orgSSOError(c, standing.org.Id, err)
		return
	}
	if !identity.Fresh || identity.Subject != standing.subject || identity.Context != sensitiveFlowContext(body.Action, standing.org.Id, resource) {
		orgSSOError(c, standing.org.Id, oauth.ErrOrgOIDCFlowMismatch)
		return
	}
	context, err := service.OrgSensitiveContextJSON(standing.org.Id, types.AuthScopeOrg, resource)
	if err != nil {
		writeSecurityOperationError(c, err)
		return
	}
	proof, err := service.CompleteOrgFreshVerification(standing.identity, service.VerificationOperation{Scope: body.Action, Context: context})
	if err != nil {
		writeSecurityOperationError(c, err)
		return
	}
	orgsvc.AuditSSOEvent(orgContext(c), standing.org.Id, standing.identity.UserID, "sso.proof_issued", map[string]any{"action": body.Action})
	c.Header("Cache-Control", "no-store")
	common.ApiSuccess(c, proof)
}

func linkFlowContext(orgID, providerID int) string {
	return "link|" + strconv.Itoa(orgID) + "|" + strconv.Itoa(providerID)
}

func linkResource(orgID int) string { return ssoResource(orgID) }

// OrgLinkBegin starts linking the signed-in GLOBAL account to the caller's
// identity at an organization's IdP. The global account is proven first, by a
// single-use proof of this action (password, 2FA or passkey of that account);
// the organization identity is proven second, by the fresh ceremony begun here.
// An org-restricted session never reaches this route.
func OrgLinkBegin(c *gin.Context) {
	org, provider, ok := orgSSOTarget(c)
	if !ok {
		return
	}
	identity, ok := middleware.GetSessionAuthIdentity(c)
	if !ok || middleware.SessionAuthScope(c) != types.AuthScopeGlobal {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrSessionScope))
		return
	}
	oidcProvider, ok := orgOIDCFor(c, provider)
	if !ok {
		return
	}
	if !requireSensitive(c, types.SensitiveIdentityLink, org.Id, linkResource(org.Id)) {
		return
	}
	begin, err := oidcProvider.Begin(c.Request.Context(), oauth.OrgOIDCBeginRequest{Fresh: true, UserID: identity.UserID,
		SessionID: identity.SessionID, Context: linkFlowContext(org.Id, provider.Id)})
	if err != nil {
		orgSSOError(c, org.Id, err)
		return
	}
	writeBegin(c, orgSSOCookieLink, begin)
}

// OrgLinkCallback completes the link. Only the identity of the ceremony and the
// global account of this session are used; no email is compared.
func OrgLinkCallback(c *gin.Context) {
	org, provider, ok := orgSSOTarget(c)
	if !ok {
		return
	}
	identity, ok := middleware.GetSessionAuthIdentity(c)
	if !ok || middleware.SessionAuthScope(c) != types.AuthScopeGlobal {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrSessionScope))
		return
	}
	body, ok := decodeSSOBody(c)
	if !ok {
		return
	}
	binding := takeOrgSSOCookie(c, orgSSOCookieLink)
	oidcProvider, ok := orgOIDCFor(c, provider)
	if !ok {
		return
	}
	proven, err := oidcProvider.Complete(c.Request.Context(), oauth.OrgOIDCCallback{State: body.State, Code: body.Code,
		Issuer: body.Iss, Error: body.Error, BrowserBinding: binding, UserID: identity.UserID, SessionID: identity.SessionID})
	if err != nil {
		orgSSOError(c, org.Id, err)
		return
	}
	if !proven.Fresh || proven.Context != linkFlowContext(org.Id, provider.Id) {
		orgSSOError(c, org.Id, oauth.ErrOrgOIDCFlowMismatch)
		return
	}
	result, err := orgsvc.LinkGlobalAccount(orgContext(c), identity.UserID, org.Id, provider.Id, ssoClaims(proven))
	if err != nil {
		orgsvc.AuditSSOEvent(orgContext(c), org.Id, identity.UserID, "identity.link_failed", map[string]any{"reason": linkDenial(err)})
		respondOrgError(c, err)
		return
	}
	orgsvc.PublishLinkResult(result, org.Id)
	// Linking never upgrades or converts this session: signing in to the
	// organization is a separate, org-restricted sign-in.
	common.ApiSuccess(c, gin.H{"joined": result.Joined, "replaced": result.Replaced})
}

func linkDenial(err error) string {
	var access *types.OrgAccessError
	if errors.As(err, &access) {
		return access.Code
	}
	return "unavailable"
}
