package service

import (
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
)

// Sensitive organization operations (design section 7) reuse the proof
// machinery of security_verification.go: a signed proof token backed by a
// single-use auth flow bound to the session, with a one-minute lifetime. What
// they add is the context: the organization, the session's auth scope and the
// exact resource, so a proof for one action cannot authorize another, cannot
// be replayed on another organization or resource, and cannot cross between a
// global session and an organization-restricted one.

// VerificationMethodOrgOIDC is a fresh re-authentication at the organization's
// own IdP. It is offered only to org-restricted sessions.
const VerificationMethodOrgOIDC = "org_oidc"

const orgSensitivePrefix = "org."

// OrgSensitiveContext is the normalized context of every org.* scope.
type OrgSensitiveContext struct {
	OrgID     int    `json:"org_id"`
	AuthScope string `json:"auth_scope"`
	Resource  string `json:"resource"`
}

// IsOrgSensitiveScope reports whether scope is one of the org.* operations.
func IsOrgSensitiveScope(scope string) bool { return strings.HasPrefix(scope, orgSensitivePrefix) }

// OrgSessionSensitiveScopes are the operations an org-restricted session may
// prove. Linking a global account needs the global account's own session, so it
// is not among them, and neither is anything that moves personal funds or
// changes a global account: those scopes do not start with org. at all.
func OrgSessionSensitiveScopes() []string {
	return []string{types.SensitiveManagementKeyCreate, types.SensitiveManagementKeyRevoke, types.SensitiveOwnershipTransfer,
		types.SensitiveOrgDelete, types.SensitiveSSOUpdate}
}

func isOrgSessionSensitiveScope(scope string) bool {
	for _, allowed := range OrgSessionSensitiveScopes() {
		if allowed == scope {
			return true
		}
	}
	return false
}

func normalizeOrgSensitiveContext(fields map[string]common.RawMessage, raw []byte) (OrgSensitiveContext, bool) {
	var context OrgSensitiveContext
	if len(fields) != 3 || common.Unmarshal(raw, &context) != nil || context.OrgID <= 0 ||
		(context.AuthScope != types.AuthScopeGlobal && context.AuthScope != types.AuthScopeOrg) ||
		context.Resource == "" || len(context.Resource) > 256 || strings.ContainsAny(context.Resource, "\x00\r\n") {
		return context, false
	}
	return context, true
}

// sessionAuthScope reads the persisted scope of the session behind identity.
// An access token has no browser session and counts as global.
func sessionAuthScope(identity AuthIdentity) (scope string, orgID, providerID int, err error) {
	if _, isToken := model.ParseAccessTokenSessionID(identity.SessionID); isToken {
		return types.AuthScopeGlobal, 0, 0, nil
	}
	session, err := model.GetUserSessionCached(identity.SessionID)
	if err != nil {
		return "", 0, 0, err
	}
	return session.EffectiveAuthScope(), session.OrgID, session.ProviderID, nil
}

// orgSessionRequirements is the whole verification policy of an org-restricted
// session: org.* operations from the allowlist, answered by org_oidc only, and
// only when the person still has an active identity at the session's own
// provider. Everything else is forbidden, so no global scope (account
// deletion, passkey, password, channel keys, access tokens) is reachable.
func orgSessionRequirements(identity AuthIdentity, scope string, orgID, providerID int) (*VerificationRequirements, error) {
	if !isOrgSessionSensitiveScope(scope) {
		return nil, ErrVerificationForbidden
	}
	option := VerificationMethodOption{Method: VerificationMethodOrgOIDC, Available: true}
	if _, err := model.GetOrgIdentityByUser(model.DB, orgID, identity.UserID); err != nil || providerID <= 0 {
		option.Available, option.Reason = false, "The organization identity is not available."
	}
	return &VerificationRequirements{Scope: scope, Methods: []VerificationMethodOption{option}, OAuthProviders: []VerificationOAuthProvider{}}, nil
}

// OrgSensitiveContextJSON renders the canonical context of a proof request.
func OrgSensitiveContextJSON(orgID int, authScope, resource string) ([]byte, error) {
	return common.Marshal(OrgSensitiveContext{OrgID: orgID, AuthScope: authScope, Resource: resource})
}

// CompleteOrgFreshVerification issues the proof for an operation after the
// organization IdP re-authenticated the person. The caller has already checked
// that the ceremony was fresh, for this session, and returned the expected
// subject; this checks the session is still live and still org-restricted.
func CompleteOrgFreshVerification(identity AuthIdentity, operation VerificationOperation) (*SecurityProof, error) {
	binding, err := BindVerificationOperation(operation)
	if err != nil {
		return nil, err
	}
	return CompleteSecurityVerification(identity, binding, VerificationMethodOrgOIDC)
}
