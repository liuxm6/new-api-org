package types

// Identity, management credential and sensitive-operation vocabulary shared by
// model, middleware, service and controller code.

// org_identities.status
const (
	OrgIdentityActive   = 1
	OrgIdentityDisabled = 2
	OrgIdentityRemoved  = 3
)

// org_identities.source
const (
	OrgIdentitySourceSSO  = "sso"
	OrgIdentitySourceSCIM = "scim"
)

// Management credential scopes (design section 7).
const (
	MgmtScopeKeysRead        = "keys:read"
	MgmtScopeKeysWrite       = "keys:write"
	MgmtScopeMembersRead     = "members:read"
	MgmtScopeMembersWrite    = "members:write"
	MgmtScopeUsageRead       = "usage:read"
	MgmtScopeBillingRead     = "billing:read"
	MgmtScopeAuditRead       = "audit:read"
	MgmtScopeGuardrailsWrite = "guardrails:write"
	MgmtScopeSCIM            = "scim"
)

// Management credential statuses.
const (
	OrgAccessTokenActive  = 1
	OrgAccessTokenRevoked = 2
)

// Plaintext prefixes. Neither is a sk- inference key prefix, so TokenAuth on
// /v1 can never resolve them.
const (
	ManagementKeyPrefix = "omk-"
	SCIMTokenPrefix     = "osc-"
)

// Refusals specific to identity and credential handling.
const (
	// OrgErrCredentialInvalid is any failure to authenticate a management or
	// SCIM credential. It is deliberately one code: the response must not tell
	// a caller whether a hash exists, expired or was revoked.
	OrgErrCredentialInvalid = "management_credential_invalid"
	OrgErrIdentityDisabled  = "sso_identity_disabled"
	OrgErrJITDisabled       = "sso_jit_disabled"
	OrgErrSSONotConfigured  = "sso_not_configured"
)

// Sensitive operation scopes. Each is one organization action that needs a
// fresh, single-use proof bound to the session, the organization and the exact
// resource (design section 7).
const (
	SensitiveManagementKeyCreate = "org.management_key.create"
	SensitiveManagementKeyRevoke = "org.management_key.revoke"
	SensitiveOwnershipTransfer   = "org.ownership.transfer"
	SensitiveOrgDelete           = "org.delete"
	SensitiveSSOUpdate           = "org.sso.update"
	SensitiveIdentityLink        = "org.identity.link"
	// SensitiveCreditTransfer moves personal money into an organization wallet.
	// Like SensitiveIdentityLink it needs the person's own global session; an
	// org-restricted session can never prove it.
	SensitiveCreditTransfer = "org.credits.transfer"
)

// OrgMemberSourceSSO marks members admitted by just-in-time provisioning or an
// identity link. Like a domain match it can never revive a removed member.
const OrgMemberSourceSSO = "sso"
