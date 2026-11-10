package types

import "net/http"

// OrgAccessError is a structured refusal of an organization request. Code is one
// of the OrgErr* constants; controllers and middleware map it to the HTTP status
// and error shape of design section 4.7.
type OrgAccessError struct {
	Code   string
	Status int
}

func (e *OrgAccessError) Error() string { return e.Code }

// NewOrgAccessError builds the refusal for a code using the status fixed by the
// design: 404 hides existence, 403 is a known-but-denied state, 503 is a
// transient authorization failure that must never be read as permission.
func NewOrgAccessError(code string) *OrgAccessError {
	status := http.StatusForbidden
	switch code {
	case OrgErrNotFound, OrgErrWorkspaceNotFound:
		status = http.StatusNotFound
	case OrgErrSlugTaken, OrgErrSlugReserved, OrgErrSeatLimitReached, OrgErrLastOwner, OrgErrDeleteBlocked, OrgErrQuotaInUse,
		OrgErrInviteEmailMismatch, OrgErrConflict, OrgErrOwnerRole, OrgErrDefaultWorkspace, OrgErrKeyLimit:
		status = http.StatusConflict
	case OrgErrInviteExpired, OrgErrInviteRevoked, OrgErrInviteUsed:
		status = http.StatusGone
	case OrgErrInviteNotFound, OrgErrKeyNotFound, OrgErrMemberNotFound, OrgErrGuardrailNotFound:
		status = http.StatusNotFound
	case OrgErrInvalidInput:
		status = http.StatusBadRequest
	case OrgErrCredentialInvalid:
		status = http.StatusUnauthorized
	case OrgErrBillingRecovery, OrgErrStateUnavailable:
		status = http.StatusServiceUnavailable
	}
	return &OrgAccessError{Code: code, Status: status}
}

// OrgErrStateUnavailable means the primary database could not prove the
// authorization state. Requests are refused rather than treated as personal.
const OrgErrStateUnavailable = "org_state_unavailable"

// Codes used by the control plane (design section 4.7 and sections 5 and 6).
const (
	// OrgErrSessionScope means an org-restricted session reached a route outside
	// its allowlist. It is a 403 and never reveals whether the target exists.
	OrgErrSessionScope = "session_scope_denied"
	// OrgErrEmailNotVerified blocks organization creation and invite acceptance
	// for accounts without a verified email address.
	OrgErrEmailNotVerified = "email_not_verified"

	OrgErrInviteExpired       = "invite_expired"
	OrgErrInviteRevoked       = "invite_revoked"
	OrgErrInviteUsed          = "invite_used"
	OrgErrInviteEmailMismatch = "invite_email_mismatch"
	OrgErrInviteNotFound      = "invite_not_found"

	OrgErrInvalidInput     = "org_invalid_input"
	OrgErrConflict         = "org_conflict"
	OrgErrOwnerRole        = "owner_role_protected"
	OrgErrMemberNotFound   = "member_not_found"
	OrgErrKeyNotFound      = "key_not_found"
	OrgErrKeyLimit         = "workspace_key_limit_reached"
	OrgErrDefaultWorkspace = "default_workspace_protected"

	// OrgErrGuardrailNotFound hides guardrails of other scopes and organizations.
	OrgErrGuardrailNotFound = "guardrail_not_found"
)
