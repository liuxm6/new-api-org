// Package org holds the organization and workspace business logic. It depends
// only on model, common and types; it must never import the parent service
// package. Mail, notification and billing-preference concerns are injected by
// the caller.
package org

import (
	"errors"
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"
)

// ConsoleResponse is the web-console rendering of an organization failure.
type ConsoleResponse struct {
	Status  int
	Code    string
	Message *common.Message
}

// consoleMessages maps each refusal code to its English source text, which is
// also its key in the web locale files.
var consoleMessages = map[string]string{
	types.OrgErrNotFound:            "Organization not found",
	types.OrgErrWorkspaceNotFound:   "Workspace not found",
	types.OrgErrForbidden:           "You do not have permission to do this in the organization",
	types.OrgErrWorkspaceForbidden:  "You do not have permission to do this in the workspace",
	types.OrgErrSuspended:           "The organization is suspended",
	types.OrgErrWorkspaceSuspended:  "The workspace is suspended",
	types.OrgErrMemberSuspended:     "Your membership in the organization is suspended",
	types.OrgErrStateUnavailable:    "The organization state could not be verified, retry later",
	types.OrgErrSessionScope:        "This session is limited to one organization and cannot perform this action",
	types.OrgErrEmailNotVerified:    "A verified email address is required",
	types.OrgErrSlugTaken:           "This identifier is already in use",
	types.OrgErrSlugReserved:        "This identifier is reserved",
	types.OrgErrSeatLimitReached:    "The organization has no free seats",
	types.OrgErrLastOwner:           "The organization must keep at least one owner",
	types.OrgErrOwnerRole:           "Only an owner can grant, change or remove the owner role",
	types.OrgErrInviteExpired:       "This invitation has expired",
	types.OrgErrInviteRevoked:       "This invitation has been revoked",
	types.OrgErrInviteUsed:          "This invitation has already been used",
	types.OrgErrInviteEmailMismatch: "This invitation was sent to a different email address",
	types.OrgErrInviteNotFound:      "Invitation not found",
	types.OrgErrMemberNotFound:      "Member not found",
	types.OrgErrKeyNotFound:         "Key not found",
	types.OrgErrGuardrailNotFound:   "Guardrail not found",
	types.OrgErrKeyLimit:            "The workspace has reached its key limit",
	types.OrgErrDefaultWorkspace:    "The default workspace cannot be deleted or renamed away",
	types.OrgErrDeleteBlocked:       "The organization cannot be deleted yet",
	types.OrgErrConflict:            "The change conflicts with the current state",
	types.OrgErrInvalidInput:        "Invalid parameters",
	types.OrgErrQuotaInUse:          "The balance is held by in-flight requests",
	types.OrgErrBillingRecovery:     "Billing operations need review before new asynchronous tasks can start",
	types.OrgErrWorkspaceBudget:     "The workspace budget is exhausted",
	types.OrgErrBudgetExceeded:      "The organization budget is exhausted",
	types.OrgErrMemberBudget:        "The member budget is exhausted",
	types.OrgErrKeyBudget:           "The key budget is exhausted",
	types.OrgErrQuotaExhausted:      "The organization balance is exhausted",
	types.OrgErrCredentialInvalid:   "The credential is invalid, expired or revoked",
	types.OrgErrIdentityDisabled:    "Your organization sign-in has been disabled",
	types.OrgErrJITDisabled:         "This organization does not allow new members to join by signing in",
	types.OrgErrSSONotConfigured:    "Single sign-on is not configured for this organization",
}

// ConsoleMessageKeys lists every message key this package can produce, so the
// locale files can be checked against it.
func ConsoleMessageKeys() []string {
	keys := make([]string, 0, len(consoleMessages)+1)
	for _, text := range consoleMessages {
		keys = append(keys, text)
	}
	return append(keys, "Database error, please contact the administrator")
}

// ConsoleError converts an error into the HTTP status, stable code and message
// for a web-console response. Anything that is not a recognised refusal is a
// database-class failure: it is logged and never echoed to the client.
func ConsoleError(err error) ConsoleResponse {
	var access *types.OrgAccessError
	if errors.As(err, &access) {
		text, ok := consoleMessages[access.Code]
		if !ok {
			text = consoleMessages[types.OrgErrForbidden]
		}
		return ConsoleResponse{Status: access.Status, Code: access.Code, Message: common.NewMessage(text)}
	}
	var message *common.Message
	if errors.As(err, &message) {
		return ConsoleResponse{Status: http.StatusBadRequest, Code: types.OrgErrInvalidInput, Message: message}
	}
	common.SysError(common.LogText("organization request failed: %v", err))
	return ConsoleResponse{Status: http.StatusInternalServerError, Code: types.OrgErrStateUnavailable,
		Message: common.NewMessage("Database error, please contact the administrator")}
}
