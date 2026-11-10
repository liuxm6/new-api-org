package types

// Org billing vocabulary. Amounts are 64-bit quota units that must be checked
// against common.MaxWalletQuota before they reach the wallet; a single
// request's charge stays inside the int32 saturation domain.

// Operation states.
const (
	OrgOpStatePrepared         = "prepared"
	OrgOpStateReserved         = "reserved"
	OrgOpStateCaptured         = "captured"
	OrgOpStateClosed           = "closed"
	OrgOpStateCanceled         = "canceled"
	OrgOpStateRecoveryRequired = "recovery_required"
)

// Billing actions applied through model.ApplyOrgBilling.
const (
	OrgBillingActionReserve      = "reserve"
	OrgBillingActionTopUpReserve = "topup_reserve"
	OrgBillingActionCapture      = "capture"
	OrgBillingActionFinalize     = "finalize"
	OrgBillingActionCancel       = "cancel"
	OrgBillingActionRefund       = "refund"
)

// Hold targets and sources.
const (
	OrgHoldTargetWallet = "wallet"
	OrgHoldTargetBudget = "budget"
	OrgHoldTargetToken  = "token"

	// OrgHoldSourceDirect marks a hold taken by locking the target row. Any
	// other source is the decimal id of an org_quota_leases row.
	OrgHoldSourceDirect = "direct"
)

// Lease targets and states.
const (
	OrgLeaseTargetWallet = "wallet"
	OrgLeaseTargetBudget = "budget"

	OrgLeaseStatusActive  = "active"
	OrgLeaseStatusRevoked = "revoked"
	OrgLeaseStatusClosed  = "closed"
)

// Fold queue row kinds.
const (
	OrgFoldKindCapture = "capture"
	OrgFoldKindRefund  = "refund"
)

// Spend event kinds.
const (
	OrgSpendEventCapture = "capture"
	OrgSpendEventRefund  = "refund"
)

// How an operation was settled when no live request did it.
const (
	OrgSettledByRequest  = "request"
	OrgSettledByRecovery = "recovery"
)

// Billing job kinds and states.
const (
	OrgJobKindFold      = "fold"
	OrgJobKindReceipt   = "receipt"
	OrgJobKindStatement = "statement"
	OrgJobKindNotify    = "notify"

	OrgJobStatusPending = "pending"
	OrgJobStatusRunning = "running"
	OrgJobStatusDone    = "done"
	OrgJobStatusFailed  = "failed"
)

// Ledger entry types.
const (
	OrgLedgerTopUp      = "topup"
	OrgLedgerTransferIn = "transfer_in"
	OrgLedgerAdjust     = "adjust"
)

// Invoice kinds and states.
const (
	OrgInvoiceReceipt   = "receipt"
	OrgInvoiceStatement = "statement"

	OrgInvoiceStatusIssued = "issued"
	OrgInvoiceStatusVoid   = "void"
)

// Error codes returned to AI clients and the console (design section 4.7).
const (
	OrgErrNotFound              = "org_not_found"
	OrgErrWorkspaceNotFound     = "workspace_not_found"
	OrgErrForbidden             = "org_forbidden"
	OrgErrWorkspaceForbidden    = "workspace_forbidden"
	OrgErrQuotaExhausted        = "org_quota_exhausted"
	OrgErrQuotaInUse            = "org_quota_in_use"
	OrgErrBudgetExceeded        = "org_budget_exceeded"
	OrgErrWorkspaceBudget       = "workspace_budget_exceeded"
	OrgErrMemberBudget          = "member_budget_exceeded"
	OrgErrKeyBudget             = "key_budget_exceeded"
	OrgErrCostUnbounded         = "org_cost_unbounded"
	OrgErrWriteoffLimited       = "org_cost_writeoff_limited"
	OrgErrBillingRecovery       = "org_billing_recovery_required"
	OrgErrMemberSuspended       = "org_member_suspended"
	OrgErrSuspended             = "org_suspended"
	OrgErrWorkspaceSuspended    = "workspace_suspended"
	OrgErrSeatLimitReached      = "seat_limit_reached"
	OrgErrLastOwner             = "last_owner"
	OrgErrDeleteBlocked         = "org_delete_blocked"
	OrgErrGuardrailModelDenied  = "guardrail_model_denied"
	OrgErrGuardrailProviderDeny = "guardrail_provider_denied"
	OrgErrSlugTaken             = "slug_taken"
	OrgErrSlugReserved          = "slug_reserved"
)

// Source kinds recorded on an operation. Synchronous kinds settle with one
// Capture and close; asynchronous kinds hold the full bound with a direct
// reservation until Finalize or Cancel and may revise their charge in between.
const (
	OrgSourceRelay        = "relay"
	OrgSourceViolationFee = "violation_fee"
	OrgSourceTask         = "task"
	OrgSourceMidjourney   = "midjourney"
)

// OrgSourceIsAsync reports whether operations of this source kind follow the
// asynchronous lifecycle (design section 4.2.4).
func OrgSourceIsAsync(sourceKind string) bool {
	return sourceKind == OrgSourceTask || sourceKind == OrgSourceMidjourney
}

// OrgSourceForcesDirect reports whether the kind must take locked-row holds
// instead of lease holds: asynchronous work and violation fees.
func OrgSourceForcesDirect(sourceKind string) bool {
	return OrgSourceIsAsync(sourceKind) || sourceKind == OrgSourceViolationFee
}

// OrgHold is one entry of an operation's holds array: exactly one per target.
// TargetId is the wallet user id, the token id, or the org_budget_usage id.
// Source is OrgHoldSourceDirect or the decimal id of an org_quota_leases row.
// Scope is set on budget holds only and selects the error code on refusal.
type OrgHold struct {
	TargetType string `json:"target_type"`
	TargetId   int    `json:"target_id"`
	Source     string `json:"source"`
	Amount     int64  `json:"amount"`
	Captured   int64  `json:"captured"`
	Released   int64  `json:"released"`
	Scope      string `json:"scope,omitempty"`
}

// OrgLeaseHint tells Reserve which lease an instance would like to draw from
// for one target. Hints are advisory: the conditional update on the lease row
// is the only authority, and any failure falls back to a locked-row hold.
// TargetId is the wallet user id or the budget usage row id.
type OrgLeaseHint struct {
	TargetType string
	TargetId   int
	LeaseId    int
}

// OrgBillingCommand is one step of an operation's life. Subject and pricing
// metadata come from the server; a caller never supplies another tenant's ids.
//
// Revision rules: Reserve and TopUpReserve carry the operation's current
// revision (0 for a new operation). Capture carries the next revision (current
// + 1); repeating the committed revision with the same amount replays the
// stored result. Finalize and Cancel carry the current revision. Refund has its
// own sequence starting at 1.
type OrgBillingCommand struct {
	OperationID string
	Subject     OrgSubject
	Action      string
	// Bound is the cost upper bound for reserve; for topup_reserve it is the new
	// total bound, which must be larger than the current one.
	Bound int64
	// Amount is the target charge for capture and finalize, the refund for refund.
	Amount     int64
	Revision   int64
	LeaseOwner string

	ModelName      string
	SourceKind     string
	SourceID       string
	BillingChannel int
	PriceSnapshot  string
	EstimatedQuota int64

	// LeaseHints lists leases the caller wants to draw from (reserve and
	// topup_reserve). ForceDirect skips them regardless of the source kind.
	LeaseHints  []OrgLeaseHint
	ForceDirect bool
	// SettledBy is OrgSettledByRecovery for a capture issued by the recovery
	// worker; empty means the requesting instance.
	SettledBy string
}

// OrgBillingResult reports the committed state of an operation.
type OrgBillingResult struct {
	OperationID string
	State       string
	Revision    int64
	Bound       int64
	// Captured is the net charge: gross captured minus refunds.
	Captured int64
	Writeoff int64
	// AppliedDelta is the confirmed consumption change this command made:
	// positive or negative for capture, negative for refund, zero otherwise.
	AppliedDelta int64
	// Replayed is true when the command repeated an already committed revision.
	Replayed bool
	// Holds is the committed holds array after the command.
	Holds []OrgHold
}
