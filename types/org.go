package types

// Organization and workspace enumerations shared by model, middleware and
// service code. This file must not import any other package of this module.

const (
	OrgStatusActive    = 1
	OrgStatusSuspended = 2
	OrgStatusDeleted   = 3
)

const (
	OrgMemberStatusActive    = 1
	OrgMemberStatusSuspended = 2
	OrgMemberStatusRemoved   = 3
)

const (
	WorkspaceStatusActive    = 1
	WorkspaceStatusSuspended = 2
	WorkspaceStatusDeleted   = 3
)

const (
	OrgRoleOwner   = "owner"
	OrgRoleAdmin   = "admin"
	OrgRoleBilling = "billing"
	OrgRoleMember  = "member"
)

const (
	WorkspaceRoleAdmin   = "admin"
	WorkspaceRoleMember  = "member"
	WorkspaceRoleAuditor = "auditor"
)

const (
	OrgMemberSourceManual = "manual"
	OrgMemberSourceInvite = "invite"
	OrgMemberSourceSCIM   = "scim"
	OrgMemberSourceDomain = "domain"
)

const (
	InviteStatusPending  = 1
	InviteStatusAccepted = 2
	InviteStatusRevoked  = 3
	InviteStatusExpired  = 4
)

// Token owner types. The empty string marks a personal or legacy token.
const (
	TokenOwnerPersonal  = ""
	TokenOwnerMember    = "member"
	TokenOwnerWorkspace = "workspace"
)

// users.kind values. Zero is every pre-existing and ordinary human account.
const (
	UserKindHuman   = 0
	UserKindBilling = 1
)

// Session auth scopes. Sessions created before organizations are global.
const (
	AuthScopeGlobal = "global"
	AuthScopeOrg    = "org"
)

// Budget scopes and periods. Periods are fixed to UTC.
const (
	BudgetScopeOrg       = "org"
	BudgetScopeWorkspace = "workspace"
	BudgetScopeMember    = "member"
	BudgetScopeKey       = "key"
)

const (
	BudgetPeriodDaily    = "daily"
	BudgetPeriodWeekly   = "weekly"
	BudgetPeriodMonthly  = "monthly"
	BudgetPeriodLifetime = "lifetime"
)

// Guardrail targets.
const (
	GuardrailTargetMember           = "member"
	GuardrailTargetKey              = "key"
	GuardrailTargetWorkspaceDefault = "workspace_default"
	GuardrailTargetOrgDefault       = "org_default"
)

// Management credential kinds.
const (
	OrgAccessTokenPersonalManagement = "personal_management"
	OrgAccessTokenSCIMService        = "scim_service"
)

// OrgSubject identifies who a request is billed and attributed to. It must be
// built only from a trusted credential or a persisted operation snapshot,
// never from request bodies or headers.
type OrgSubject struct {
	OrgID             int
	WorkspaceID       int
	ActorUserID       int
	TokenID           int
	AccessPrincipalID string
	OwnerType         string
}
