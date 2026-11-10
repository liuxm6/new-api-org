package model

import (
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// Organization owns billing and identity. Its single wallet is a hidden users
// row (kind = users.kind billing); workspaces under it hold keys, budgets and
// guardrails but never a balance.
type Organization struct {
	Id            int    `json:"id"`
	Slug          string `json:"slug" gorm:"type:varchar(32);uniqueIndex"`
	Name          string `json:"name" gorm:"type:varchar(120)"`
	OwnerUserId   int    `json:"owner_user_id" gorm:"index"`
	BillingUserId int    `json:"billing_user_id" gorm:"uniqueIndex"`
	Plan          string `json:"plan" gorm:"type:varchar(32);default:'team'"`
	SeatLimit     int    `json:"seat_limit" gorm:"default:10"`
	Status        int    `json:"status" gorm:"default:1;index"`
	Settings      string `json:"settings" gorm:"type:text"`
	PolicyVersion int64  `json:"policy_version" gorm:"type:bigint;default:1"`
	// InvoiceSequence is advanced under the organization row lock.
	InvoiceSequence int64          `json:"-" gorm:"type:bigint;default:0"`
	BillingGroup    string         `json:"billing_group" gorm:"type:varchar(64);default:'default'"`
	CreatedAt       int64          `json:"created_at" gorm:"type:bigint"`
	UpdatedAt       int64          `json:"updated_at" gorm:"type:bigint"`
	DeletedAt       gorm.DeletedAt `json:"-" gorm:"index"`
}

func (Organization) TableName() string { return "organizations" }

func (o *Organization) IsActive() bool { return o != nil && o.Status == types.OrgStatusActive }

// OrganizationMember is the organization-level membership and role.
type OrganizationMember struct {
	Id           int    `json:"id"`
	OrgId        int    `json:"org_id" gorm:"uniqueIndex:uk_org_member_user,priority:1;index:idx_org_member_status,priority:1"`
	UserId       int    `json:"user_id" gorm:"uniqueIndex:uk_org_member_user,priority:2;index:idx_org_member_user_status,priority:1"`
	Role         string `json:"role" gorm:"type:varchar(16)"`
	Status       int    `json:"status" gorm:"default:1;index:idx_org_member_status,priority:2;index:idx_org_member_user_status,priority:2"`
	Source       string `json:"source" gorm:"type:varchar(16);default:'manual'"`
	ExternalId   string `json:"external_id" gorm:"type:varchar(128);default:''"`
	InvitedBy    int    `json:"invited_by" gorm:"default:0"`
	JoinedAt     int64  `json:"joined_at" gorm:"type:bigint"`
	LastActiveAt int64  `json:"last_active_at" gorm:"type:bigint"`
	CreatedAt    int64  `json:"created_at" gorm:"type:bigint"`
	UpdatedAt    int64  `json:"updated_at" gorm:"type:bigint"`
}

func (OrganizationMember) TableName() string { return "organization_members" }

// Workspace is a project or environment boundary inside an organization.
type Workspace struct {
	Id        int            `json:"id"`
	OrgId     int            `json:"org_id" gorm:"uniqueIndex:uk_workspace_org_slug,priority:1;index:idx_workspace_org_status,priority:1"`
	Slug      string         `json:"slug" gorm:"type:varchar(32);uniqueIndex:uk_workspace_org_slug,priority:2"`
	Name      string         `json:"name" gorm:"type:varchar(120)"`
	IsDefault bool           `json:"is_default"`
	Status    int            `json:"status" gorm:"default:1;index:idx_workspace_org_status,priority:2"`
	Settings  string         `json:"settings" gorm:"type:text"`
	CreatedAt int64          `json:"created_at" gorm:"type:bigint"`
	UpdatedAt int64          `json:"updated_at" gorm:"type:bigint"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

func (Workspace) TableName() string { return "workspaces" }

// WorkspaceMember is the effective workspace role. It is a projection of
// WorkspaceMemberGrant and is written only by grant-change transactions.
type WorkspaceMember struct {
	Id          int    `json:"id"`
	WorkspaceId int    `json:"workspace_id" gorm:"uniqueIndex:uk_ws_member_user,priority:1"`
	OrgId       int    `json:"org_id" gorm:"index:idx_ws_member_org_user,priority:1"`
	UserId      int    `json:"user_id" gorm:"uniqueIndex:uk_ws_member_user,priority:2;index:idx_ws_member_org_user,priority:2"`
	Role        string `json:"role" gorm:"type:varchar(16)"`
	Status      int    `json:"status" gorm:"default:1"`
	CreatedAt   int64  `json:"created_at" gorm:"type:bigint"`
	UpdatedAt   int64  `json:"updated_at" gorm:"type:bigint"`
}

func (WorkspaceMember) TableName() string { return "workspace_members" }

// WorkspaceMemberGrant is the source of truth for workspace access. One user
// can hold grants from several sources (manual, each SCIM group); the effective
// role is the highest role among live grants.
type WorkspaceMemberGrant struct {
	Id          int    `json:"id"`
	OrgId       int    `json:"org_id" gorm:"uniqueIndex:uk_ws_grant,priority:1"`
	WorkspaceId int    `json:"workspace_id" gorm:"uniqueIndex:uk_ws_grant,priority:2"`
	UserId      int    `json:"user_id" gorm:"uniqueIndex:uk_ws_grant,priority:3"`
	Source      string `json:"source" gorm:"type:varchar(16);uniqueIndex:uk_ws_grant,priority:4"`
	SourceRef   string `json:"source_ref" gorm:"type:varchar(191);default:'';uniqueIndex:uk_ws_grant,priority:5"`
	Role        string `json:"role" gorm:"type:varchar(16)"`
	CreatedAt   int64  `json:"created_at" gorm:"type:bigint"`
	UpdatedAt   int64  `json:"updated_at" gorm:"type:bigint"`
}

func (WorkspaceMemberGrant) TableName() string { return "workspace_member_grants" }

// Invite covers organization and workspace invitations. Only the SHA-256 of the
// 256-bit token is stored.
type Invite struct {
	Id          int    `json:"id"`
	OrgId       int    `json:"org_id" gorm:"index:idx_invite_org_email,priority:1"`
	WorkspaceId int    `json:"workspace_id" gorm:"default:0"`
	Email       string `json:"email" gorm:"type:varchar(255);index:idx_invite_org_email,priority:2"`
	OrgRole     string `json:"org_role" gorm:"type:varchar(16)"`
	WsRole      string `json:"ws_role" gorm:"type:varchar(16)"`
	TokenHash   string `json:"-" gorm:"type:char(64);uniqueIndex"`
	Status      int    `json:"status" gorm:"default:1;index:idx_invite_org_email,priority:3"`
	InvitedBy   int    `json:"invited_by"`
	AcceptedBy  int    `json:"accepted_by" gorm:"default:0"`
	ExpiresAt   int64  `json:"expires_at" gorm:"type:bigint"`
	AcceptedAt  int64  `json:"accepted_at" gorm:"type:bigint"`
	CreatedAt   int64  `json:"created_at" gorm:"type:bigint"`
}

func (Invite) TableName() string { return "invites" }

// OrgIdentity maps a tenant IdP subject to a human users row. SCIMExternalId is
// a pointer so rows without one store NULL and never collide on the unique key.
type OrgIdentity struct {
	Id                   int     `json:"id"`
	OrgId                int     `json:"org_id" gorm:"uniqueIndex:uk_org_identity_sub,priority:1;uniqueIndex:uk_org_identity_scim,priority:1;index:idx_org_identity_user,priority:1"`
	ProviderId           int     `json:"provider_id" gorm:"uniqueIndex:uk_org_identity_sub,priority:2;uniqueIndex:uk_org_identity_scim,priority:2"`
	Issuer               string  `json:"issuer" gorm:"type:varchar(255)"`
	Subject              string  `json:"subject" gorm:"type:varchar(191);uniqueIndex:uk_org_identity_sub,priority:3"`
	UserId               int     `json:"user_id" gorm:"index:idx_org_identity_user,priority:2"`
	ScimExternalId       *string `json:"scim_external_id" gorm:"type:varchar(191);uniqueIndex:uk_org_identity_scim,priority:3"`
	ClaimEmail           string  `json:"claim_email" gorm:"type:varchar(255)"`
	Source               string  `json:"source" gorm:"type:varchar(16)"`
	Status               int     `json:"status" gorm:"default:1"`
	GlobalLinkVerifiedAt int64   `json:"global_link_verified_at" gorm:"type:bigint;default:0"`
	CreatedAt            int64   `json:"created_at" gorm:"type:bigint"`
	UpdatedAt            int64   `json:"updated_at" gorm:"type:bigint"`
}

func (OrgIdentity) TableName() string { return "org_identities" }

// ScimGroupMapping grants a workspace role to members of an IdP group.
type ScimGroupMapping struct {
	Id          int    `json:"id"`
	OrgId       int    `json:"org_id" gorm:"uniqueIndex:uk_scim_group,priority:1"`
	IdpGroup    string `json:"idp_group" gorm:"type:varchar(191);uniqueIndex:uk_scim_group,priority:2"`
	WorkspaceId int    `json:"workspace_id"`
	WsRole      string `json:"ws_role" gorm:"type:varchar(16)"`
	CreatedAt   int64  `json:"created_at" gorm:"type:bigint"`
	UpdatedAt   int64  `json:"updated_at" gorm:"type:bigint"`
}

func (ScimGroupMapping) TableName() string { return "scim_group_mappings" }
