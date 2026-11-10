package model

// OrgAccessToken is an organization-level control-plane credential
// (personal_management or scim_service). It is never accepted on /v1. Only the
// SHA-256 of the plaintext is stored, mirroring UserAccessToken.
type OrgAccessToken struct {
	Id         int    `json:"id"`
	OrgId      int    `json:"org_id" gorm:"index"`
	Name       string `json:"name" gorm:"type:varchar(64)"`
	TokenHash  string `json:"token_ref" gorm:"type:varchar(64);uniqueIndex"`
	TokenHint  string `json:"token_hint" gorm:"type:varchar(8)"`
	Scopes     string `json:"-" gorm:"type:varchar(2048)"`
	CreatedBy  int    `json:"created_by"`
	Kind       string `json:"kind" gorm:"type:varchar(32)"`
	ExpiresAt  int64  `json:"expires_at" gorm:"type:bigint"`
	LastUsedAt int64  `json:"last_used_at" gorm:"type:bigint"`
	LastUsedIp string `json:"last_used_ip" gorm:"type:varchar(64)"`
	Status     int    `json:"status" gorm:"default:1"`
	CreatedAt  int64  `json:"created_at" gorm:"type:bigint"`
	UpdatedAt  int64  `json:"updated_at" gorm:"type:bigint"`
}

func (OrgAccessToken) TableName() string { return "org_access_tokens" }

// OrgAuditLog is the organization audit trail. It lives in the main database,
// is independent of the optional consume log, and must never contain secrets.
type OrgAuditLog struct {
	Id            int    `json:"id"`
	OrgId         int    `json:"org_id" gorm:"index:idx_org_audit_time,priority:1"`
	WorkspaceId   int    `json:"workspace_id" gorm:"default:0"`
	ActorUserId   int    `json:"actor_user_id"`
	ActorKind     string `json:"actor_kind" gorm:"type:varchar(24)"`
	CredentialRef string `json:"credential_ref" gorm:"type:varchar(64)"`
	Action        string `json:"action" gorm:"type:varchar(64);index"`
	TargetType    string `json:"target_type" gorm:"type:varchar(32)"`
	TargetId      string `json:"target_id" gorm:"type:varchar(191)"`
	Detail        string `json:"detail" gorm:"type:text"`
	Ip            string `json:"ip" gorm:"type:varchar(64)"`
	CreatedAt     int64  `json:"created_at" gorm:"type:bigint;index:idx_org_audit_time,priority:2"`
}

func (OrgAuditLog) TableName() string { return "org_audit_logs" }

// OrgBillingProfile is the invoice header; one row per organization.
type OrgBillingProfile struct {
	Id           int    `json:"id"`
	OrgId        int    `json:"org_id" gorm:"uniqueIndex"`
	LegalName    string `json:"legal_name" gorm:"type:varchar(255)"`
	TaxId        string `json:"tax_id" gorm:"type:varchar(64)"`
	Address      string `json:"address" gorm:"type:text"`
	BillingEmail string `json:"billing_email" gorm:"type:varchar(255)"`
	CreatedAt    int64  `json:"created_at" gorm:"type:bigint"`
	UpdatedAt    int64  `json:"updated_at" gorm:"type:bigint"`
}

func (OrgBillingProfile) TableName() string { return "org_billing_profiles" }

// OrgInvoice is a receipt (one top-up) or a monthly statement. Receipts and
// statements are billing documents, not tax invoices.
type OrgInvoice struct {
	Id              int    `json:"id"`
	OrgId           int    `json:"org_id" gorm:"uniqueIndex:uk_org_invoice_number,priority:1;uniqueIndex:uk_org_invoice_key,priority:1;index:idx_org_invoice_type,priority:1"`
	Number          string `json:"number" gorm:"type:varchar(32);uniqueIndex:uk_org_invoice_number,priority:2"`
	Type            string `json:"type" gorm:"type:varchar(16);index:idx_org_invoice_type,priority:2"`
	PeriodStart     int64  `json:"period_start" gorm:"type:bigint"`
	PeriodEnd       int64  `json:"period_end" gorm:"type:bigint"`
	Currency        string `json:"currency" gorm:"type:varchar(8);default:'USD'"`
	AmountCents     int64  `json:"amount_cents" gorm:"type:bigint"`
	Quota           int64  `json:"quota" gorm:"type:bigint"`
	Status          string `json:"status" gorm:"type:varchar(16)"`
	ProfileSnapshot string `json:"profile_snapshot" gorm:"type:text"`
	LineSnapshot    string `json:"line_snapshot" gorm:"type:text"`
	TopupId         int    `json:"topup_id" gorm:"default:0"`
	ReceiptRef      string `json:"receipt_ref" gorm:"type:varchar(128)"`
	BusinessKey     string `json:"business_key" gorm:"type:varchar(128);uniqueIndex:uk_org_invoice_key,priority:2"`
	IssuedBy        int    `json:"issued_by"`
	CreatedAt       int64  `json:"created_at" gorm:"type:bigint;index:idx_org_invoice_type,priority:3"`
	UpdatedAt       int64  `json:"updated_at" gorm:"type:bigint"`
}

func (OrgInvoice) TableName() string { return "org_invoices" }
