package model

// orgModels lists every table introduced by the organization and workspace
// feature. Financial tables (operations, events, queue, leases, usage, ledger,
// jobs, invoices, audit) belong to the main database and must never be moved
// to the optional log database.
func orgModels() []any {
	return []any{
		&Organization{},
		&OrganizationMember{},
		&Workspace{},
		&WorkspaceMember{},
		&WorkspaceMemberGrant{},
		&Invite{},
		&OrgIdentity{},
		&ScimGroupMapping{},
		&Budget{},
		&OrgBudgetUsage{},
		&Guardrail{},
		&OrgAccessToken{},
		&OrgAuditLog{},
		&OrgBillingProfile{},
		&OrgInvoice{},
		&OrgBillingLedger{},
		&OrgBillingOperation{},
		&OrgSpendEvent{},
		&OrgSpendFoldQueue{},
		&OrgFoldBatch{},
		&OrgSpendRollup{},
		&OrgQuotaLease{},
		&OrgWriteoffDaily{},
		&OrgBillingJob{},
	}
}

// migrateOrgTables creates the organization tables. It adds no rows and
// touches no existing data, so running it twice is a no-op.
func migrateOrgTables() error {
	return DB.AutoMigrate(orgModels()...)
}
