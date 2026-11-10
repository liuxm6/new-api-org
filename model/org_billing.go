package model

// OrgBillingOperation is the durable record of one billed request or task. It
// is created before the first reservation and reused by every channel retry.
// holds is a JSON array with exactly one entry per target:
// [{target_type, target_id, source, amount, captured, released}].
type OrgBillingOperation struct {
	Id               int    `json:"id"`
	OperationId      string `json:"operation_id" gorm:"type:varchar(64);uniqueIndex"`
	OrgId            int    `json:"org_id" gorm:"index:idx_org_op_state,priority:1"`
	WorkspaceId      int    `json:"workspace_id"`
	ActorUserId      int    `json:"actor_user_id"`
	TokenId          int    `json:"token_id"`
	AccessPrincipal  string `json:"access_principal_id" gorm:"column:access_principal_id;type:varchar(64)"`
	OwnerType        string `json:"owner_type" gorm:"type:varchar(16)"`
	BillingUserId    int    `json:"billing_user_id"`
	BillingChannelId int    `json:"billing_channel_id" gorm:"default:0"`
	SourceKind       string `json:"source_kind" gorm:"type:varchar(32)"`
	SourceId         string `json:"source_id" gorm:"type:varchar(191)"`
	ModelName        string `json:"model_name" gorm:"type:varchar(191)"`
	// EstimatedQuota is the input-only estimate; ProgressQuota is the output
	// cost seen so far, written on lease renewal for crash recovery.
	EstimatedQuota int64  `json:"estimated_quota" gorm:"type:bigint;default:0"`
	ProgressQuota  int64  `json:"progress_quota" gorm:"type:bigint;default:0"`
	Bound          int64  `json:"bound" gorm:"type:bigint;default:0"`
	Holds          string `json:"holds" gorm:"type:text"`
	WriteoffQuota  int64  `json:"writeoff_quota" gorm:"type:bigint;default:0"`
	State          string `json:"state" gorm:"type:varchar(24);index:idx_org_op_state,priority:2;index:idx_org_op_lease,priority:1"`
	ReservedQuota  int64  `json:"reserved_quota" gorm:"type:bigint;default:0"`
	CapturedQuota  int64  `json:"captured_quota" gorm:"type:bigint;default:0"`
	Revision       int64  `json:"revision" gorm:"type:bigint;default:0"`
	// RefundedQuota is the sum of refunds after the terminal state;
	// CapturedQuota stays the gross charge, so a replayed capture still matches.
	RefundedQuota int64 `json:"refunded_quota" gorm:"type:bigint;default:0"`
	// RefundRevision is the refund sequence, independent of Revision.
	RefundRevision int64 `json:"refund_revision" gorm:"type:bigint;default:0"`
	// EffectiveAt is the reservation instant; budget windows and the original
	// event period follow it.
	EffectiveAt int64  `json:"effective_at" gorm:"type:bigint;default:0"`
	UpstreamRef string `json:"upstream_ref" gorm:"type:varchar(191)"`
	LeaseOwner  string `json:"lease_owner" gorm:"type:varchar(64)"`
	LeaseUntil  int64  `json:"lease_until" gorm:"type:bigint;default:0;index:idx_org_op_lease,priority:2"`
	SettledBy   string `json:"settled_by" gorm:"type:varchar(16)"`
	CreatedAt   int64  `json:"created_at" gorm:"type:bigint"`
	UpdatedAt   int64  `json:"updated_at" gorm:"type:bigint"`
}

func (OrgBillingOperation) TableName() string { return "org_billing_operations" }

// OrgSpendEvent is the immutable accounting fact. It is appended, never edited,
// and is not stored in the log database.
type OrgSpendEvent struct {
	Id              int    `json:"id"`
	OrgId           int    `json:"org_id" gorm:"index:idx_org_event_effective,priority:1"`
	WorkspaceId     int    `json:"workspace_id"`
	ActorUserId     int    `json:"actor_user_id"`
	TokenId         int    `json:"token_id"`
	AccessPrincipal string `json:"access_principal_id" gorm:"column:access_principal_id;type:varchar(64)"`
	OperationId     string `json:"operation_id" gorm:"type:varchar(64);uniqueIndex:uk_org_event,priority:1"`
	EventKind       string `json:"event_kind" gorm:"type:varchar(16);uniqueIndex:uk_org_event,priority:2"`
	Revision        int64  `json:"revision" gorm:"type:bigint;uniqueIndex:uk_org_event,priority:3"`
	DeltaQuota      int64  `json:"delta_quota" gorm:"type:bigint"`
	EffectiveAt     int64  `json:"effective_at" gorm:"type:bigint;index:idx_org_event_effective,priority:2"`
	RecordedAt      int64  `json:"recorded_at" gorm:"type:bigint"`
	ModelName       string `json:"model_name" gorm:"type:varchar(191)"`
	OriginalEventId int    `json:"original_event_id" gorm:"default:0"`
	PriceSnapshot   string `json:"price_snapshot" gorm:"type:text"`
}

func (OrgSpendEvent) TableName() string { return "org_spend_events" }

// OrgSpendFoldQueue holds consumption not yet folded into budget usage,
// rollups and used_quota. A row is created in the same transaction as its
// event and deleted by the one fold transaction that applies it.
type OrgSpendFoldQueue struct {
	Id            int    `json:"id" gorm:"index:idx_org_fold_queue,priority:2"`
	OrgId         int    `json:"org_id" gorm:"index:idx_org_fold_queue,priority:1"`
	EventId       int    `json:"event_id" gorm:"default:0"`
	OperationId   string `json:"operation_id" gorm:"type:varchar(64)"`
	WorkspaceId   int    `json:"workspace_id"`
	ActorUserId   int    `json:"actor_user_id"`
	TokenId       int    `json:"token_id"`
	EffectiveAt   int64  `json:"effective_at" gorm:"type:bigint"`
	Kind          string `json:"kind" gorm:"type:varchar(8)"`
	ModelName     string `json:"model_name" gorm:"type:varchar(191)"`
	SpendDelta    int64  `json:"spend_delta" gorm:"type:bigint;default:0"`
	WriteoffQuota int64  `json:"writeoff_quota" gorm:"type:bigint;default:0"`
	Holds         string `json:"holds" gorm:"type:text"`
	RollupKey     string `json:"rollup_key" gorm:"type:varchar(128)"`
	// Revision is the capture revision; only revision 1 counts as a request.
	Revision  int64 `json:"revision" gorm:"type:bigint;default:0"`
	CreatedAt int64 `json:"created_at" gorm:"type:bigint"`
}

func (OrgSpendFoldQueue) TableName() string { return "org_spend_fold_queue" }

// OrgFoldBatch records each fold transaction. Statement close uses folded_at.
type OrgFoldBatch struct {
	Id       int    `json:"id"`
	OrgId    int    `json:"org_id" gorm:"index:idx_org_fold_batch,priority:1"`
	FoldedAt int64  `json:"folded_at" gorm:"type:bigint;index:idx_org_fold_batch,priority:2"`
	Period   string `json:"period" gorm:"type:varchar(7)"`
	RowCount int    `json:"row_count"`
	SpendSum int64  `json:"spend_sum" gorm:"type:bigint"`
}

func (OrgFoldBatch) TableName() string { return "org_fold_batches" }

// OrgSpendRollup is the monthly statement source. Period is the UTC month of
// the fold; EffectivePeriod is the month the spend belongs to.
type OrgSpendRollup struct {
	Id              int    `json:"id"`
	OrgId           int    `json:"org_id" gorm:"uniqueIndex:uk_org_rollup,priority:1"`
	Period          string `json:"period" gorm:"type:varchar(7);uniqueIndex:uk_org_rollup,priority:2"`
	RollupKey       string `json:"rollup_key" gorm:"type:varchar(128);uniqueIndex:uk_org_rollup,priority:3"`
	WorkspaceId     int    `json:"workspace_id" gorm:"uniqueIndex:uk_org_rollup,priority:4"`
	EffectivePeriod string `json:"effective_period" gorm:"type:varchar(7);uniqueIndex:uk_org_rollup,priority:5"`
	SpendQuota      int64  `json:"spend_quota" gorm:"type:bigint;default:0"`
	EventCount      int64  `json:"event_count" gorm:"type:bigint;default:0"`
	UpdatedAt       int64  `json:"updated_at" gorm:"type:bigint"`
}

func (OrgSpendRollup) TableName() string { return "org_spend_rollups" }

// OrgQuotaLease is a per-instance slice of the wallet or of a budget row. A
// wallet lease's amount has already left users.quota; a budget lease's amount
// is counted in the usage row's held_quota.
//
// Invariants: allocated + consumed <= amount and folded <= consumed. A request
// may take from a lease only through a conditional UPDATE on this row that
// checks status = active, so a revoked or closed lease can never be used.
type OrgQuotaLease struct {
	Id         int    `json:"id"`
	OrgId      int    `json:"org_id"`
	TargetType string `json:"target_type" gorm:"type:varchar(8);index:idx_org_lease_target,priority:1"`
	TargetId   int    `json:"target_id" gorm:"index:idx_org_lease_target,priority:2"`
	// WindowEnd bounds a budget lease to its window; zero for wallet leases.
	WindowEnd  int64  `json:"window_end" gorm:"type:bigint;default:0"`
	InstanceId string `json:"instance_id" gorm:"type:varchar(64)"`
	ShardNo    int    `json:"shard_no" gorm:"default:0"`
	Amount     int64  `json:"amount" gorm:"type:bigint"`
	Allocated  int64  `json:"allocated" gorm:"type:bigint;default:0"`
	Consumed   int64  `json:"consumed" gorm:"type:bigint;default:0"`
	Folded     int64  `json:"folded" gorm:"type:bigint;default:0"`
	Status     string `json:"status" gorm:"type:varchar(8);index:idx_org_lease_target,priority:3;index:idx_org_lease_expiry,priority:1"`
	ExpiresAt  int64  `json:"expires_at" gorm:"type:bigint;index:idx_org_lease_expiry,priority:2"`
	CreatedAt  int64  `json:"created_at" gorm:"type:bigint"`
}

func (OrgQuotaLease) TableName() string { return "org_quota_leases" }

// OrgWriteoffDaily accumulates platform-absorbed overage per organization,
// model and UTC day (by fold time) to enforce the daily cap.
type OrgWriteoffDaily struct {
	Id            int    `json:"id"`
	OrgId         int    `json:"org_id" gorm:"uniqueIndex:uk_org_writeoff,priority:1"`
	Day           string `json:"day" gorm:"type:varchar(10);uniqueIndex:uk_org_writeoff,priority:2"`
	ModelName     string `json:"model_name" gorm:"type:varchar(128);uniqueIndex:uk_org_writeoff,priority:3"`
	WriteoffQuota int64  `json:"writeoff_quota" gorm:"type:bigint;default:0"`
}

func (OrgWriteoffDaily) TableName() string { return "org_writeoff_daily" }

// OrgBillingJob is a durable work item claimed under a database lease, so it
// survives restarts and runs on one instance at a time.
type OrgBillingJob struct {
	Id          int    `json:"id"`
	OrgId       int    `json:"org_id" gorm:"uniqueIndex:uk_org_job,priority:1"`
	Kind        string `json:"kind" gorm:"type:varchar(16);uniqueIndex:uk_org_job,priority:2;index:idx_org_job_due,priority:1"`
	BusinessKey string `json:"business_key" gorm:"type:varchar(128);uniqueIndex:uk_org_job,priority:3"`
	Payload     string `json:"payload" gorm:"type:text"`
	Status      string `json:"status" gorm:"type:varchar(16);index:idx_org_job_due,priority:2"`
	Attempts    int    `json:"attempts" gorm:"default:0"`
	NextRunAt   int64  `json:"next_run_at" gorm:"type:bigint;index:idx_org_job_due,priority:3"`
	LeaseUntil  int64  `json:"lease_until" gorm:"type:bigint;default:0"`
	LastError   string `json:"last_error" gorm:"type:text"`
	CreatedAt   int64  `json:"created_at" gorm:"type:bigint"`
	UpdatedAt   int64  `json:"updated_at" gorm:"type:bigint"`
}

func (OrgBillingJob) TableName() string { return "org_billing_jobs" }

// OrgBillingLedger records money entering the organization wallet.
// Consumption is recorded by OrgSpendEvent, not here.
type OrgBillingLedger struct {
	Id             int    `json:"id"`
	OrgId          int    `json:"org_id" gorm:"uniqueIndex:uk_org_ledger_key,priority:1;index"`
	Type           string `json:"type" gorm:"type:varchar(16)"`
	AmountQuota    int64  `json:"amount_quota" gorm:"type:bigint"`
	BalanceAfter   int64  `json:"balance_after" gorm:"type:bigint"`
	RefType        string `json:"ref_type" gorm:"type:varchar(32)"`
	RefId          string `json:"ref_id" gorm:"type:varchar(191)"`
	IdempotencyKey string `json:"idempotency_key" gorm:"type:varchar(128);not null;uniqueIndex:uk_org_ledger_key,priority:2"`
	OperatorUserId int    `json:"operator_user_id"`
	CreatedAt      int64  `json:"created_at" gorm:"type:bigint"`
}

func (OrgBillingLedger) TableName() string { return "org_billing_ledger" }
