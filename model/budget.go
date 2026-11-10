package model

import "gorm.io/gorm"

// Budget is the configured limit for one subject and period. Consumption is
// never stored here; it lives in OrgBudgetUsage so editing a limit cannot reset
// spend.
type Budget struct {
	Id         int    `json:"id"`
	OrgId      int    `json:"org_id" gorm:"uniqueIndex:uk_budget_subject,priority:1"`
	Scope      string `json:"scope" gorm:"type:varchar(16);uniqueIndex:uk_budget_subject,priority:2"`
	SubjectId  int    `json:"subject_id" gorm:"uniqueIndex:uk_budget_subject,priority:3"`
	Period     string `json:"period" gorm:"type:varchar(16);uniqueIndex:uk_budget_subject,priority:4"`
	LimitQuota int64  `json:"limit_quota" gorm:"type:bigint"`
	// Enabled is a plain flag; zero limit means "block", never "unlimited".
	Enabled   bool  `json:"enabled"`
	Version   int64 `json:"version" gorm:"type:bigint;default:1"`
	CreatedAt int64 `json:"created_at" gorm:"type:bigint"`
	UpdatedAt int64 `json:"updated_at" gorm:"type:bigint"`
}

func (Budget) TableName() string { return "budgets" }

// OrgBudgetUsage is the per-window projection of spend and in-flight holds.
// For an enabled budget the invariant spent_quota + held_quota <= limit holds
// at admission time; held_quota is changed only by lease grants, direct holds
// and the fold worker.
type OrgBudgetUsage struct {
	Id          int    `json:"id"`
	OrgId       int    `json:"org_id" gorm:"uniqueIndex:uk_budget_usage,priority:1"`
	Scope       string `json:"scope" gorm:"type:varchar(16);uniqueIndex:uk_budget_usage,priority:2"`
	SubjectId   int    `json:"subject_id" gorm:"uniqueIndex:uk_budget_usage,priority:3"`
	Period      string `json:"period" gorm:"type:varchar(16);uniqueIndex:uk_budget_usage,priority:4"`
	WindowStart int64  `json:"window_start" gorm:"type:bigint;uniqueIndex:uk_budget_usage,priority:5"`
	SpentQuota  int64  `json:"spent_quota" gorm:"type:bigint;default:0"`
	HeldQuota   int64  `json:"held_quota" gorm:"type:bigint;default:0"`
	UpdatedAt   int64  `json:"updated_at" gorm:"type:bigint"`
}

func (OrgBudgetUsage) TableName() string { return "org_budget_usage" }

// Guardrail restricts models and providers. It deliberately has no budget
// reference: budgets are configured only through the budget API.
type Guardrail struct {
	Id          int    `json:"id"`
	OrgId       int    `json:"org_id" gorm:"index:idx_guardrail_org_ws,priority:1"`
	WorkspaceId int    `json:"workspace_id" gorm:"default:0;index:idx_guardrail_org_ws,priority:2"`
	Name        string `json:"name" gorm:"type:varchar(120)"`
	TargetType  string `json:"target_type" gorm:"type:varchar(32);index:idx_guardrail_target,priority:1"`
	TargetId    int    `json:"target_id" gorm:"default:0;index:idx_guardrail_target,priority:2"`
	Config      string `json:"config" gorm:"type:text"`
	Status      int    `json:"status" gorm:"default:1"`
	CreatedAt   int64  `json:"created_at" gorm:"type:bigint"`
	UpdatedAt   int64  `json:"updated_at" gorm:"type:bigint"`
}

func (Guardrail) TableName() string { return "guardrails" }

// LockGuardrailInScopeTx reads one guardrail under a row lock, only when it
// lives in exactly the given organization and workspace scope (workspace 0 is
// the organization scope). It returns nil when there is none.
func LockGuardrailInScopeTx(tx *gorm.DB, orgID, workspaceID, id int) (*Guardrail, error) {
	var rows []Guardrail
	err := lockForUpdate(tx).Where("id = ? AND org_id = ? AND workspace_id = ?", id, orgID, workspaceID).Limit(1).Find(&rows).Error
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}
