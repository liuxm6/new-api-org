package controller

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

type budgetPeriodView struct {
	Period    string `json:"period"`
	Limit     int64  `json:"limit"`
	Spent     int64  `json:"spent"`
	Held      int64  `json:"held"`
	Available int64  `json:"available"`
	OverBy    int64  `json:"over_by"`
	Enabled   bool   `json:"enabled"`
}

func budgetSetView(set model.OrgBudgetSet) gin.H {
	rows := make([]budgetPeriodView, 0, len(set.Periods))
	for _, p := range set.Periods {
		rows = append(rows, budgetPeriodView{Period: p.Period, Limit: p.Limit, Spent: p.Spent, Held: p.Held,
			Available: p.Available, OverBy: p.OverBy, Enabled: p.Enabled})
	}
	return gin.H{"version": set.Version, "budgets": rows}
}

// budgetTarget resolves which budget a route is about from what the middleware
// proved. Subjects come from the path, never from the body.
func budgetTarget(c *gin.Context, scope string) (orgsvc.BudgetTarget, bool) {
	access, ok := requestedOrg(c)
	if !ok {
		return orgsvc.BudgetTarget{}, false
	}
	target := orgsvc.BudgetTarget{OrgID: access.Org.Id, Scope: scope, SubjectID: access.Org.Id}
	switch scope {
	case types.BudgetScopeMember:
		id, ok := pathID(c, "mid")
		if !ok {
			return target, false
		}
		target.SubjectID = id
	case types.BudgetScopeWorkspace, types.BudgetScopeKey:
		wsAccess, ok := requestedWorkspace(c)
		if !ok {
			return target, false
		}
		target.WorkspaceID, target.SubjectID = wsAccess.Workspace.Id, wsAccess.Workspace.Id
		if scope == types.BudgetScopeKey {
			id, ok := pathID(c, "kid")
			if !ok {
				return target, false
			}
			target.SubjectID = id
		}
	}
	return target, true
}

func getBudgets(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		target, ok := budgetTarget(c, scope)
		if !ok {
			return
		}
		set, err := orgsvc.GetBudgets(orgContext(c), c.GetInt("id"), target)
		if err != nil {
			respondOrgError(c, err)
			return
		}
		common.ApiSuccess(c, budgetSetView(set))
	}
}

func putBudgets(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		target, ok := budgetTarget(c, scope)
		if !ok {
			return
		}
		fields, ok := decodeOrgFields(c, "version", "budgets")
		if !ok {
			return
		}
		var version int64
		if _, err := orgField(fields, "version", &version); err != nil || version < 0 {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
		periods, ok := decodeBudgetPeriods(c, fields["budgets"])
		if !ok {
			return
		}
		set, err := orgsvc.PutBudgets(orgContext(c), c.GetInt("id"), target, periods, version)
		if err != nil {
			respondOrgError(c, err)
			return
		}
		common.ApiSuccess(c, budgetSetView(set))
	}
}

// decodeBudgetPeriods reads the budgets array strictly: every row carries a
// period and a limit, and nothing else is accepted.
func decodeBudgetPeriods(c *gin.Context, raw common.RawMessage) ([]model.OrgBudgetPeriodInput, bool) {
	invalid := func() ([]model.OrgBudgetPeriodInput, bool) {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return nil, false
	}
	var rows []map[string]common.RawMessage
	if len(raw) == 0 || common.Unmarshal(raw, &rows) != nil || len(rows) > 8 {
		return invalid()
	}
	periods := make([]model.OrgBudgetPeriodInput, 0, len(rows))
	for _, row := range rows {
		for key := range row {
			if key != "period" && key != "limit" && key != "enabled" {
				return invalid()
			}
		}
		input := model.OrgBudgetPeriodInput{Enabled: true}
		if common.Unmarshal(row["period"], &input.Period) != nil || common.Unmarshal(row["limit"], &input.LimitQuota) != nil {
			return invalid()
		}
		if enabled, present := row["enabled"]; present && common.Unmarshal(enabled, &input.Enabled) != nil {
			return invalid()
		}
		periods = append(periods, input)
	}
	return periods, true
}

var (
	GetOrganizationBudgets = getBudgets(types.BudgetScopeOrg)
	PutOrganizationBudgets = putBudgets(types.BudgetScopeOrg)
	GetMemberBudgets       = getBudgets(types.BudgetScopeMember)
	PutMemberBudgets       = putBudgets(types.BudgetScopeMember)
	GetWorkspaceBudgets    = getBudgets(types.BudgetScopeWorkspace)
	PutWorkspaceBudgets    = putBudgets(types.BudgetScopeWorkspace)
	GetKeyBudgets          = getBudgets(types.BudgetScopeKey)
	PutKeyBudgets          = putBudgets(types.BudgetScopeKey)
)
