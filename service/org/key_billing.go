package org

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// KeyBilling is what an organization key may learn about its own quota. It is
// derived from the key row, the budgets that apply to the key and the
// organization's available balance (design 4.3); total consumption is never an input.
type KeyBilling struct {
	// Remaining is the smallest of the key's remaining quota (if limited), the
	// smallest headroom (limit - spent - held) of the enabled budgets that apply
	// to the key, and the organization's available balance.
	Remaining   int64
	Used        int64
	ExpiredTime int64
}

// budgetWindowStart is the UTC start of the budget window containing now
// (design section 3.1: daily midnight, weekly Monday, monthly day 1, lifetime 0).
func budgetWindowStart(period string, now time.Time) int64 {
	now = now.UTC()
	switch period {
	case types.BudgetPeriodDaily:
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Unix()
	case types.BudgetPeriodWeekly:
		offset := (int(now.Weekday()) + 6) % 7
		return time.Date(now.Year(), now.Month(), now.Day()-offset, 0, 0, 0, 0, time.UTC).Unix()
	case types.BudgetPeriodMonthly:
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Unix()
	}
	return 0
}

// KeyBillingFor reads the key's own quota view. The subject is the trusted one
// TokenAuth stored; the key is looked up by id inside its organization, so a
// stale or forged context cannot point it at another tenant's key.
func KeyBillingFor(ctx context.Context, subject types.OrgSubject) (*KeyBilling, error) {
	db := model.DB.WithContext(ctx)
	var keys []model.Token
	if err := db.Where("id = ? AND org_id = ?", subject.TokenID, subject.OrgID).Limit(1).Find(&keys).Error; err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	key := keys[0]
	result := &KeyBilling{Used: int64(key.UsedQuota), ExpiredTime: key.ExpiredTime, Remaining: math.MaxInt64}
	if !key.UnlimitedQuota {
		result.Remaining = max(int64(key.RemainQuota), 0)
	}

	scopes := []struct {
		scope string
		id    int
	}{{types.BudgetScopeOrg, subject.OrgID}, {types.BudgetScopeWorkspace, subject.WorkspaceID}, {types.BudgetScopeKey, key.Id}}
	if subject.ActorUserID > 0 {
		scopes = append(scopes, struct {
			scope string
			id    int
		}{types.BudgetScopeMember, subject.ActorUserID})
	}
	now := time.Now()
	for _, target := range scopes {
		var budgets []model.Budget
		if err := db.Where("org_id = ? AND scope = ? AND subject_id = ? AND enabled = ?", subject.OrgID, target.scope, target.id, true).
			Find(&budgets).Error; err != nil {
			return nil, err
		}
		for _, budget := range budgets {
			var usages []model.OrgBudgetUsage
			if err := db.Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ? AND window_start = ?",
				subject.OrgID, target.scope, target.id, budget.Period, budgetWindowStart(budget.Period, now)).
				Limit(1).Find(&usages).Error; err != nil {
				return nil, err
			}
			headroom := budget.LimitQuota
			if len(usages) == 1 {
				headroom -= usages[0].SpentQuota + usages[0].HeldQuota
			}
			result.Remaining = min(result.Remaining, max(headroom, 0))
		}
	}
	// Design 4.3: the smallest of the key's remaining quota, the budget headroom
	// and the organization's available balance.
	var org model.Organization
	if err := db.Unscoped().Select("billing_user_id").Where("id = ?", subject.OrgID).Take(&org).Error; err != nil {
		return nil, err
	}
	available, err := model.OrgWalletAvailable(db, org.BillingUserId)
	if err != nil {
		return nil, err
	}
	result.Remaining = min(result.Remaining, max(available, 0))
	return result, nil
}

// ErrKeyBillingUnavailable wraps a lookup failure for callers that map it to a
// generic error without echoing internals.
var ErrKeyBillingUnavailable = errors.New("key billing is unavailable")
