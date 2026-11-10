package model

import (
	"context"
	"slices"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// OrgBudgetStatus is one budget row as the console shows it. OverBy is the part
// of spent + held that already passes the limit, which happens when a limit is
// lowered below what had been admitted.
type OrgBudgetStatus struct {
	OrgID       int
	Scope       string
	SubjectID   int
	Period      string
	WindowStart int64
	Limit       int64
	Spent       int64
	Held        int64
	Available   int64
	OverBy      int64
	Version     int64
	Enabled     bool
}

// OrgBudgetChange creates or edits a budget. ExpectedVersion > 0 makes the
// write conditional on the stored version.
type OrgBudgetChange struct {
	OrgID           int
	Scope           string
	SubjectID       int
	Period          string
	LimitQuota      int64
	Enabled         bool
	ExpectedVersion int64
}

func orgBudgetStatus(budget *Budget, usage *OrgBudgetUsage, key orgUsageKey, orgID int) OrgBudgetStatus {
	status := OrgBudgetStatus{OrgID: orgID, Scope: key.Scope, SubjectID: key.SubjectID, Period: key.Period, WindowStart: key.WindowStart}
	if usage != nil {
		status.Spent, status.Held = usage.SpentQuota, usage.HeldQuota
	}
	if budget != nil {
		status.Limit, status.Version, status.Enabled = budget.LimitQuota, budget.Version, budget.Enabled
	}
	status.Available = max(0, status.Limit-status.Spent-status.Held)
	status.OverBy = max(0, status.Spent+status.Held-status.Limit)
	return status
}

func validateOrgBudgetChange(change OrgBudgetChange) error {
	if !slices.Contains([]string{types.BudgetScopeOrg, types.BudgetScopeWorkspace, types.BudgetScopeMember, types.BudgetScopeKey}, change.Scope) ||
		!slices.Contains(orgBudgetPeriods, change.Period) || change.SubjectID <= 0 ||
		change.LimitQuota < 0 || change.LimitQuota > common.MaxWalletQuota || change.ExpectedVersion < 0 {
		return orgInvalidError()
	}
	if change.Scope == types.BudgetScopeOrg && change.SubjectID != change.OrgID {
		return orgInvalidError()
	}
	return nil
}

// retryOrgTx runs fn in a transaction and replays it after a deadlock or lock
// timeout.
func retryOrgTx(ctx context.Context, fn func(tx *gorm.DB) error) error {
	var err error
	for attempt := 1; attempt <= orgBillingMaxAttempts; attempt++ {
		if err = DB.WithContext(ctx).Transaction(fn); err == nil || !isRetryableOrgError(err) {
			return err
		}
	}
	return err
}

// ChangeBudgetLimit creates or edits a budget and takes effect at once
// (design 4.2.6). Anything but a pure raise revokes the leases of the current
// window and gives their unused part back, so no instance can admit against
// the old limit; requests admitted earlier keep settling and show up as OverBy.
func ChangeBudgetLimit(ctx context.Context, change OrgBudgetChange) (OrgBudgetStatus, error) {
	if err := validateOrgBudgetChange(change); err != nil {
		return OrgBudgetStatus{}, err
	}
	var status OrgBudgetStatus
	err := retryOrgTx(ctx, func(tx *gorm.DB) error {
		var err error
		status, err = changeBudgetLimitTx(tx, change)
		return err
	})
	return status, err
}

// changeBudgetLimitTx is ChangeBudgetLimit inside the caller's transaction, so a
// whole period set can be replaced atomically.
func changeBudgetLimitTx(tx *gorm.DB, change OrgBudgetChange) (status OrgBudgetStatus, err error) {
	now, err := orgDBNow(tx)
	if err != nil {
		return status, err
	}
	start, _ := OrgBudgetWindow(change.Period, now)
	key := orgUsageKey{change.Scope, change.SubjectID, change.Period, start}
	usage, err := ensureOrgUsageTx(tx, change.OrgID, key, true)
	if err != nil {
		return status, err
	}
	budget, err := orgFindOne[Budget](lockForUpdate(tx.Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ?",
		change.OrgID, change.Scope, change.SubjectID, change.Period)))
	if err != nil {
		return status, err
	}
	if budget == nil {
		if change.ExpectedVersion > 0 {
			return status, orgConflictError()
		}
		budget = &Budget{OrgId: change.OrgID, Scope: change.Scope, SubjectId: change.SubjectID, Period: change.Period,
			LimitQuota: change.LimitQuota, Enabled: change.Enabled, Version: 1, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(budget).Error; err != nil {
			return status, err
		}
	} else {
		if change.ExpectedVersion > 0 && change.ExpectedVersion != budget.Version {
			return status, orgConflictError()
		}
		if !change.Enabled || !budget.Enabled || change.LimitQuota < budget.LimitQuota {
			if err := revokeBudgetLeasesTx(tx, usage.Id); err != nil {
				return status, err
			}
		}
		budget.LimitQuota, budget.Enabled, budget.Version, budget.UpdatedAt = change.LimitQuota, change.Enabled, budget.Version+1, now
		err = tx.Model(&Budget{}).Where("id = ?", budget.Id).Updates(map[string]any{"limit_quota": budget.LimitQuota,
			"enabled": budget.Enabled, "version": budget.Version, "updated_at": now}).Error
		if err != nil {
			return status, err
		}
	}
	if err := BumpOrgPolicyVersionTx(tx, change.OrgID); err != nil {
		return status, err
	}
	fresh, err := orgFindOne[OrgBudgetUsage](lockForUpdate(tx.Where("id = ?", usage.Id))) // latest committed, not the snapshot
	if err != nil {
		return status, err
	}
	status = orgBudgetStatus(budget, fresh, key, change.OrgID)
	return status, nil
}

// revokeBudgetLeasesTx revokes every active lease of a usage row and returns
// the part nobody is using: held drops by amount - allocated - consumed and the
// lease shrinks to what is still in flight or already consumed. The usage row
// is already locked by the caller; the leases are locked after it.
func revokeBudgetLeasesTx(tx *gorm.DB, usageID int) error {
	var leases []OrgQuotaLease
	err := lockForUpdate(tx.Where("target_type = ? AND target_id = ? AND status = ?",
		types.OrgLeaseTargetBudget, usageID, types.OrgLeaseStatusActive)).Order("id ASC").Find(&leases).Error
	if err != nil {
		return err
	}
	for _, lease := range leases {
		unused := lease.Amount - lease.Allocated - lease.Consumed
		if unused > 0 {
			if err := tx.Model(&OrgBudgetUsage{}).Where("id = ?", usageID).
				Update("held_quota", gorm.Expr("held_quota - ?", unused)).Error; err != nil {
				return err
			}
		}
		err := tx.Model(&OrgQuotaLease{}).Where("id = ?", lease.Id).
			Updates(map[string]any{"status": types.OrgLeaseStatusRevoked, "amount": lease.Allocated + lease.Consumed}).Error
		if err != nil {
			return err
		}
	}
	return nil
}

// GetOrgBudgetStatus reads a budget and the usage of its current window.
func GetOrgBudgetStatus(ctx context.Context, orgID int, scope string, subjectID int, period string) (OrgBudgetStatus, error) {
	db := DB.WithContext(ctx)
	now, err := orgDBNow(db)
	if err != nil {
		return OrgBudgetStatus{}, err
	}
	start, _ := OrgBudgetWindow(period, now)
	budget, err := orgFindOne[Budget](db.Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ?", orgID, scope, subjectID, period))
	if err != nil {
		return OrgBudgetStatus{}, err
	}
	if budget == nil {
		return OrgBudgetStatus{}, orgNotFoundError()
	}
	usage, err := orgFindOne[OrgBudgetUsage](db.Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ? AND window_start = ?",
		orgID, scope, subjectID, period, start))
	if err != nil {
		return OrgBudgetStatus{}, err
	}
	return orgBudgetStatus(budget, usage, orgUsageKey{scope, subjectID, period, start}, orgID), nil
}

// OrgBudgetPeriodInput is one period of a subject's budget set.
type OrgBudgetPeriodInput struct {
	Period     string
	LimitQuota int64
	Enabled    bool
}

// OrgBudgetSet is every period of one subject with the version the whole set
// carries: the highest version among its rows, 0 when it has none.
type OrgBudgetSet struct {
	Version int64
	Periods []OrgBudgetStatus
}

// periodsOrdered lists the periods from the shortest to the longest.
var periodsOrdered = []string{types.BudgetPeriodDaily, types.BudgetPeriodWeekly, types.BudgetPeriodMonthly, types.BudgetPeriodLifetime}

// validateBudgetPeriods checks a set before anything is written: every period
// known and listed once, limits inside the wallet domain, and each enabled
// longer period at least as large as every enabled shorter one (lifetime >=
// monthly >= weekly >= daily), comparing only the periods that are configured.
func validateBudgetPeriods(periods []OrgBudgetPeriodInput) error {
	seen := map[string]OrgBudgetPeriodInput{}
	for _, p := range periods {
		if _, dup := seen[p.Period]; dup || !slices.Contains(periodsOrdered, p.Period) ||
			p.LimitQuota < 0 || p.LimitQuota > common.MaxWalletQuota {
			return orgInvalidError()
		}
		seen[p.Period] = p
	}
	var floor int64
	for _, name := range periodsOrdered {
		p, ok := seen[name]
		if !ok || !p.Enabled {
			continue
		}
		if p.LimitQuota < floor {
			return orgInvalidError()
		}
		floor = p.LimitQuota
	}
	return nil
}

// GetOrgBudgetSet reads every configured period of a subject with its usage.
func GetOrgBudgetSet(ctx context.Context, orgID int, scope string, subjectID int) (OrgBudgetSet, error) {
	set := OrgBudgetSet{}
	var budgets []Budget
	if err := DB.WithContext(ctx).Where("org_id = ? AND scope = ? AND subject_id = ?", orgID, scope, subjectID).
		Find(&budgets).Error; err != nil {
		return set, err
	}
	for _, name := range periodsOrdered {
		for _, budget := range budgets {
			if budget.Period != name {
				continue
			}
			set.Version = max(set.Version, budget.Version)
			status, err := GetOrgBudgetStatus(ctx, orgID, scope, subjectID, name)
			if err != nil {
				return set, err
			}
			set.Periods = append(set.Periods, status)
		}
	}
	return set, nil
}

// ReplaceOrgBudgetSet makes the listed periods the subject's whole budget in one
// transaction. A period that is not listed but is configured is disabled, not
// deleted, so its spend history stays. Each period takes effect the way
// ChangeBudgetLimit does (a lowering revokes leases). expectedVersion > 0 must
// equal the set's current version, or nothing is written. tighten makes the
// write one that can only lower limits and cannot disable or add a period, for
// a person narrowing their own key.
func ReplaceOrgBudgetSet(ctx context.Context, orgID int, scope string, subjectID int, periods []OrgBudgetPeriodInput,
	expectedVersion int64, tighten bool) (OrgBudgetSet, error) {
	if err := validateBudgetPeriods(periods); err != nil {
		return OrgBudgetSet{}, err
	}
	err := retryOrgTx(ctx, func(tx *gorm.DB) error {
		var current []Budget
		if err := lockForUpdate(tx.Where("org_id = ? AND scope = ? AND subject_id = ?", orgID, scope, subjectID)).
			Order("id ASC").Find(&current).Error; err != nil {
			return err
		}
		var version int64
		existing := map[string]Budget{}
		for _, budget := range current {
			existing[budget.Period] = budget
			version = max(version, budget.Version)
		}
		if expectedVersion > 0 && expectedVersion != version {
			return orgConflictError()
		}
		listed := map[string]bool{}
		for _, p := range periods {
			listed[p.Period] = true
			if tighten && !isTightening(existing[p.Period], existing[p.Period].Period != "", p) {
				return types.NewOrgAccessError(types.OrgErrForbidden)
			}
		}
		for _, budget := range current {
			if tighten && budget.Enabled && !listed[budget.Period] {
				return types.NewOrgAccessError(types.OrgErrForbidden) // dropping a period would loosen it
			}
		}
		for _, name := range periodsOrdered {
			p, isListed := periodInput(periods, name)
			prior, hadRow := existing[name]
			if !isListed {
				if !hadRow || !prior.Enabled {
					continue
				}
				p = OrgBudgetPeriodInput{Period: name, LimitQuota: prior.LimitQuota, Enabled: false}
			}
			if hadRow && prior.Enabled == p.Enabled && prior.LimitQuota == p.LimitQuota {
				continue // unchanged: no new version, no churn
			}
			if _, err := changeBudgetLimitTx(tx, OrgBudgetChange{OrgID: orgID, Scope: scope, SubjectID: subjectID,
				Period: name, LimitQuota: p.LimitQuota, Enabled: p.Enabled}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return OrgBudgetSet{}, err
	}
	return GetOrgBudgetSet(ctx, orgID, scope, subjectID)
}

func periodInput(periods []OrgBudgetPeriodInput, name string) (OrgBudgetPeriodInput, bool) {
	for _, p := range periods {
		if p.Period == name {
			return p, true
		}
	}
	return OrgBudgetPeriodInput{}, false
}

// isTightening reports whether replacing prior by next can only make the budget
// stricter: an existing enabled period stays enabled with a limit that does not
// go up. Adding a period that was never set is also a tightening; enabling one
// that had been switched off is not.
func isTightening(prior Budget, hadRow bool, next OrgBudgetPeriodInput) bool {
	if !hadRow {
		return next.Enabled
	}
	if !prior.Enabled {
		return !next.Enabled
	}
	return next.Enabled && next.LimitQuota <= prior.LimitQuota
}
