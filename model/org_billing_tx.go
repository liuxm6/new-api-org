package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	orgBillingMaxAttempts = 8
	// OrgOperationLeaseSeconds is how long an operation's lease_owner stays
	// valid before the recovery worker may claim the operation (design 4.2.6).
	OrgOperationLeaseSeconds = 120
)

// errOrgRetry marks a transaction that lost a race it can simply replay.
var errOrgRetry = errors.New("organization billing: concurrent change, retry")

// orgLeaseRejected means a conditional update on a lease affected no row. The
// whole command rolls back and runs again with that target forced to a
// locked-row hold, so a revoked or exhausted lease can never admit anything.
// key names the target: "wallet" or "budget:<usage id>".
type orgLeaseRejected struct{ key string }

func (e *orgLeaseRejected) Error() string {
	return fmt.Sprintf("organization lease for %s cannot cover the change", e.key)
}

func orgConflictError() error { return types.NewOrgAccessError(types.OrgErrConflict) }

func orgInvalidError() error { return types.NewOrgAccessError(types.OrgErrInvalidInput) }

func orgNotFoundError() error { return types.NewOrgAccessError(types.OrgErrNotFound) }

// orgFindOne runs the query and returns its first row, or nil when there is
// none. It avoids the "record not found" error that would abort a PostgreSQL
// transaction.
func orgFindOne[T any](query *gorm.DB) (*T, error) {
	var rows []T
	if err := query.Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// orgDBNow reads the database clock in whole seconds. Callers that need the
// time after a lock was granted must call it in a new statement after the lock.
// PostgreSQL uses clock_timestamp(), not now(), which is frozen at transaction
// start.
func orgDBNow(tx *gorm.DB) (int64, error) {
	query := "SELECT CAST(strftime('%s', 'now') AS INTEGER)"
	switch {
	case common.UsingMainDatabase(common.DatabaseTypePostgreSQL):
		query = "SELECT CAST(FLOOR(EXTRACT(EPOCH FROM clock_timestamp())) AS BIGINT)"
	case common.UsingMainDatabase(common.DatabaseTypeMySQL):
		query = "SELECT CAST(UNIX_TIMESTAMP() AS SIGNED)"
	}
	var now int64
	if err := tx.Raw(query).Scan(&now).Error; err != nil {
		return 0, err
	}
	return now, nil
}

// IncreaseOrgWalletTx credits users.quota inside the caller's transaction with
// the same overflow guard as IncreaseUserQuota. It is also the only path that
// may touch an organization wallet.
func IncreaseOrgWalletTx(tx *gorm.DB, userID int, quota int64) error {
	if quota < 0 {
		return errors.New("quota cannot be negative")
	}
	if quota > common.MaxWalletQuota {
		return ErrWalletQuotaLimitExceeded
	}
	if quota == 0 {
		return nil
	}
	result := tx.Unscoped().Model(&User{}).
		Where("id = ? AND quota <= ?", userID, common.MaxWalletQuota-quota).
		Update("quota", gorm.Expr("quota + ?", quota))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 1 {
		return nil
	}
	existing, err := orgFindOne[User](tx.Unscoped().Select("id").Where("id = ?", userID))
	if err != nil {
		return err
	}
	if existing == nil {
		return gorm.ErrRecordNotFound
	}
	return ErrWalletQuotaLimitExceeded
}

// DecreaseOrgWalletTx debits users.quota only while the balance covers it. It
// reports false, without error, when the balance is too small.
func DecreaseOrgWalletTx(tx *gorm.DB, userID int, quota int64) (bool, error) {
	if quota < 0 {
		return false, errors.New("quota cannot be negative")
	}
	if quota == 0 {
		return true, nil
	}
	result := tx.Unscoped().Model(&User{}).
		Where("id = ? AND quota >= ?", userID, quota).
		Update("quota", gorm.Expr("quota - ?", quota))
	return result.RowsAffected == 1, result.Error
}

// OrgWalletAvailable is the spendable part of an organization wallet: the
// users.quota that no lease or direct hold has claimed.
func OrgWalletAvailable(tx *gorm.DB, billingUserID int) (int64, error) {
	user, err := orgFindOne[User](tx.Unscoped().Select("quota").Where("id = ?", billingUserID))
	if err != nil {
		return 0, err
	}
	if user == nil {
		return 0, orgNotFoundError()
	}
	return int64(user.Quota), nil
}

// OrgBudgetWindow returns the UTC window [start, end) containing unix for a
// period. Lifetime budgets have no window: start and end are both zero.
func OrgBudgetWindow(period string, unix int64) (start, end int64) {
	at := time.Unix(unix, 0).UTC()
	day := time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
	switch period {
	case types.BudgetPeriodDaily:
		return day.Unix(), day.AddDate(0, 0, 1).Unix()
	case types.BudgetPeriodWeekly:
		monday := day.AddDate(0, 0, -((int(day.Weekday()) + 6) % 7))
		return monday.Unix(), monday.AddDate(0, 0, 7).Unix()
	case types.BudgetPeriodMonthly:
		first := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
		return first.Unix(), first.AddDate(0, 1, 0).Unix()
	}
	return 0, 0
}

var orgBudgetPeriods = []string{types.BudgetPeriodDaily, types.BudgetPeriodWeekly, types.BudgetPeriodMonthly, types.BudgetPeriodLifetime}

var orgScopeRank = map[string]int{types.BudgetScopeOrg: 0, types.BudgetScopeWorkspace: 1, types.BudgetScopeMember: 2, types.BudgetScopeKey: 3}

var orgPeriodRank = map[string]int{types.BudgetPeriodDaily: 0, types.BudgetPeriodWeekly: 1, types.BudgetPeriodMonthly: 2, types.BudgetPeriodLifetime: 3}

// OrgLeaseExpiry is the expiry of a lease granted at now: ten seconds, and for a
// budget lease never later than two seconds before its window ends. ok is false
// when the window is too close to its end to lease from at all.
func OrgLeaseExpiry(now, windowEnd int64) (expiresAt int64, ok bool) {
	expiresAt = now + OrgLeaseTTLSeconds
	if windowEnd == 0 {
		return expiresAt, true
	}
	expiresAt = min(expiresAt, windowEnd-OrgLeaseWindowMarginSeconds)
	if expiresAt <= now {
		return 0, false
	}
	return expiresAt, true
}

// orgUsageKey names one budget usage row.
type orgUsageKey struct {
	Scope       string
	SubjectID   int
	Period      string
	WindowStart int64
}

func sortOrgUsageKeys(keys []orgUsageKey) {
	slices.SortFunc(keys, func(a, b orgUsageKey) int {
		for _, c := range []int{orgScopeRank[a.Scope] - orgScopeRank[b.Scope], a.SubjectID - b.SubjectID,
			orgPeriodRank[a.Period] - orgPeriodRank[b.Period]} {
			if c != 0 {
				return c
			}
		}
		return int(a.WindowStart - b.WindowStart)
	})
}

// orgBudgetSubjects lists the (scope, subject) pairs an operation touches. A
// system key (actor 0) has no member projection (design 3.1).
func orgBudgetSubjects(orgID, workspaceID, actorID, tokenID int) map[string]int {
	subjects := map[string]int{types.BudgetScopeOrg: orgID}
	if workspaceID > 0 {
		subjects[types.BudgetScopeWorkspace] = workspaceID
	}
	if actorID > 0 {
		subjects[types.BudgetScopeMember] = actorID
	}
	if tokenID > 0 {
		subjects[types.BudgetScopeKey] = tokenID
	}
	return subjects
}

// orgUsageKeysAt lists every usage row an operation belongs to at a time.
func orgUsageKeysAt(orgID, workspaceID, actorID, tokenID int, at int64) []orgUsageKey {
	var keys []orgUsageKey
	for scope, subject := range orgBudgetSubjects(orgID, workspaceID, actorID, tokenID) {
		for _, period := range orgBudgetPeriods {
			start, _ := OrgBudgetWindow(period, at)
			keys = append(keys, orgUsageKey{scope, subject, period, start})
		}
	}
	sortOrgUsageKeys(keys)
	return keys
}

// ensureOrgUsageTx returns the usage row for a key, creating it empty when it
// does not exist. With lock set the read is a locking current read, which also
// sees rows other transactions committed after this transaction's snapshot.
func ensureOrgUsageTx(tx *gorm.DB, orgID int, key orgUsageKey, lock bool) (*OrgBudgetUsage, error) {
	find := func(locked bool) (*OrgBudgetUsage, error) {
		query := tx.Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ? AND window_start = ?",
			orgID, key.Scope, key.SubjectID, key.Period, key.WindowStart)
		if locked {
			query = lockForUpdate(query)
		}
		return orgFindOne[OrgBudgetUsage](query)
	}
	row, err := find(false)
	if err != nil {
		return nil, err
	}
	if row == nil {
		fresh := OrgBudgetUsage{OrgId: orgID, Scope: key.Scope, SubjectId: key.SubjectID, Period: key.Period,
			WindowStart: key.WindowStart, UpdatedAt: common.GetTimestamp()}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&fresh).Error; err != nil {
			return nil, err
		}
	}
	if row != nil && !lock {
		return row, nil
	}
	row, err = find(lock)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, errOrgRetry
	}
	return row, nil
}

// orgRollupKey normalizes model, pricing version, currency and quota
// conversion into the statement grouping key (design 3.1).
func orgRollupKey(modelName, priceSnapshot string) string {
	var snap struct {
		PricingVersion string `json:"pricing_version"`
		Currency       string `json:"currency"`
		QuotaPerUnit   string `json:"quota_per_unit"`
	}
	if priceSnapshot != "" {
		if err := common.UnmarshalJsonStr(priceSnapshot, &snap); err != nil {
			snap.PricingVersion, snap.Currency, snap.QuotaPerUnit = "", "", ""
		}
	}
	key := strings.Join([]string{modelName, snap.PricingVersion, snap.Currency, snap.QuotaPerUnit}, "|")
	if len(key) > 120 {
		sum := sha256.Sum256([]byte(key))
		key = "h:" + hex.EncodeToString(sum[:])[:60]
	}
	return key
}
