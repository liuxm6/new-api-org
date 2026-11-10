package model

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// OrgFoldResult reports one fold batch. SpendSum includes refunds.
type OrgFoldResult struct {
	Rows        int
	SpendSum    int64
	WriteoffSum int64
}

// FoldOrgSpend applies up to limit queued consumption rows of an organization
// in one transaction (design 4.2.5): budget spent and held, lease folded, the
// monthly rollup, the daily write-off total, wallet and key counters, and a
// batch record. It never changes users.quota. Folding is serialized per
// organization by the wallet row lock, and folded_at is read only after that
// lock is granted, so batches are ordered by commit.
func FoldOrgSpend(ctx context.Context, orgID, limit int) (OrgFoldResult, error) {
	if limit <= 0 {
		return OrgFoldResult{}, orgInvalidError()
	}
	// The wallet id never changes, so it is read before the transaction. The
	// transaction must open with the wallet lock and only then read anything
	// without locking: under MySQL repeatable read the first plain read fixes the
	// snapshot, and a snapshot taken before the lock wait would let every waiting
	// worker fold the same rows again.
	org, err := orgFindOne[Organization](DB.WithContext(ctx).Unscoped().Select("id", "billing_user_id").Where("id = ?", orgID))
	if err != nil {
		return OrgFoldResult{}, err
	}
	if org == nil {
		return OrgFoldResult{}, orgNotFoundError()
	}
	var result OrgFoldResult
	err = retryOrgTx(ctx, func(tx *gorm.DB) error {
		var err error
		result, err = foldOrgSpendTx(tx, orgID, org.BillingUserId, limit)
		return err
	})
	return result, err
}

// OrgWriteoffToday is what the platform has absorbed for an organization and
// model since 00:00 UTC; the admission check compares it with the daily cap.
func OrgWriteoffToday(ctx context.Context, orgID int, modelName string) (int64, error) {
	row, err := orgFindOne[OrgWriteoffDaily](DB.WithContext(ctx).Where("org_id = ? AND day = ? AND model_name = ?",
		orgID, time.Now().UTC().Format("2006-01-02"), modelName))
	if row == nil || err != nil {
		return 0, err
	}
	return row.WriteoffQuota, nil
}

// foldCell is the change to one usage row.
type foldCell struct{ spent, held int64 }

// foldRollup identifies one monthly rollup row.
type foldRollup struct {
	period, key, effective string
	workspace              int
}

// foldTotals is everything one batch adds up to.
type foldTotals struct {
	usage     map[orgUsageKey]*foldCell
	leases    map[int]int64            // lease id -> spend taken from it
	tokens    map[int]int64            // token id -> spend
	rollups   map[foldRollup]*[2]int64 // spend, events
	writeoffs map[[2]string]int64      // day, model -> written off
	spend     int64
	writeoff  int64
	requests  int64
}

func foldOrgSpendTx(tx *gorm.DB, orgID, walletUserID, limit int) (OrgFoldResult, error) {
	wallet, err := orgFindOne[User](lockForUpdate(tx.Unscoped().Select("id").Where("id = ?", walletUserID)))
	if err != nil {
		return OrgFoldResult{}, err
	}
	if wallet == nil {
		return OrgFoldResult{}, orgNotFoundError()
	}
	// A new statement after the lock was granted: on PostgreSQL this is
	// clock_timestamp(), not the transaction start time.
	foldedAt, err := orgDBNow(tx)
	if err != nil {
		return OrgFoldResult{}, err
	}
	var rows []OrgSpendFoldQueue
	if err := tx.Where("org_id = ?", orgID).Order("id ASC").Limit(limit).Find(&rows).Error; err != nil {
		return OrgFoldResult{}, err
	}
	if len(rows) == 0 {
		return OrgFoldResult{}, nil
	}
	totals, err := totalOrgFold(tx, orgID, rows, foldedAt)
	if err != nil {
		return OrgFoldResult{}, err
	}
	if err := applyOrgFold(tx, orgID, walletUserID, totals, foldedAt); err != nil {
		return OrgFoldResult{}, err
	}
	ids := make([]int, len(rows))
	for i, row := range rows {
		ids[i] = row.Id
	}
	if err := tx.Where("id IN ?", ids).Delete(&OrgSpendFoldQueue{}).Error; err != nil {
		return OrgFoldResult{}, err
	}
	batch := OrgFoldBatch{OrgId: orgID, FoldedAt: foldedAt, Period: time.Unix(foldedAt, 0).UTC().Format("2006-01"),
		RowCount: len(rows), SpendSum: totals.spend}
	if err := tx.Create(&batch).Error; err != nil {
		return OrgFoldResult{}, err
	}
	if err := applyOrgFoldHot(tx, orgID, totals, foldedAt); err != nil {
		return OrgFoldResult{}, err
	}
	return OrgFoldResult{Rows: len(rows), SpendSum: totals.spend, WriteoffSum: totals.writeoff}, nil
}

// totalOrgFold adds a batch up in memory. Every capture row adds its spend to
// each usage row of its subjects and, where it held budget, releases that much
// held quota; a refund only changes spend and so never touches held.
func totalOrgFold(tx *gorm.DB, orgID int, rows []OrgSpendFoldQueue, foldedAt int64) (*foldTotals, error) {
	totals := &foldTotals{usage: map[orgUsageKey]*foldCell{}, leases: map[int]int64{}, tokens: map[int]int64{},
		rollups: map[foldRollup]*[2]int64{}, writeoffs: map[[2]string]int64{}}
	holdsByRow := make([][]types.OrgHold, len(rows))
	var usageIDs []int
	for i, row := range rows {
		holds, err := decodeOrgHolds(row.Holds)
		if err != nil {
			return nil, err
		}
		holdsByRow[i] = holds
		for _, hold := range holds {
			usageIDs = append(usageIDs, hold.TargetId)
		}
	}
	keyOf := map[int]orgUsageKey{}
	if len(usageIDs) > 0 {
		var usages []OrgBudgetUsage
		if err := tx.Where("id IN ?", usageIDs).Find(&usages).Error; err != nil {
			return nil, err
		}
		for _, usage := range usages {
			keyOf[usage.Id] = orgUsageKey{usage.Scope, usage.SubjectId, usage.Period, usage.WindowStart}
		}
	}
	cell := func(key orgUsageKey) *foldCell {
		if totals.usage[key] == nil {
			totals.usage[key] = &foldCell{}
		}
		return totals.usage[key]
	}
	foldedPeriod := time.Unix(foldedAt, 0).UTC().Format("2006-01")
	foldedDay := time.Unix(foldedAt, 0).UTC().Format("2006-01-02")
	for i, row := range rows {
		for _, key := range orgUsageKeysAt(orgID, row.WorkspaceId, row.ActorUserId, row.TokenId, row.EffectiveAt) {
			cell(key).spent += row.SpendDelta
		}
		if row.Kind == types.OrgFoldKindCapture {
			for _, hold := range holdsByRow[i] {
				key, ok := keyOf[hold.TargetId]
				if !ok {
					return nil, orgConflictError() // a held usage row vanished
				}
				cell(key).held -= row.SpendDelta
				if hold.Source != types.OrgHoldSourceDirect {
					leaseID, err := strconv.Atoi(hold.Source)
					if err != nil {
						return nil, err
					}
					totals.leases[leaseID] += row.SpendDelta
				}
			}
			if row.Revision == 1 {
				totals.requests++
			}
		}
		totals.spend += row.SpendDelta
		totals.writeoff += row.WriteoffQuota
		if row.TokenId > 0 {
			totals.tokens[row.TokenId] += row.SpendDelta
		}
		if row.WriteoffQuota != 0 {
			totals.writeoffs[[2]string{foldedDay, row.ModelName}] += row.WriteoffQuota
		}
		id := foldRollup{period: foldedPeriod, key: row.RollupKey, workspace: row.WorkspaceId,
			effective: time.Unix(row.EffectiveAt, 0).UTC().Format("2006-01")}
		if totals.rollups[id] == nil {
			totals.rollups[id] = &[2]int64{}
		}
		totals.rollups[id][0] += row.SpendDelta
		totals.rollups[id][1]++
	}
	return totals, nil
}

// applyOrgFold writes the part of a batch that only the fold touches, plus the
// key counters. Keys come first, the order reservation and settlement lock
// them in, and the usage rows and leases follow in applyOrgFoldHot in the same
// order every reservation locks them, so a fold cannot deadlock with admission
// or settlement.
func applyOrgFold(tx *gorm.DB, orgID, walletUserID int, totals *foldTotals, foldedAt int64) error {
	// Keys come before usage rows and leases, the order reservation and
	// settlement lock them in (design 4.2.4); the other way round deadlocks with
	// a request that holds a key and wants its lease.
	if err := foldOrgKeyCounters(tx, totals); err != nil {
		return err
	}
	if err := foldOrgCounters(tx, walletUserID, totals); err != nil {
		return err
	}
	return foldOrgRollups(tx, orgID, totals, foldedAt)
}

// applyOrgFoldHot writes the rows that requests also lock: usage rows, then
// leases. It runs last in the transaction so those locks are held only until
// the commit that follows, not through the rollup and queue statements.
func applyOrgFoldHot(tx *gorm.DB, orgID int, totals *foldTotals, foldedAt int64) error {
	keys := make([]orgUsageKey, 0, len(totals.usage))
	for key := range totals.usage {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareOrgUsageKey)
	for _, key := range keys {
		change := totals.usage[key]
		update := func() (int64, error) {
			res := tx.Model(&OrgBudgetUsage{}).
				Where("org_id = ? AND scope = ? AND subject_id = ? AND period = ? AND window_start = ?",
					orgID, key.Scope, key.SubjectID, key.Period, key.WindowStart).
				Updates(map[string]any{"spent_quota": gorm.Expr("spent_quota + ?", change.spent),
					"held_quota": gorm.Expr("held_quota + ?", change.held), "updated_at": foldedAt})
			return res.RowsAffected, res.Error
		}
		// The row almost always exists, so the update is the only statement; zero
		// affected rows (MySQL also reports an unchanged row that way) falls back to
		// creating the row and updating it.
		affected, err := update()
		if err != nil {
			return err
		}
		if affected == 0 {
			if _, err := ensureOrgUsageTx(tx, orgID, key, true); err != nil {
				return err
			}
			if _, err := update(); err != nil {
				return err
			}
		}
	}
	leaseIDs := sortedKeys(totals.leases)
	for _, id := range leaseIDs {
		if err := tx.Model(&OrgQuotaLease{}).Where("id = ?", id).
			Update("folded", gorm.Expr("folded + ?", totals.leases[id])).Error; err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// foldOrgKeyCounters moves used_quota of unlimited keys. A limited key already
// moved its used_quota when it reserved and settled, so only unlimited keys
// are counted here.
func foldOrgKeyCounters(tx *gorm.DB, totals *foldTotals) error {
	tokenIDs := sortedKeys(totals.tokens)
	if len(tokenIDs) == 0 {
		return nil
	}
	// A plain read picks the unlimited keys. Putting the condition on the UPDATE
	// instead makes MySQL lock every scanned key row before it filters, so the
	// fold would queue behind each in-flight request of a limited key.
	var unlimited []int
	if err := tx.Unscoped().Model(&Token{}).Where("id IN ? AND unlimited_quota = ?", tokenIDs, true).
		Order("id ASC").Pluck("id", &unlimited).Error; err != nil {
		return err
	}
	for _, id := range unlimited {
		if err := tx.Unscoped().Model(&Token{}).Where("id = ?", id).
			Update("used_quota", gorm.Expr("used_quota + ?", totals.tokens[id])).Error; err != nil {
			return err
		}
	}
	return nil
}

// foldOrgCounters moves the wallet's used_quota and request_count.
func foldOrgCounters(tx *gorm.DB, walletUserID int, totals *foldTotals) error {
	return tx.Unscoped().Model(&User{}).Where("id = ?", walletUserID).
		Updates(map[string]any{"used_quota": gorm.Expr("used_quota + ?", totals.spend),
			"request_count": gorm.Expr("request_count + ?", totals.requests)}).Error
}

// foldOrgRollups adds the batch to the monthly rollup and the daily write-off
// totals. Folds of one organization are serialized by the wallet lock, so the
// insert-if-missing followed by an increment cannot race with another fold.
func foldOrgRollups(tx *gorm.DB, orgID int, totals *foldTotals, foldedAt int64) error {
	ids := make([]foldRollup, 0, len(totals.rollups))
	for id := range totals.rollups {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b foldRollup) int {
		return strings.Compare(a.period+"|"+a.key+"|"+strconv.Itoa(a.workspace)+"|"+a.effective,
			b.period+"|"+b.key+"|"+strconv.Itoa(b.workspace)+"|"+b.effective)
	})
	for _, id := range ids {
		sum := totals.rollups[id]
		update := func() (int64, error) {
			res := tx.Model(&OrgSpendRollup{}).Where("org_id = ? AND period = ? AND rollup_key = ? AND workspace_id = ? AND effective_period = ?",
				orgID, id.period, id.key, id.workspace, id.effective).
				Updates(map[string]any{"spend_quota": gorm.Expr("spend_quota + ?", sum[0]),
					"event_count": gorm.Expr("event_count + ?", sum[1]), "updated_at": foldedAt})
			return res.RowsAffected, res.Error
		}
		affected, err := update()
		if err != nil {
			return err
		}
		if affected == 0 {
			row := OrgSpendRollup{OrgId: orgID, Period: id.period, RollupKey: id.key, WorkspaceId: id.workspace,
				EffectivePeriod: id.effective, UpdatedAt: foldedAt}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
				return err
			}
			if _, err := update(); err != nil {
				return err
			}
		}
	}
	for day, written := range totals.writeoffs {
		row := OrgWriteoffDaily{OrgId: orgID, Day: day[0], ModelName: day[1]}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			return err
		}
		err := tx.Model(&OrgWriteoffDaily{}).Where("org_id = ? AND day = ? AND model_name = ?", orgID, day[0], day[1]).
			Update("writeoff_quota", gorm.Expr("writeoff_quota + ?", written)).Error
		if err != nil {
			return err
		}
	}
	return nil
}
