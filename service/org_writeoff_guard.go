package service

import (
	"context"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/model_setting"
	hosttypes "github.com/QuantumNous/new-api/types"
)

// writeoffGuardTTL bounds how stale the day's write-off total may be. The total
// only moves when the fold runs, once a second, so a few seconds of lag costs a
// few requests at most and saves a query on every admission.
const writeoffGuardTTL = 5 * time.Second

type writeoffKey struct {
	orgID int
	model string
	day   string
}

type writeoffEntry struct {
	total   int64
	fetched time.Time
}

var writeoffGuard = struct {
	mu      sync.Mutex
	entries map[writeoffKey]writeoffEntry
}{entries: map[writeoffKey]writeoffEntry{}}

// ResetOrgWriteoffGuard forgets cached totals (for tests).
func ResetOrgWriteoffGuard() {
	writeoffGuard.mu.Lock()
	defer writeoffGuard.mu.Unlock()
	writeoffGuard.entries = map[writeoffKey]writeoffEntry{}
}

// checkOrgWriteoffLimit refuses new work for a model once the platform has
// absorbed more than the daily cap of overage for this organization and model
// since 00:00 UTC (design 4.2.3). Settlement of work already admitted is never
// affected, and the next UTC day starts a new total.
func checkOrgWriteoffLimit(ctx context.Context, subject hosttypes.OrgSubject, modelName string) error {
	limit := int64(model_setting.OrgWriteoffDailyLimitUSD() * common.QuotaPerUnit)
	if limit <= 0 || subject.OrgID <= 0 {
		return nil
	}
	now := time.Now()
	key := writeoffKey{orgID: subject.OrgID, model: modelName, day: now.UTC().Format("2006-01-02")}
	writeoffGuard.mu.Lock()
	entry, ok := writeoffGuard.entries[key]
	writeoffGuard.mu.Unlock()
	if !ok || now.Sub(entry.fetched) > writeoffGuardTTL {
		total, err := model.OrgWriteoffToday(ctx, subject.OrgID, modelName)
		if err != nil {
			return err
		}
		entry = writeoffEntry{total: total, fetched: now}
		writeoffGuard.mu.Lock()
		if len(writeoffGuard.entries) > 4096 {
			writeoffGuard.entries = map[writeoffKey]writeoffEntry{}
		}
		writeoffGuard.entries[key] = entry
		writeoffGuard.mu.Unlock()
	}
	if entry.total > limit {
		return hosttypes.NewOrgAccessError(hosttypes.OrgErrWriteoffLimited)
	}
	return nil
}
