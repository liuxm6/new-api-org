package model

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadParam(name string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(name)); err == nil && value > 0 {
		return value
	}
	return fallback
}

// TestOrgBillingLoad drives the whole money path of one organization at once:
// reserve and capture under wallet and four budget layers while the fold worker
// runs. The defaults are a two-second correctness run; set TEST_ORG_LOAD_WORKERS
// and TEST_ORG_LOAD_SECONDS for a capacity run on MySQL or PostgreSQL. Latency
// is logged, not asserted: it depends on the hardware, and the target is read
// against a personal-billing baseline measured on the same machine.
func TestOrgBillingLoad(t *testing.T) {
	for _, mode := range []string{"direct", "leases"} {
		t.Run(mode, func(t *testing.T) { runOrgBillingLoad(t, mode == "leases") })
	}
}

// loadLeases keeps a few active leases per target and renews them, as the
// instance lease manager does: the shard a worker uses spreads the contention.
type loadLeases struct {
	mu      sync.Mutex
	hints   [][]types.OrgLeaseHint
	byKey   map[int][][]types.OrgLeaseHint
	current map[int][][]types.OrgLeaseHint
}

func (l *loadLeases) pick(worker int, key Token) []types.OrgLeaseHint {
	l.mu.Lock()
	defer l.mu.Unlock()
	shards := l.current[key.Id]
	if len(shards) == 0 {
		return nil
	}
	return shards[worker%len(shards)]
}

func (l *loadLeases) renew(t *testing.T, e *billingEnv, keys []Token, recent int64) {
	started := time.Now()
	defer func() {
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Logf("%s: one lease renewal round took %v (leases live %ds)", e.dialect, elapsed, OrgLeaseTTLSeconds)
		}
	}()
	// The usage ids are read here: the shards below run concurrently, as the
	// requests of a real instance do, and a testing.T must not fail from them.
	shared := []struct {
		targetType string
		id         int
	}{{types.OrgLeaseTargetWallet, e.f.wallet.Id}}
	for _, subject := range []struct {
		scope string
		id    int
	}{{types.BudgetScopeOrg, e.f.org.Id}, {types.BudgetScopeWorkspace, e.f.workspace.Id},
		{types.BudgetScopeMember, e.f.member.Id}} {
		shared = append(shared, struct {
			targetType string
			id         int
		}{types.OrgLeaseTargetBudget, e.usage(t, subject.scope, subject.id, types.BudgetPeriodMonthly).Id})
	}
	keyUsage := make([]int, len(keys))
	for i, key := range keys {
		keyUsage[i] = e.usage(t, types.BudgetScopeKey, key.Id, types.BudgetPeriodMonthly).Id
	}

	shards := make([][]types.OrgLeaseHint, OrgLeaseShards)
	perKey := make([][][]types.OrgLeaseHint, OrgLeaseShards) // shard -> key index -> hints
	var wg sync.WaitGroup
	for shard := range OrgLeaseShards {
		wg.Go(func() {
			ask := func(targetType string, targetID int) (types.OrgLeaseHint, bool) {
				lease, err := AcquireOrgQuotaLease(context.Background(), OrgLeaseRequest{OrgID: e.f.org.Id, TargetType: targetType,
					TargetID: targetID, InstanceID: "load", Shard: shard, RecentConsumed: recent})
				if err != nil || lease == nil {
					return types.OrgLeaseHint{}, false
				}
				return types.OrgLeaseHint{TargetType: targetType, TargetId: targetID, LeaseId: lease.Id}, true
			}
			var hints []types.OrgLeaseHint
			for _, target := range shared {
				if hint, ok := ask(target.targetType, target.id); ok {
					hints = append(hints, hint)
				}
			}
			shards[shard] = hints
			perKey[shard] = make([][]types.OrgLeaseHint, len(keys))
			for i := range keys {
				keyHints := slices.Clone(hints)
				if hint, ok := ask(types.OrgLeaseTargetBudget, keyUsage[i]); ok {
					keyHints = append(keyHints, hint)
				}
				perKey[shard][i] = keyHints
			}
		})
	}
	wg.Wait()
	byKey := map[int][][]types.OrgLeaseHint{}
	for _, shardKeys := range perKey {
		for i, key := range keys {
			byKey[key.Id] = append(byKey[key.Id], shardKeys[i])
		}
	}
	l.mu.Lock()
	l.hints = shards
	l.current = byKey
	l.mu.Unlock()
}

func runOrgBillingLoad(t *testing.T, useLeases bool) {
	t.Helper()
	workers := loadParam("TEST_ORG_LOAD_WORKERS", 16)
	duration := time.Duration(loadParam("TEST_ORG_LOAD_SECONDS", 2)) * time.Second
	const bound, price = 10, 7

	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		ctx := context.Background()
		OrgLeaseShards, leaseGrantDivisor = loadParam("TEST_ORG_LOAD_SHARDS", orgLeaseShardsFromEnv()), 0
		if e.dialect == "sqlite" && workers > 32 {
			t.Skip("SQLite has one writer; the capacity run is for MySQL and PostgreSQL")
		}
		e.reset(t, 1<<40)
		e.seedLedger(t, 1<<40) // the reconciliation counts credits from the ledger
		e.setBudget(t, types.BudgetScopeOrg, e.f.org.Id, types.BudgetPeriodMonthly, 1<<40)
		e.setBudget(t, types.BudgetScopeWorkspace, e.f.workspace.Id, types.BudgetPeriodMonthly, 1<<40)
		e.setBudget(t, types.BudgetScopeMember, e.f.member.Id, types.BudgetPeriodMonthly, 1<<40)
		// A team has many keys; one limited key is a shared counter that every
		// request on it must lock, so a single key measures its own worst case.
		keyCount := loadParam("TEST_ORG_LOAD_KEYS", 1)
		keys := []Token{e.f.memberKey}
		for i := 1; i < keyCount; i++ {
			keys = append(keys, e.limitedKey(t, fmt.Sprintf("load-%d", i), 1<<40))
		}
		for _, key := range keys {
			e.setBudget(t, types.BudgetScopeKey, key.Id, types.BudgetPeriodMonthly, 1<<40)
		}

		var (
			sequence  atomic.Int64
			failures  atomic.Int64
			firstFail atomic.Value
			mu        sync.Mutex
			latencies []time.Duration
			stopFold  = make(chan struct{})
			foldDone  = make(chan struct{})
			maxLag    atomic.Int64
			foldRuns  atomic.Int64
			foldRows  atomic.Int64
			foldTime  atomic.Int64
		)
		go func() {
			defer close(foldDone)
			for {
				select {
				case <-stopFold:
					return
				case <-time.After(time.Duration(loadParam("TEST_ORG_FOLD_MS", 100)) * time.Millisecond):
				}
				if os.Getenv("TEST_ORG_NO_FOLD") != "" {
					continue // lets a capacity run measure the hot path without the fold
				}
				started := time.Now()
				result, err := FoldOrgSpend(ctx, e.f.org.Id, loadParam("TEST_ORG_FOLD_LIMIT", 2000))
				if err != nil {
					failures.Add(1)
					firstFail.CompareAndSwap(nil, "fold: "+err.Error())
				}
				if result.Rows > 0 {
					foldRuns.Add(1)
					foldRows.Add(int64(result.Rows))
					foldTime.Add(int64(time.Since(started)))
				}
				maxLag.Store(max(maxLag.Load(), int64(time.Since(started))))
			}
		}()

		leases := &loadLeases{byKey: map[int][][]types.OrgLeaseHint{}}
		stopRenew := make(chan struct{})
		var renewDone sync.WaitGroup
		if useLeases {
			// 10 seconds of lease at the offered rate: about a second of spend, doubled by the grant rule
			recent := int64(price) * int64(workers) * 100
			leases.renew(t, e, keys, recent)
			renewDone.Go(func() {
				for {
					select {
					case <-stopRenew:
						return
					case <-time.After(3 * time.Second):
						leases.renew(t, e, keys, recent)
					}
				}
			})
		}

		// TEST_ORG_SAMPLE_MS turns on a sampler for long capacity runs: the age of
		// the oldest queued row (the fold lag, a plan target is p99 < 3s) and a
		// reconciliation of the whole organization while the load is running.
		var (
			lagMu      sync.Mutex
			lagSamples []time.Duration
			driftSeen  atomic.Int64
			firstDrift atomic.Value
			reconciles atomic.Int64
		)
		stopSample := make(chan struct{})
		var sampleDone sync.WaitGroup
		if every := loadParam("TEST_ORG_SAMPLE_MS", 0); every > 0 {
			reconcileEvery := loadParam("TEST_ORG_RECONCILE_MS", 30_000)
			sampleDone.Go(func() {
				lastReconcile := time.Now()
				for {
					select {
					case <-stopSample:
						return
					case <-time.After(time.Duration(every) * time.Millisecond):
					}
					var oldest int64
					if err := e.db.Model(&OrgSpendFoldQueue{}).Where("org_id = ?", e.f.org.Id).
						Select("COALESCE(MIN(created_at), 0)").Scan(&oldest).Error; err == nil && oldest > 0 {
						lagMu.Lock()
						lagSamples = append(lagSamples, time.Since(time.Unix(oldest, 0)))
						lagMu.Unlock()
					} else if err == nil {
						lagMu.Lock()
						lagSamples = append(lagSamples, 0)
						lagMu.Unlock()
					}
					if time.Since(lastReconcile) >= time.Duration(reconcileEvery)*time.Millisecond {
						lastReconcile = time.Now()
						drifts, err := ReconcileOrg(ctx, e.f.org.Id)
						reconciles.Add(1)
						if err == nil && len(drifts) > 0 {
							// work in flight can look like drift; only a repeat counts
							time.Sleep(3 * time.Second)
							if drifts, err = ReconcileOrg(ctx, e.f.org.Id); err == nil && len(drifts) > 0 {
								driftSeen.Add(1)
								firstDrift.CompareAndSwap(nil, drifts[0].String())
							}
						}
					}
				}
			})
		}

		stopNegative := e.watchNeverNegative(t)
		deadline := time.Now().Add(duration)
		var wg sync.WaitGroup
		for worker := range workers {
			wg.Go(func() {
				var own []time.Duration
				for time.Now().Before(deadline) {
					id := fmt.Sprintf("load-%d", sequence.Add(1))
					started := time.Now()
					reserve := e.cmd(t, keys[worker%len(keys)], id, types.OrgBillingActionReserve)
					reserve.Bound = bound
					reserve.LeaseHints = leases.pick(worker, keys[worker%len(keys)])
					if _, err := ApplyOrgBilling(ctx, reserve); err != nil {
						failures.Add(1)
						firstFail.CompareAndSwap(nil, "reserve: "+err.Error())
						continue
					}
					capture := e.cmd(t, keys[worker%len(keys)], id, types.OrgBillingActionCapture)
					capture.Amount, capture.Revision = price, 1
					if _, err := ApplyOrgBilling(ctx, capture); err != nil {
						failures.Add(1)
						firstFail.CompareAndSwap(nil, "capture: "+err.Error())
						continue
					}
					own = append(own, time.Since(started))
				}
				mu.Lock()
				latencies = append(latencies, own...)
				mu.Unlock()
			})
		}
		wg.Wait()
		close(stopRenew)
		renewDone.Wait()
		stopNegative()
		close(stopFold)
		<-foldDone
		close(stopSample)
		sampleDone.Wait()

		for {
			result, err := FoldOrgSpend(ctx, e.f.org.Id, 2000)
			require.NoError(t, err)
			if result.Rows == 0 {
				break
			}
		}

		require.NoError(t, e.db.Model(&OrgQuotaLease{}).Where("status = ?", types.OrgLeaseStatusActive).
			Update("expires_at", time.Now().Unix()-5).Error)
		for {
			swept, err := SweepOrgQuotaLeases(ctx, 500)
			require.NoError(t, err)
			if swept.Revoked+swept.Closed == 0 {
				break
			}
		}
		for {
			result, err := FoldOrgSpend(ctx, e.f.org.Id, 2000)
			require.NoError(t, err)
			if result.Rows == 0 {
				break
			}
		}

		require.NotEmpty(t, latencies, "no request completed")
		assert.Zero(t, failures.Load(), "unexpected failures, first: %v", firstFail.Load())
		slices.Sort(latencies)
		p := func(q float64) time.Duration { return latencies[min(len(latencies)-1, int(float64(len(latencies))*q))] }
		t.Logf("%s leases=%v: %d workers, %v, %d requests (%.0f/s), reserve+capture p50=%v p99=%v, slowest fold %v",
			e.dialect, useLeases, workers, duration, len(latencies), float64(len(latencies))/duration.Seconds(),
			p(0.50), p(0.99), time.Duration(maxLag.Load()))
		if len(lagSamples) > 0 {
			slices.Sort(lagSamples)
			q := func(f float64) time.Duration {
				return lagSamples[min(len(lagSamples)-1, int(float64(len(lagSamples))*f))]
			}
			t.Logf("%s leases=%v: fold lag (age of the oldest queued row) over %d samples: p50=%v p99=%v max=%v; %d mid-run reconciliations, %d confirmed drifts",
				e.dialect, useLeases, len(lagSamples), q(0.50), q(0.99), lagSamples[len(lagSamples)-1], reconciles.Load(), driftSeen.Load())
			assert.Zero(t, driftSeen.Load(), "a reconciliation under load found drift: %v", firstDrift.Load())
		}
		if sqlDB, err := e.db.DB(); err == nil {
			stats := sqlDB.Stats()
			t.Logf("%s leases=%v: connection pool: max %d, open at the end %d, %d waits totalling %v",
				e.dialect, useLeases, stats.MaxOpenConnections, stats.OpenConnections, stats.WaitCount, stats.WaitDuration)
		}
		if runs := foldRuns.Load(); runs > 0 {
			t.Logf("%s leases=%v: %d folds, %d rows (%.0f rows per fold), %v per fold on average",
				e.dialect, useLeases, runs, foldRows.Load(), float64(foldRows.Load())/float64(runs),
				time.Duration(foldTime.Load()/runs))
		}

		var operations []OrgBillingOperation
		require.NoError(t, e.db.Select("holds").Where("org_id = ?", e.f.org.Id).Find(&operations).Error)
		direct := map[string]int{}
		total := map[string]int{}
		for _, operation := range operations {
			holds, err := decodeOrgHolds(operation.Holds)
			require.NoError(t, err)
			for _, hold := range holds {
				total[hold.TargetType]++
				if hold.Source == types.OrgHoldSourceDirect {
					direct[hold.TargetType]++
				}
			}
		}
		t.Logf("%s leases=%v: holds taken directly (locked row) by target: wallet %d/%d, budget %d/%d, token %d/%d",
			e.dialect, useLeases, direct[types.OrgHoldTargetWallet], total[types.OrgHoldTargetWallet],
			direct[types.OrgHoldTargetBudget], total[types.OrgHoldTargetBudget],
			direct[types.OrgHoldTargetToken], total[types.OrgHoldTargetToken])

		n := int64(len(latencies))
		assert.EqualValues(t, (1<<40)-n*price, e.walletQuota(t), "wallet identity: every request paid exactly its price")
		var spent int64
		require.NoError(t, e.db.Model(&OrgBudgetUsage{}).Where("org_id = ? AND scope = ? AND period = ?", e.f.org.Id, types.BudgetScopeOrg, types.BudgetPeriodMonthly).
			Select("COALESCE(SUM(spent_quota), 0)").Scan(&spent).Error)
		assert.Equal(t, n*price, spent, "the organization budget folded every charge")
		var held int64
		require.NoError(t, e.db.Model(&OrgBudgetUsage{}).Where("org_id = ?", e.f.org.Id).
			Select("COALESCE(SUM(held_quota), 0)").Scan(&held).Error)
		assert.Zero(t, held, "no budget keeps a hold after every request closed")
		assert.Zero(t, e.count(t, &OrgSpendFoldQueue{}), "the fold queue drained")
		e.assertInvariants(t)
	})
}
