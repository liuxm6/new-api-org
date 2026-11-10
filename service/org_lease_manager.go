package service

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	hosttypes "github.com/QuantumNous/new-api/types"

	"github.com/google/uuid"
)

const (
	leaseTargetsTTL    = 2 * time.Second
	leaseRefreshAfter  = 6 * time.Second
	leaseRetryAfter    = time.Second
	leaseRecentBucket  = 5 * time.Second
	leaseMinimumRecent = 1
)

// orgLeaseManager keeps this instance's quota leases (design 4.2.2). A request
// asks it for hints; a lease only ever makes a reservation cheaper, so a stale
// or missing hint is harmless: the conditional update inside the reservation is
// the authority and falls back to a locked-row hold.
type orgLeaseManager struct {
	instance string
	disabled atomic.Bool

	mu      sync.Mutex
	targets map[hosttypes.OrgSubject]cachedTargets
	leases  map[leaseKey]*cachedLease
	recent  map[int]*recentSpend
	turn    atomic.Uint64
}

type cachedTargets struct {
	list    []model.OrgLeaseTarget
	fetched time.Time
}

type leaseKey struct {
	orgID  int
	target model.OrgLeaseTarget
	shard  int
}

type cachedLease struct {
	id       int
	acquired time.Time
	attempt  time.Time
	stale    bool
}

// recentSpend approximates the spend of the last ten seconds with two buckets.
type recentSpend struct {
	bucket   int64
	current  int64
	previous int64
}

var leaseManager = newOrgLeaseManager()

func newOrgLeaseManager() *orgLeaseManager {
	m := &orgLeaseManager{instance: common.NodeName + ":" + uuid.NewString(),
		targets: map[hosttypes.OrgSubject]cachedTargets{}, leases: map[leaseKey]*cachedLease{}, recent: map[int]*recentSpend{}}
	if off, _ := strconv.ParseBool(os.Getenv("ORG_QUOTA_LEASES_DISABLED")); off {
		m.disabled.Store(true)
	}
	return m
}

// SetOrgQuotaLeasesEnabled turns the lease path on or off. Off, every
// reservation takes locked-row holds, which is correct and slower.
func SetOrgQuotaLeasesEnabled(enabled bool) { leaseManager.disabled.Store(!enabled) }

// ResetOrgQuotaLeases forgets everything the manager cached (for tests).
func ResetOrgQuotaLeases() {
	leaseManager.mu.Lock()
	defer leaseManager.mu.Unlock()
	leaseManager.targets = map[hosttypes.OrgSubject]cachedTargets{}
	leaseManager.leases = map[leaseKey]*cachedLease{}
	leaseManager.recent = map[int]*recentSpend{}
}

// RevokeOrgInstanceQuotaLeases returns this instance's leases on a normal exit.
func RevokeOrgInstanceQuotaLeases(ctx context.Context) {
	if _, err := model.RevokeOrgInstanceLeases(ctx, leaseManager.instance); err != nil {
		logger.LogError(ctx, common.LogText("cannot revoke this instance's organization leases: %s", err.Error()))
	}
}

func (m *orgLeaseManager) bucket(now time.Time) int64 {
	return now.UnixNano() / int64(leaseRecentBucket)
}

// consumed records what a settled request cost, the basis of the next grant.
func (m *orgLeaseManager) consumed(orgID int, quota int64) {
	if quota <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	spend := m.recent[orgID]
	if spend == nil {
		spend = &recentSpend{}
		m.recent[orgID] = spend
	}
	m.roll(spend, time.Now())
	spend.current += quota
}

func (m *orgLeaseManager) roll(spend *recentSpend, now time.Time) {
	current := m.bucket(now)
	switch {
	case current == spend.bucket:
	case current == spend.bucket+1:
		spend.previous, spend.current = spend.current, 0
	default:
		spend.previous, spend.current = 0, 0
	}
	spend.bucket = current
}

func (m *orgLeaseManager) recentSpend(orgID int, now time.Time) int64 {
	spend := m.recent[orgID]
	if spend == nil {
		return 0
	}
	m.roll(spend, now)
	return spend.current + spend.previous
}

// hints returns the lease hints for one reservation of the subject.
func (m *orgLeaseManager) hints(ctx context.Context, subject hosttypes.OrgSubject) []hosttypes.OrgLeaseHint {
	if m.disabled.Load() {
		return nil
	}
	now := time.Now()
	m.mu.Lock()
	recent := m.recentSpend(subject.OrgID, now)
	cached, ok := m.targets[subject]
	m.mu.Unlock()
	if recent < leaseMinimumRecent {
		return nil // a quiet organization has nothing to lease against yet
	}
	if !ok || now.Sub(cached.fetched) > leaseTargetsTTL {
		list, err := model.OrgLeaseTargets(ctx, subject)
		if err != nil {
			return nil
		}
		cached = cachedTargets{list: list, fetched: now}
		m.mu.Lock()
		m.targets[subject] = cached
		m.mu.Unlock()
	}
	// Each target gets its own shard number. One number for all of them would
	// make requests that draw the same shard wait on one another along the whole
	// chain of lease rows instead of queueing on each row independently.
	turn := m.turn.Add(1)
	hints := make([]hosttypes.OrgLeaseHint, 0, len(cached.list))
	for i, target := range cached.list {
		shard := int(mixShard(turn, uint64(i)) % uint64(model.OrgLeaseShards))
		if id := m.lease(ctx, leaseKey{orgID: subject.OrgID, target: target, shard: shard}, recent, now); id > 0 {
			hints = append(hints, hosttypes.OrgLeaseHint{TargetType: target.TargetType, TargetId: target.TargetID, LeaseId: id})
		}
	}
	return hints
}

// lease returns a usable lease id for the key, acquiring a new one when the
// cached one is missing, old or known to be used up.
func (m *orgLeaseManager) lease(ctx context.Context, key leaseKey, recent int64, now time.Time) int {
	m.mu.Lock()
	entry := m.leases[key]
	if entry != nil && entry.id > 0 && !entry.stale && now.Sub(entry.acquired) < leaseRefreshAfter {
		id := entry.id
		m.mu.Unlock()
		return id
	}
	if entry != nil && now.Sub(entry.attempt) < leaseRetryAfter {
		id := entry.id
		if entry.stale {
			id = 0
		}
		m.mu.Unlock()
		return id
	}
	if entry == nil {
		entry = &cachedLease{}
		m.leases[key] = entry
	}
	entry.attempt = now
	m.mu.Unlock()

	granted, err := model.AcquireOrgQuotaLease(ctx, model.OrgLeaseRequest{OrgID: key.orgID, TargetType: key.target.TargetType,
		TargetID: key.target.TargetID, InstanceID: m.instance, Shard: key.shard, RecentConsumed: recent})
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil || granted == nil {
		entry.id, entry.stale = 0, false
		return 0
	}
	entry.id, entry.acquired, entry.stale = granted.Id, now, false
	return granted.Id
}

// observe marks a hinted lease stale when the reservation had to take a locked
// row instead: the lease was full, revoked or expired.
func (m *orgLeaseManager) observe(subject hosttypes.OrgSubject, hints []hosttypes.OrgLeaseHint, holds []hosttypes.OrgHold) {
	if len(hints) == 0 {
		return
	}
	used := map[int]bool{}
	for _, hold := range holds {
		if id, err := strconv.Atoi(hold.Source); err == nil {
			used[id] = true
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, entry := range m.leases {
		if key.orgID != subject.OrgID || entry.id == 0 || used[entry.id] {
			continue
		}
		for _, hint := range hints {
			if hint.LeaseId == entry.id {
				entry.stale = true
			}
		}
	}
}

// mixShard spreads a request counter over the shards differently for each
// target position, so two requests rarely meet on the same shard of every target.
func mixShard(turn, position uint64) uint64 {
	x := turn*0x9E3779B97F4A7C15 + position*0xBF58476D1CE4E5B9
	x ^= x >> 31
	return x
}
