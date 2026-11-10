package org

import (
	"fmt"
	"sync"
	"time"
)

// The membership cache is a performance aid for the control plane only. Its
// keys embed the organization's policy_version, which is read from the primary
// database on every request and advanced in the same transaction as any role,
// status, grant or policy write. A write therefore changes the key of every
// later read, so a stale entry is unreachable rather than invalidated, and the
// cache cannot disagree with the database about who may do what. Write paths
// never rely on it (see RequireOrgRoleTx).
const (
	accessCacheTTL = 30 * time.Second
	accessCacheCap = 20000
)

type accessCacheEntry struct {
	role    string
	status  int
	found   bool
	expires time.Time
}

type accessCache struct {
	mu      sync.Mutex
	entries map[string]accessCacheEntry
}

var memberAccessCache = &accessCache{entries: map[string]accessCacheEntry{}}

// orgMemberCacheKey is org:member:{org}:{user}:{version}.
func orgMemberCacheKey(orgID, userID int, version int64) string {
	return fmt.Sprintf("org:member:%d:%d:%d", orgID, userID, version)
}

// wsMemberCacheKey is org:wsmember:{org}:{workspace}:{user}:{version}.
func wsMemberCacheKey(orgID, workspaceID, userID int, version int64) string {
	return fmt.Sprintf("org:wsmember:%d:%d:%d:%d", orgID, workspaceID, userID, version)
}

func (c *accessCache) get(key string) (accessCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expires) {
		delete(c.entries, key)
		return accessCacheEntry{}, false
	}
	return entry, true
}

func (c *accessCache) put(key string, entry accessCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= accessCacheCap {
		c.entries = map[string]accessCacheEntry{}
	}
	entry.expires = time.Now().Add(accessCacheTTL)
	c.entries[key] = entry
}

// ResetAccessCache drops every entry. Production never needs it because keys
// are versioned by policy_version. It exists for code that swaps the database
// under a running process (tests), since ids and versions repeat across
// databases, and for an operator who edited membership rows by hand without
// bumping policy_version.
func ResetAccessCache() {
	memberAccessCache.mu.Lock()
	memberAccessCache.entries = map[string]accessCacheEntry{}
	memberAccessCache.mu.Unlock()
}

func resetAccessCache() { ResetAccessCache() }
