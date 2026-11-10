package middleware

import (
	"errors"
	"fmt"
	"sync"

	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// Context keys set once a dashboard session has passed the scope check.
const (
	sessionAuthScopeContextKey = "session_auth_scope"
	sessionOrgIDContextKey     = "session_org_id"
)

// errSessionScopeDenied is returned by session authentication when a session
// restricted to one organization reaches a route outside its allowlist.
var errSessionScopeDenied = errors.New("session scope does not permit this route")

var (
	orgSessionRoutesMu sync.RWMutex
	orgSessionRoutes   = map[string]bool{}
)

// DeclareOrgSessionRoute allows org-restricted sessions to call a route. The
// default is deny: a route nobody declared is unreachable for an org session,
// so a forgotten route can never expose personal funds, personal keys, other
// organizations or the platform.
func DeclareOrgSessionRoute(method, fullPath string) {
	orgSessionRoutesMu.Lock()
	defer orgSessionRoutesMu.Unlock()
	orgSessionRoutes[method+" "+fullPath] = true
}

// OrgSessionRouteAllowed reports whether an org-restricted session may call
// the route.
func OrgSessionRouteAllowed(method, fullPath string) bool {
	orgSessionRoutesMu.RLock()
	defer orgSessionRoutesMu.RUnlock()
	return orgSessionRoutes[method+" "+fullPath]
}

// OrgSessionRouteKeys lists the allowlist, for tests and audits.
func OrgSessionRouteKeys() []string {
	orgSessionRoutesMu.RLock()
	defer orgSessionRoutesMu.RUnlock()
	keys := make([]string, 0, len(orgSessionRoutes))
	for key := range orgSessionRoutes {
		keys = append(keys, key)
	}
	return keys
}

// checkSessionScope applies the session's auth_scope to the matched route. A
// global session always passes. An org session passes only on declared routes
// and only while it is bound to an organization. Anything else, including a
// scope value this build does not know, is refused.
func checkSessionScope(c *gin.Context, scope string, orgID int) error {
	switch scope {
	case types.AuthScopeGlobal:
		c.Set(sessionAuthScopeContextKey, types.AuthScopeGlobal)
		return nil
	case types.AuthScopeOrg:
		if orgID > 0 && OrgSessionRouteAllowed(c.Request.Method, c.FullPath()) {
			c.Set(sessionAuthScopeContextKey, types.AuthScopeOrg)
			c.Set(sessionOrgIDContextKey, orgID)
			return nil
		}
	}
	return fmt.Errorf("%w: %s %s", errSessionScopeDenied, c.Request.Method, c.FullPath())
}

// SessionOrgScope returns the organization an org-restricted session is bound
// to, or 0 for a global session.
func SessionOrgScope(c *gin.Context) int {
	return c.GetInt(sessionOrgIDContextKey)
}
