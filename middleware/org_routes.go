package middleware

import (
	"fmt"
	"net/http"
)

// DeclareOrgControlRoute registers a tenant control-plane route. Such routes
// are session-only for personal access tokens, which therefore can never reach
// them, and are optionally reachable by org-restricted sessions.
//
// Routes that move personal funds, create or join organizations, or list the
// caller's other organizations pass orgSession = false.
func DeclareOrgControlRoute(method, fullPath string, orgSession bool) {
	key := method + " " + fullPath
	if _, ok := accessTokenRouteRules[key]; ok {
		panic(fmt.Sprintf("access token route %s is declared twice", key))
	}
	permissionRouteRulesMu.Lock()
	if existing, ok := permissionRouteRules[key]; ok && existing != accessTokenSessionRule {
		permissionRouteRulesMu.Unlock()
		panic(fmt.Sprintf("access token route %s is declared with conflicting rules", key))
	}
	permissionRouteRules[key] = accessTokenSessionRule
	permissionRouteRulesMu.Unlock()
	if orgSession {
		DeclareOrgSessionRoute(method, fullPath)
	}
}

// orgRouteMethods are the methods a control route can use.
var orgRouteMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
