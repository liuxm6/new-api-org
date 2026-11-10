package middleware

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	orgsvc "github.com/QuantumNous/new-api/service/org"

	"github.com/gin-gonic/gin"
)

// WorkspaceAuth authorizes the :ws path parameter inside :org. It re-resolves
// the organization itself, so it can be used alone, and stores both results.
// Organization owners and admins are implicit workspace admins; the billing
// role grants nothing here. With no roles any active workspace role passes. A
// workspace of another organization is a 404, a suspended workspace a 403.
//
// Routes that must stay reachable while a workspace is suspended (resume) are
// parent-organization routes guarded by OrgAuth, not WorkspaceAuth.
func WorkspaceAuth(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetInt("id")
		if userID <= 0 {
			abortWithWebMessage(c, http.StatusUnauthorized, "AUTH_UNAUTHORIZED", common.NewMessage("Unauthorized, invalid access token"))
			return
		}
		access, err := orgsvc.ResolveWorkspaceAccess(c.Request.Context(), userID, c.Param("org"), c.Param("ws"), SessionOrgScope(c), roles...)
		if err != nil {
			abortWithOrgError(c, err)
			return
		}
		c.Set(orgAccessContextKey, &access.OrgAccess)
		c.Set(workspaceAccessContextKey, access)
		c.Next()
	}
}
