package middleware

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	orgsvc "github.com/QuantumNous/new-api/service/org"

	"github.com/gin-gonic/gin"
)

const (
	orgAccessContextKey       = "org_access"
	workspaceAccessContextKey = "workspace_access"
)

// OrgAccessFromContext returns the standing OrgAuth proved for this request.
func OrgAccessFromContext(c *gin.Context) (*orgsvc.OrgAccess, bool) {
	value, ok := c.Get(orgAccessContextKey)
	if !ok {
		return nil, false
	}
	access, ok := value.(*orgsvc.OrgAccess)
	return access, ok && access != nil
}

// WorkspaceAccessFromContext returns the standing WorkspaceAuth proved.
func WorkspaceAccessFromContext(c *gin.Context) (*orgsvc.WorkspaceAccess, bool) {
	value, ok := c.Get(workspaceAccessContextKey)
	if !ok {
		return nil, false
	}
	access, ok := value.(*orgsvc.WorkspaceAccess)
	return access, ok && access != nil
}

// abortWithOrgError writes the web-console refusal for an organization error.
func abortWithOrgError(c *gin.Context, err error) {
	response := orgsvc.ConsoleError(err)
	abortWithWebMessage(c, response.Status, response.Code, response.Message)
}

// OrgAuth authorizes the :org path parameter for the authenticated human. It
// must run after UserAuth. With no roles any active member passes; otherwise
// the member's current role must be listed. An org-restricted session can only
// ever resolve the organization it is bound to. The response is 404 for a
// stranger, a removed member or a foreign organization, 403 for suspended
// state or insufficient role.
func OrgAuth(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetInt("id")
		if userID <= 0 {
			abortWithWebMessage(c, http.StatusUnauthorized, "AUTH_UNAUTHORIZED", common.NewMessage("Unauthorized, invalid access token"))
			return
		}
		access, err := orgsvc.ResolveOrgAccess(c.Request.Context(), userID, c.Param("org"), SessionOrgScope(c), roles...)
		if err != nil {
			abortWithOrgError(c, err)
			return
		}
		c.Set(orgAccessContextKey, access)
		c.Next()
	}
}
