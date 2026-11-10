package router

import (
	"net/http"

	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"

	"github.com/gin-gonic/gin"
)

// registerOrgUsageRoutes mounts the organization usage, audit and task read
// routes (design sections 5.5 and 6) and the audited platform read entry. Like
// every organization route they are declared through orgRoute, so an
// org-restricted session can reach exactly these and nothing else.
//
// What a caller sees is decided by the controller from the standing the
// middleware proved: an organization owner, admin or billing member reads the
// organization, a workspace admin or auditor the workspace, anyone else only
// their own rows. Task and artifact reads additionally exclude the billing role.
func registerOrgUsageRoutes(apiRouter *gin.RouterGroup) {
	userAuth := []gin.HandlerFunc{middleware.UserAuth(), middleware.DisableCache()}

	orgs := apiRouter.Group("/orgs/:org", userAuth...)
	orgRoute(orgs, http.MethodGet, "/activity", true, middleware.OrgAuth(), controller.GetOrgActivity)
	orgRoute(orgs, http.MethodGet, "/audit-logs", true, middleware.OrgAuth(), controller.ListOrgAuditLogs)
	orgRoute(orgs, http.MethodGet, "/audit-logs/export", true, middleware.CriticalRateLimit(), middleware.OrgAuth(), controller.ExportOrgAuditLogs)

	workspaces := orgs.Group("/workspaces/:ws")
	member := []gin.HandlerFunc{middleware.OrgAuth(), middleware.WorkspaceAuth()}
	read := func(path string, handler gin.HandlerFunc, extra ...gin.HandlerFunc) {
		orgRoute(workspaces, http.MethodGet, path, true, append(append(extra, member...), handler)...)
	}
	read("/usage", controller.GetWorkspaceUsage)
	read("/logs", controller.ListWorkspaceLogs)
	read("/logs/export", controller.ExportWorkspaceLogs, middleware.CriticalRateLimit())
	read("/audit-logs", controller.ListWorkspaceAuditLogs)
	read("/audit-logs/export", controller.ExportWorkspaceAuditLogs, middleware.CriticalRateLimit())
	read("/tasks", controller.ListWorkspaceTasks)
	read("/tasks/:task_id", controller.GetWorkspaceTask)
	read("/tasks/:task_id/artifacts", controller.GetWorkspaceTaskArtifacts)
	read("/midjourney", controller.ListWorkspaceMidjourney)

	// Platform staff read one organization through their own entry: a global
	// platform session only (personal access tokens and org-restricted sessions
	// are refused), read-only, and every call is recorded as platform.access.
	platform := apiRouter.Group("/admin/orgs/:org", middleware.AdminAuth(), middleware.DisableCache())
	orgRoute(platform, http.MethodGet, "/activity", false, controller.PlatformOrgActivity)
	orgRoute(platform, http.MethodGet, "/logs", false, controller.PlatformOrgLogs)
	orgRoute(platform, http.MethodGet, "/audit-logs", false, controller.PlatformOrgAuditLogs)
	orgRoute(platform, http.MethodGet, "/tasks", false, controller.PlatformOrgTasks)
	orgRoute(platform, http.MethodGet, "/midjourney", false, controller.PlatformOrgMidjourney)

	// Platform operations: every write carries a reason and is audited in the
	// organization's own trail as a platform action.
	list := apiRouter.Group("/admin/orgs", middleware.AdminAuth(), middleware.DisableCache())
	orgRoute(list, http.MethodGet, "", false, controller.PlatformListOrganizations)
	orgRoute(platform, http.MethodPatch, "", false, middleware.CriticalRateLimit(), controller.PlatformUpdateOrganization)
	orgRoute(platform, http.MethodPost, "/adjust", false, middleware.CriticalRateLimit(), controller.PlatformAdjustOrganization)
	orgRoute(platform, http.MethodGet, "/billing-operations", false, controller.PlatformListBillingOperations)
	orgRoute(platform, http.MethodPost, "/billing-operations/:operation/resolve", false, middleware.CriticalRateLimit(),
		controller.PlatformResolveBillingOperation)
}
