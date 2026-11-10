package router

import (
	"net/http"

	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"

	"github.com/gin-gonic/gin"
)

// registerOrgBudgetRoutes mounts the budget routes (design 6.1 and 6.2). The
// routes only prove membership; the service decides who may read or write which
// budget, so a workspace admin can never reach an organization member's budget
// and a key's creator can only tighten it.
func registerOrgBudgetRoutes(apiRouter *gin.RouterGroup) {
	userAuth := []gin.HandlerFunc{middleware.UserAuth(), middleware.DisableCache()}
	orgs := apiRouter.Group("/orgs/:org", userAuth...)
	member := []gin.HandlerFunc{middleware.OrgAuth()}
	inWorkspace := []gin.HandlerFunc{middleware.OrgAuth(), middleware.WorkspaceAuth()}

	orgRoute(orgs, http.MethodGet, "/budgets", true, append(member, controller.GetOrganizationBudgets)...)
	orgRoute(orgs, http.MethodPut, "/budgets", true, append(member, controller.PutOrganizationBudgets)...)
	orgRoute(orgs, http.MethodGet, "/members/:mid/budgets", true, append(member, controller.GetMemberBudgets)...)
	orgRoute(orgs, http.MethodPut, "/members/:mid/budgets", true, append(member, controller.PutMemberBudgets)...)

	workspaces := orgs.Group("/workspaces")
	orgRoute(workspaces, http.MethodGet, "/:ws/budgets", true, append(inWorkspace, controller.GetWorkspaceBudgets)...)
	orgRoute(workspaces, http.MethodPut, "/:ws/budgets", true, append(inWorkspace, controller.PutWorkspaceBudgets)...)
	orgRoute(workspaces, http.MethodGet, "/:ws/keys/:kid/budgets", true, append(inWorkspace, controller.GetKeyBudgets)...)
	orgRoute(workspaces, http.MethodPut, "/:ws/keys/:kid/budgets", true, append(inWorkspace, controller.PutKeyBudgets)...)
}
