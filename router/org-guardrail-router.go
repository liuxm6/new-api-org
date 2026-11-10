package router

import (
	"net/http"

	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// registerOrgGuardrailRoutes mounts guardrail management (design sections 5.1
// and 8.3). Organization defaults and organization-wide member rules belong to
// organization owners and admins; workspace defaults, workspace member rules
// and key rules belong to workspace admins, and auditors may read.
func registerOrgGuardrailRoutes(apiRouter *gin.RouterGroup) {
	userAuth := []gin.HandlerFunc{middleware.UserAuth(), middleware.DisableCache()}
	orgs := apiRouter.Group("/orgs/:org", userAuth...)

	admins := []gin.HandlerFunc{middleware.OrgAuth(types.OrgRoleOwner, types.OrgRoleAdmin)}
	orgRoute(orgs, http.MethodGet, "/guardrails", true, append(admins, controller.ListGuardrails)...)
	orgRoute(orgs, http.MethodPost, "/guardrails", true, append(admins, controller.CreateGuardrail)...)
	orgRoute(orgs, http.MethodPatch, "/guardrails/:gid", true, append(admins, controller.UpdateGuardrail)...)
	orgRoute(orgs, http.MethodDelete, "/guardrails/:gid", true, append(admins, controller.DeleteGuardrail)...)

	workspaces := orgs.Group("/workspaces")
	reader := []gin.HandlerFunc{middleware.OrgAuth(), middleware.WorkspaceAuth(types.WorkspaceRoleAdmin, types.WorkspaceRoleAuditor)}
	writer := []gin.HandlerFunc{middleware.OrgAuth(), middleware.WorkspaceAuth(types.WorkspaceRoleAdmin)}
	orgRoute(workspaces, http.MethodGet, "/:ws/guardrails", true, append(reader, controller.ListGuardrails)...)
	orgRoute(workspaces, http.MethodPost, "/:ws/guardrails", true, append(writer, controller.CreateGuardrail)...)
	orgRoute(workspaces, http.MethodPatch, "/:ws/guardrails/:gid", true, append(writer, controller.UpdateGuardrail)...)
	orgRoute(workspaces, http.MethodDelete, "/:ws/guardrails/:gid", true, append(writer, controller.DeleteGuardrail)...)
}
