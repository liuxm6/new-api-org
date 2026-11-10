package router

import (
	"net/http"

	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// orgRoute registers one tenant control-plane route and declares it in the
// same call: personal access tokens are refused (session-only), and an
// org-restricted session may reach it only when orgSession is true. Declaring
// and registering together means a route cannot exist without a rule.
func orgRoute(group *gin.RouterGroup, method, path string, orgSession bool, handlers ...gin.HandlerFunc) {
	middleware.DeclareOrgControlRoute(method, joinPaths(group.BasePath(), path), orgSession)
	group.Handle(method, path, handlers...)
}

// registerOrgRoutes mounts /api/orgs and /api/invites (design section 6.1).
// Task 5 owns organization CRUD and ownership transfer, Task 6 members and
// invitations; later tasks append their groups here.
//
// Routes that create organizations, list the caller's other organizations or
// redeem an invitation to a different organization need a global session and
// are declared with orgSession = false. Everything under /:org goes through
// OrgAuth, which also pins an org-restricted session to its own organization.
func registerOrgRoutes(apiRouter *gin.RouterGroup) {
	userAuth := []gin.HandlerFunc{middleware.UserAuth(), middleware.DisableCache()}

	orgs := apiRouter.Group("/orgs", userAuth...)
	orgRoute(orgs, http.MethodGet, "", false, controller.ListMyOrganizations)
	orgRoute(orgs, http.MethodPost, "", false, middleware.CriticalRateLimit(), middleware.UserCriticalRateLimit("org-create"),
		controller.CreateOrganization)

	one := orgs.Group("/:org")
	orgRoute(one, http.MethodGet, "", true, middleware.OrgAuth(), controller.GetOrganization)
	orgRoute(one, http.MethodPatch, "", true, middleware.OrgAuth(types.OrgRoleOwner), controller.UpdateOrganization)
	// Transfer and delete are irreversible owner actions. Both global and
	// org-restricted sessions may call them, but only with a single-use proof
	// bound to the session, its auth scope, the organization and the exact
	// resource (controller.requireSensitive, design section 7).
	orgRoute(one, http.MethodPost, "/transfer-ownership", true, middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-ownership"), middleware.OrgAuth(types.OrgRoleOwner),
		controller.TransferOrganizationOwnership)

	orgRoute(one, http.MethodDelete, "", true, middleware.CriticalRateLimit(), middleware.UserCriticalRateLimit("org-delete"),
		middleware.OrgAuth(types.OrgRoleOwner), controller.DeleteOrganization)

	admins := []gin.HandlerFunc{middleware.OrgAuth(types.OrgRoleOwner, types.OrgRoleAdmin)}
	orgRoute(one, http.MethodGet, "/members", true, append(admins, controller.ListOrganizationMembers)...)
	orgRoute(one, http.MethodGet, "/invites", true, append(admins, controller.ListOrganizationInvites)...)
	orgRoute(one, http.MethodPost, "/invites", true, append([]gin.HandlerFunc{middleware.UserCriticalRateLimit("org-invite")},
		append(admins, controller.CreateOrganizationInvite)...)...)
	orgRoute(one, http.MethodDelete, "/invites/:iid", true, append(admins, controller.RevokeOrganizationInvite)...)

	// :mid is the member's user id. Any member may remove themselves, so the
	// delete route admits every role and the service decides.
	orgRoute(one, http.MethodPatch, "/members/:mid", true, append(admins, controller.UpdateOrganizationMember)...)
	orgRoute(one, http.MethodDelete, "/members/:mid", true, middleware.OrgAuth(), controller.RemoveOrganizationMember)

	workspaces := one.Group("/workspaces")
	orgRoute(workspaces, http.MethodGet, "", true, middleware.OrgAuth(), controller.ListWorkspaces)
	orgRoute(workspaces, http.MethodPost, "", true, append(admins, controller.CreateWorkspace)...)
	// Suspend, resume and delete are parent-organization routes (OrgAuth only), so a
	// suspended workspace can always be resumed or removed from above.
	orgRoute(workspaces, http.MethodPost, "/:ws/suspend", true, append(admins, controller.SuspendWorkspace)...)
	orgRoute(workspaces, http.MethodPost, "/:ws/resume", true, append(admins, controller.ResumeWorkspace)...)
	orgRoute(workspaces, http.MethodDelete, "/:ws", true, append(admins, controller.DeleteWorkspace)...)
	wsAdmin := []gin.HandlerFunc{middleware.OrgAuth(), middleware.WorkspaceAuth(types.WorkspaceRoleAdmin)}
	orgRoute(workspaces, http.MethodGet, "/:ws", true, middleware.OrgAuth(), middleware.WorkspaceAuth(), controller.GetWorkspace)
	orgRoute(workspaces, http.MethodPatch, "/:ws", true, append(wsAdmin, controller.UpdateWorkspace)...)
	orgRoute(workspaces, http.MethodGet, "/:ws/members", true, middleware.OrgAuth(),
		middleware.WorkspaceAuth(types.WorkspaceRoleAdmin, types.WorkspaceRoleAuditor), controller.ListWorkspaceMembers)
	// Keys: members manage their own, admins all, auditors only read the masked list.
	keyReader := []gin.HandlerFunc{middleware.OrgAuth(), middleware.WorkspaceAuth(types.WorkspaceRoleAdmin, types.WorkspaceRoleAuditor, types.WorkspaceRoleMember)}
	keyWriter := []gin.HandlerFunc{middleware.OrgAuth(), middleware.WorkspaceAuth(types.WorkspaceRoleAdmin, types.WorkspaceRoleMember)}
	orgRoute(workspaces, http.MethodGet, "/:ws/keys", true, append(keyReader, controller.ListWorkspaceKeys)...)
	orgRoute(workspaces, http.MethodPost, "/:ws/keys", true, append([]gin.HandlerFunc{middleware.UserCriticalRateLimit("org-key")},
		append(keyWriter, controller.CreateWorkspaceKey)...)...)
	orgRoute(workspaces, http.MethodPatch, "/:ws/keys/:kid", true, append(keyWriter, controller.UpdateWorkspaceKey)...)
	orgRoute(workspaces, http.MethodDelete, "/:ws/keys/:kid", true, append(keyWriter, controller.DeleteWorkspaceKey)...)
	orgRoute(workspaces, http.MethodPost, "/:ws/keys/:kid/rotate", true, append([]gin.HandlerFunc{middleware.UserCriticalRateLimit("org-key")},
		append(keyWriter, controller.RotateWorkspaceKey)...)...)
	orgRoute(workspaces, http.MethodPut, "/:ws/members/:uid", true, append(wsAdmin, controller.SetWorkspaceMember)...)
	orgRoute(workspaces, http.MethodDelete, "/:ws/members/:uid", true, append(wsAdmin, controller.RemoveWorkspaceMember)...)

	// The token is a bearer credential in the path: global session only, strict
	// per-IP and per-user limits against guessing, never cached.
	invites := apiRouter.Group("/invites", userAuth...)
	orgRoute(invites, http.MethodPost, "/:token/accept", false, middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-invite-accept"), controller.AcceptInvite)
}
