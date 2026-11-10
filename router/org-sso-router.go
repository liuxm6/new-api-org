package router

import (
	"net/http"

	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// registerOrgSSORoutes mounts everything Task 13 adds on top of the tenant
// control plane (design sections 6.1, 6.4, 7 and 8):
//
//   - /api/orgs/:org/management-keys, /scim/mappings, /sso and /sensitive:
//     human-session routes. Credential creation and revocation, SSO changes
//     and the org-session proof ceremony need an owner/admin role (SSO: owner)
//     and, for the irreversible ones, a single-use proof.
//   - /api/org-sso/:org: public sign-in begin/callback for a tenant IdP, and the
//     global-session-only account link.
//   - /api/mgmt/orgs/:org: the narrow tree a personal management credential can
//     reach. Credential administration, ownership, deletion, SSO and billing
//     writes are deliberately not on it.
//   - /scim/v2: the SCIM 2.0 service, reachable only with a scim_service
//     credential.
func registerOrgSSORoutes(engine *gin.Engine, apiRouter *gin.RouterGroup) {
	userAuth := []gin.HandlerFunc{middleware.UserAuth(), middleware.DisableCache()}
	admins := []gin.HandlerFunc{middleware.OrgAuth(types.OrgRoleOwner, types.OrgRoleAdmin)}
	owners := []gin.HandlerFunc{middleware.OrgAuth(types.OrgRoleOwner)}

	one := apiRouter.Group("/orgs", userAuth...).Group("/:org")
	orgRoute(one, http.MethodGet, "/management-keys", true, append(admins, controller.ListManagementKeys)...)
	orgRoute(one, http.MethodPost, "/management-keys", true, append([]gin.HandlerFunc{middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-mgmt-key")}, append(admins, controller.CreateManagementKey)...)...)
	orgRoute(one, http.MethodPatch, "/management-keys/:mkid", true, append(admins, controller.RenameManagementKey)...)
	orgRoute(one, http.MethodDelete, "/management-keys/:mkid", true, append([]gin.HandlerFunc{middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-mgmt-key")}, append(admins, controller.RevokeManagementKey)...)...)

	orgRoute(one, http.MethodGet, "/scim/mappings", true, append(admins, controller.ListScimMappings)...)
	orgRoute(one, http.MethodPost, "/scim/mappings", true, append(admins, controller.CreateScimMapping)...)
	orgRoute(one, http.MethodPatch, "/scim/mappings/:mid", true, append(admins, controller.UpdateScimMapping)...)
	orgRoute(one, http.MethodDelete, "/scim/mappings/:mid", true, append(admins, controller.DeleteScimMapping)...)

	orgRoute(one, http.MethodGet, "/sso", true, append(owners, controller.GetOrgSSO)...)
	orgRoute(one, http.MethodPut, "/sso", true, append([]gin.HandlerFunc{middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-sso-config")}, append(owners, controller.UpdateOrgSSO)...)...)

	// The org-session proof ceremony: the only verification an org-restricted
	// session can run, and only for the org.* operations it is allowed to prove.
	// Global sessions use /api/verify instead.
	orgRoute(one, http.MethodPost, "/sensitive/begin", true, append([]gin.HandlerFunc{middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-sensitive")}, append(admins, controller.OrgSensitiveBegin)...)...)
	orgRoute(one, http.MethodPost, "/sensitive/callback", true, append([]gin.HandlerFunc{middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-sensitive")}, append(admins, controller.OrgSensitiveCallback)...)...)

	// Public sign-in. Authentication is the IdP ceremony itself: state, nonce,
	// PKCE and the HttpOnly binding cookie. The origin guard blocks login CSRF.
	sso := apiRouter.Group("/org-sso/:org", middleware.SessionCookieOriginGuard(), middleware.CriticalRateLimit(), middleware.DisableCache())
	sso.POST("/begin", controller.OrgSSOBegin)
	sso.POST("/callback", controller.OrgSSOCallback)

	// Linking a global account to the org identity needs the global session: an
	// org-restricted session is refused by the route allowlist and again in the
	// handler.
	link := apiRouter.Group("/org-sso/:org/link", append(userAuth, middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-identity-link"))...)
	orgRoute(link, http.MethodPost, "/begin", false, controller.OrgLinkBegin)
	orgRoute(link, http.MethodPost, "/callback", false, controller.OrgLinkCallback)

	registerManagementRoutes(apiRouter)
	registerSCIMRoutes(engine)
}

// registerManagementRoutes is the personal-management-credential tree. Each
// route names the one scope it needs; ManagementAuth re-proves the creator's
// live role on every call, and the services cap the acting role at admin.
func registerManagementRoutes(apiRouter *gin.RouterGroup) {
	mgmt := apiRouter.Group("/mgmt/orgs/:org", middleware.DisableCache())
	read := func(scope string, handlers ...gin.HandlerFunc) []gin.HandlerFunc {
		return append([]gin.HandlerFunc{middleware.ManagementAuth(scope)}, handlers...)
	}
	wsAdmin := func(scope string, handler gin.HandlerFunc) []gin.HandlerFunc {
		return read(scope, middleware.WorkspaceAuth(types.WorkspaceRoleAdmin), handler)
	}
	mgmt.GET("/members", read(types.MgmtScopeMembersRead, controller.ListOrganizationMembers)...)
	mgmt.PATCH("/members/:mid", read(types.MgmtScopeMembersWrite, controller.UpdateOrganizationMember)...)
	mgmt.DELETE("/members/:mid", read(types.MgmtScopeMembersWrite, controller.RemoveOrganizationMember)...)
	mgmt.GET("/invites", read(types.MgmtScopeMembersRead, controller.ListOrganizationInvites)...)
	mgmt.POST("/invites", read(types.MgmtScopeMembersWrite, controller.CreateOrganizationInvite)...)
	mgmt.DELETE("/invites/:iid", read(types.MgmtScopeMembersWrite, controller.RevokeOrganizationInvite)...)
	mgmt.GET("/workspaces", read(types.MgmtScopeKeysRead, controller.ListWorkspaces)...)
	mgmt.GET("/workspaces/:ws/keys", wsAdmin(types.MgmtScopeKeysRead, controller.ListWorkspaceKeys)...)
	mgmt.POST("/workspaces/:ws/keys", wsAdmin(types.MgmtScopeKeysWrite, controller.CreateWorkspaceKey)...)
	mgmt.PATCH("/workspaces/:ws/keys/:kid", wsAdmin(types.MgmtScopeKeysWrite, controller.UpdateWorkspaceKey)...)
	mgmt.DELETE("/workspaces/:ws/keys/:kid", wsAdmin(types.MgmtScopeKeysWrite, controller.DeleteWorkspaceKey)...)
	mgmt.POST("/workspaces/:ws/keys/:kid/rotate", wsAdmin(types.MgmtScopeKeysWrite, controller.RotateWorkspaceKey)...)
}

// registerSCIMRoutes mounts /scim/v2. ScimAuth is the only authenticator on the
// tree, so nothing else (a session, an inference key, a management credential)
// can reach a SCIM handler.
func registerSCIMRoutes(engine *gin.Engine) {
	scim := engine.Group("/scim/v2", middleware.RouteTag("scim"), middleware.GlobalAPIRateLimit(), middleware.ScimAuth())
	scim.GET("/ServiceProviderConfig", controller.ScimServiceProviderConfig)
	scim.POST("/Users", controller.ScimCreateUser)
	scim.GET("/Users", controller.ScimListUsers)
	scim.GET("/Users/:id", controller.ScimGetUser)
	scim.PATCH("/Users/:id", controller.ScimPatchUser)
	scim.DELETE("/Users/:id", controller.ScimDeleteUser)
	scim.POST("/Groups", controller.ScimCreateGroup)
	scim.GET("/Groups", controller.ScimListGroups)
	scim.GET("/Groups/:id", controller.ScimGetGroup)
	scim.PUT("/Groups/:id", controller.ScimReplaceGroup)
	scim.PATCH("/Groups/:id", controller.ScimPatchGroup)
	scim.DELETE("/Groups/:id", controller.ScimDeleteGroup)
}
