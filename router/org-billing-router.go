package router

import (
	"net/http"

	"github.com/QuantumNous/new-api/controller"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// registerOrgBillingRoutes mounts the finance routes (design 5.1 and 6.1):
// owners, admins and billing members read; owners and billing members put money
// in. Moving personal money is a global-session route only.
func registerOrgBillingRoutes(apiRouter *gin.RouterGroup) {
	userAuth := []gin.HandlerFunc{middleware.UserAuth(), middleware.DisableCache()}
	orgs := apiRouter.Group("/orgs/:org", userAuth...)

	readers := []gin.HandlerFunc{middleware.OrgAuth(types.OrgRoleOwner, types.OrgRoleAdmin, types.OrgRoleBilling)}
	payers := []gin.HandlerFunc{middleware.OrgAuth(types.OrgRoleOwner, types.OrgRoleBilling)}
	orgRoute(orgs, http.MethodGet, "/billing", true, append(readers, controller.GetOrganizationBilling)...)
	orgRoute(orgs, http.MethodPost, "/topup", true, append([]gin.HandlerFunc{middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-topup")}, append(payers, controller.TopUpOrganization)...)...)
	// Receipts, statements and the invoice header (design 4.6).
	orgRoute(orgs, http.MethodGet, "/invoices", true, append(readers, controller.ListOrganizationInvoices)...)
	orgRoute(orgs, http.MethodGet, "/invoices/:iid", true, append(readers, controller.GetOrganizationInvoice)...)
	orgRoute(orgs, http.MethodPost, "/invoices/:iid/void", true, middleware.OrgAuth(types.OrgRoleOwner), controller.VoidOrganizationInvoice)
	orgRoute(orgs, http.MethodGet, "/billing-profile", true, append(readers, controller.GetOrganizationBillingProfile)...)
	orgRoute(orgs, http.MethodPut, "/billing-profile", true, append(payers, controller.SaveOrganizationBillingProfile)...)
	orgRoute(orgs, http.MethodPost, "/credits/transfer", false, append([]gin.HandlerFunc{middleware.CriticalRateLimit(),
		middleware.UserCriticalRateLimit("org-transfer")}, append(payers, controller.TransferCreditsToOrganization)...)...)
}
