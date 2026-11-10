package controller

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/relaykit/types"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/gin-gonic/gin"
)

func displayQuota(quota float64) float64 {
	switch operation_setting.GetQuotaDisplayType() {
	case operation_setting.QuotaDisplayTypeCNY:
		return quota / common.QuotaPerUnit * operation_setting.USDExchangeRate
	case operation_setting.QuotaDisplayTypeTokens:
		return quota
	}
	return quota / common.QuotaPerUnit
}

// orgKeyBilling answers the dashboard billing endpoints for an organization
// key, whatever DisplayTokenStatEnabled says: the figures come from the key and
// its budgets and the organization's available balance (design 4.3). It reports true when it handled the request.
func orgKeyBilling(c *gin.Context, usage bool) bool {
	subject, isOrg := middleware.OrgSubjectFromContext(c)
	if !isOrg {
		return false
	}
	view, err := orgsvc.KeyBillingFor(c.Request.Context(), subject)
	if err != nil {
		common.SysError(common.LogText("organization key billing view failed: %v", err))
		c.JSON(http.StatusOK, gin.H{"error": types.OpenAIError{Message: "failed to read key quota", Type: "upstream_error"}})
		return true
	}
	if usage {
		c.JSON(http.StatusOK, OpenAIUsageResponse{Object: "list", TotalUsage: displayQuota(float64(view.Used)) * 100})
		return true
	}
	amount := displayQuota(float64(view.Remaining + view.Used))
	expired := view.ExpiredTime
	if expired <= 0 {
		expired = 0
	}
	c.JSON(http.StatusOK, OpenAISubscriptionResponse{Object: "billing_subscription", HasPaymentMethod: true,
		SoftLimitUSD: amount, HardLimitUSD: amount, SystemHardLimitUSD: amount, AccessUntil: expired})
	return true
}
