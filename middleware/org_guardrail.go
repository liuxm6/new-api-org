package middleware

import (
	"net/http"

	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	relaytypes "github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"
	orgservice "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// enforceOrgGuardrails applies the organization's guardrails to one request. It
// refuses a denied model and registers the provider rules as a channel filter,
// so first selection, retries, cross-group fallback, affinity and pinned
// channels are all constrained by the same rule. It returns false after writing
// the refusal. Personal requests pass through untouched.
func enforceOrgGuardrails(c *gin.Context, modelName string) bool {
	subject, ok := OrgSubjectFromContext(c)
	if !ok {
		return true
	}
	policyVersion := c.GetInt64(string(constant.ContextKeyOrgPolicyVersion))
	policy, err := orgservice.ResolveGuardrails(subject, policyVersion)
	if err != nil {
		// A policy that cannot be read is not "no policy".
		abortWithOpenAiMessage(c, http.StatusServiceUnavailable,
			orgAccessMessage(types.OrgErrStateUnavailable), relaytypes.ErrorCode(types.OrgErrStateUnavailable))
		return false
	}
	if modelName != "" && !policy.AllowsModel(modelName) {
		abortWithOpenAiMessage(c, http.StatusForbidden,
			i18n.T(c, i18n.MsgDistributorTokenModelForbidden, map[string]any{"Model": modelName}),
			relaytypes.ErrorCode(types.OrgErrGuardrailModelDenied))
		return false
	}
	if filter, restricted := policy.ProviderFilter(); restricted {
		service.GetChannelConstraints(c).AddFilter(filter)
	}
	return true
}
