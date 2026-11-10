package service

import (
	"math"

	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
)

const (
	// orgStreamBytesPerToken is far above what a streamed token costs on the
	// wire, SSE envelope included, so a request that stays inside its output
	// limit never meets the budget.
	orgStreamBytesPerToken = 256
	// orgStreamMinBytes keeps a small output limit from starving the role,
	// usage and finish events around the text.
	orgStreamMinBytes = 64 << 10
)

// orgStreamByteBudget is the most upstream stream data the gateway forwards for
// one organization attempt (design 4.2.3). Usage is only reported at the end of
// most streams, so the cap is counted in bytes: it ends a runaway upstream that
// ignores the output limit, it is not an exact stop at the cost bound. Only
// text streams are capped; image and audio streams carry large payloads that
// are priced another way. 0 means no cap.
func orgStreamByteBudget(info *relaycommon.RelayInfo, bound OrgBound) int64 {
	if info == nil || info.OrgSubject.OrgID <= 0 || !info.IsStream || info.PriceData.UsePrice {
		return 0
	}
	switch info.RelayMode {
	case relayconstant.RelayModeChatCompletions, relayconstant.RelayModeCompletions,
		relayconstant.RelayModeResponses, relayconstant.RelayModeGemini:
	default:
		return 0
	}
	tokens := bound.MaxOutput
	if tokens <= 0 {
		price := info.PriceData
		perToken := price.ModelRatio * max(price.CompletionRatio, 1) * price.GroupRatioInfo.GroupRatio
		if perToken <= 0 || bound.Quota <= 0 {
			return 0
		}
		derived := float64(bound.Quota) / perToken
		if math.IsNaN(derived) || math.IsInf(derived, 0) || derived > float64(math.MaxInt64/orgStreamBytesPerToken) {
			return 0
		}
		tokens = int64(derived)
	}
	if tokens > math.MaxInt64/orgStreamBytesPerToken {
		return 0
	}
	return max(tokens*orgStreamBytesPerToken, orgStreamMinBytes)
}
