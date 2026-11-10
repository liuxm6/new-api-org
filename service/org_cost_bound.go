package service

import (
	"errors"
	"math"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/pkg/billingexpr"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/setting/model_setting"
	hosttypes "github.com/QuantumNous/new-api/types"
)

// OrgBound is the proven upper bound of one upstream attempt (design 4.2.1).
type OrgBound struct {
	// Quota is the most the attempt can cost, group ratio included. It is what
	// the wallet, the key and every budget hold.
	Quota int64
	// MaxOutput is the output limit the final request body must carry; 0 when
	// the request is not priced by output tokens.
	MaxOutput int64
	// Capped means the bound is an administrator's max_request_cost rather than
	// a proof, so the gateway cuts the response off at Quota.
	Capped bool
}

// ErrOrgCostUnbounded means no true upper bound exists and the model has no
// max_request_cost: the request is refused before any upstream call.
var ErrOrgCostUnbounded = errors.New("organization request cost has no upper bound")

func orgUnboundedError() *types.NewAPIError {
	return types.NewErrorWithStatusCode(ErrOrgCostUnbounded, types.ErrorCode(hosttypes.OrgErrCostUnbounded), 403,
		types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
}

// orgCappedBound turns the model's max_request_cost into the bound.
func orgCappedBound(modelName string) (OrgBound, bool) {
	usd, ok := model_setting.OrgMaxRequestCostUSD(modelName)
	if !ok {
		return OrgBound{}, false
	}
	quota, clamp := common.QuotaFromFloatChecked(usd * common.QuotaPerUnit)
	if clamp != nil || quota <= 0 {
		return OrgBound{}, false
	}
	return OrgBound{Quota: int64(quota), Capped: true}, true
}

// orgBoundOr returns the capped bound when the model has one, else the refusal.
func orgBoundOr(modelName string) (OrgBound, *types.NewAPIError) {
	if capped, ok := orgCappedBound(modelName); ok {
		return capped, nil
	}
	return OrgBound{}, orgUnboundedError()
}

// orgOutputCoversReasoning reports whether the output limit also caps thinking.
// Before a channel is chosen the answer is provisionally yes; every attempt
// recomputes the bound once the channel is known.
func orgOutputCoversReasoning(info *relaycommon.RelayInfo) bool {
	if info.ChannelMeta == nil {
		return true
	}
	return relaycommon.OutputCapCoversReasoning(info)
}

// orgPassThrough reports a request body the gateway cannot rewrite.
func orgPassThrough(info *relaycommon.RelayInfo) bool {
	if model_setting.GetGlobalSettings().PassThroughRequestEnabled {
		return true
	}
	return info.ChannelMeta != nil && info.ChannelSetting.PassThroughBodyEnabled
}

// EstimateOrgUpperBound proves the most one upstream attempt can cost, from the
// body that will be sent and the price in force. Anything it cannot prove
// (a passthrough body, Realtime, vendor-run tools, unpriced media, a thinking
// budget nobody caps, an expression that is not monotone) has no bound and is
// refused unless the model has a max_request_cost.
func EstimateOrgUpperBound(info *relaycommon.RelayInfo, body []byte) (OrgBound, *types.NewAPIError) {
	return estimateOrgUpperBound(info, body, 0)
}

// estimateOrgUpperBound is EstimateOrgUpperBound with an optional lower output
// limit: outputLimit > 0 prices the request as if its output were cut to that.
func estimateOrgUpperBound(info *relaycommon.RelayInfo, body []byte, outputLimit int64) (OrgBound, *types.NewAPIError) {
	modelName := info.GetBillingModelName()
	if info.RelayMode == relayconstant.RelayModeRealtime || orgPassThrough(info) {
		return orgBoundOr(modelName)
	}
	if info.PriceData.UsePrice {
		// A fixed price per call is its own bound; quantities were validated when
		// the price was computed.
		return orgBoundFromQuota(int64(info.PriceData.QuotaToPreConsume), 0)
	}
	scan, err := ScanOrgBody(body)
	if err != nil {
		return orgBoundOr(modelName)
	}
	if scan.BuiltinTools > 0 {
		return orgBoundOr(modelName)
	}
	inputTokens, ok := orgInputTokenBound(modelName, scan)
	if !ok {
		return orgBoundOr(modelName)
	}
	outputTokens, maxOutput, ok := orgOutputTokenBound(info, modelName, scan, outputLimit)
	if !ok {
		return orgBoundOr(modelName)
	}
	if snap := info.TieredBillingSnapshot; snap != nil && snap.BillingMode == "tiered_expr" {
		return orgTieredBound(info, snap, inputTokens, outputTokens, maxOutput)
	}
	return orgRatioBound(info, inputTokens, outputTokens, maxOutput)
}

// orgBoundFromQuota checks that a quota bound is finite and inside the
// single-request domain.
func orgBoundFromQuota(quota, maxOutput int64) (OrgBound, *types.NewAPIError) {
	if quota < 0 || quota > math.MaxInt32 {
		return OrgBound{}, orgUnboundedError()
	}
	return OrgBound{Quota: quota, MaxOutput: maxOutput}, nil
}

// orgInputTokenBound bounds the input tokens: UTF-8 bytes (a token never covers
// less than a byte) plus per-message and per-tool template overhead, plus the
// configured cap of each media item. Media without a configured cap is
// unbounded. The model's context window, when set, is the ceiling.
func orgInputTokenBound(modelName string, scan *OrgBodyScan) (int64, bool) {
	tokens := int64(scan.TextBytes) + int64(scan.Messages)*int64(model_setting.OrgMessageOverheadTokens()) +
		int64(scan.Tools)*int64(model_setting.OrgToolDefOverheadTokens())
	for kind, count := range scan.Media {
		if count == 0 {
			continue
		}
		perItem, ok := model_setting.OrgMaxInputTokensPerMedia(modelName, kind)
		if !ok {
			return 0, false
		}
		tokens += int64(count) * int64(perItem)
	}
	if window := model_setting.OrgMaxInputTokens(modelName); window > 0 {
		tokens = min(tokens, int64(window))
	}
	return tokens, true
}

// orgOutputTokenBound bounds the output tokens and returns the limit the final
// request body must carry. The client's limit counts only up to the model's
// ceiling; no limit means the model default. When the channel's limit does not
// also cap thinking, an explicit thinking budget is added on top, and without
// one the cost has no bound.
func orgOutputTokenBound(info *relaycommon.RelayInfo, modelName string, scan *OrgBodyScan, outputLimit int64) (total, maxOutput int64, ok bool) {
	ceiling := int64(model_setting.OrgMaxOutputTokens(modelName))
	maxOutput = int64(model_setting.OrgDefaultOutputTokens(modelName, info.RelayFormat == types.RelayFormatClaude))
	if scan.OutputCapSet && scan.OutputCap > 0 {
		maxOutput = min(scan.OutputCap, ceiling)
	}
	if outputLimit > 0 {
		maxOutput = min(maxOutput, outputLimit)
	}
	total = maxOutput * scan.Choices
	if !orgOutputCoversReasoning(info) {
		if scan.ThinkingBudget <= 0 {
			return 0, 0, false
		}
		total += scan.ThinkingBudget * scan.Choices
	}
	return total, maxOutput, total > 0 && total <= math.MaxInt32
}

// orgViolationFeeQuota is the most a failed request can add after the fact.
func orgViolationFeeQuota() int64 {
	return int64(math.Ceil(model_setting.OrgViolationFeeMaxUSD() * common.QuotaPerUnit))
}

// orgRatioBound prices the token bounds with the dearest ratio each side can
// bill at: input at the highest of plain, cache-write, image and audio ratio,
// output at the completion ratio (audio output included).
func orgRatioBound(info *relaycommon.RelayInfo, inputTokens, outputTokens, maxOutput int64) (OrgBound, *types.NewAPIError) {
	price := info.PriceData
	inputMultiplier := max(1, price.CacheCreationRatio, price.CacheCreation5mRatio, price.CacheCreation1hRatio,
		price.CacheCreation12hRatio, price.ImageRatio, price.AudioRatio)
	outputMultiplier := max(price.CompletionRatio, 1) * max(1, price.AudioCompletionRatio)
	raw := (float64(inputTokens)*inputMultiplier + float64(outputTokens)*outputMultiplier) *
		price.ModelRatio * price.GroupRatioInfo.GroupRatio
	quota, clamp := common.QuotaFromFloatChecked(raw)
	if clamp != nil || math.IsNaN(raw) || math.IsInf(raw, 0) {
		return orgBoundOr(info.GetBillingModelName())
	}
	return orgBoundFromQuota(int64(quota)+orgViolationFeeQuota(), maxOutput)
}

// orgTieredBound evaluates the billing expression at the dearest corner of the
// feasible token region. An expression that is not monotone, or reads something
// without a ceiling, has no proven bound.
func orgTieredBound(info *relaycommon.RelayInfo, snap *billingexpr.BillingSnapshot, inputTokens, outputTokens, maxOutput int64) (OrgBound, *types.NewAPIError) {
	in := billingexpr.OrgBoundInput{MaxInput: float64(inputTokens), MaxOutput: float64(outputTokens)}
	if info.BillingRequestInput != nil {
		in.Request = *info.BillingRequestInput
	}
	beforeGroup, err := billingexpr.OrgUpperBoundQuotaBeforeGroup(snap, in)
	if err != nil {
		return orgBoundOr(info.GetBillingModelName())
	}
	quota, clamp := common.QuotaFromFloatChecked(beforeGroup * info.PriceData.GroupRatioInfo.GroupRatio)
	if clamp != nil {
		return orgBoundOr(info.GetBillingModelName())
	}
	return orgBoundFromQuota(int64(quota)+orgViolationFeeQuota(), maxOutput)
}
