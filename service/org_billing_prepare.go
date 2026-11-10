package service

import (
	"errors"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	hosttypes "github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// orgMinOutputTokens is the smallest output cap worth sending after a tighten.
const orgMinOutputTokens = 16

// orgRequestBody reads the body the next upstream attempt starts from. The
// organization bound is computed from it, never from what the client claims.
func orgRequestBody(c *gin.Context) ([]byte, error) {
	storage, err := common.GetBodyStorage(c)
	if err != nil {
		return nil, err
	}
	return storage.Bytes()
}

// PrepareOrgRequestBilling reserves the proven upper bound of an organization
// request before any channel is chosen (design 4.2.3, first reservation). It is
// provisional where the channel matters; PrepareOrgAttemptBilling recomputes
// once the channel is known and before anything is sent.
func PrepareOrgRequestBilling(c *gin.Context, info *relaycommon.RelayInfo) *types.NewAPIError {
	if info.Billing != nil {
		return nil
	}
	body, err := orgRequestBody(c)
	if err != nil {
		return types.NewErrorWithStatusCode(err, types.ErrorCodeReadRequestBodyFailed, 400, types.ErrOptionWithSkipRetry())
	}
	bound, apiErr := EstimateOrgUpperBound(info, body)
	if apiErr != nil {
		return apiErr
	}
	info.OrgStreamByteBudget = orgStreamByteBudget(info, bound)
	return reserveOrgBound(c, info, bound, hosttypes.OrgSourceRelay)
}

// reserveOrgBound creates the session, or raises the held bound of an existing
// one, so a channel retry reuses its operation instead of reserving twice.
func reserveOrgBound(c *gin.Context, info *relaycommon.RelayInfo, bound OrgBound, source string) *types.NewAPIError {
	if session, ok := info.Billing.(*OrgBillingSession); ok {
		if err := session.Reserve(int(bound.Quota)); err != nil {
			return orgBillingAPIError(err)
		}
		return nil
	}
	if err := checkOrgWriteoffLimit(requestContext(c), info.OrgSubject, info.GetBillingModelName()); err != nil {
		return orgBillingAPIError(err)
	}
	session, apiErr := NewOrgBillingSession(c, info, bound.Quota, source)
	if apiErr != nil {
		return apiErr
	}
	info.Billing = session
	info.FinalPreConsumedQuota = session.GetPreConsumedQuota()
	return nil
}

// clampOutputCap lowers a client's output limit to limit, or sets it when the
// client set none. A smaller client value is kept.
func clampOutputCap(field **uint, limit uint) {
	if *field == nil || **field > limit {
		value := limit
		*field = &value
	}
}

// ApplyOrgOutputCap writes the output limit the bound was computed for into the
// request that will be sent. The bound assumes it, so a request that asked for
// more, or for nothing, must not reach the upstream unlimited (design 4.2.3).
// Request types without an output-token limit are left as they are.
func ApplyOrgOutputCap(request dto.Request, maxOutput int64) {
	if maxOutput <= 0 {
		return
	}
	limit := uint(maxOutput)
	switch r := request.(type) {
	case *dto.GeneralOpenAIRequest:
		switch {
		case r.MaxCompletionTokens != nil:
			clampOutputCap(&r.MaxCompletionTokens, limit)
			if r.MaxTokens != nil {
				clampOutputCap(&r.MaxTokens, limit)
			}
		default:
			clampOutputCap(&r.MaxTokens, limit)
		}
	case *dto.ClaudeRequest:
		clampOutputCap(&r.MaxTokens, limit)
	case *dto.OpenAIResponsesRequest:
		clampOutputCap(&r.MaxOutputTokens, limit)
	case *dto.GeminiChatRequest:
		clampOutputCap(&r.GenerationConfig.MaxOutputTokens, limit)
	}
}

// PrepareOrgAttemptBilling is the check before each upstream attempt, once the
// channel is known (design 4.2.3). It recomputes the bound for the channel
// chosen, writes the output limit into the request, and holds any extra. When
// the extra cannot be held the output limit is tightened to what fits; below
// orgMinOutputTokens, or for a request that cannot be shortened, the attempt
// fails with the refusal of the target that ran out.
func PrepareOrgAttemptBilling(c *gin.Context, info *relaycommon.RelayInfo) *types.NewAPIError {
	session, ok := info.Billing.(*OrgBillingSession)
	if !ok {
		return nil
	}
	body, err := orgRequestBody(c)
	if err != nil {
		return types.NewErrorWithStatusCode(err, types.ErrorCodeReadRequestBodyFailed, 400, types.ErrOptionWithSkipRetry())
	}
	bound, apiErr := EstimateOrgUpperBound(info, body)
	if apiErr != nil {
		return apiErr
	}
	ApplyOrgOutputCap(info.Request, bound.MaxOutput)
	info.OrgOutputCap = bound.MaxOutput
	info.OrgStreamByteBudget = orgStreamByteBudget(info, bound)
	if bound.Quota <= session.heldBound() {
		return nil
	}
	reserveErr := session.Reserve(int(bound.Quota))
	if reserveErr == nil {
		return nil
	}
	var refusal *hosttypes.OrgAccessError
	if !errors.As(reserveErr, &refusal) || bound.MaxOutput <= 0 {
		return orgBillingAPIError(reserveErr)
	}
	// Shorten the output to the largest cap whose bound still fits what is held.
	// The bound is not proportional to the cap (the input part is fixed), so the
	// cap is searched, not scaled.
	held := session.heldBound()
	tightened, found := largestOutputCapWithin(info, body, held, bound.MaxOutput)
	if !found {
		return orgBillingAPIError(reserveErr)
	}
	ApplyOrgOutputCap(info.Request, tightened)
	info.OrgOutputCap = tightened
	c.Header("X-NewAPI-Budget-Max-Tokens", strconv.FormatInt(tightened, 10))
	return nil
}

// largestOutputCapWithin finds the biggest output limit below current whose
// upper bound does not exceed held. The bound never falls as the cap grows, so
// a binary search is exact. found is false when even orgMinOutputTokens costs
// more than is held.
func largestOutputCapWithin(info *relaycommon.RelayInfo, body []byte, held, current int64) (int64, bool) {
	fits := func(limit int64) bool {
		bound, err := estimateOrgUpperBound(info, body, limit)
		return err == nil && !bound.Capped && bound.Quota <= held
	}
	if current <= orgMinOutputTokens || !fits(orgMinOutputTokens) {
		return 0, false
	}
	low, high := int64(orgMinOutputTokens), current-1 // low fits, current does not
	for low < high {
		mid := low + (high-low+1)/2
		if fits(mid) {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return low, true
}

func (s *OrgBillingSession) heldBound() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bound
}

// errOrgLegacyBilling is what a personal-billing path returns when an
// organization request reaches it. It is a bug in the caller, never a free
// request: the money path is closed, the attempt fails and the log says where.
func errOrgLegacyBilling(path string, info *relaycommon.RelayInfo) error {
	common.SysError(common.LogText("organization request %d reached the personal billing path %s", info.OrgSubject.OrgID, path))
	return errors.New("organization requests are billed only through the organization billing session")
}

// preConsumeOrgBilling reserves a price that is already final for an
// organization request: tiered group refresh, images, tasks and Midjourney.
// Asynchronous work reserves with locked-row holds (the model forces that from
// the source kind).
func preConsumeOrgBilling(c *gin.Context, info *relaycommon.RelayInfo, quota int) *types.NewAPIError {
	if quota < 0 {
		return types.NewErrorWithStatusCode(errors.New("pre-consume quota cannot be negative"), types.ErrorCodeModelPriceError, 400,
			types.ErrOptionWithSkipRetry())
	}
	source := hosttypes.OrgSourceRelay
	if info.TaskRelayInfo != nil {
		source = hosttypes.OrgSourceTask
	}
	return reserveOrgBound(c, info, OrgBound{Quota: int64(max(quota, 1))}, source)
}
