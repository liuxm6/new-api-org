package service

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/types"
	hosttypes "github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// orgLeaseRenewInterval renews the operation lease well inside its 120 seconds,
// so a long stream is never mistaken for a dead instance by the recovery worker.
const orgLeaseRenewInterval = 30 * time.Second

// OrgBillingSession is the billing lifecycle of one organization request
// (design 4.2.4). It implements relaycommon.BillingSettler without touching the
// wallet and subscription funding sources of personal billing: every change is
// one model.ApplyOrgBilling command on a durable operation.
type OrgBillingSession struct {
	relayInfo   *relaycommon.RelayInfo
	subject     hosttypes.OrgSubject
	operationID string
	owner       string // lease owner: this instance plus this session
	sourceKind  string

	mu        sync.Mutex
	bound     int64
	settled   bool
	refunded  bool
	stopRenew chan struct{}
}

// NewOrgBillingSession reserves the upper bound of the request and returns the
// session. The reservation either holds the wallet, the limited key and every
// enabled budget, or fails and holds nothing.
func NewOrgBillingSession(c *gin.Context, info *relaycommon.RelayInfo, bound int64, sourceKind string) (*OrgBillingSession, *types.NewAPIError) {
	session := &OrgBillingSession{relayInfo: info, subject: info.OrgSubject, sourceKind: sourceKind,
		operationID: "org-" + uuid.NewString(), owner: common.NodeName + ":" + uuid.NewString()}
	// The first reservation precedes channel selection, so ChannelMeta may be nil.
	channelID := 0
	if info.ChannelMeta != nil {
		channelID = info.ChannelId
	}
	var hints []hosttypes.OrgLeaseHint
	if !hosttypes.OrgSourceForcesDirect(sourceKind) {
		hints = leaseManager.hints(context.WithoutCancel(requestContext(c)), info.OrgSubject)
	}
	result, err := session.apply(c, hosttypes.OrgBillingCommand{Action: hosttypes.OrgBillingActionReserve, Bound: bound,
		ModelName: info.GetBillingModelName(), SourceKind: sourceKind, SourceID: info.RequestId,
		BillingChannel: channelID, LeaseHints: hints})
	if err != nil {
		return nil, orgBillingAPIError(err)
	}
	leaseManager.observe(info.OrgSubject, hints, result.Holds)
	session.bound = result.Bound
	session.startRenewal()
	return session, nil
}

func (s *OrgBillingSession) apply(c *gin.Context, cmd hosttypes.OrgBillingCommand) (hosttypes.OrgBillingResult, error) {
	cmd.OperationID, cmd.Subject, cmd.LeaseOwner = s.operationID, s.subject, s.owner
	// Settlement and cancellation must outlive a client that hangs up, or the
	// money would stay held; keep the request's values but drop its cancellation.
	ctx := context.Background()
	if c != nil && c.Request != nil {
		ctx = context.WithoutCancel(c.Request.Context())
	}
	return model.ApplyOrgBilling(ctx, cmd)
}

// Settle records the real cost. The model caps it at the bound and writes the
// excess off; a repeated call replays the stored result.
func (s *OrgBillingSession) Settle(actualQuota int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled {
		return nil
	}
	if s.refunded {
		return errors.New("organization billing session was already cancelled")
	}
	if actualQuota < 0 {
		actualQuota = 0
	}
	cmd := hosttypes.OrgBillingCommand{Action: hosttypes.OrgBillingActionCapture, Amount: int64(actualQuota), Revision: 1,
		PriceSnapshot: orgPriceSnapshot(s.relayInfo)}
	if _, err := s.apply(nil, cmd); err != nil {
		return err
	}
	leaseManager.consumed(s.subject.OrgID, int64(min(actualQuota, int(s.bound))))
	s.settled = true
	s.stopRenewalLocked()
	return nil
}

// Refund cancels the reservation of a request that failed. It is idempotent and
// a request that already settled is left alone.
func (s *OrgBillingSession) Refund(c *gin.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled || s.refunded {
		return
	}
	_, err := s.apply(c, hosttypes.OrgBillingCommand{Action: hosttypes.OrgBillingActionCancel})
	if err != nil {
		logger.LogError(c, common.LogText("failed to cancel organization reservation %s: %s", s.operationID, err.Error()))
		return
	}
	s.refunded = true
	s.stopRenewalLocked()
}

// OperationID is the durable operation a task or Midjourney row stores, so its
// later refund and price revision find the same operation.
func (s *OrgBillingSession) OperationID() string { return s.operationID }

func (s *OrgBillingSession) NeedsRefund() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.settled && !s.refunded
}

// GetPreConsumedQuota is the amount currently held, which is the bound.
func (s *OrgBillingSession) GetPreConsumedQuota() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int(min(s.bound, int64(^uint32(0)>>1)))
}

// Reserve raises the held bound to targetQuota (design 4.2.3). A target that is
// not higher changes nothing; when the extra cannot be held the caller tightens
// the output cap or fails the attempt.
func (s *OrgBillingSession) Reserve(targetQuota int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.settled || s.refunded {
		return errors.New("organization billing session is closed")
	}
	if int64(targetQuota) <= s.bound {
		return nil
	}
	result, err := s.apply(nil, hosttypes.OrgBillingCommand{Action: hosttypes.OrgBillingActionTopUpReserve, Bound: int64(targetQuota)})
	if err != nil {
		return err
	}
	s.bound = result.Bound
	return nil
}

// ReserveBeforeSubmit is Reserve for a price that is already final.
func (s *OrgBillingSession) ReserveBeforeSubmit(targetQuota int) error {
	return s.Reserve(targetQuota)
}

// startRenewal keeps the operation lease alive for as long as the request runs.
func (s *OrgBillingSession) startRenewal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	stop := make(chan struct{})
	s.stopRenew = stop
	go func() {
		ticker := time.NewTicker(orgLeaseRenewInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if ok, err := model.RenewOrgOperationLease(context.Background(), s.operationID, s.owner, 0); err != nil || !ok {
					return // settled, cancelled, or taken over by recovery
				}
			}
		}
	}()
}

func (s *OrgBillingSession) stopRenewalLocked() {
	if s.stopRenew != nil {
		close(s.stopRenew)
		s.stopRenew = nil
	}
}

// orgBillingAPIError maps a model refusal to the OpenAI-style error the client
// sees: money and budget refusals are 403 with a stable code and never retry.
func orgBillingAPIError(err error) *types.NewAPIError {
	var refusal *hosttypes.OrgAccessError
	if errors.As(err, &refusal) {
		return types.NewErrorWithStatusCode(err, types.ErrorCode(refusal.Code), refusal.Status,
			types.ErrOptionWithSkipRetry(), types.ErrOptionWithNoRecordErrorLog())
	}
	return types.NewErrorWithStatusCode(err, types.ErrorCodeQueryDataError, http.StatusInternalServerError, types.ErrOptionWithSkipRetry())
}

func formatOrgRatio(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

// orgPriceSnapshot is the pricing identity that groups spend into statement
// lines (design 4.6): the pricing version, the currency and the quota
// conversion. Spend priced differently never shares a line. A tiered
// expression is identified by its hash, ratio pricing by the ratios in force.
func orgPriceSnapshot(info *relaycommon.RelayInfo) string {
	version := ""
	switch {
	case info.TieredBillingSnapshot != nil:
		version = "expr:" + info.TieredBillingSnapshot.ExprHash
	case info.PriceData.UsePrice:
		version = "price:" + formatOrgRatio(info.PriceData.ModelPrice)
	default:
		version = "ratio:" + formatOrgRatio(info.PriceData.ModelRatio) + ":" +
			formatOrgRatio(info.PriceData.CompletionRatio) + ":" + formatOrgRatio(info.PriceData.GroupRatioInfo.GroupRatio)
	}
	data, err := common.Marshal(map[string]string{"pricing_version": version, "currency": "USD",
		"quota_per_unit": formatOrgRatio(common.QuotaPerUnit)})
	if err != nil {
		return ""
	}
	return string(data)
}

func requestContext(c *gin.Context) context.Context {
	if c != nil && c.Request != nil {
		return c.Request.Context()
	}
	return context.Background()
}
