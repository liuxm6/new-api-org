package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	hosttypes "github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type orgSessionEnv struct {
	db      *gorm.DB
	wallet  *model.User
	subject hosttypes.OrgSubject
}

// newOrgSessionEnv builds one organization with a funded wallet and one key.
func newOrgSessionEnv(t *testing.T, quota int) *orgSessionEnv {
	t.Helper()
	previousDB, previousLog, previousType := model.DB, model.LOG_DB, common.MainDatabaseType()
	previousRedis := common.RedisEnabled
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	model.DB, model.LOG_DB = db, db
	common.SetMainDatabaseType(common.DatabaseTypeSQLite)
	common.RedisEnabled = false
	model.InitColumnNames()
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Token{}, &model.Organization{}, &model.Workspace{}))
	require.NoError(t, model.MigrateOrgTables())
	t.Cleanup(func() {
		model.DB, model.LOG_DB = previousDB, previousLog
		common.SetMainDatabaseType(previousType)
		common.RedisEnabled = previousRedis
		model.InitColumnNames()
		_ = sqlDB.Close()
	})

	// These tests assert exact wallet figures; a lease would move money first.
	SetOrgQuotaLeasesEnabled(false)
	ResetOrgQuotaLeases()
	t.Cleanup(func() { SetOrgQuotaLeasesEnabled(true); ResetOrgQuotaLeases() })

	e := &orgSessionEnv{db: db}
	require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
		var err error
		e.wallet, err = model.CreateBillingAccountTx(tx, "default")
		return err
	}))
	require.NoError(t, db.Model(&model.User{}).Where("id = ?", e.wallet.Id).Update("quota", quota).Error)
	member := &model.User{Username: "member", Password: "x", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AffCode: "m1"}
	require.NoError(t, db.Create(member).Error)
	org := model.Organization{Slug: "acme", Name: "Acme", OwnerUserId: member.Id, BillingUserId: e.wallet.Id, Status: 1, PolicyVersion: 1}
	require.NoError(t, db.Create(&org).Error)
	ws := model.Workspace{OrgId: org.Id, Slug: "default", Name: "Default", IsDefault: true, Status: 1}
	require.NoError(t, db.Create(&ws).Error)
	key := model.Token{UserId: e.wallet.Id, Key: "orgsessionkey", Name: "k", Status: common.TokenStatusEnabled, ExpiredTime: -1,
		UnlimitedQuota: true, OrgId: org.Id, WorkspaceId: ws.Id, CreatedBy: member.Id, OwnerType: hosttypes.TokenOwnerMember, AccessPrincipalId: "prn"}
	require.NoError(t, db.Create(&key).Error)
	e.subject = hosttypes.OrgSubject{OrgID: org.Id, WorkspaceID: ws.Id, ActorUserID: member.Id, TokenID: key.Id,
		AccessPrincipalID: "prn", OwnerType: hosttypes.TokenOwnerMember}
	return e
}

func (e *orgSessionEnv) quota(t *testing.T) int {
	t.Helper()
	var quota int
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", e.wallet.Id).Select("quota").Scan(&quota).Error)
	return quota
}

func (e *orgSessionEnv) info() *relaycommon.RelayInfo {
	info := &relaycommon.RelayInfo{OriginModelName: "m", BillingModelName: "m", RequestId: "req-1", UserId: e.wallet.Id, OrgSubject: e.subject}
	info.PriceData = hosttypes.PriceData{ModelRatio: 1, CompletionRatio: 2, GroupRatioInfo: hosttypes.GroupRatioInfo{GroupRatio: 1}}
	return info
}

func testContext(body string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	return c
}

func TestOrgBillingSessionLifecycle(t *testing.T) {
	t.Run("reserve holds the bound, settle keeps only the real cost", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		session, apiErr := NewOrgBillingSession(testContext(""), e.info(), 1000, hosttypes.OrgSourceRelay)
		require.Nil(t, apiErr)
		assert.EqualValues(t, 9000, e.quota(t))
		assert.Equal(t, 1000, session.GetPreConsumedQuota())
		assert.True(t, session.NeedsRefund())

		require.NoError(t, session.Settle(400))
		assert.EqualValues(t, 9600, e.quota(t), "600 of the bound comes back")
		assert.False(t, session.NeedsRefund())
		require.NoError(t, session.Settle(400), "settling twice changes nothing")
		assert.EqualValues(t, 9600, e.quota(t))
	})

	t.Run("the charge is capped at the bound and the rest is written off", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		session, apiErr := NewOrgBillingSession(testContext(""), e.info(), 100, hosttypes.OrgSourceRelay)
		require.Nil(t, apiErr)
		require.NoError(t, session.Settle(5_000))
		assert.EqualValues(t, 9_900, e.quota(t), "the organization never pays more than it held")
		var queue model.OrgSpendFoldQueue
		require.NoError(t, e.db.First(&queue).Error)
		assert.EqualValues(t, 100, queue.SpendDelta)
		assert.EqualValues(t, 4_900, queue.WriteoffQuota)
	})

	t.Run("a failed request gives everything back and cannot settle afterwards", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		session, apiErr := NewOrgBillingSession(testContext(""), e.info(), 700, hosttypes.OrgSourceRelay)
		require.Nil(t, apiErr)
		session.Refund(testContext(""))
		assert.EqualValues(t, 10_000, e.quota(t))
		assert.False(t, session.NeedsRefund())
		session.Refund(testContext(""))
		assert.EqualValues(t, 10_000, e.quota(t), "refunding twice cannot refund twice")
		assert.Error(t, session.Settle(10))
		var events int64
		require.NoError(t, e.db.Model(&model.OrgSpendEvent{}).Count(&events).Error)
		assert.Zero(t, events, "a cancelled request leaves no accounting trace")
	})

	t.Run("settlement and cancellation survive a client that hung up", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		settled, _ := NewOrgBillingSession(testContext(""), e.info(), 500, hosttypes.OrgSourceRelay)
		gone := testContext("")
		cancelled, cancel := context.WithCancel(gone.Request.Context())
		gone.Request = gone.Request.WithContext(cancelled)
		cancel()
		_, err := settled.apply(gone, hosttypes.OrgBillingCommand{Action: hosttypes.OrgBillingActionCapture, Amount: 200, Revision: 1})
		require.NoError(t, err, "a cancelled request context must not abort the settlement")
		assert.EqualValues(t, 9_800, e.quota(t))

		failed, _ := NewOrgBillingSession(testContext(""), e.info(), 300, hosttypes.OrgSourceRelay)
		failed.Refund(gone)
		assert.EqualValues(t, 9_800, e.quota(t), "the reservation was released even though the client left")
		assert.False(t, failed.NeedsRefund())
	})

	t.Run("a settled request is not refunded", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		session, _ := NewOrgBillingSession(testContext(""), e.info(), 500, hosttypes.OrgSourceRelay)
		require.NoError(t, session.Settle(200))
		session.Refund(testContext(""))
		assert.EqualValues(t, 9_800, e.quota(t))
	})

	t.Run("reserve raises the bound and never lowers it", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		session, _ := NewOrgBillingSession(testContext(""), e.info(), 500, hosttypes.OrgSourceRelay)
		require.NoError(t, session.Reserve(300))
		assert.Equal(t, 500, session.GetPreConsumedQuota())
		require.NoError(t, session.Reserve(800))
		assert.Equal(t, 800, session.GetPreConsumedQuota())
		assert.EqualValues(t, 9_200, e.quota(t))
		require.NoError(t, session.Settle(800))
		assert.Error(t, session.Reserve(900), "a closed session holds nothing more")
	})
}

func TestOrgBillingSessionRefusals(t *testing.T) {
	t.Run("an empty wallet refuses with a stable code and holds nothing", func(t *testing.T) {
		e := newOrgSessionEnv(t, 50)
		_, apiErr := NewOrgBillingSession(testContext(""), e.info(), 1000, hosttypes.OrgSourceRelay)
		require.NotNil(t, apiErr)
		assert.EqualValues(t, hosttypes.OrgErrQuotaExhausted, apiErr.GetErrorCode())
		assert.Equal(t, 403, apiErr.StatusCode)
		assert.EqualValues(t, 50, e.quota(t))
		var ops int64
		require.NoError(t, e.db.Model(&model.OrgBillingOperation{}).Count(&ops).Error)
		assert.Zero(t, ops)
	})

	t.Run("a failed top-up leaves the session as it was", func(t *testing.T) {
		e := newOrgSessionEnv(t, 1_000)
		session, apiErr := NewOrgBillingSession(testContext(""), e.info(), 600, hosttypes.OrgSourceRelay)
		require.Nil(t, apiErr)
		assert.Error(t, session.Reserve(5_000))
		assert.Equal(t, 600, session.GetPreConsumedQuota())
		assert.EqualValues(t, 400, e.quota(t))
		require.NoError(t, session.Settle(100))
		assert.EqualValues(t, 900, e.quota(t))
	})
}

func TestOrgLegacyBillingPathsAreClosed(t *testing.T) {
	e := newOrgSessionEnv(t, 10_000)
	info := e.info()
	// The model refuses an organization wallet too (second line of defence), so
	// the message proves the service-layer guard itself stopped the call.
	const sealed = "organization requests are billed only through the organization billing session"
	t.Run("PostConsumeQuota", func(t *testing.T) {
		assert.ErrorContains(t, PostConsumeQuota(info, 100, 0, false), sealed)
		assert.EqualValues(t, 10_000, e.quota(t))
	})
	t.Run("settling without a session", func(t *testing.T) {
		assert.ErrorContains(t, SettleBilling(testContext(""), info, 100), sealed)
		assert.EqualValues(t, 10_000, e.quota(t))
	})
	t.Run("a zero difference is not a silent pass for a request that skipped admission", func(t *testing.T) {
		// Nothing was pre-consumed and nothing is owed: the personal path would
		// return nil here, which would hide an organization request that never
		// reserved anything.
		info.FinalPreConsumedQuota = 0
		assert.ErrorContains(t, SettleBilling(testContext(""), info, 0), sealed)
	})
	t.Run("legacy usage counters ignore an organization wallet", func(t *testing.T) {
		model.UpdateUserUsedQuotaAndRequestCount(e.wallet.Id, 500)
		model.UpdateUserUsedQuota(e.wallet.Id, 500)
		var wallet model.User
		require.NoError(t, e.db.First(&wallet, e.wallet.Id).Error)
		assert.Zero(t, wallet.UsedQuota)
		assert.Zero(t, wallet.RequestCount)
	})
	t.Run("a personal request is untouched", func(t *testing.T) {
		personal := &relaycommon.RelayInfo{UserId: 1}
		assert.False(t, personal.IsOrgRequest())
	})
}

func TestOrgAttemptBilling(t *testing.T) {
	const body = `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	prepare := func(t *testing.T, quota int, request string) (*orgSessionEnv, *relaycommon.RelayInfo, *gin.Context) {
		e := newOrgSessionEnv(t, quota)
		info := e.info()
		info.Request = &dto.GeneralOpenAIRequest{Model: "m"}
		c := testContext(request)
		require.Nil(t, PrepareOrgRequestBilling(c, info))
		require.NotNil(t, info.Billing)
		return e, info, c
	}

	t.Run("the first reservation is the proven bound for the body", func(t *testing.T) {
		e, info, _ := prepare(t, 1_000_000, body)
		held := int64(info.Billing.GetPreConsumedQuota())
		bound, apiErr := EstimateOrgUpperBound(info, []byte(body))
		require.Nil(t, apiErr)
		assert.Equal(t, bound.Quota, held)
		assert.EqualValues(t, 1_000_000-held, e.quota(t))
	})

	t.Run("an attempt writes the output limit the bound assumed", func(t *testing.T) {
		_, info, c := prepare(t, 1_000_000, body)
		require.Nil(t, PrepareOrgAttemptBilling(c, info))
		request := info.Request.(*dto.GeneralOpenAIRequest)
		require.NotNil(t, request.MaxTokens)
		assert.EqualValues(t, 16384, *request.MaxTokens, "no client limit means the model default is sent")
	})

	t.Run("a client limit below the ceiling is kept", func(t *testing.T) {
		// The body and the request DTO describe the same request, as in production.
		_, info, c := prepare(t, 1_000_000, `{"max_tokens":200,"messages":[]}`)
		small := uint(200)
		info.Request = &dto.GeneralOpenAIRequest{Model: "m", MaxTokens: &small}
		require.Nil(t, PrepareOrgAttemptBilling(c, info))
		assert.EqualValues(t, 200, *info.Request.(*dto.GeneralOpenAIRequest).MaxTokens)
	})

	t.Run("a client limit above the ceiling is cut to it", func(t *testing.T) {
		_, info, c := prepare(t, 1_000_000, `{"max_tokens":10000000,"messages":[]}`)
		huge := uint(10_000_000)
		info.Request = &dto.GeneralOpenAIRequest{Model: "m", MaxTokens: &huge}
		require.Nil(t, PrepareOrgAttemptBilling(c, info))
		assert.EqualValues(t, 16384, *info.Request.(*dto.GeneralOpenAIRequest).MaxTokens)
	})

	t.Run("when the extra cannot be held the output is cut to what fits", func(t *testing.T) {
		// Every bound carries the violation-fee margin, so the wallet is sized
		// from it: room for that margin and a few hundred tokens, not 5000.
		e := newOrgSessionEnv(t, int(orgViolationFeeQuota())+3_000)
		info := e.info()
		info.Request = &dto.GeneralOpenAIRequest{Model: "m"}
		c := testContext(`{"max_tokens":100,"messages":[]}`)
		require.Nil(t, PrepareOrgRequestBilling(c, info)) // holds the bound for 100 output tokens
		held := int64(info.Billing.GetPreConsumedQuota())
		// The body now asks for far more output than the wallet can hold.
		c = testContext(`{"max_tokens":5000,"messages":[]}`)
		info.Request = &dto.GeneralOpenAIRequest{Model: "m"}
		require.Nil(t, PrepareOrgAttemptBilling(c, info))
		request := info.Request.(*dto.GeneralOpenAIRequest)
		require.NotNil(t, request.MaxTokens)
		sent := int64(*request.MaxTokens)
		assert.Less(t, sent, int64(5000))
		assert.GreaterOrEqual(t, sent, int64(100), "at least what was already held")
		assert.NotEmpty(t, c.Writer.Header().Get("X-NewAPI-Budget-Max-Tokens"))
		fitted, err := EstimateOrgUpperBound(info, []byte(`{"max_tokens":`+strings.TrimSpace(c.Writer.Header().Get("X-NewAPI-Budget-Max-Tokens"))+`,"messages":[]}`))
		require.Nil(t, err)
		assert.LessOrEqual(t, fitted.Quota, int64(info.Billing.GetPreConsumedQuota()), "the cut request is covered by what is held")
		assert.GreaterOrEqual(t, int64(info.Billing.GetPreConsumedQuota()), held)
		assert.GreaterOrEqual(t, e.quota(t), 0)
	})

	t.Run("a request nobody can bound is refused before the upstream", func(t *testing.T) {
		e := newOrgSessionEnv(t, 1_000_000)
		info := e.info()
		info.Request = &dto.GeneralOpenAIRequest{Model: "m"}
		apiErr := PrepareOrgRequestBilling(testContext(`{"tools":[{"type":"web_search"}]}`), info)
		require.NotNil(t, apiErr)
		assert.EqualValues(t, hosttypes.OrgErrCostUnbounded, apiErr.GetErrorCode())
		assert.Nil(t, info.Billing)
		assert.EqualValues(t, 1_000_000, e.quota(t))
	})

	t.Run("a personal request has no organization session", func(t *testing.T) {
		info := &relaycommon.RelayInfo{UserId: 1}
		assert.Nil(t, PrepareOrgAttemptBilling(testContext(body), info))
	})
}

func TestOrgCostWriteoffLimit(t *testing.T) {
	cap := int64(5 * common.QuotaPerUnit)
	today := time.Now().UTC().Format("2006-01-02")
	absorb := func(t *testing.T, e *orgSessionEnv, day, modelName string, quota int64) {
		t.Helper()
		require.NoError(t, e.db.Create(&model.OrgWriteoffDaily{OrgId: e.subject.OrgID, Day: day, ModelName: modelName,
			WriteoffQuota: quota}).Error)
		ResetOrgWriteoffGuard()
	}
	admit := func(e *orgSessionEnv) *types.NewAPIError {
		info := e.info()
		return reserveOrgBound(testContext(""), info, OrgBound{Quota: 100}, hosttypes.OrgSourceRelay)
	}
	operations := func(t *testing.T, e *orgSessionEnv) int64 {
		var n int64
		require.NoError(t, e.db.Model(&model.OrgBillingOperation{}).Count(&n).Error)
		return n
	}
	t.Cleanup(ResetOrgWriteoffGuard)

	t.Run("a model over the daily cap is refused with 403 before anything is held", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		absorb(t, e, today, "m", cap+1)
		apiErr := admit(e)
		require.NotNil(t, apiErr)
		assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
		assert.EqualValues(t, hosttypes.OrgErrWriteoffLimited, apiErr.GetErrorCode())
		assert.EqualValues(t, 10_000, e.quota(t), "nothing was reserved")
		assert.Zero(t, operations(t, e), "no operation was opened")
	})

	t.Run("exactly the cap is still admitted", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		absorb(t, e, today, "m", cap)
		assert.Nil(t, admit(e))
	})

	t.Run("another model and yesterday's total do not count", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		absorb(t, e, today, "other-model", cap*10)
		absorb(t, e, time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02"), "m", cap*10)
		assert.Nil(t, admit(e))
	})

	t.Run("another organization is not limited by this one", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		require.NoError(t, e.db.Create(&model.OrgWriteoffDaily{OrgId: e.subject.OrgID + 100, Day: today, ModelName: "m",
			WriteoffQuota: cap * 10}).Error)
		ResetOrgWriteoffGuard()
		assert.Nil(t, admit(e))
	})

	t.Run("work admitted before the cap was reached still settles, and a retry reuses its session", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		info := e.info()
		require.Nil(t, reserveOrgBound(testContext(""), info, OrgBound{Quota: 100}, hosttypes.OrgSourceRelay))
		absorb(t, e, today, "m", cap+1)
		require.Nil(t, reserveOrgBound(testContext(""), info, OrgBound{Quota: 100}, hosttypes.OrgSourceRelay),
			"a channel retry keeps the operation it already holds")
		require.NoError(t, info.Billing.Settle(60))
		assert.EqualValues(t, 9_940, e.quota(t))
		fresh := e.info()
		fresh.RequestId = "req-2"
		refused := reserveOrgBound(testContext(""), fresh, OrgBound{Quota: 100}, hosttypes.OrgSourceRelay)
		require.NotNil(t, refused, "a new request for the limited model is still refused")
		assert.EqualValues(t, hosttypes.OrgErrWriteoffLimited, refused.GetErrorCode())
	})

	t.Run("the next UTC day starts from zero", func(t *testing.T) {
		e := newOrgSessionEnv(t, 10_000)
		absorb(t, e, today, "m", cap+1)
		require.NotNil(t, admit(e))
		require.NoError(t, e.db.Model(&model.OrgWriteoffDaily{}).Where("org_id = ?", e.subject.OrgID).
			Update("day", time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")).Error)
		ResetOrgWriteoffGuard()
		assert.Nil(t, admit(e))
	})
}
