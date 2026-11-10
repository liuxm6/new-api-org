package router

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const e2eModel = "e2e-model"

// e2eUpstream starts a chat completion upstream and a channel that points at it.
func (f *keyFixture) e2eUpstream(t *testing.T, status int) *int {
	t.Helper()
	return f.e2eUpstreamFor(t, status, e2eModel)
}

func (f *keyFixture) e2eUpstreamFor(t *testing.T, status int, name string) *int {
	t.Helper()
	require.NoError(t, f.db.AutoMigrate(&model.Channel{}, &model.Ability{}, &model.Log{}, &model.TopUp{}, &model.Redemption{}))
	calls := new(int)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"id":"c1","object":"chat.completion","model":"` + name + `","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`))
	}))
	t.Cleanup(upstream.Close)
	base := upstream.URL
	channel := &model.Channel{Name: "e2e", Key: "upstream-key", Status: common.ChannelStatusEnabled, Type: constant.ChannelTypeOpenAI,
		Group: "default", Models: name, BaseURL: &base}
	require.NoError(t, f.db.Create(channel).Error)
	require.NoError(t, f.db.Create(&model.Ability{ChannelId: channel.Id, Model: name, Group: "default", Enabled: true}).Error)
	require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"`+e2eModel+`":0.002,"e2e-fail":0.002,"e2e-slow":0.002}`))
	return calls
}

func (f *keyFixture) chat(t *testing.T, plaintext string) routeReply {
	t.Helper()
	return f.chatModel(t, plaintext, e2eModel)
}

func (f *keyFixture) chatModel(t *testing.T, plaintext, name string) routeReply {
	t.Helper()
	request := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"`+name+`","messages":[{"role":"user","content":"hello"}]}`))
	request.Header.Set("Authorization", "Bearer "+plaintext)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.30:1234"
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	reply := routeReply{Status: recorder.Code, Raw: recorder.Body.String(), Body: map[string]any{}}
	_ = common.Unmarshal(recorder.Body.Bytes(), &reply.Body)
	return reply
}

func TestOrgEndToEnd(t *testing.T) {
	f := setupOrgRoutes(t)
	SetDashboardRouter(f.engine)
	SetRelayRouter(f.engine)
	kf := &keyFixture{orgRoutesFixture: f}
	for _, name := range []string{"owner", "dev"} {
		f.user(t, name, name+"@example.com")
	}
	base := "/api/orgs/acme"
	wallet := func() int64 {
		var quota int64
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", kf.walletID).Select("quota").Scan(&quota).Error)
		return quota
	}
	fold := func() {
		_, err := model.FoldOrgSpend(t.Context(), kf.orgID, 1000)
		require.NoError(t, err)
	}

	t.Run("create the organization, invite a developer and give the workspace", func(t *testing.T) {
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)
		var org model.Organization
		require.NoError(t, f.db.Where("slug = ?", "acme").First(&org).Error)
		var ws model.Workspace
		require.NoError(t, f.db.Where("org_id = ? AND is_default = ?", org.Id, true).First(&ws).Error)
		kf.orgID, kf.wsID, kf.walletID = org.Id, ws.Id, org.BillingUserId

		issued := f.do(t, f.tokens["owner"], "POST", base+"/invites", `{"email":"dev@example.com","org_role":"member"}`)
		require.Equal(t, 200, issued.Status, issued.Raw)
		link, _ := issued.data()["invite_url"].(string)
		require.Equal(t, 200, f.do(t, f.tokens["dev"], "POST", "/api/invites/"+link[strings.LastIndex(link, "/")+1:]+"/accept", "").Status)
		uid := strconv.Itoa(f.users["dev"].Id)
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "PUT", base+"/workspaces/default/members/"+uid, `{"role":"member"}`).Status)
	})

	calls := kf.e2eUpstream(t, 200)

	t.Run("an empty wallet refuses the request before the upstream is called", func(t *testing.T) {
		key := kf.issue(t, "dev", `{"name":"early","owner":"me"}`)
		reply := kf.chat(t, key.Plaintext)
		assert.Equal(t, 403, reply.Status, reply.Raw)
		assert.Zero(t, *calls)
	})

	t.Run("a redemption code funds the wallet and the ledger records it", func(t *testing.T) {
		require.NoError(t, f.db.Create(&model.Redemption{Key: "E2E-1", Name: "c", Quota: 5_000_000, Status: common.RedemptionCodeStatusEnabled,
			CreatedTime: common.GetTimestamp(), UserId: f.users["owner"].Id}).Error)
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", base+"/topup", `{"key":"E2E-1"}`).Status)
		assert.EqualValues(t, 5_000_000, wallet())
	})

	key := kf.issue(t, "dev", `{"name":"e2e","owner":"me"}`)

	t.Run("a request is reserved, settled at the real price and attributed", func(t *testing.T) {
		before := wallet()
		reply := kf.chat(t, key.Plaintext)
		require.Equal(t, 200, reply.Status, reply.Raw)
		assert.Equal(t, 1, *calls)
		assert.EqualValues(t, 1000, before-wallet(), "0.002 of a dollar at 500000 quota per dollar")
		var held int64
		require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("org_id = ? AND state IN ?", kf.orgID,
			[]string{"prepared", "reserved"}).Count(&held).Error)
		assert.Zero(t, held, "nothing stays reserved")
		var op model.OrgBillingOperation
		require.NoError(t, f.db.Where("org_id = ? AND token_id = ?", kf.orgID, key.ID).First(&op).Error)
		assert.Equal(t, f.users["dev"].Id, op.ActorUserId)
		assert.EqualValues(t, 1000, op.CapturedQuota)
	})

	t.Run("the fold feeds the organization budget and spend", func(t *testing.T) {
		fold()
		put := f.do(t, f.tokens["owner"], "PUT", base+"/budgets", `{"version":0,"budgets":[{"period":"monthly","limit":2500,"enabled":true}]}`)
		require.Equal(t, 200, put.Status, put.Raw)
		got := f.do(t, f.tokens["owner"], "GET", base+"/budgets", "")
		require.Equal(t, 200, got.Status, got.Raw)
		row := got.data()["budgets"].([]any)[0].(map[string]any)
		assert.EqualValues(t, 1000, row["spent"])
		assert.EqualValues(t, 1500, row["available"])
	})

	t.Run("a request over the budget is refused and charges nothing", func(t *testing.T) {
		require.Equal(t, 200, kf.chat(t, key.Plaintext).Status, "2000 of 2500 is still inside the budget")
		fold() // an unfolded charge still counts as held, which the budget also refuses
		before, upstreamCalls := wallet(), *calls
		reply := kf.chat(t, key.Plaintext)
		assert.Equal(t, 403, reply.Status, reply.Raw)
		assert.Equal(t, upstreamCalls, *calls, "the upstream is not called")
		assert.Equal(t, before, wallet())
	})

	t.Run("a failing upstream returns the reservation", func(t *testing.T) {
		require.NoError(t, f.db.Model(&model.Budget{}).Where("org_id = ?", kf.orgID).Update("enabled", false).Error)
		failing := kf.e2eUpstreamFor(t, 500, "e2e-fail")
		before := wallet()
		reply := kf.chatModel(t, key.Plaintext, "e2e-fail")
		assert.GreaterOrEqual(t, reply.Status, 400)
		assert.Positive(t, *failing)
		assert.Equal(t, before, wallet(), "nothing is charged for a failed request")
		var open int64
		require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("org_id = ? AND state IN ?", kf.orgID,
			[]string{"prepared", "reserved", "captured"}).Count(&open).Error)
		assert.Zero(t, open)
	})

	t.Run("receipt, ledger and audit trail tell the same story", func(t *testing.T) {
		// the receipt worker's three steps: claim, issue, finish
		jobs, err := model.ClaimOrgJobs(t.Context(), []string{"receipt"}, 10)
		require.NoError(t, err)
		require.Len(t, jobs, 1, "the top-up queued one receipt job")
		_, err = model.IssueOrgReceipt(t.Context(), jobs[0].OrgId, jobs[0].BusinessKey)
		require.NoError(t, err)
		require.NoError(t, model.FinishOrgJob(t.Context(), jobs[0].Id))
		invoices := f.do(t, f.tokens["owner"], "GET", base+"/invoices", "")
		require.Equal(t, 200, invoices.Status, invoices.Raw)
		assert.EqualValues(t, 1, invoices.data()["total"], "one receipt for the one top-up")
		billing := f.do(t, f.tokens["owner"], "GET", base+"/billing", "")
		require.Equal(t, 200, billing.Status)
		wallets := billing.data()["wallet"].(map[string]any)
		assert.EqualValues(t, wallet(), wallets["available_quota"])
		audit := f.do(t, f.tokens["owner"], "GET", base+"/audit-logs", "")
		require.Equal(t, 200, audit.Status, audit.Raw)
		for _, action := range []string{"org.create", "invite", "billing.topup"} {
			assert.Contains(t, audit.Raw, action)
		}
	})

	t.Run("the money adds up", func(t *testing.T) {
		var captured, folded int64
		require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("org_id = ?", kf.orgID).
			Select("COALESCE(SUM(captured_quota - refunded_quota), 0)").Scan(&captured).Error)
		assert.EqualValues(t, 5_000_000-captured, wallet())
		fold()
		require.NoError(t, f.db.Model(&model.OrgSpendEvent{}).Where("org_id = ?", kf.orgID).
			Select("COALESCE(SUM(delta_quota), 0)").Scan(&folded).Error)
		assert.Equal(t, captured, folded, "events equal the charges")
	})
}

// slowUpstream answers only after release is closed, so a test can change the
// world while a request is in flight.
func (f *keyFixture) slowUpstream(t *testing.T, started chan<- struct{}, release <-chan struct{}) {
	t.Helper()
	require.NoError(t, f.db.AutoMigrate(&model.Channel{}, &model.Ability{}, &model.Log{}))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c1","object":"chat.completion","model":"e2e-slow","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`))
	}))
	t.Cleanup(upstream.Close)
	base := upstream.URL
	channel := &model.Channel{Name: "slow", Key: "k", Status: common.ChannelStatusEnabled, Type: constant.ChannelTypeOpenAI,
		Group: "default", Models: "e2e-slow", BaseURL: &base}
	require.NoError(t, f.db.Create(channel).Error)
	require.NoError(t, f.db.Create(&model.Ability{ChannelId: channel.Id, Model: "e2e-slow", Group: "default", Enabled: true}).Error)
	require.NoError(t, ratio_setting.UpdateModelPriceByJSONString(`{"`+e2eModel+`":0.002,"e2e-fail":0.002,"e2e-slow":0.002}`))
}

func TestOrgFaultsThroughTheRoutes(t *testing.T) {
	f := setupKeyFixture(t)
	f.e2eUpstream(t, 200)
	started, release := make(chan struct{}, 4), make(chan struct{})
	f.slowUpstream(t, started, release)
	wallet := func() int64 {
		var quota int64
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.walletID).Select("quota").Scan(&quota).Error)
		return quota
	}
	openOperations := func() int64 {
		var n int64
		require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("org_id = ? AND state IN ?", f.orgID,
			[]string{"prepared", "reserved", "captured"}).Count(&n).Error)
		return n
	}

	t.Run("a key deleted while its request is in flight is still charged once", func(t *testing.T) {
		key := f.issue(t, "dev", `{"name":"doomed","owner":"me"}`)
		before := wallet()
		done := make(chan routeReply, 1)
		go func() { done <- f.chatModel(t, key.Plaintext, "e2e-slow") }()
		<-started
		assert.EqualValues(t, before-1000, wallet(), "the bound is held while the request runs")
		require.Equal(t, 200, f.do(t, f.tokens["dev"], "DELETE",
			"/api/orgs/acme/workspaces/default/keys/"+strconv.Itoa(key.ID), "").Status)
		close(release)
		reply := <-done
		assert.Equal(t, 200, reply.Status, reply.Raw)
		assert.EqualValues(t, before-1000, wallet(), "charged exactly once at the real price")
		assert.Zero(t, openOperations())
	})

	t.Run("a log store outage does not change what is charged", func(t *testing.T) {
		key := f.issue(t, "dev", `{"name":"logs","owner":"me"}`)
		injected := 0
		require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("fail_logs", func(tx *gorm.DB) {
			if tx.Statement.Table == "logs" {
				injected++
				_ = tx.AddError(errors.New("log store down"))
			}
		}))
		t.Cleanup(func() { _ = f.db.Callback().Create().Remove("fail_logs") })
		before := wallet()
		reply := f.chat(t, key.Plaintext)
		assert.Equal(t, 200, reply.Status, reply.Raw)
		assert.Positive(t, injected, "the outage really hit the log write")
		assert.EqualValues(t, before-1000, wallet())
		assert.Zero(t, openOperations())
	})

	t.Run("a repeated redemption callback credits once", func(t *testing.T) {
		require.NoError(t, f.db.AutoMigrate(&model.Redemption{}, &model.TopUp{}))
		require.NoError(t, f.db.Create(&model.Redemption{Key: "FAULT-1", Name: "c", Quota: 700, Status: common.RedemptionCodeStatusEnabled,
			CreatedTime: common.GetTimestamp(), UserId: f.users["owner"].Id}).Error)
		before := wallet()
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/topup", `{"key":"FAULT-1"}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/topup", `{"key":"FAULT-1"}`).Status)
		assert.Equal(t, before+700, wallet())
	})
}

// mjUpstream starts a Midjourney proxy answering every submit with the given
// code (1 accepted, anything else rejected).
func (f *keyFixture) mjUpstream(t *testing.T, code *int) *int {
	t.Helper()
	require.NoError(t, f.db.AutoMigrate(&model.Channel{}, &model.Ability{}, &model.Log{}, &model.Midjourney{}))
	calls := new(int)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":` + strconv.Itoa(*code) + `,"description":"x","result":"mj-` + strconv.Itoa(*calls) + `"}`))
	}))
	t.Cleanup(upstream.Close)
	base := upstream.URL
	channel := &model.Channel{Name: "mj", Key: "k", Status: common.ChannelStatusEnabled, Type: constant.ChannelTypeMidjourneyPlus,
		Group: "default", Models: "mj_imagine", BaseURL: &base}
	require.NoError(t, f.db.Create(channel).Error)
	require.NoError(t, f.db.Create(&model.Ability{ChannelId: channel.Id, Model: "mj_imagine", Group: "default", Enabled: true}).Error)
	return calls
}

func (f *keyFixture) imagine(t *testing.T, plaintext string) routeReply {
	t.Helper()
	request := httptest.NewRequest("POST", "/mj/submit/imagine", strings.NewReader(`{"prompt":"a cat"}`))
	request.Header.Set("Authorization", "Bearer "+plaintext)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.40:1234"
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	reply := routeReply{Status: recorder.Code, Raw: recorder.Body.String(), Body: map[string]any{}}
	_ = common.Unmarshal(recorder.Body.Bytes(), &reply.Body)
	return reply
}

func TestOrgMidjourneyThroughTheRoutes(t *testing.T) {
	service.InitHttpClient()
	f := setupKeyFixture(t)
	answer := 1
	calls := f.mjUpstream(t, &answer)
	key := f.issue(t, "dev", `{"name":"mj","owner":"me"}`)
	wallet := func() int64 {
		var quota int64
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.walletID).Select("quota").Scan(&quota).Error)
		return quota
	}
	const price = 50_000 // $0.10 at 500000 quota per dollar

	t.Run("an over-budget call never reaches the upstream", func(t *testing.T) {
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "PUT", "/api/orgs/acme/budgets",
			`{"version":0,"budgets":[{"period":"monthly","limit":`+strconv.Itoa(price-1)+`,"enabled":true}]}`).Status)
		before := wallet()
		reply := f.imagine(t, key.Plaintext)
		assert.GreaterOrEqual(t, reply.Status, 400, reply.Raw)
		assert.Zero(t, *calls, "the upstream is not called")
		assert.Equal(t, before, wallet())
	})

	t.Run("an accepted call is billed once through one durable operation", func(t *testing.T) {
		require.NoError(t, f.db.Model(&model.Budget{}).Where("org_id = ?", f.orgID).Update("enabled", false).Error)
		before := wallet()
		reply := f.imagine(t, key.Plaintext)
		require.Equal(t, 200, reply.Status, reply.Raw)
		assert.Equal(t, 1, *calls)
		assert.EqualValues(t, price, before-wallet())
		var task model.Midjourney
		require.NoError(t, f.db.Where("org_id = ?", f.orgID).First(&task).Error)
		assert.NotEmpty(t, task.BillingOperationId)
		assert.EqualValues(t, price, task.Quota)
		var op model.OrgBillingOperation
		require.NoError(t, f.db.Where("operation_id = ?", task.BillingOperationId).First(&op).Error)
		assert.Equal(t, "closed", op.State)
		assert.EqualValues(t, price, op.CapturedQuota)
	})

	t.Run("a rejected prompt is not charged and leaves nothing held", func(t *testing.T) {
		answer = 24 // the proxy refuses the prompt
		before := wallet()
		reply := f.imagine(t, key.Plaintext)
		assert.Equal(t, 24, int(reply.Body["code"].(float64)), reply.Raw)
		assert.Equal(t, before, wallet(), "nothing is charged for a rejected prompt")
		var open int64
		require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("org_id = ? AND state IN ?", f.orgID,
			[]string{"prepared", "reserved"}).Count(&open).Error)
		assert.Zero(t, open)
	})

	t.Run("a failed task is refunded through its operation", func(t *testing.T) {
		var task model.Midjourney
		require.NoError(t, f.db.Where("org_id = ? AND quota > 0", f.orgID).First(&task).Error)
		before := wallet()
		require.True(t, service.RefundMidjourneyQuota(t.Context(), &task, "Composition failed"))
		assert.EqualValues(t, before+price, wallet())
		assert.True(t, service.RefundMidjourneyQuota(t.Context(), &task, "again"))
		assert.EqualValues(t, before+price, wallet(), "a second refund moves nothing")
	})
}

func TestOrgRequestsUseInstanceLeases(t *testing.T) {
	f := setupKeyFixture(t)
	service.SetOrgQuotaLeasesEnabled(true) // the fixture turns leases off
	service.ResetOrgQuotaLeases()
	f.e2eUpstream(t, 200)
	key := f.issue(t, "dev", `{"name":"leased","owner":"me"}`)
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "PUT", "/api/orgs/acme/budgets",
		`{"version":0,"budgets":[{"period":"monthly","limit":900000,"enabled":true}]}`).Status)
	const price = 1000

	var wg sync.WaitGroup
	var failed atomic.Int64
	// the first request settles without a lease and teaches the manager the rate
	require.Equal(t, 200, f.chat(t, key.Plaintext).Status)
	for range 8 {
		wg.Go(func() {
			for range 6 {
				if f.chat(t, key.Plaintext).Status != 200 {
					failed.Add(1)
				}
			}
		})
	}
	wg.Wait()
	assert.Zero(t, failed.Load())

	var leased, sources int64
	require.NoError(t, f.db.Model(&model.OrgQuotaLease{}).Where("org_id = ?", f.orgID).Count(&leased).Error)
	assert.Positive(t, leased, "requests drew on instance leases")
	require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("org_id = ? AND holds LIKE ?", f.orgID, `%"source":"1"%`).Count(&sources).Error)

	// give every lease back, fold, and the books must close exactly
	require.NoError(t, f.db.Model(&model.OrgQuotaLease{}).Where("status = ?", "active").Update("expires_at", time.Now().Unix()-5).Error)
	for {
		swept, err := model.SweepOrgQuotaLeases(t.Context(), 500)
		require.NoError(t, err)
		if swept.Revoked+swept.Closed == 0 {
			break
		}
	}
	for {
		result, err := model.FoldOrgSpend(t.Context(), f.orgID, 1000)
		require.NoError(t, err)
		if result.Rows == 0 {
			break
		}
	}
	var wallet, captured, held, activeLeases int64
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.walletID).Select("quota").Scan(&wallet).Error)
	require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("org_id = ?", f.orgID).
		Select("COALESCE(SUM(captured_quota - refunded_quota), 0)").Scan(&captured).Error)
	require.NoError(t, f.db.Model(&model.OrgBudgetUsage{}).Where("org_id = ?", f.orgID).
		Select("COALESCE(SUM(held_quota), 0)").Scan(&held).Error)
	require.NoError(t, f.db.Model(&model.OrgQuotaLease{}).Where("org_id = ? AND status <> ?", f.orgID, "closed").Count(&activeLeases).Error)
	assert.EqualValues(t, 49*price, captured, "49 requests at the fixed price")
	assert.EqualValues(t, walletQuota-captured, wallet, "the wallet paid exactly what was captured")
	assert.Zero(t, held, "no budget keeps a hold once the leases are back")
	assert.Zero(t, activeLeases)
}
