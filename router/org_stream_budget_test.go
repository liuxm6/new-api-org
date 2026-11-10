package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/model_setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runawayUpstream streams far more text than its model's output limit allows
// and counts the chunks it managed to write before the gateway hung up.
func (f *keyFixture) runawayUpstream(t *testing.T, name string, chunks int, sent *atomic.Int64) {
	t.Helper()
	require.NoError(t, f.db.AutoMigrate(&model.Channel{}, &model.Ability{}, &model.Log{}))
	text := strings.Repeat("word ", 200) // spaced words, so the local estimate counts real tokens
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < chunks; i++ {
			if _, err := w.Write([]byte(`data: {"id":"s","object":"chat.completion.chunk","model":"` + name +
				`","choices":[{"index":0,"delta":{"content":"` + text + `"}}]}` + "\n\n")); err != nil {
				return
			}
			flusher.Flush()
			sent.Add(1)
			if r.Context().Err() != nil {
				return
			}
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)
	base := upstream.URL
	channel := &model.Channel{Name: "runaway", Key: "k", Status: common.ChannelStatusEnabled, Type: constant.ChannelTypeOpenAI,
		Group: "default", Models: name, BaseURL: &base}
	require.NoError(t, f.db.Create(channel).Error)
	require.NoError(t, f.db.Create(&model.Ability{ChannelId: channel.Id, Model: name, Group: "default", Enabled: true}).Error)
}

func (f *keyFixture) streamChat(t *testing.T, plaintext, name string) (int, string) {
	t.Helper()
	request := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"`+name+`","stream":true,"messages":[{"role":"user","content":"hello"}]}`))
	request.Header.Set("Authorization", "Bearer "+plaintext)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.31:1234"
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	return recorder.Code, recorder.Body.String()
}

func TestOrgStreamIsCutAtItsByteBudget(t *testing.T) {
	f := setupKeyFixture(t)
	const name = "e2e-runaway"
	previousTimeout := constant.StreamingTimeout
	constant.StreamingTimeout = 30
	t.Cleanup(func() { constant.StreamingTimeout = previousTimeout })

	previousRatios := ratio_setting.GetModelRatioCopy()
	require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(`{"`+name+`":1}`))
	t.Cleanup(func() {
		encoded, err := common.Marshal(previousRatios)
		require.NoError(t, err)
		require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(string(encoded)))
	})
	// a 256 token limit leaves the 64 KiB floor as the stream budget
	settings := model_setting.DefaultOrgQuotaSettingsForTest()
	settings.MaxOutputTokens = map[string]int{name: 256}
	t.Cleanup(model_setting.SetOrgQuotaSettingsForTest(settings))

	var sent atomic.Int64
	f.runawayUpstream(t, name, 2000, &sent) // about 2 MB of text against a 64 KiB budget
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
	key := f.issue(t, "dev", `{"name":"runaway","owner":"me"}`)

	before := wallet()
	status, body := f.streamChat(t, key.Plaintext, name)

	assert.Equal(t, 200, status, body)
	assert.Less(t, len(body), 400<<10, "the client got a fraction of the 2 MB the upstream wanted to send")
	assert.Contains(t, body, "[DONE]", "the client's stream ends the normal way")
	assert.Less(t, sent.Load(), int64(2000), "the gateway hung up on the upstream before it finished")
	assert.Zero(t, openOperations(), "the request settled")
	assert.Less(t, wallet(), before, "the organization paid for what it received")
	assert.Positive(t, wallet(), "the wallet is intact")
	var captured int64
	require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("org_id = ?", f.orgID).
		Select("COALESCE(SUM(captured_quota), 0)").Scan(&captured).Error)
	var bound int64
	require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("org_id = ?", f.orgID).
		Select("COALESCE(MAX(bound), 0)").Scan(&bound).Error)
	assert.Positive(t, captured, "the organization pays for what it received")
	assert.LessOrEqual(t, captured, bound, "never charged above the bound")
}
