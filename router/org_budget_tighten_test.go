package router

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A retry that lands on a dearer group needs more than was held. When the extra
// cannot be held the output limit is cut to what fits, the upstream gets the
// shorter limit, and the client is told through X-NewAPI-Budget-Max-Tokens.
func TestRetryToDearerGroupTightensTheOutputLimit(t *testing.T) {
	f := setupKeyFixture(t)
	const name = "e2e-tighten"
	require.NoError(t, f.db.AutoMigrate(&model.Channel{}, &model.Ability{}, &model.Log{}))

	previousRatios := ratio_setting.GetModelRatioCopy()
	require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(`{"`+name+`":1}`))
	previousGroups := ratio_setting.GetGroupRatioCopy()
	require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(`{"default":1,"cheap":1,"dear":20}`))
	previousUsable := setting.UserUsableGroups2JSONString()
	require.NoError(t, setting.UpdateUserUsableGroupsByJSONString(`{"auto":"auto","cheap":"cheap","dear":"dear"}`))
	previousAuto := setting.AutoGroups2JsonString()
	require.NoError(t, setting.UpdateAutoGroupsByJsonString(`["cheap","dear"]`))
	previousRetry := common.RetryTimes
	common.RetryTimes = 1
	t.Cleanup(func() {
		encoded, err := common.Marshal(previousRatios)
		require.NoError(t, err)
		require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(string(encoded)))
		encoded, err = common.Marshal(previousGroups)
		require.NoError(t, err)
		require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(string(encoded)))
		require.NoError(t, setting.UpdateUserUsableGroupsByJSONString(previousUsable))
		require.NoError(t, setting.UpdateAutoGroupsByJsonString(previousAuto))
		common.RetryTimes = previousRetry
	})

	var mu sync.Mutex
	var cheapCalls int
	var dearLimits []float64
	cheap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		cheapCalls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream failure","type":"server_error"}}`))
	}))
	t.Cleanup(cheap.Close)
	dear := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		if v, ok := body["max_tokens"].(float64); ok {
			dearLimits = append(dearLimits, v)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","model":"` + name + `","choices":[{"index":0,` +
			`"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	t.Cleanup(dear.Close)
	for group, server := range map[string]*httptest.Server{"cheap": cheap, "dear": dear} {
		base := server.URL
		channel := &model.Channel{Name: group, Key: "k", Status: common.ChannelStatusEnabled, Type: constant.ChannelTypeOpenAI,
			Group: group, Models: name, BaseURL: &base}
		require.NoError(t, f.db.Create(channel).Error)
		require.NoError(t, f.db.Create(&model.Ability{ChannelId: channel.Id, Model: name, Group: group, Enabled: true}).Error)
	}

	key := f.issue(t, "dev", `{"name":"tighten","owner":"me","quota_limit":100000}`)
	require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", key.ID).
		Updates(map[string]any{"group": "auto", "cross_group_retry": true}).Error)

	const asked = 16000
	request := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(
		`{"model":"`+name+`","max_tokens":`+strconv.Itoa(asked)+`,"messages":[{"role":"user","content":"hi"}]}`))
	request.Header.Set("Authorization", "Bearer "+key.Plaintext)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.33:1234"
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 200, recorder.Code, recorder.Body.String())
	assert.Positive(t, cheapCalls, "the request first went to the cheap group")
	require.Len(t, dearLimits, 1, "and was retried once on the dear group")
	header := recorder.Header().Get("X-NewAPI-Budget-Max-Tokens")
	require.NotEmpty(t, header, "the client is told the limit was tightened")
	told, err := strconv.ParseFloat(header, 64)
	require.NoError(t, err)
	assert.Less(t, told, float64(asked))
	assert.Equal(t, told, dearLimits[0], "the upstream received the tightened limit")
}
