package router

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A channel's parameter override runs after the reservation was sized, so it
// must not be able to send more output than the reservation assumed.
func TestChannelOverrideCannotRaiseAnOrgOutputLimit(t *testing.T) {
	f := setupKeyFixture(t)
	const name = "e2e-override"
	require.NoError(t, f.db.AutoMigrate(&model.Channel{}, &model.Ability{}, &model.Log{}))

	previousRatios := ratio_setting.GetModelRatioCopy()
	require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(`{"`+name+`":1}`))
	t.Cleanup(func() {
		encoded, err := common.Marshal(previousRatios)
		require.NoError(t, err)
		require.NoError(t, ratio_setting.UpdateModelRatioByJSONString(string(encoded)))
	})

	var mu sync.Mutex
	var received []float64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		if v, ok := body["max_tokens"].(float64); ok {
			received = append(received, v)
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","model":"` + name + `","choices":[{"index":0,` +
			`"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	t.Cleanup(upstream.Close)
	base := upstream.URL
	override := `{"max_tokens": 4000}`
	channel := &model.Channel{Name: "override", Key: "k", Status: common.ChannelStatusEnabled, Type: constant.ChannelTypeOpenAI,
		Group: "default", Models: name, BaseURL: &base, ParamOverride: &override}
	require.NoError(t, f.db.Create(channel).Error)
	require.NoError(t, f.db.Create(&model.Ability{ChannelId: channel.Id, Model: name, Group: "default", Enabled: true}).Error)

	key := f.issue(t, "dev", `{"name":"override","owner":"me"}`)
	post := func(maxTokens int) (int, string) {
		request := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(
			`{"model":"`+name+`","max_tokens":`+itoa(maxTokens)+`,"messages":[{"role":"user","content":"hi"}]}`))
		request.Header.Set("Authorization", "Bearer "+key.Plaintext)
		request.Header.Set("Content-Type", "application/json")
		request.RemoteAddr = "192.0.2.32:1234"
		recorder := httptest.NewRecorder()
		f.engine.ServeHTTP(recorder, request)
		return recorder.Code, recorder.Body.String()
	}

	status, body := post(16)
	require.Equal(t, 200, status, body)
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 1, "the upstream saw exactly one request")
	assert.LessOrEqual(t, received[0], float64(16),
		"the channel override asked for 4000 but the reservation was sized for the client's 16")
}

func itoa(n int) string {
	raw, _ := json.Marshal(n)
	return string(raw)
}
