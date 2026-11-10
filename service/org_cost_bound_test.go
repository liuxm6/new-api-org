package service

import (
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/setting/model_setting"
	hosttypes "github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// orgBoundInfo is a ratio-priced request: model 1, completion 2, group 1.
func orgBoundInfo(modelName string) *relaycommon.RelayInfo {
	info := &relaycommon.RelayInfo{OriginModelName: modelName, BillingModelName: modelName}
	info.PriceData = hosttypes.PriceData{ModelRatio: 1, CompletionRatio: 2, GroupRatioInfo: hosttypes.GroupRatioInfo{GroupRatio: 1}}
	return info
}

func useOrgQuotaSettings(t *testing.T, mutate func(*model_setting.OrgQuotaSettings)) {
	t.Helper()
	settings := model_setting.DefaultOrgQuotaSettingsForTest()
	mutate(&settings)
	t.Cleanup(model_setting.SetOrgQuotaSettingsForTest(settings))
}

func TestScanOrgBody(t *testing.T) {
	t.Run("counts text bytes, messages and an output limit", func(t *testing.T) {
		scan, err := ScanOrgBody([]byte(`{"model":"m","max_tokens":100,"messages":[{"role":"user","content":"héllo"},{"role":"assistant","content":"ok"}]}`))
		require.NoError(t, err)
		assert.Equal(t, 2, scan.Messages)
		assert.True(t, scan.OutputCapSet)
		assert.EqualValues(t, 100, scan.OutputCap)
		assert.EqualValues(t, 1, scan.Choices)
		// "m" + "user" + "héllo" (6 bytes) + "assistant" + "ok" + the two role keys' values
		assert.GreaterOrEqual(t, scan.TextBytes, len("héllo")+len("ok"))
	})

	t.Run("the largest of several output limits wins", func(t *testing.T) {
		scan, err := ScanOrgBody([]byte(`{"max_tokens":10,"max_completion_tokens":500,"generationConfig":{"maxOutputTokens":50}}`))
		require.NoError(t, err)
		assert.EqualValues(t, 500, scan.OutputCap)
	})

	t.Run("choices and thinking budgets are read", func(t *testing.T) {
		scan, err := ScanOrgBody([]byte(`{"n":3,"thinking":{"budget_tokens":2000}}`))
		require.NoError(t, err)
		assert.EqualValues(t, 3, scan.Choices)
		assert.EqualValues(t, 2000, scan.ThinkingBudget)
		scan, err = ScanOrgBody([]byte(`{"generationConfig":{"candidateCount":2,"thinkingConfig":{"thinkingBudget":64}}}`))
		require.NoError(t, err)
		assert.EqualValues(t, 2, scan.Choices)
		assert.EqualValues(t, 64, scan.ThinkingBudget)
	})

	t.Run("media is counted and its payload is not text", func(t *testing.T) {
		huge := strings.Repeat("A", 100000)
		scan, err := ScanOrgBody([]byte(`{"messages":[{"role":"user","content":[` +
			`{"type":"image_url","image_url":{"url":"data:image/png;base64,` + huge + `"}},` +
			`{"type":"input_audio","input_audio":{"data":"` + huge + `"}},` +
			`{"type":"text","text":"hi"}]}]}`))
		require.NoError(t, err)
		assert.Equal(t, 1, scan.Media[orgMediaImage])
		assert.Equal(t, 1, scan.Media[orgMediaAudio])
		assert.Less(t, scan.TextBytes, 1000, "base64 payloads must not inflate the text bound")

		scan, err = ScanOrgBody([]byte(`{"contents":[{"parts":[{"inlineData":{"mimeType":"application/pdf","data":"` + huge + `"}}]}]}`))
		require.NoError(t, err)
		assert.Equal(t, 1, scan.Media[orgMediaPDF])
		assert.Less(t, scan.TextBytes, 1000)
	})

	t.Run("vendor-run tools are counted apart from functions", func(t *testing.T) {
		scan, err := ScanOrgBody([]byte(`{"tools":[{"type":"function","function":{"name":"f"}},{"type":"web_search"},{"googleSearch":{}}]}`))
		require.NoError(t, err)
		assert.Equal(t, 3, scan.Tools)
		assert.Equal(t, 2, scan.BuiltinTools)
		scan, err = ScanOrgBody([]byte(`{"tools":[{"type":"function","function":{"name":"f"}}]}`))
		require.NoError(t, err)
		assert.Zero(t, scan.BuiltinTools)
	})

	t.Run("a body that is not an object has no scan", func(t *testing.T) {
		for _, body := range []string{``, `[1]`, `"x"`, `null`, `{broken`} {
			_, err := ScanOrgBody([]byte(body))
			assert.Error(t, err, body)
		}
	})
}

func requireUnbounded(t *testing.T, apiErr *types.NewAPIError) {
	t.Helper()
	require.NotNil(t, apiErr)
	assert.Equal(t, types.ErrorCode(hosttypes.OrgErrCostUnbounded), apiErr.GetErrorCode())
	assert.Equal(t, 403, apiErr.StatusCode)
}

func TestEstimateOrgUpperBoundRatio(t *testing.T) {
	useOrgQuotaSettings(t, func(s *model_setting.OrgQuotaSettings) {})
	const body = `{"model":"m","max_tokens":1000,"messages":[{"role":"user","content":"abcd"}]}`

	t.Run("input bytes plus overhead, output at the completion ratio", func(t *testing.T) {
		info := orgBoundInfo("m")
		bound, err := EstimateOrgUpperBound(info, []byte(body))
		require.Nil(t, err)
		scan, scanErr := ScanOrgBody([]byte(body))
		require.NoError(t, scanErr)
		input := int64(scan.TextBytes) + 16 + 0
		assert.EqualValues(t, (input+1000*2)+0, bound.Quota-orgViolationFeeQuota())
		assert.EqualValues(t, 1000, bound.MaxOutput)
		assert.False(t, bound.Capped)
	})

	t.Run("a client limit above the model ceiling is held to the ceiling", func(t *testing.T) {
		useOrgQuotaSettings(t, func(s *model_setting.OrgQuotaSettings) { s.MaxOutputTokens = map[string]int{"m": 300} })
		bound, err := EstimateOrgUpperBound(orgBoundInfo("m"), []byte(body))
		require.Nil(t, err)
		assert.EqualValues(t, 300, bound.MaxOutput)
	})

	t.Run("no client limit uses the model default and n multiplies the output", func(t *testing.T) {
		single, err := EstimateOrgUpperBound(orgBoundInfo("m"), []byte(`{"messages":[]}`))
		require.Nil(t, err)
		assert.EqualValues(t, model_setting.DefaultOrgMaxOutputTokens, single.MaxOutput)
		triple, err := EstimateOrgUpperBound(orgBoundInfo("m"), []byte(`{"messages":[],"n":3}`))
		require.Nil(t, err)
		assert.Greater(t, triple.Quota, 2*(single.Quota-orgViolationFeeQuota()))
	})

	t.Run("the group ratio and the dearest input ratio raise the bound", func(t *testing.T) {
		plain, _ := EstimateOrgUpperBound(orgBoundInfo("m"), []byte(body))
		info := orgBoundInfo("m")
		info.PriceData.GroupRatioInfo.GroupRatio = 2
		doubled, err := EstimateOrgUpperBound(info, []byte(body))
		require.Nil(t, err)
		assert.InDelta(t, 2*float64(plain.Quota-orgViolationFeeQuota()), float64(doubled.Quota-orgViolationFeeQuota()), 2)
		info = orgBoundInfo("m")
		info.PriceData.CacheCreation1hRatio = 5
		dearer, err := EstimateOrgUpperBound(info, []byte(body))
		require.Nil(t, err)
		assert.Greater(t, dearer.Quota, plain.Quota)
	})

	t.Run("the context window caps the input", func(t *testing.T) {
		long := `{"max_tokens":10,"messages":[{"role":"user","content":"` + strings.Repeat("x", 50000) + `"}]}`
		open, err := EstimateOrgUpperBound(orgBoundInfo("m"), []byte(long))
		require.Nil(t, err)
		useOrgQuotaSettings(t, func(s *model_setting.OrgQuotaSettings) { s.MaxInputTokens = map[string]int{"m": 1000} })
		capped, err := EstimateOrgUpperBound(orgBoundInfo("m"), []byte(long))
		require.Nil(t, err)
		assert.Less(t, capped.Quota, open.Quota)
		assert.EqualValues(t, 1000+10*2, capped.Quota-orgViolationFeeQuota(), "window of 1000 input tokens plus 10 output at ratio 2")
	})

	t.Run("a fixed price per call is its own bound", func(t *testing.T) {
		info := orgBoundInfo("m")
		info.PriceData.UsePrice, info.PriceData.QuotaToPreConsume = true, 777
		bound, err := EstimateOrgUpperBound(info, []byte(`not even json`))
		require.Nil(t, err)
		assert.EqualValues(t, 777, bound.Quota)
	})
}

func TestEstimateOrgUpperBoundUnbounded(t *testing.T) {
	const body = `{"max_tokens":100,"messages":[{"role":"user","content":"hi"}]}`
	useOrgQuotaSettings(t, func(s *model_setting.OrgQuotaSettings) {})

	cases := map[string]func() (*relaycommon.RelayInfo, string){
		"a body that is not JSON": func() (*relaycommon.RelayInfo, string) { return orgBoundInfo("m"), `plain text` },
		"vendor-run tools":        func() (*relaycommon.RelayInfo, string) { return orgBoundInfo("m"), `{"tools":[{"type":"web_search"}]}` },
		"unpriced pdf": func() (*relaycommon.RelayInfo, string) {
			return orgBoundInfo("m"), `{"messages":[{"content":[{"type":"file","file":{}}]}]}`
		},
		"a non-finite price": func() (*relaycommon.RelayInfo, string) {
			i := orgBoundInfo("m")
			i.PriceData.ModelRatio = 1e300
			return i, body
		},
		"a realtime session": func() (*relaycommon.RelayInfo, string) {
			i := orgBoundInfo("m")
			i.RelayMode = relayconstant.RelayModeRealtime
			return i, body
		},
		"thinking nobody caps": func() (*relaycommon.RelayInfo, string) {
			i := orgBoundInfo("m")
			i.ChannelMeta = &relaycommon.ChannelMeta{ChannelType: constant.ChannelTypeAli}
			return i, body
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			info, request := build()
			_, err := EstimateOrgUpperBound(info, []byte(request))
			requireUnbounded(t, err)
		})
	}

	t.Run("max_request_cost turns every one of them into a capped bound", func(t *testing.T) {
		useOrgQuotaSettings(t, func(s *model_setting.OrgQuotaSettings) { s.MaxRequestCost = map[string]float64{"m": 2} })
		for name, build := range cases {
			info, request := build()
			bound, err := EstimateOrgUpperBound(info, []byte(request))
			require.Nil(t, err, name)
			assert.True(t, bound.Capped, name)
			assert.EqualValues(t, 2*500000, bound.Quota, name)
		}
	})

	t.Run("a thinking budget makes an uncapped channel boundable", func(t *testing.T) {
		info := orgBoundInfo("m")
		info.ChannelMeta = &relaycommon.ChannelMeta{ChannelType: constant.ChannelTypeAli}
		with, err := EstimateOrgUpperBound(info, []byte(`{"max_tokens":100,"thinking":{"budget_tokens":5000}}`))
		require.Nil(t, err)
		plain, _ := EstimateOrgUpperBound(orgBoundInfo("m"), []byte(`{"max_tokens":100}`))
		assert.Greater(t, with.Quota, plain.Quota)
	})
}
