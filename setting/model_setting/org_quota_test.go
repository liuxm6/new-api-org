package model_setting

import (
	"testing"

	"github.com/QuantumNous/new-api/setting/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrgQuotaSettingsLookupAndDefaults(t *testing.T) {
	restore := SetOrgQuotaSettingsForTest(DefaultOrgQuotaSettingsForTest())
	defer restore()

	assert.Equal(t, DefaultOrgMaxOutputTokens, OrgMaxOutputTokens("any-model"))
	assert.Equal(t, 0, OrgMaxInputTokens("any-model"))
	tokens, ok := OrgMaxInputTokensPerMedia("any-model", "image")
	assert.True(t, ok)
	assert.Equal(t, DefaultOrgImageInputTokens, tokens)
	for _, mediaType := range []string{"pdf", "audio", "video", "file"} {
		_, ok = OrgMaxInputTokensPerMedia("any-model", mediaType)
		assert.Falsef(t, ok, "%s has no default bound", mediaType)
	}
	_, ok = OrgMaxRequestCostUSD("any-model")
	assert.False(t, ok, "max_request_cost has no default")
	assert.Equal(t, 20, OrgMaxToolCalls())
	assert.Equal(t, 5.0, OrgWriteoffDailyLimitUSD())
	count, usd := OrgRecoveryRequiredThreshold()
	assert.Equal(t, 20, count)
	assert.Equal(t, 50.0, usd)
	assert.Equal(t, 16, OrgMessageOverheadTokens())

	settings := DefaultOrgQuotaSettingsForTest()
	settings.MaxOutputTokens = map[string]int{"gpt-*": 4096, "gpt-4o*": 8192, "claude-x": 100000, "default": 2048}
	settings.MaxRequestCost = map[string]float64{"plugin::video-1": 3.5, "video-*": 1.25, "default": 99}
	settings.MaxInputTokensPerMedia = map[string]map[string]int{"default": {"image": 8000}, "claude-*": {"image": 1600, "pdf": 5000}}
	restoreCustom := SetOrgQuotaSettingsForTest(settings)
	defer restoreCustom()

	tests := []struct {
		name string
		got  int
		want int
	}{
		{"exact beats prefix", OrgMaxOutputTokens("claude-x"), 100000},
		{"longest prefix wins", OrgMaxOutputTokens("gpt-4o-mini"), 8192},
		{"shorter prefix", OrgMaxOutputTokens("gpt-3.5"), 4096},
		{"default key", OrgMaxOutputTokens("other"), 2048},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.got, tt.name)
	}

	usd, ok = OrgMaxRequestCostUSD("plugin::video-1")
	assert.True(t, ok)
	assert.Equal(t, 3.5, usd)
	usd, ok = OrgMaxRequestCostUSD("video-pro")
	assert.True(t, ok)
	assert.Equal(t, 1.25, usd)
	_, ok = OrgMaxRequestCostUSD("unlisted")
	assert.False(t, ok, "max_request_cost ignores the default key")

	tokens, ok = OrgMaxInputTokensPerMedia("claude-sonnet", "pdf")
	assert.True(t, ok)
	assert.Equal(t, 5000, tokens)
	_, ok = OrgMaxInputTokensPerMedia("other", "pdf")
	assert.False(t, ok)
}

func TestOrgDefaultOutputTokensTakesSmallerOfClaudeDefault(t *testing.T) {
	restore := SetOrgQuotaSettingsForTest(DefaultOrgQuotaSettingsForTest())
	defer restore()

	assert.Equal(t, 8192, OrgDefaultOutputTokens("claude-sonnet", true), "Claude default 8192 is smaller than 16384")
	assert.Equal(t, DefaultOrgMaxOutputTokens, OrgDefaultOutputTokens("gpt-4o", false))

	settings := DefaultOrgQuotaSettingsForTest()
	settings.MaxOutputTokens = map[string]int{"claude-sonnet": 4000}
	restoreSmaller := SetOrgQuotaSettingsForTest(settings)
	defer restoreSmaller()
	assert.Equal(t, 4000, OrgDefaultOutputTokens("claude-sonnet", true))
}

func TestOrgViolationFeeMaxFollowsGrokDeduction(t *testing.T) {
	restore := SetOrgQuotaSettingsForTest(DefaultOrgQuotaSettingsForTest())
	defer restore()
	grok := GetGrokSettings()
	original := *grok
	defer func() { *grok = original }()

	grok.ViolationDeductionEnabled, grok.ViolationDeductionAmount = true, 0.05
	assert.Equal(t, 0.05, OrgViolationFeeMaxUSD())
	grok.ViolationDeductionEnabled = false
	assert.Equal(t, 0.0, OrgViolationFeeMaxUSD())

	grok.ViolationDeductionEnabled = true
	settings := DefaultOrgQuotaSettingsForTest()
	settings.ViolationFeeMaxUSD = 0.5
	restoreConfigured := SetOrgQuotaSettingsForTest(settings)
	defer restoreConfigured()
	assert.Equal(t, 0.5, OrgViolationFeeMaxUSD())
	settings.ViolationFeeMaxUSD = 0.01
	orgQuotaSettings = settings
	assert.Equal(t, 0.05, OrgViolationFeeMaxUSD(), "a configured value never undercuts the deduction actually charged")
}

func TestOrgQuotaOptionRoundTripAndValidation(t *testing.T) {
	restore := SetOrgQuotaSettingsForTest(DefaultOrgQuotaSettingsForTest())
	defer restore()

	keys := OrgQuotaOptionKeys()
	assert.Contains(t, keys, "org_quota.max_output_tokens")
	assert.Contains(t, keys, "org_quota.max_request_cost")
	assert.Contains(t, keys, "org_quota.writeoff_daily_limit_usd")

	validTests := map[string]string{
		"org_quota.max_output_tokens":           `{"gpt-*": 4096}`,
		"org_quota.max_input_tokens_per_media":  `{"default": {"image": 8000, "pdf": 12000}}`,
		"org_quota.max_request_cost":            `{"plugin::video-1": 2.5}`,
		"org_quota.max_tool_calls":              `30`,
		"org_quota.writeoff_daily_limit_usd":    `7.5`,
		"org_quota.violation_fee_max_usd":       `-1`,
		"org_quota.max_task_duration_seconds":   `{"default": 600}`,
		"org_quota.recovery_required_max_count": `10`,
	}
	for key, value := range validTests {
		require.NoErrorf(t, ValidateOrgQuotaOption(key, value), "%s=%s", key, value)
	}
	invalidTests := map[string]string{
		"org_quota.max_output_tokens":          `{"gpt-*": -1}`,
		"org_quota.max_input_tokens":           `[1]`,
		"org_quota.max_input_tokens_per_media": `{"default": {"image": -5}}`,
		"org_quota.max_request_cost":           `{"m": 0}`,
		"org_quota.max_tool_calls":             `0`,
		"org_quota.writeoff_daily_limit_usd":   `"5"`,
		"org_quota.unknown_field":              `1`,
		"other.max_output_tokens":              `{}`,
	}
	for key, value := range invalidTests {
		assert.Errorf(t, ValidateOrgQuotaOption(key, value), "%s=%s", key, value)
	}

	// The option system loads persisted values through the registered config.
	cfg := config.GlobalConfig.Get("org_quota")
	require.NotNil(t, cfg)
	require.NoError(t, config.UpdateConfigFromMap(cfg, map[string]string{
		"max_output_tokens":          `{"gpt-*": 4096}`,
		"max_request_cost":           `{"m": 2.5}`,
		"max_tool_calls":             `30`,
		"writeoff_daily_limit_usd":   `7.5`,
		"max_input_tokens_per_media": `{"default": {"image": 1000}}`,
	}))
	assert.Equal(t, 4096, OrgMaxOutputTokens("gpt-4"))
	assert.Equal(t, 30, OrgMaxToolCalls())
	assert.Equal(t, 7.5, OrgWriteoffDailyLimitUSD())
	usd, ok := OrgMaxRequestCostUSD("m")
	assert.True(t, ok)
	assert.Equal(t, 2.5, usd)
	tokens, ok := OrgMaxInputTokensPerMedia("x", "image")
	assert.True(t, ok)
	assert.Equal(t, 1000, tokens)
}
