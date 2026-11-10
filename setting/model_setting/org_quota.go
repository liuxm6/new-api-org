package model_setting

import (
	"fmt"
	"math"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/config"
)

// Platform defaults of the organization cost upper bound (design 4.2.1, 13.1
// items 12 to 14).
const (
	DefaultOrgMaxOutputTokens        = 16384
	DefaultOrgImageInputTokens       = 8000
	DefaultOrgMaxToolCalls           = 20
	DefaultOrgWriteoffDailyLimitUSD  = 5.0
	DefaultOrgRecoveryMaxCount       = 20
	DefaultOrgRecoveryMaxUSD         = 50.0
	DefaultOrgMessageOverheadTokens  = 16
	DefaultOrgToolDefOverheadTokens  = 16
	orgQuotaDefaultModelKey          = "default"
	orgQuotaOptionPrefix             = "org_quota."
	orgQuotaMaxConfiguredTokens      = 1 << 30
	orgQuotaMaxConfiguredSeconds     = 24 * 3600
	orgQuotaMaxConfiguredToolCalls   = 10_000
	orgQuotaMaxConfiguredOverheadTok = 4096
)

// OrgQuotaSettings is maintained by platform administrators and bounds what one
// organization request may cost. Model keys are an exact model name, a prefix
// ending in "*" (longest prefix wins) or, where the field has a default, "default".
// Money values are USD. Registered with the option system as "org_quota", so the
// persisted keys are "org_quota.<json name>".
type OrgQuotaSettings struct {
	// MaxOutputTokens is the model's output ceiling, reasoning included.
	MaxOutputTokens map[string]int `json:"max_output_tokens"`
	// MaxInputTokens is the model's context window; it caps the input bound.
	MaxInputTokens map[string]int `json:"max_input_tokens"`
	// MaxInputTokensPerMedia maps model -> media type (image, pdf, audio, video,
	// file) -> tokens one item may cost. A missing type has no bound.
	MaxInputTokensPerMedia map[string]map[string]int `json:"max_input_tokens_per_media"`
	// MaxRequestCost maps a model, or "plugin::model" for task plugins, to the
	// request charge cap in USD, used only when no true bound exists. No default.
	MaxRequestCost map[string]float64 `json:"max_request_cost"`
	// MaxTaskDurationSeconds is the longest duration a task model can be asked
	// for, used when the vendor decides the length (duration=-1).
	MaxTaskDurationSeconds map[string]int `json:"max_task_duration_seconds"`

	MaxToolCalls             int     `json:"max_tool_calls"`
	WriteoffDailyLimitUSD    float64 `json:"writeoff_daily_limit_usd"`
	RecoveryRequiredMaxCount int     `json:"recovery_required_max_count"`
	RecoveryRequiredMaxUSD   float64 `json:"recovery_required_max_usd"`
	// ViolationFeeMaxUSD bounds the fee charged after a failed request. -1 (the
	// default) follows the Grok violation deduction setting.
	ViolationFeeMaxUSD    float64 `json:"violation_fee_max_usd"`
	MessageOverheadTokens int     `json:"message_overhead_tokens"`
	ToolDefOverheadTokens int     `json:"tool_def_overhead_tokens"`
}

func defaultOrgQuotaSettings() OrgQuotaSettings {
	return OrgQuotaSettings{
		MaxOutputTokens:          map[string]int{},
		MaxInputTokens:           map[string]int{},
		MaxInputTokensPerMedia:   map[string]map[string]int{orgQuotaDefaultModelKey: {"image": DefaultOrgImageInputTokens}},
		MaxRequestCost:           map[string]float64{},
		MaxTaskDurationSeconds:   map[string]int{},
		MaxToolCalls:             DefaultOrgMaxToolCalls,
		WriteoffDailyLimitUSD:    DefaultOrgWriteoffDailyLimitUSD,
		RecoveryRequiredMaxCount: DefaultOrgRecoveryMaxCount,
		RecoveryRequiredMaxUSD:   DefaultOrgRecoveryMaxUSD,
		ViolationFeeMaxUSD:       -1,
		MessageOverheadTokens:    DefaultOrgMessageOverheadTokens,
		ToolDefOverheadTokens:    DefaultOrgToolDefOverheadTokens,
	}
}

var orgQuotaSettings = defaultOrgQuotaSettings()

func init() {
	config.GlobalConfig.Register("org_quota", &orgQuotaSettings)
}

// GetOrgQuotaSettings returns the live settings object. Treat it as read-only.
func GetOrgQuotaSettings() *OrgQuotaSettings {
	return &orgQuotaSettings
}

// SetOrgQuotaSettingsForTest replaces the settings and returns a restore func. Tests only.
func SetOrgQuotaSettingsForTest(settings OrgQuotaSettings) func() {
	previous := orgQuotaSettings
	orgQuotaSettings = settings
	return func() { orgQuotaSettings = previous }
}

// DefaultOrgQuotaSettingsForTest returns a fresh copy of the platform defaults.
func DefaultOrgQuotaSettingsForTest() OrgQuotaSettings {
	return defaultOrgQuotaSettings()
}

// lookupOrgModelValue resolves exact name, then the longest "prefix*" key, then
// (when allowDefault) the "default" key.
func lookupOrgModelValue[T any](values map[string]T, model string, allowDefault bool) (T, bool) {
	if value, ok := values[model]; ok {
		return value, true
	}
	bestPrefix := -1
	var best T
	for key, value := range values {
		prefix, wildcard := strings.CutSuffix(key, "*")
		if !wildcard || !strings.HasPrefix(model, prefix) || len(prefix) <= bestPrefix {
			continue
		}
		bestPrefix = len(prefix)
		best = value
	}
	if bestPrefix >= 0 {
		return best, true
	}
	if allowDefault {
		if value, ok := values[orgQuotaDefaultModelKey]; ok {
			return value, true
		}
	}
	var zero T
	return zero, false
}

// OrgMaxOutputTokens is the model's output ceiling: the configured value, or the
// platform default 16,384 when none is set.
func OrgMaxOutputTokens(model string) int {
	if value, ok := lookupOrgModelValue(orgQuotaSettings.MaxOutputTokens, model, true); ok && value > 0 {
		return value
	}
	return DefaultOrgMaxOutputTokens
}

// OrgDefaultOutputTokens is the value to write into a request whose client set no
// output limit. A Claude-format request is also bounded by the existing Claude
// default, which the Claude adaptor writes itself; the smaller value wins.
func OrgDefaultOutputTokens(model string, claudeFormat bool) int {
	limit := OrgMaxOutputTokens(model)
	if !claudeFormat {
		return limit
	}
	claudeDefault := GetClaudeSettings().GetDefaultMaxTokens(model)
	if claudeDefault > 0 && claudeDefault < limit {
		return claudeDefault
	}
	return limit
}

// OrgMaxInputTokens returns the configured context window, or 0 when unset.
func OrgMaxInputTokens(model string) int {
	if value, ok := lookupOrgModelValue(orgQuotaSettings.MaxInputTokens, model, true); ok && value > 0 {
		return value
	}
	return 0
}

// OrgMaxInputTokensPerMedia returns the per-item token cap of a media type for
// the model. ok is false when the type has no configured bound.
func OrgMaxInputTokensPerMedia(model, mediaType string) (tokens int, ok bool) {
	// A model entry replaces the default entry as a whole, so an administrator
	// can remove the image default for one model by listing the model.
	perModel, found := lookupOrgModelValue(orgQuotaSettings.MaxInputTokensPerMedia, model, true)
	if !found {
		return 0, false
	}
	tokens, ok = perModel[mediaType]
	if !ok || tokens <= 0 {
		return 0, false
	}
	return tokens, true
}

// OrgMaxRequestCostUSD returns the request charge cap of a model (or a
// "plugin::model" key). ok is false when none is configured; there is no default.
func OrgMaxRequestCostUSD(key string) (usd float64, ok bool) {
	value, found := lookupOrgModelValue(orgQuotaSettings.MaxRequestCost, key, false)
	if !found || !(value > 0) || math.IsInf(value, 0) {
		return 0, false
	}
	return value, true
}

// OrgMaxTaskDurationSeconds returns the longest configured task duration, or 0.
func OrgMaxTaskDurationSeconds(model string) int {
	if value, ok := lookupOrgModelValue(orgQuotaSettings.MaxTaskDurationSeconds, model, true); ok && value > 0 {
		return value
	}
	return 0
}

func OrgMaxToolCalls() int {
	if orgQuotaSettings.MaxToolCalls > 0 {
		return orgQuotaSettings.MaxToolCalls
	}
	return DefaultOrgMaxToolCalls
}

func OrgWriteoffDailyLimitUSD() float64 {
	if orgQuotaSettings.WriteoffDailyLimitUSD > 0 {
		return orgQuotaSettings.WriteoffDailyLimitUSD
	}
	return DefaultOrgWriteoffDailyLimitUSD
}

// OrgRecoveryRequiredThreshold returns the pending-reconciliation limits that
// stop new asynchronous submissions: a count and a held amount in USD.
func OrgRecoveryRequiredThreshold() (count int, usd float64) {
	count, usd = orgQuotaSettings.RecoveryRequiredMaxCount, orgQuotaSettings.RecoveryRequiredMaxUSD
	if count <= 0 {
		count = DefaultOrgRecoveryMaxCount
	}
	if !(usd > 0) {
		usd = DefaultOrgRecoveryMaxUSD
	}
	return count, usd
}

// OrgViolationFeeMaxUSD returns the largest fee a failed request can add. A
// configured value never undercuts the Grok deduction that is actually charged.
func OrgViolationFeeMaxUSD() float64 {
	charged := 0.0
	if grok := GetGrokSettings(); grok.ViolationDeductionEnabled && grok.ViolationDeductionAmount > 0 {
		charged = grok.ViolationDeductionAmount
	}
	if configured := orgQuotaSettings.ViolationFeeMaxUSD; configured >= 0 {
		return max(configured, charged)
	}
	return charged
}

func OrgMessageOverheadTokens() int {
	if orgQuotaSettings.MessageOverheadTokens > 0 {
		return orgQuotaSettings.MessageOverheadTokens
	}
	return DefaultOrgMessageOverheadTokens
}

func OrgToolDefOverheadTokens() int {
	if orgQuotaSettings.ToolDefOverheadTokens > 0 {
		return orgQuotaSettings.ToolDefOverheadTokens
	}
	return DefaultOrgToolDefOverheadTokens
}

// OrgQuotaOptionKeys lists the persisted option keys a management page may write.
func OrgQuotaOptionKeys() []string {
	configMap, err := config.ConfigToMap(&orgQuotaSettings)
	if err != nil {
		return nil
	}
	keys := make([]string, 0, len(configMap))
	for key := range configMap {
		keys = append(keys, orgQuotaOptionPrefix+key)
	}
	return keys
}

func validateOrgModelIntMap(name string, values map[string]int, limit int) error {
	for model, value := range values {
		if strings.TrimSpace(model) == "" {
			return fmt.Errorf("%s has an empty model name", name)
		}
		if value < 0 || value > limit {
			return fmt.Errorf("%s for %q must be between 0 and %d", name, model, limit)
		}
	}
	return nil
}

// ValidateOrgQuotaOption validates the value of a persisted "org_quota.<field>"
// option before it is written. Writing goes through the regular option update
// (model.UpdateOption), which loads the value back into the settings.
func ValidateOrgQuotaOption(key, value string) error {
	field, ok := strings.CutPrefix(key, orgQuotaOptionPrefix)
	if !ok {
		return fmt.Errorf("%q is not an org_quota option", key)
	}
	switch field {
	case "max_output_tokens", "max_input_tokens", "max_task_duration_seconds":
		var values map[string]int
		if err := common.UnmarshalJsonStr(value, &values); err != nil || values == nil {
			return fmt.Errorf("%s must be a JSON map of model to integer", field)
		}
		limit := orgQuotaMaxConfiguredTokens
		if field == "max_task_duration_seconds" {
			limit = orgQuotaMaxConfiguredSeconds
		}
		return validateOrgModelIntMap(field, values, limit)
	case "max_input_tokens_per_media":
		var values map[string]map[string]int
		if err := common.UnmarshalJsonStr(value, &values); err != nil || values == nil {
			return fmt.Errorf("%s must be a JSON map of model to media type to integer", field)
		}
		for model, perType := range values {
			if err := validateOrgModelIntMap(field+" for "+model, perType, orgQuotaMaxConfiguredTokens); err != nil {
				return err
			}
		}
		return nil
	case "max_request_cost":
		var values map[string]float64
		if err := common.UnmarshalJsonStr(value, &values); err != nil || values == nil {
			return fmt.Errorf("%s must be a JSON map of model to USD amount", field)
		}
		for model, usd := range values {
			if strings.TrimSpace(model) == "" || !(usd > 0) || math.IsInf(usd, 0) {
				return fmt.Errorf("%s for %q must be a positive finite USD amount", field, model)
			}
		}
		return nil
	case "max_tool_calls", "recovery_required_max_count":
		return validateOrgScalar(field, value, 1, orgQuotaMaxConfiguredToolCalls)
	case "message_overhead_tokens", "tool_def_overhead_tokens":
		return validateOrgScalar(field, value, 1, orgQuotaMaxConfiguredOverheadTok)
	case "writeoff_daily_limit_usd", "recovery_required_max_usd":
		return validateOrgScalar(field, value, 0.01, 1e9)
	case "violation_fee_max_usd":
		return validateOrgScalar(field, value, -1, 1e9)
	default:
		return fmt.Errorf("unknown org_quota option %q", field)
	}
}

func validateOrgScalar(field, value string, lower, upper float64) error {
	var number float64
	if err := common.UnmarshalJsonStr(strings.TrimSpace(value), &number); err != nil || math.IsNaN(number) || number < lower || number > upper {
		return fmt.Errorf("%s must be a number between %g and %g", field, lower, upper)
	}
	return nil
}
