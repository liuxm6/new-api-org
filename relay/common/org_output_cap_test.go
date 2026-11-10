package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClampOrgOutputLimits(t *testing.T) {
	clamp := func(t *testing.T, body string, limit int64) string {
		t.Helper()
		out, err := ClampOrgOutputLimits([]byte(body), limit)
		require.NoError(t, err)
		return string(out)
	}

	t.Run("a limit above the cap is cut to it, for every protocol field", func(t *testing.T) {
		assert.JSONEq(t, `{"max_tokens":16}`, clamp(t, `{"max_tokens":4000}`, 16))
		assert.JSONEq(t, `{"max_completion_tokens":16}`, clamp(t, `{"max_completion_tokens":4000}`, 16))
		assert.JSONEq(t, `{"max_output_tokens":16}`, clamp(t, `{"max_output_tokens":4000}`, 16))
		assert.JSONEq(t, `{"generationConfig":{"maxOutputTokens":16,"temperature":1}}`,
			clamp(t, `{"generationConfig":{"maxOutputTokens":4000,"temperature":1}}`, 16))
	})
	t.Run("a smaller or equal limit is kept", func(t *testing.T) {
		assert.JSONEq(t, `{"max_tokens":10}`, clamp(t, `{"max_tokens":10}`, 16))
		assert.JSONEq(t, `{"max_tokens":16}`, clamp(t, `{"max_tokens":16}`, 16))
	})
	t.Run("several fields are each cut", func(t *testing.T) {
		assert.JSONEq(t, `{"max_tokens":16,"max_completion_tokens":16}`,
			clamp(t, `{"max_tokens":9000,"max_completion_tokens":4000}`, 16))
	})
	t.Run("absent fields are not invented and the rest of the body is untouched", func(t *testing.T) {
		body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"temperature":0.2}`
		assert.Equal(t, body, clamp(t, body, 16))
	})
	t.Run("a non-positive cap changes nothing", func(t *testing.T) {
		body := `{"max_tokens":4000}`
		assert.Equal(t, body, clamp(t, body, 0))
		assert.Equal(t, body, clamp(t, body, -5))
	})
	t.Run("a non-numeric limit is replaced by the cap", func(t *testing.T) {
		assert.JSONEq(t, `{"max_tokens":16}`, clamp(t, `{"max_tokens":"lots"}`, 16))
	})
}

func TestParamOverrideCannotRaiseTheOrgOutputCap(t *testing.T) {
	info := &RelayInfo{ChannelMeta: &ChannelMeta{ParamOverride: map[string]any{"max_tokens": 4000}}}

	t.Run("without an organization cap the override is applied as written", func(t *testing.T) {
		out, err := ApplyParamOverrideWithRelayInfo([]byte(`{"max_tokens":16}`), info)
		require.NoError(t, err)
		assert.JSONEq(t, `{"max_tokens":4000}`, string(out))
	})
	t.Run("with an organization cap the final body never exceeds what was reserved", func(t *testing.T) {
		info.OrgOutputCap = 16
		out, err := ApplyParamOverrideWithRelayInfo([]byte(`{"max_tokens":16}`), info)
		require.NoError(t, err)
		assert.JSONEq(t, `{"max_tokens":16}`, string(out))
	})
	t.Run("the cap holds when no override is configured", func(t *testing.T) {
		bare := &RelayInfo{OrgOutputCap: 16, ChannelMeta: &ChannelMeta{}}
		out, err := ApplyParamOverrideWithRelayInfo([]byte(`{"max_tokens":4000}`), bare)
		require.NoError(t, err)
		assert.JSONEq(t, `{"max_tokens":16}`, string(out))
	})
}
