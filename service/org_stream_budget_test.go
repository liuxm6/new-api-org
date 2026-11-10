package service

import (
	"testing"

	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	hosttypes "github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
)

func TestOrgStreamByteBudget(t *testing.T) {
	stream := func(mode int) *relaycommon.RelayInfo {
		info := &relaycommon.RelayInfo{IsStream: true, RelayMode: mode, OrgSubject: hosttypes.OrgSubject{OrgID: 1}}
		info.PriceData = hosttypes.PriceData{ModelRatio: 1, CompletionRatio: 2, GroupRatioInfo: hosttypes.GroupRatioInfo{GroupRatio: 1}}
		return info
	}

	t.Run("an output limit sets the budget from tokens", func(t *testing.T) {
		got := orgStreamByteBudget(stream(relayconstant.RelayModeChatCompletions), OrgBound{Quota: 1_000_000, MaxOutput: 4096})
		assert.EqualValues(t, 4096*orgStreamBytesPerToken, got)
	})

	t.Run("a small output limit still leaves room for the framing events", func(t *testing.T) {
		got := orgStreamByteBudget(stream(relayconstant.RelayModeChatCompletions), OrgBound{Quota: 1000, MaxOutput: 16})
		assert.EqualValues(t, orgStreamMinBytes, got)
	})

	t.Run("a capped cost bound derives the tokens it can pay for", func(t *testing.T) {
		// 2 per output token at ratio 1 x completion 2 x group 1: 10_000 quota buys 5_000 tokens
		got := orgStreamByteBudget(stream(relayconstant.RelayModeResponses), OrgBound{Quota: 10_000, Capped: true})
		assert.EqualValues(t, 5_000*orgStreamBytesPerToken, got)
	})

	t.Run("every text mode is capped", func(t *testing.T) {
		for _, mode := range []int{relayconstant.RelayModeChatCompletions, relayconstant.RelayModeCompletions,
			relayconstant.RelayModeResponses, relayconstant.RelayModeGemini} {
			assert.Positive(t, orgStreamByteBudget(stream(mode), OrgBound{Quota: 1000, MaxOutput: 1000}), mode)
		}
	})

	t.Run("images, audio, personal and non-streaming requests are never capped", func(t *testing.T) {
		bound := OrgBound{Quota: 1000, MaxOutput: 1000}
		assert.Zero(t, orgStreamByteBudget(stream(relayconstant.RelayModeImagesGenerations), bound))
		assert.Zero(t, orgStreamByteBudget(stream(relayconstant.RelayModeAudioSpeech), bound))
		personal := stream(relayconstant.RelayModeChatCompletions)
		personal.OrgSubject = hosttypes.OrgSubject{}
		assert.Zero(t, orgStreamByteBudget(personal, bound))
		sync := stream(relayconstant.RelayModeChatCompletions)
		sync.IsStream = false
		assert.Zero(t, orgStreamByteBudget(sync, bound))
		assert.Zero(t, orgStreamByteBudget(nil, bound))
	})

	t.Run("a fixed price per call has no token meaning and is not capped", func(t *testing.T) {
		info := stream(relayconstant.RelayModeChatCompletions)
		info.PriceData.UsePrice = true
		assert.Zero(t, orgStreamByteBudget(info, OrgBound{Quota: 1000, MaxOutput: 1000}))
	})

	t.Run("no usable price and no output limit means no cap", func(t *testing.T) {
		info := stream(relayconstant.RelayModeChatCompletions)
		info.PriceData.ModelRatio = 0
		assert.Zero(t, orgStreamByteBudget(info, OrgBound{Quota: 1000, Capped: true}))
		assert.Zero(t, orgStreamByteBudget(stream(relayconstant.RelayModeChatCompletions), OrgBound{}))
	})

	t.Run("an output limit too large to count in bytes is not capped", func(t *testing.T) {
		assert.Zero(t, orgStreamByteBudget(stream(relayconstant.RelayModeChatCompletions),
			OrgBound{Quota: 1000, MaxOutput: 1 << 62}))
	})
}
