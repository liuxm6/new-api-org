package gemini

import (
	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
)

func init() {
	// generationConfig.maxOutputTokens counts thinking tokens against the limit
	// (a response can end with MAX_TOKENS before any visible text); see
	// https://ai.google.dev/gemini-api/docs/thinking.
	relaycommon.DeclareOutputCapCoversReasoning(true, constant.ChannelTypeGemini)
}
