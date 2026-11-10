package openai

import (
	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
)

func init() {
	// max_completion_tokens (and max_output_tokens on the Responses API) bound
	// visible output and reasoning tokens together on OpenAI and Azure OpenAI
	// (https://platform.openai.com/docs/guides/reasoning). Other channels served
	// by this adaptor keep the conservative default.
	relaycommon.DeclareOutputCapCoversReasoning(true, constant.ChannelTypeOpenAI, constant.ChannelTypeAzure)
}
