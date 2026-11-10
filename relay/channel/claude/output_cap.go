package claude

import (
	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
)

func init() {
	// Extended thinking is billed as output and budget_tokens must stay below
	// max_tokens, so max_tokens bounds thinking and visible output together
	// (https://docs.claude.com/en/docs/build-with-claude/extended-thinking).
	relaycommon.DeclareOutputCapCoversReasoning(true, constant.ChannelTypeAnthropic)
}
