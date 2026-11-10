package common

import "sync"

// Channel adaptors declare whether the output-limit field they send upstream
// also caps reasoning (thinking) tokens. The organization cost bound
// (design 4.2.1) relies on it: when the declaration is false the request must
// carry an explicit thinking cap, or the cost has no upper bound.
//
// The default is false. An adaptor sets true for the channel types whose
// upstream documents that reasoning tokens count against the limit. The
// registry lives here because relay/channel imports service, so service cannot
// import the adaptors.

var outputCapCoversReasoning sync.Map // channel type (int) -> bool

// DeclareOutputCapCoversReasoning records the declaration of a channel type.
func DeclareOutputCapCoversReasoning(covers bool, channelTypes ...int) {
	for _, channelType := range channelTypes {
		outputCapCoversReasoning.Store(channelType, covers)
	}
}

// OutputCapCoversReasoning reports the declaration of the channel type serving
// the current attempt. Undeclared channel types and a request without channel
// metadata report false.
func OutputCapCoversReasoning(info *RelayInfo) bool {
	if info == nil || info.ChannelMeta == nil {
		return false
	}
	covers, _ := outputCapCoversReasoning.Load(info.ChannelType)
	declared, _ := covers.(bool)
	return declared
}
