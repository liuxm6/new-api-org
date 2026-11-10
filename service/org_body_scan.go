package service

import (
	"errors"
	"strings"

	"github.com/QuantumNous/new-api/common"
)

var errOrgBodyNotObject = errors.New("request body is not a JSON object")

// Media kinds a request body can carry. Each needs a configured per-item token
// cap before an organization may send it (design 4.2.1).
const (
	orgMediaImage = "image"
	orgMediaAudio = "audio"
	orgMediaPDF   = "pdf"
	orgMediaVideo = "video"
	orgMediaOther = "file"
)

// OrgBodyScan is what the cost bound reads from a request body.
type OrgBodyScan struct {
	// TextBytes is the UTF-8 size of every text string. A byte-level BPE token
	// never covers less than a byte, so this bounds the text tokens.
	TextBytes int
	// Messages and Tools count the items that each add template overhead.
	Messages int
	Tools    int
	// BuiltinTools counts vendor-run tools (web search, code execution ...). They
	// bill per call and the request carries no cap on the calls.
	BuiltinTools int
	// Media counts items by media kind.
	Media map[string]int
	// OutputCap is the client's output limit, 0 when it set none. OutputCapSet
	// tells "0" from "absent".
	OutputCap    int64
	OutputCapSet bool
	// Choices multiplies the output (n, candidateCount); at least 1.
	Choices int64
	// ThinkingBudget is an explicit reasoning cap, 0 when none was set.
	ThinkingBudget int64
}

var orgOutputCapPaths = [][]string{
	{"max_completion_tokens"}, {"max_tokens"}, {"max_output_tokens"}, {"generationConfig", "maxOutputTokens"},
}

var orgThinkingPaths = [][]string{
	{"thinking", "budget_tokens"}, {"generationConfig", "thinkingConfig", "thinkingBudget"},
	{"reasoning", "max_tokens"}, {"reasoning_budget"},
}

var orgChoicePaths = [][]string{{"n"}, {"generationConfig", "candidateCount"}}

func orgNumberAt(root map[string]any, path []string) (int64, bool) {
	var node any = root
	for _, key := range path {
		object, ok := node.(map[string]any)
		if !ok {
			return 0, false
		}
		if node, ok = object[key]; !ok {
			return 0, false
		}
	}
	number, ok := node.(float64)
	if !ok || number < 0 || number > 1<<53 {
		return 0, false
	}
	return int64(number), true
}

// orgMediaOfType maps a content-part "type" (OpenAI, Claude, Responses) to a kind.
func orgMediaOfType(partType string) string {
	switch partType {
	case "image", "image_url", "input_image":
		return orgMediaImage
	case "input_audio", "audio":
		return orgMediaAudio
	case "video", "video_url", "input_video":
		return orgMediaVideo
	case "document", "file", "input_file":
		return orgMediaPDF
	}
	return ""
}

// orgMediaOfMime maps a Gemini mimeType to a kind.
func orgMediaOfMime(mime string) string {
	switch {
	case strings.HasPrefix(mime, "image/"):
		return orgMediaImage
	case strings.HasPrefix(mime, "audio/"):
		return orgMediaAudio
	case strings.HasPrefix(mime, "video/"):
		return orgMediaVideo
	case mime == "application/pdf":
		return orgMediaPDF
	}
	return orgMediaOther
}

// orgMediaOfKey recognizes the keys that wrap a media payload.
func orgMediaOfKey(key string) string {
	switch key {
	case "image_url":
		return orgMediaImage
	case "input_audio":
		return orgMediaAudio
	case "video_url":
		return orgMediaVideo
	}
	return ""
}

// orgBuiltinToolCount is 1 for a tool that the vendor runs: a typed tool other
// than "function", or a Gemini tool object with a built-in key.
func orgBuiltinToolCount(tool any) int {
	object, ok := tool.(map[string]any)
	if !ok {
		return 0
	}
	if toolType, ok := object["type"].(string); ok && toolType != "function" && toolType != "custom" {
		return 1
	}
	for _, key := range []string{"googleSearch", "google_search", "googleSearchRetrieval", "codeExecution", "code_execution", "urlContext", "url_context"} {
		if _, ok := object[key]; ok {
			return 1
		}
	}
	return 0
}

func (scan *OrgBodyScan) walk(node any) {
	switch value := node.(type) {
	case string:
		scan.TextBytes += len(value)
	case []any:
		for _, item := range value {
			scan.walk(item)
		}
	case map[string]any:
		if partType, _ := value["type"].(string); orgMediaOfType(partType) != "" {
			scan.Media[orgMediaOfType(partType)]++
			return // the payload under a media part is not text
		}
		for _, key := range []string{"inlineData", "inline_data", "fileData", "file_data"} {
			if part, ok := value[key].(map[string]any); ok {
				mime, _ := part["mimeType"].(string)
				if mime == "" {
					mime, _ = part["mime_type"].(string)
				}
				scan.Media[orgMediaOfMime(mime)]++
			}
		}
		for key, child := range value {
			switch {
			case key == "inlineData" || key == "inline_data" || key == "fileData" || key == "file_data":
			case orgMediaOfKey(key) != "":
				scan.Media[orgMediaOfKey(key)]++
			case key == "tools" || key == "functions":
				if encoded, err := common.Marshal(child); err == nil {
					scan.TextBytes += len(encoded)
				}
				if list, ok := child.([]any); ok {
					scan.Tools += len(list)
					for _, item := range list {
						scan.BuiltinTools += orgBuiltinToolCount(item)
					}
				}
			default:
				scan.walk(child)
			}
		}
	}
}

// ScanOrgBody reads the quantities the cost bound depends on from a JSON
// request body. A body that is not a JSON object is an error, never a free
// request: the caller treats it as having no provable bound.
func ScanOrgBody(body []byte) (*OrgBodyScan, error) {
	var root map[string]any
	if err := common.Unmarshal(body, &root); err != nil || root == nil {
		return nil, errOrgBodyNotObject
	}
	scan := &OrgBodyScan{Media: map[string]int{}, Choices: 1}
	scan.walk(root)
	for _, key := range []string{"messages", "contents", "input"} {
		if list, ok := root[key].([]any); ok {
			scan.Messages += len(list)
		}
	}
	// With several limit fields the largest one is what the upstream may honor.
	for _, path := range orgOutputCapPaths {
		if value, ok := orgNumberAt(root, path); ok {
			scan.OutputCap, scan.OutputCapSet = max(scan.OutputCap, value), true
		}
	}
	for _, path := range orgChoicePaths {
		if value, ok := orgNumberAt(root, path); ok && value > 0 {
			scan.Choices = max(scan.Choices, value)
		}
	}
	for _, path := range orgThinkingPaths {
		if value, ok := orgNumberAt(root, path); ok {
			scan.ThinkingBudget = max(scan.ThinkingBudget, value)
		}
	}
	return scan, nil
}
