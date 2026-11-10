package common

import "github.com/MoeForge/moego/ojson"

// orgOutputLimitPaths are the body fields that cap a response's output tokens,
// the same set the organization cost bound reads (service.orgOutputCapPaths).
var orgOutputLimitPaths = []string{
	"max_completion_tokens", "max_tokens", "max_output_tokens", "generationConfig.maxOutputTokens",
}

// ClampOrgOutputLimits cuts every output limit in a request body to limit. The
// reservation of an organization request assumed that cap, so nothing that runs
// afterwards (a channel's parameter override, an adapter default) may raise it.
// A field that is absent is left absent; a field that is present but not a
// positive number is replaced by the cap. limit <= 0 means no cap.
func ClampOrgOutputLimits(body []byte, limit int64) ([]byte, error) {
	if limit <= 0 {
		return body, nil
	}
	out := body
	for _, path := range orgOutputLimitPaths {
		field := ojson.GetBytes(out, path)
		if !field.Exists() {
			continue
		}
		if field.Type == ojson.Number && field.Int() >= 1 && field.Int() <= limit {
			continue
		}
		next, err := ojson.SetBytes(out, path, limit)
		if err != nil {
			return body, err
		}
		out = next
	}
	return out, nil
}
