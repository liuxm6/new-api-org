package middleware

// OrgKeyEndpointClass says how an organization key may use a read-only
// endpoint that is authenticated by an API key (TokenAuth or
// TokenAuthReadOnly) rather than by a person.
type OrgKeyEndpointClass string

const (
	// OrgKeyOwnData: answered from the key itself and the budgets that apply to
	// it, never from the shared wallet (dashboard billing).
	OrgKeyOwnData OrgKeyEndpointClass = "key_only"
	// OrgKeyDenied: refused for organization keys (TokenAuthReadOnly routes).
	// Usage and logs of a workspace are read through the control plane.
	OrgKeyDenied OrgKeyEndpointClass = "denied"
	// OrgKeyRelay: a relay-protocol endpoint. Its authorization and billing run in
	// the relay chain (TokenAuth, distributor, organization billing session) and
	// object-level task and artifact reads are covered by Task 14.
	OrgKeyRelay OrgKeyEndpointClass = "relay"
	// OrgKeyPublic: carries no key at all.
	OrgKeyPublic OrgKeyEndpointClass = "public"
)

// orgKeyEndpointRules is the audited inventory of every read-only route an API
// key can reach outside the relay write path. A new GET route that a key can
// call must be added here, and router tests fail until it is: the rule decides
// whether an organization key may see wallet-level figures there (it may not).
var orgKeyEndpointRules = map[string]OrgKeyEndpointClass{
	"GET /dashboard/billing/subscription":    OrgKeyOwnData,
	"GET /dashboard/billing/usage":           OrgKeyOwnData,
	"GET /v1/dashboard/billing/subscription": OrgKeyOwnData,
	"GET /v1/dashboard/billing/usage":        OrgKeyOwnData,
	"GET /api/usage/token/":                  OrgKeyDenied,
	"GET /api/log/token":                     OrgKeyDenied,

	"GET /v1/models":                                     OrgKeyRelay,
	"GET /v1/models/:model":                              OrgKeyRelay,
	"GET /v1beta/models":                                 OrgKeyRelay,
	"GET /v1beta/openai/models":                          OrgKeyRelay,
	"GET /v1/files":                                      OrgKeyRelay,
	"GET /v1/files/:id/content":                          OrgKeyRelay,
	"GET /v1/fine-tunes":                                 OrgKeyRelay,
	"GET /v1/fine-tunes/:id":                             OrgKeyRelay,
	"GET /v1/fine-tunes/:id/events":                      OrgKeyRelay,
	"GET /v1/realtime":                                   OrgKeyRelay,
	"GET /v1/responses":                                  OrgKeyRelay,
	"GET /v1/responses/:response_id":                     OrgKeyRelay,
	"GET /v1/tasks/:key":                                 OrgKeyRelay,
	"GET /v1/tasks/:key/artifacts":                       OrgKeyRelay,
	"GET /v1/video/generations/:task_id":                 OrgKeyRelay,
	"GET /v1/videos/:task_id":                            OrgKeyRelay,
	"GET /v1/videos/:task_id/content":                    OrgKeyRelay,
	"GET /mj/task/:id/fetch":                             OrgKeyRelay,
	"GET /mj/task/:id/image-seed":                        OrgKeyRelay,
	"GET /:mode/mj/task/:id/fetch":                       OrgKeyRelay,
	"GET /:mode/mj/task/:id/image-seed":                  OrgKeyRelay,
	"GET /v1/tasks/:key/artifacts/:artifact_key/content": OrgKeyRelay,

	"GET /mj/image/:id":       OrgKeyPublic,
	"GET /:mode/mj/image/:id": OrgKeyPublic,
}

// OrgKeyEndpoint returns the class of "METHOD /full/path" and whether it is
// declared.
func OrgKeyEndpoint(key string) (OrgKeyEndpointClass, bool) {
	class, ok := orgKeyEndpointRules[key]
	return class, ok
}

// OrgKeyEndpointKeys lists the inventory, for tests.
func OrgKeyEndpointKeys() []string {
	keys := make([]string, 0, len(orgKeyEndpointRules))
	for key := range orgKeyEndpointRules {
		keys = append(keys, key)
	}
	return keys
}
