package middleware

// OrgTaskEntryClass says how a route that reads, serves or continues a task
// authorizes its caller. Every such route must be classified here; the router
// tests walk the real route table, so a new entry that nobody classified, or a
// classified entry that was removed, fails them.
type OrgTaskEntryClass string

const (
	// OrgTaskKeyRead: an API key reads a task through its trusted subject
	// (model.TaskScopeFromContext). Cross-organization and cross-workspace reads
	// are refused, a member key must be the task's actor, a system key must hold
	// its principal.
	OrgTaskKeyRead OrgTaskEntryClass = "key_read"
	// OrgTaskTicketRead: serves artifact content with either an API key or a
	// signed ticket. A v2 ticket is checked without state, then limited, then
	// rechecked against the database; a personal capability never opens an
	// organization task.
	OrgTaskTicketRead OrgTaskEntryClass = "ticket_read"
	// OrgTaskPublicTicket: carries no key, only a v2 ticket for organization tasks.
	OrgTaskPublicTicket OrgTaskEntryClass = "public_ticket"
	// OrgTaskSubmit: submits work and may continue an earlier task; the origin
	// task is read through the caller's subject, and the new task is stamped with
	// it.
	OrgTaskSubmit OrgTaskEntryClass = "submit"
	// OrgTaskConsole: a person reads through a session. WorkspaceAuth proves a
	// role and the role decides the scope; the billing role has no task access.
	OrgTaskConsole OrgTaskEntryClass = "console"
	// OrgTaskPersonal: a person reads their own personal tasks. Rows with an
	// organization are excluded in the query itself.
	OrgTaskPersonal OrgTaskEntryClass = "personal"
	// OrgTaskPlatformTable: the platform administrators' task table. It lists
	// personal tasks only; an organization is read through the audited entry.
	OrgTaskPlatformTable OrgTaskEntryClass = "platform_table"
	// OrgTaskPlatformAudited: the only way platform staff read an organization,
	// read-only and recorded as platform.access before any data is returned.
	OrgTaskPlatformAudited OrgTaskEntryClass = "platform_audited"
	// OrgTaskPlatformOps: platform operations on one organization (settings,
	// balance adjustment, review and resolution of billing operations). Global
	// platform session only; every write carries a reason and is recorded in the
	// organization's own trail as a platform action.
	OrgTaskPlatformOps OrgTaskEntryClass = "platform_ops"
	// OrgUsageConsole: usage, statistics, logs, audit trail and their exports for
	// an organization or a workspace, bounded by the reader's role.
	OrgUsageConsole OrgTaskEntryClass = "usage_console"
	// OrgTaskPluginAdmin: plugin and system-task administration. These routes
	// manage plugin code and scheduler rows, not tenant tasks.
	OrgTaskPluginAdmin OrgTaskEntryClass = "plugin_admin"
	// OrgTaskNotStored: a route that names tasks or media but reads no stored task.
	OrgTaskNotStored OrgTaskEntryClass = "not_stored"
)

// orgTaskEntryRules is the audited inventory of every registered route whose
// path concerns tasks, videos, Midjourney, artifacts, responses, image
// generation or organization usage. The :mode variants of the Midjourney routes
// are the same handlers behind a different prefix.
var orgTaskEntryRules = map[string]OrgTaskEntryClass{
	"GET /v1/tasks/:key":                    OrgTaskKeyRead,
	"GET /v1/tasks/:key/artifacts":          OrgTaskKeyRead,
	"GET /v1/video/generations/:task_id":    OrgTaskKeyRead,
	"GET /v1/videos/:task_id":               OrgTaskKeyRead,
	"GET /v1/videos/:task_id/content":       OrgTaskKeyRead,
	"HEAD /v1/videos/:task_id/content":      OrgTaskKeyRead,
	"GET /v1/responses/:response_id":        OrgTaskKeyRead,
	"GET /mj/task/:id/fetch":                OrgTaskKeyRead,
	"GET /mj/task/:id/image-seed":           OrgTaskKeyRead,
	"POST /mj/task/list-by-condition":       OrgTaskKeyRead,
	"GET /:mode/mj/task/:id/fetch":          OrgTaskKeyRead,
	"GET /:mode/mj/task/:id/image-seed":     OrgTaskKeyRead,
	"POST /:mode/mj/task/list-by-condition": OrgTaskKeyRead,

	"GET /v1/tasks/:key/artifacts/:artifact_key/content":  OrgTaskTicketRead,
	"HEAD /v1/tasks/:key/artifacts/:artifact_key/content": OrgTaskTicketRead,

	"GET /mj/image/:id":       OrgTaskPublicTicket,
	"GET /:mode/mj/image/:id": OrgTaskPublicTicket,

	"POST /v1/tasks/:key":                         OrgTaskSubmit,
	"POST /v1/video/generations":                  OrgTaskSubmit,
	"POST /v1/videos":                             OrgTaskSubmit,
	"POST /v1/videos/:video_id/remix":             OrgTaskSubmit,
	"POST /v1/responses":                          OrgTaskSubmit,
	"POST /v1/responses/compact":                  OrgTaskSubmit,
	"POST /v1/images/generations":                 OrgTaskSubmit,
	"POST /v1/images/edits":                       OrgTaskSubmit,
	"POST /v1/images/variations":                  OrgTaskSubmit,
	"POST /mj/submit/action":                      OrgTaskSubmit,
	"POST /mj/submit/blend":                       OrgTaskSubmit,
	"POST /mj/submit/change":                      OrgTaskSubmit,
	"POST /mj/submit/describe":                    OrgTaskSubmit,
	"POST /mj/submit/edits":                       OrgTaskSubmit,
	"POST /mj/submit/imagine":                     OrgTaskSubmit,
	"POST /mj/submit/modal":                       OrgTaskSubmit,
	"POST /mj/submit/shorten":                     OrgTaskSubmit,
	"POST /mj/submit/simple-change":               OrgTaskSubmit,
	"POST /mj/submit/upload-discord-images":       OrgTaskSubmit,
	"POST /mj/submit/video":                       OrgTaskSubmit,
	"POST /mj/insight-face/swap":                  OrgTaskSubmit,
	"POST /:mode/mj/submit/action":                OrgTaskSubmit,
	"POST /:mode/mj/submit/blend":                 OrgTaskSubmit,
	"POST /:mode/mj/submit/change":                OrgTaskSubmit,
	"POST /:mode/mj/submit/describe":              OrgTaskSubmit,
	"POST /:mode/mj/submit/edits":                 OrgTaskSubmit,
	"POST /:mode/mj/submit/imagine":               OrgTaskSubmit,
	"POST /:mode/mj/submit/modal":                 OrgTaskSubmit,
	"POST /:mode/mj/submit/shorten":               OrgTaskSubmit,
	"POST /:mode/mj/submit/simple-change":         OrgTaskSubmit,
	"POST /:mode/mj/submit/upload-discord-images": OrgTaskSubmit,
	"POST /:mode/mj/submit/video":                 OrgTaskSubmit,
	"POST /:mode/mj/insight-face/swap":            OrgTaskSubmit,

	"GET /api/orgs/:org/workspaces/:ws/tasks":                    OrgTaskConsole,
	"GET /api/orgs/:org/workspaces/:ws/tasks/:task_id":           OrgTaskConsole,
	"GET /api/orgs/:org/workspaces/:ws/tasks/:task_id/artifacts": OrgTaskConsole,
	"GET /api/orgs/:org/workspaces/:ws/midjourney":               OrgTaskConsole,

	"GET /api/task/self":               OrgTaskPersonal,
	"GET /api/task/:task_id/artifacts": OrgTaskPersonal,
	"GET /api/mj/self":                 OrgTaskPersonal,

	"GET /api/task": OrgTaskPlatformTable,
	"GET /api/mj/":  OrgTaskPlatformTable,

	"GET /api/admin/orgs/:org/activity":   OrgTaskPlatformAudited,
	"GET /api/admin/orgs/:org/logs":       OrgTaskPlatformAudited,
	"GET /api/admin/orgs/:org/audit-logs": OrgTaskPlatformAudited,
	"GET /api/admin/orgs/:org/tasks":      OrgTaskPlatformAudited,
	"GET /api/admin/orgs/:org/midjourney": OrgTaskPlatformAudited,

	"PATCH /api/admin/orgs/:org":                                      OrgTaskPlatformOps,
	"POST /api/admin/orgs/:org/adjust":                                OrgTaskPlatformOps,
	"GET /api/admin/orgs/:org/billing-operations":                     OrgTaskPlatformOps,
	"POST /api/admin/orgs/:org/billing-operations/:operation/resolve": OrgTaskPlatformOps,

	"GET /api/orgs/:org/activity":                         OrgUsageConsole,
	"GET /api/orgs/:org/audit-logs":                       OrgUsageConsole,
	"GET /api/orgs/:org/audit-logs/export":                OrgUsageConsole,
	"GET /api/orgs/:org/workspaces/:ws/usage":             OrgUsageConsole,
	"GET /api/orgs/:org/workspaces/:ws/logs":              OrgUsageConsole,
	"GET /api/orgs/:org/workspaces/:ws/logs/export":       OrgUsageConsole,
	"GET /api/orgs/:org/workspaces/:ws/audit-logs":        OrgUsageConsole,
	"GET /api/orgs/:org/workspaces/:ws/audit-logs/export": OrgUsageConsole,

	"DELETE /api/plugin/task/:key/versions/:version": OrgTaskPluginAdmin,
	"GET /api/plugin/task":                           OrgTaskPluginAdmin,
	"GET /api/plugin/task/:key":                      OrgTaskPluginAdmin,
	"GET /api/plugin/task/:key/icon":                 OrgTaskPluginAdmin,
	"GET /api/plugin/task/:key/versions":             OrgTaskPluginAdmin,
	"GET /api/plugin/task/marketplace/sources":       OrgTaskPluginAdmin,
	"GET /api/plugin/task/runtime/status":            OrgTaskPluginAdmin,
	"POST /api/plugin/task":                          OrgTaskPluginAdmin,
	"POST /api/plugin/task/:key/activate":            OrgTaskPluginAdmin,
	"POST /api/plugin/task/:key/dryrun":              OrgTaskPluginAdmin,
	"POST /api/plugin/task/:key/status":              OrgTaskPluginAdmin,
	"PUT /api/plugin/task":                           OrgTaskPluginAdmin,
	"PUT /api/plugin/task/marketplace/sources":       OrgTaskPluginAdmin,

	// A WebSocket upgrade for live responses; it reads no stored task.
	"GET /v1/responses": OrgTaskNotStored,
}

// OrgTaskEntry returns the class of "METHOD /full/path" and whether it is declared.
func OrgTaskEntry(key string) (OrgTaskEntryClass, bool) {
	class, ok := orgTaskEntryRules[key]
	return class, ok
}

// OrgTaskEntryKeys lists the inventory, for tests.
func OrgTaskEntryKeys() []string {
	keys := make([]string, 0, len(orgTaskEntryRules))
	for key := range orgTaskEntryRules {
		keys = append(keys, key)
	}
	return keys
}
