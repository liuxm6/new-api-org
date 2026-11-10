package controller

import (
	"encoding/csv"
	"net/http"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

// orgAuditFilterFromQuery reads the audit search shared by the list and the
// export. The audit trail is a compliance record, so it is not cut to the log
// retention range; it is paged and indexed by organization and time.
func orgAuditFilterFromQuery(c *gin.Context) model.OrgAuditFilter {
	start, _ := strconv.ParseInt(c.Query("start_timestamp"), 10, 64)
	end, _ := strconv.ParseInt(c.Query("end_timestamp"), 10, 64)
	return model.OrgAuditFilter{Action: c.Query("action"), StartTimestamp: start, EndTimestamp: end}
}

// serveOrgAuditLogs answers the audit list of a scope.
func serveOrgAuditLogs(c *gin.Context, scope model.OrgUsageScope) {
	pageInfo := common.GetPageQuery(c)
	rows, total, err := model.ListOrgAuditLogs(scope, orgAuditFilterFromQuery(c), pageInfo.GetStartIdx(), pageInfo.GetPageSize())
	if err != nil {
		common.SysError(common.LogText("failed to read organization audit logs: %v", err))
		common.ApiErrorT(c, "Failed to query logs")
		return
	}
	pageInfo.SetTotal(int(total))
	pageInfo.SetItems(rows)
	common.ApiSuccess(c, pageInfo)
}

// serveOrgAuditExport streams the audit rows of a scope as CSV. Rows pass
// through the same redaction as the list, the credential reference is not a
// column, and every text cell is neutralized against spreadsheet formulas.
func serveOrgAuditExport(c *gin.Context, scope model.OrgUsageScope) {
	release, ok, err := service.AcquireLogExportLock(c.GetInt("id"))
	if err != nil {
		common.SysError(common.LogText("failed to lock audit export: %s", err.Error()))
		common.ApiErrorT(c, "Failed to export logs")
		return
	}
	if !ok {
		common.ApiErrorT(c, "Another log export is running. Try again after it finishes.")
		return
	}
	defer release()

	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="audit-logs.csv"`)
	c.Header("Cache-Control", "no-store")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	writer := csv.NewWriter(c.Writer)
	if err := writer.Write([]string{"id", "created_at", "org_id", "workspace_id", "actor_user_id", "actor_kind",
		"action", "target_type", "target_id", "detail", "ip"}); err != nil {
		return
	}
	ctx := c.Request.Context()
	err = model.StreamOrgAuditLogs(ctx, scope, orgAuditFilterFromQuery(c), func(row model.OrgAuditLog) error {
		return writer.Write([]string{
			strconv.Itoa(row.Id), strconv.FormatInt(row.CreatedAt, 10), strconv.Itoa(row.OrgId),
			strconv.Itoa(row.WorkspaceId), strconv.Itoa(row.ActorUserId), model.CSVSafe(row.ActorKind),
			model.CSVSafe(row.Action), model.CSVSafe(row.TargetType), model.CSVSafe(row.TargetId),
			model.CSVSafe(row.Detail), model.CSVSafe(row.Ip),
		})
	})
	writer.Flush()
	if err != nil && ctx.Err() == nil {
		// The status is already sent; the failure is for the operator.
		common.SysError(common.LogText("failed to export organization audit logs: %s", err.Error()))
	}
}

// ListOrgAuditLogs: GET /api/orgs/:org/audit-logs.
func ListOrgAuditLogs(c *gin.Context) {
	if scope, ok := orgUsageScopeOf(c, false); ok {
		serveOrgAuditLogs(c, scope)
	}
}

// ExportOrgAuditLogs: GET /api/orgs/:org/audit-logs/export.
func ExportOrgAuditLogs(c *gin.Context) {
	if scope, ok := orgUsageScopeOf(c, false); ok {
		serveOrgAuditExport(c, scope)
	}
}

// ListWorkspaceAuditLogs: GET /api/orgs/:org/workspaces/:ws/audit-logs.
func ListWorkspaceAuditLogs(c *gin.Context) {
	if scope, ok := orgUsageScopeOf(c, true); ok {
		serveOrgAuditLogs(c, scope)
	}
}

// ExportWorkspaceAuditLogs: GET /api/orgs/:org/workspaces/:ws/audit-logs/export.
func ExportWorkspaceAuditLogs(c *gin.Context) {
	if scope, ok := orgUsageScopeOf(c, true); ok {
		serveOrgAuditExport(c, scope)
	}
}

// PlatformOrgAuditLogs: GET /api/admin/orgs/:org/audit-logs.
func PlatformOrgAuditLogs(c *gin.Context) {
	platformOrgRead(c, "audit-logs", func(scope model.OrgUsageScope) { serveOrgAuditLogs(c, scope) })
}
