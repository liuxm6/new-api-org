package controller

import (
	"net/http"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Usage, logs, statistics and exports of an organization all read through one
// model.OrgUsageScope, so a list, its totals and its export can never disagree
// about whose rows they cover. The scope is built here from the standing the
// middleware proved and is never taken from the request.

// orgUsageScopeOf resolves the scope for an organization route (workspace is
// false) or a workspace route (workspace is true). It answers false after
// writing the refusal if the middleware did not prove the needed standing.
func orgUsageScopeOf(c *gin.Context, workspace bool) (model.OrgUsageScope, bool) {
	userID := c.GetInt("id")
	if workspace {
		access, ok := middleware.WorkspaceAccessFromContext(c)
		if !ok {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrStateUnavailable))
			return model.OrgUsageScope{}, false
		}
		scope := model.OrgUsageScope{OrgID: access.Org.Id, WorkspaceID: access.Workspace.Id}
		if access.Role != types.WorkspaceRoleAdmin && access.Role != types.WorkspaceRoleAuditor {
			scope.ActorUserID = userID
		}
		return scope, true
	}
	access, ok := middleware.OrgAccessFromContext(c)
	if !ok {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrStateUnavailable))
		return model.OrgUsageScope{}, false
	}
	// Owners, admins and billing see the whole organization; any other member
	// sees only their own rows.
	scope := model.OrgUsageScope{OrgID: access.Org.Id}
	switch access.Member.Role {
	case types.OrgRoleOwner, types.OrgRoleAdmin, types.OrgRoleBilling:
	default:
		scope.ActorUserID = userID
	}
	return scope, true
}

// orgUsageTimeRange reads the start and end of a usage query and keeps it within
// the longest log range, like every other log and dashboard search.
func orgUsageTimeRange(c *gin.Context) (int64, int64, error) {
	start, _ := strconv.ParseInt(c.Query("start_timestamp"), 10, 64)
	end, _ := strconv.ParseInt(c.Query("end_timestamp"), 10, 64)
	if end == 0 {
		end = common.GetTimestamp()
	}
	start, err := limitLogTimeRange(start, end)
	return start, end, err
}

// serveOrgActivity answers the usage statistics of a scope. quota_data is a
// display aggregation; the response says so, and it is never the billing record.
func serveOrgActivity(c *gin.Context, scope model.OrgUsageScope) {
	start, end, err := orgUsageTimeRange(c)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	rows, err := model.GetOrgUsage(scope, start, end)
	if err != nil {
		common.SysError(common.LogText("failed to read organization usage: %v", err))
		common.ApiErrorT(c, "Failed to query logs")
		return
	}
	var totalQuota, totalCount, totalTokens int
	for _, row := range rows {
		totalQuota += row.Quota
		totalCount += row.Count
		totalTokens += row.TokenUsed
	}
	common.ApiSuccess(c, gin.H{
		"display_only": true, "items": rows,
		"total_quota": totalQuota, "total_count": totalCount, "total_tokens": totalTokens,
	})
}

// serveOrgLogs answers the usage log list of a scope.
func serveOrgLogs(c *gin.Context, scope model.OrgUsageScope) {
	pageInfo := common.GetPageQuery(c)
	filter := logFilterFromQuery(c, false)
	start, err := limitLogTimeRange(filter.StartTimestamp, filter.EndTimestamp)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	filter.StartTimestamp = start
	logs, total, err := model.GetOrgLogs(scope, filter, pageInfo.GetStartIdx(), pageInfo.GetPageSize())
	if err != nil {
		common.ApiError(c, err)
		return
	}
	pageInfo.SetTotal(int(total))
	pageInfo.SetItems(logs)
	common.ApiSuccess(c, pageInfo)
}

// serveOrgLogExport streams the log list of a scope as one JSON log per line,
// like the personal export, ending with an API response object.
func serveOrgLogExport(c *gin.Context, scope model.OrgUsageScope) {
	filter := logFilterFromQuery(c, false)
	start, err := limitLogTimeRange(filter.StartTimestamp, filter.EndTimestamp)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	filter.StartTimestamp = start
	release, ok, err := service.AcquireLogExportLock(c.GetInt("id"))
	if err != nil {
		common.SysError(common.LogText("failed to lock log export: %s", err.Error()))
		common.ApiErrorT(c, "Failed to export logs")
		return
	}
	if !ok {
		common.ApiErrorT(c, "Another log export is running. Try again after it finishes.")
		return
	}
	defer release()

	c.Header("Content-Type", "application/x-ndjson; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)
	count := 0
	ctx := c.Request.Context()
	err = model.StreamOrgLogs(ctx, scope, filter, func(log *model.Log) error {
		line, marshalErr := common.Marshal(log)
		if marshalErr != nil {
			return marshalErr
		}
		if _, writeErr := c.Writer.Write(append(line, '\n')); writeErr != nil {
			return writeErr
		}
		count++
		return nil
	})
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		common.SysError(common.LogText("failed to export organization logs: %s", err.Error()))
		common.ApiErrorT(c, "Failed to export logs")
		return
	}
	common.ApiSuccess(c, gin.H{"count": count})
}

// GetOrgActivity: GET /api/orgs/:org/activity.
func GetOrgActivity(c *gin.Context) {
	if scope, ok := orgUsageScopeOf(c, false); ok {
		serveOrgActivity(c, scope)
	}
}

// GetWorkspaceUsage: GET /api/orgs/:org/workspaces/:ws/usage.
func GetWorkspaceUsage(c *gin.Context) {
	if scope, ok := orgUsageScopeOf(c, true); ok {
		serveOrgActivity(c, scope)
	}
}

// ListWorkspaceLogs: GET /api/orgs/:org/workspaces/:ws/logs.
func ListWorkspaceLogs(c *gin.Context) {
	if scope, ok := orgUsageScopeOf(c, true); ok {
		serveOrgLogs(c, scope)
	}
}

// ExportWorkspaceLogs: GET /api/orgs/:org/workspaces/:ws/logs/export.
func ExportWorkspaceLogs(c *gin.Context) {
	if scope, ok := orgUsageScopeOf(c, true); ok {
		serveOrgLogExport(c, scope)
	}
}

// platformOrgRead is the independent, audited entry for platform staff reading
// one organization. It is read-only, needs a global platform session, and every
// call is recorded as platform.access in the organization's own audit trail
// before anything is returned: if the record cannot be written, nothing is.
func platformOrgRead(c *gin.Context, resource string, serve func(scope model.OrgUsageScope)) {
	org, err := model.GetOrganizationByRef(model.DB, c.Param("org"))
	if err != nil {
		if model.IsOrgNotFound(err) {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrNotFound))
			return
		}
		respondOrgError(c, err)
		return
	}
	scope := model.OrgUsageScope{OrgID: org.Id}
	scope.WorkspaceID, _ = strconv.Atoi(c.Query("workspace_id"))
	scope.ActorUserID, _ = strconv.Atoi(c.Query("actor_user_id"))
	if scope.WorkspaceID < 0 || scope.ActorUserID < 0 {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	err = model.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		return model.RecordOrgAuditTx(tx, model.OrgAuditEntry{
			OrgId: org.Id, WorkspaceId: scope.WorkspaceID, ActorUserId: c.GetInt("id"), ActorKind: "platform",
			Action: "platform.access", TargetType: resource, TargetId: strconv.Itoa(org.Id), Ip: c.ClientIP(),
			Detail: map[string]any{"resource": resource, "workspace_id": scope.WorkspaceID, "actor_user_id": scope.ActorUserID},
		})
	})
	if err != nil {
		respondOrgError(c, err)
		return
	}
	serve(scope)
}

// PlatformOrgActivity: GET /api/admin/orgs/:org/activity.
func PlatformOrgActivity(c *gin.Context) {
	platformOrgRead(c, "activity", func(scope model.OrgUsageScope) { serveOrgActivity(c, scope) })
}

// PlatformOrgLogs: GET /api/admin/orgs/:org/logs.
func PlatformOrgLogs(c *gin.Context) {
	platformOrgRead(c, "logs", func(scope model.OrgUsageScope) { serveOrgLogs(c, scope) })
}
