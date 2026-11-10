package controller

import (
	"net/http"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// Human console reads of organization tasks. A reader sees what their standing
// allows: organization owners and admins and workspace admins and auditors the
// whole workspace, a workspace member only their own. The organization billing
// role reaches nothing here. The shared wallet user id and the vendor's raw
// snapshot are never part of the answer.

// consoleTaskScope proves the reader's task scope from the workspace standing
// the middleware stored. It writes the refusal and answers false otherwise.
func consoleTaskScope(c *gin.Context) (model.TaskScope, *orgsvc.WorkspaceAccess, bool) {
	access, ok := middleware.WorkspaceAccessFromContext(c)
	if !ok {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrStateUnavailable))
		return model.TaskScope{}, nil, false
	}
	scope := orgsvc.TaskScopeForWorkspaceAccess(access, c.GetInt("id"))
	if !scope.Valid() {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrWorkspaceForbidden))
		return model.TaskScope{}, nil, false
	}
	return scope, access, true
}

func orgTaskQuery(c *gin.Context) model.SyncTaskQueryParams {
	startTimestamp, _ := strconv.ParseInt(c.Query("start_timestamp"), 10, 64)
	endTimestamp, _ := strconv.ParseInt(c.Query("end_timestamp"), 10, 64)
	return model.SyncTaskQueryParams{Platform: constant.TaskPlatform(c.Query("platform")), TaskID: c.Query("task_id"),
		Status: c.Query("status"), Action: c.Query("action"), StartTimestamp: startTimestamp, EndTimestamp: endTimestamp}
}

// orgTaskItems shapes tasks for a console reader.
func orgTaskItems(tasks []*model.Task) []*dto.TaskDto {
	items := tasksToDto(tasks, false, common.RoleCommonUser)
	for _, item := range items {
		item.UserId = 0
		item.Data = nil
		item.ResultURL = ""
	}
	return items
}

func serveOrgTasks(c *gin.Context, scope model.TaskScope, fillUser bool) {
	pageInfo := common.GetPageQuery(c)
	query := orgTaskQuery(c)
	tasks, err := model.ListTasksInScope(scope, pageInfo.GetStartIdx(), pageInfo.GetPageSize(), query)
	if err == nil {
		var total int64
		if total, err = model.CountTasksInScope(scope, query); err == nil {
			pageInfo.SetTotal(int(total))
		}
	}
	if err != nil {
		common.SysError(common.LogText("failed to read organization tasks: %v", err))
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrStateUnavailable))
		return
	}
	if fillUser {
		pageInfo.SetItems(tasksToDto(tasks, true, c.GetInt("role")))
	} else {
		pageInfo.SetItems(orgTaskItems(tasks))
	}
	common.ApiSuccess(c, pageInfo)
}

// ListWorkspaceTasks: GET /api/orgs/:org/workspaces/:ws/tasks.
func ListWorkspaceTasks(c *gin.Context) {
	if scope, _, ok := consoleTaskScope(c); ok {
		serveOrgTasks(c, scope, false)
	}
}

// GetWorkspaceTask: GET /api/orgs/:org/workspaces/:ws/tasks/:task_id.
func GetWorkspaceTask(c *gin.Context) {
	scope, _, ok := consoleTaskScope(c)
	if !ok {
		return
	}
	task, exists, err := model.GetTaskInScope(scope, c.Param("task_id"))
	if err != nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrStateUnavailable))
		return
	}
	if !exists || task == nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrNotFound))
		return
	}
	common.ApiSuccess(c, orgTaskItems([]*model.Task{task})[0])
}

// GetWorkspaceTaskArtifacts: GET /api/orgs/:org/workspaces/:ws/tasks/:task_id/artifacts.
// Each content URL is a v2 ticket bound to this reader.
func GetWorkspaceTaskArtifacts(c *gin.Context) {
	scope, access, ok := consoleTaskScope(c)
	if !ok {
		return
	}
	task, exists, err := model.GetTaskInScope(scope, c.Param("task_id"))
	if err != nil {
		writeTaskArtifactError(c, http.StatusInternalServerError, "artifact_internal_error", "Failed to query task")
		return
	}
	if !exists || task == nil {
		writeTaskArtifactError(c, http.StatusNotFound, "artifact_not_found", "Task or artifact not found")
		return
	}
	claims := service.OrgArtifactClaimsForHuman(access.Org.Id, access.Workspace.Id, c.GetInt("id"), access.Org.PolicyVersion)
	writeTaskArtifacts(c, task, true, func(taskID, artifactKey string) (string, error) {
		return service.BuildOrgTaskArtifactContentURL(claims, taskID, artifactKey)
	})
}

// orgMidjourneyItem is the console shape of a legacy Midjourney task: no wallet
// user id, no token, and no upstream URL.
type orgMidjourneyItem struct {
	Id          int    `json:"id"`
	MjId        string `json:"mj_id"`
	Action      string `json:"action"`
	Prompt      string `json:"prompt"`
	Status      string `json:"status"`
	Progress    string `json:"progress"`
	FailReason  string `json:"fail_reason"`
	SubmitTime  int64  `json:"submit_time"`
	StartTime   int64  `json:"start_time"`
	FinishTime  int64  `json:"finish_time"`
	Quota       int    `json:"quota"`
	ActorUserId int    `json:"actor_user_id"`
	ImageUrl    string `json:"image_url,omitempty"`
}

func serveOrgMidjourney(c *gin.Context, scope model.TaskScope, claims *service.OrgArtifactTicketClaims) {
	pageInfo := common.GetPageQuery(c)
	query := model.TaskQueryParams{MjID: c.Query("mj_id"), StartTimestamp: c.Query("start_timestamp"), EndTimestamp: c.Query("end_timestamp")}
	tasks, err := model.ListMJInScope(scope, pageInfo.GetStartIdx(), pageInfo.GetPageSize(), query)
	if err == nil {
		var total int64
		if total, err = model.CountMJInScope(scope, query); err == nil {
			pageInfo.SetTotal(int(total))
		}
	}
	if err != nil {
		common.SysError(common.LogText("failed to read organization midjourney tasks: %v", err))
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrStateUnavailable))
		return
	}
	items := make([]orgMidjourneyItem, 0, len(tasks))
	for _, task := range tasks {
		item := orgMidjourneyItem{Id: task.Id, MjId: task.MjId, Action: task.Action, Prompt: task.Prompt, Status: task.Status,
			Progress: task.Progress, FailReason: task.FailReason, SubmitTime: task.SubmitTime, StartTime: task.StartTime,
			FinishTime: task.FinishTime, Quota: task.Quota, ActorUserId: task.ActorUserId}
		if claims != nil && task.ImageUrl != "" {
			if imageURL, buildErr := service.BuildOrgMidjourneyImageURL(*claims, task.MjId); buildErr == nil {
				item.ImageUrl = imageURL
			}
		}
		items = append(items, item)
	}
	pageInfo.SetItems(items)
	common.ApiSuccess(c, pageInfo)
}

// ListWorkspaceMidjourney: GET /api/orgs/:org/workspaces/:ws/midjourney.
func ListWorkspaceMidjourney(c *gin.Context) {
	scope, access, ok := consoleTaskScope(c)
	if !ok {
		return
	}
	claims := service.OrgArtifactClaimsForHuman(access.Org.Id, access.Workspace.Id, c.GetInt("id"), access.Org.PolicyVersion)
	serveOrgMidjourney(c, scope, &claims)
}

// PlatformOrgTasks: GET /api/admin/orgs/:org/tasks.
func PlatformOrgTasks(c *gin.Context) {
	platformOrgRead(c, "tasks", func(scope model.OrgUsageScope) {
		serveOrgTasks(c, model.PlatformTaskScope(scope.OrgID, scope.WorkspaceID, scope.ActorUserID), true)
	})
}

// PlatformOrgMidjourney: GET /api/admin/orgs/:org/midjourney.
func PlatformOrgMidjourney(c *gin.Context) {
	platformOrgRead(c, "midjourney", func(scope model.OrgUsageScope) {
		serveOrgMidjourney(c, model.PlatformTaskScope(scope.OrgID, scope.WorkspaceID, scope.ActorUserID), nil)
	})
}
