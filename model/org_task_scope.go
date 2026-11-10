package model

import (
	"context"

	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// TaskScopeKind says on whose behalf a task or Midjourney row is read. The zero
// value matches nothing, so a scope that was never built (or built from an
// incomplete subject) can only ever see an empty result.
type TaskScopeKind int

const (
	TaskScopeNone TaskScopeKind = iota
	// TaskScopePersonal: a personal key or a personal dashboard session. Only
	// rows with org_id = 0 owned by the user.
	TaskScopePersonal
	// TaskScopeOrgMember: an organization member key. Same organization and
	// workspace, and the same actor.
	TaskScopeOrgMember
	// TaskScopeOrgSystem: a workspace (system) key. Same organization and
	// workspace, and the same access principal. Controlled rotation inherits the
	// principal, so a rotated key still reads its history.
	TaskScopeOrgSystem
	// TaskScopeOrgWorkspace: a human console reader who may see every task of one
	// workspace (organization owner/admin, workspace admin/auditor).
	TaskScopeOrgWorkspace
	// TaskScopeOrgSelf: a human console reader who may see only their own member
	// tasks of one workspace.
	TaskScopeOrgSelf
	// TaskScopeOrgPlatform: the audited platform operations entry. It spans one
	// organization, optionally narrowed to one workspace, and is never derived
	// from an API key or a tenant session.
	TaskScopeOrgPlatform
)

// TaskScope is the single authorization predicate for reading tasks. Every task
// and Midjourney read goes through it, so authorization is by object and never
// by billing_user_id alone: the shared organization wallet id is not an owner.
type TaskScope struct {
	Kind              TaskScopeKind
	UserID            int
	OrgID             int
	WorkspaceID       int
	ActorUserID       int
	AccessPrincipalID string
}

// PersonalTaskScope scopes a personal user. A non-positive id matches nothing.
func PersonalTaskScope(userID int) TaskScope {
	if userID <= 0 {
		return TaskScope{}
	}
	return TaskScope{Kind: TaskScopePersonal, UserID: userID}
}

// TaskScopeForOrgSubject scopes an organization key by its trusted subject. A
// member key needs an actor, a system key needs a principal, and both need an
// organization and a workspace; anything less fails closed.
func TaskScopeForOrgSubject(subject types.OrgSubject) TaskScope {
	if subject.OrgID <= 0 || subject.WorkspaceID <= 0 {
		return TaskScope{}
	}
	switch subject.OwnerType {
	case types.TokenOwnerMember:
		if subject.ActorUserID <= 0 {
			return TaskScope{}
		}
		return TaskScope{Kind: TaskScopeOrgMember, OrgID: subject.OrgID, WorkspaceID: subject.WorkspaceID, ActorUserID: subject.ActorUserID}
	case types.TokenOwnerWorkspace:
		if subject.AccessPrincipalID == "" {
			return TaskScope{}
		}
		return TaskScope{Kind: TaskScopeOrgSystem, OrgID: subject.OrgID, WorkspaceID: subject.WorkspaceID, AccessPrincipalID: subject.AccessPrincipalID}
	}
	return TaskScope{}
}

// WorkspaceTaskScope scopes a human console reader to a whole workspace.
func WorkspaceTaskScope(orgID, workspaceID int) TaskScope {
	if orgID <= 0 || workspaceID <= 0 {
		return TaskScope{}
	}
	return TaskScope{Kind: TaskScopeOrgWorkspace, OrgID: orgID, WorkspaceID: workspaceID}
}

// WorkspaceSelfTaskScope scopes a human console reader to their own tasks.
func WorkspaceSelfTaskScope(orgID, workspaceID, actorUserID int) TaskScope {
	if orgID <= 0 || workspaceID <= 0 || actorUserID <= 0 {
		return TaskScope{}
	}
	return TaskScope{Kind: TaskScopeOrgSelf, OrgID: orgID, WorkspaceID: workspaceID, ActorUserID: actorUserID}
}

// PlatformTaskScope scopes the audited platform entry to an organization,
// narrowed to one workspace and one actor when those ids are positive.
func PlatformTaskScope(orgID, workspaceID, actorUserID int) TaskScope {
	if orgID <= 0 {
		return TaskScope{}
	}
	return TaskScope{Kind: TaskScopeOrgPlatform, OrgID: orgID, WorkspaceID: workspaceID, ActorUserID: actorUserID}
}

// ReadTaskScope is the scope of a caller identified by the trusted organization
// subject TokenAuth proved, or, for a personal caller, by userID. An
// organization key never falls back to its wallet id: a subject too incomplete
// to scope reads nothing.
func ReadTaskScope(subject types.OrgSubject, userID int) TaskScope {
	if subject.OrgID > 0 {
		return TaskScopeForOrgSubject(subject)
	}
	return PersonalTaskScope(userID)
}

// TaskScopeFromContext is ReadTaskScope for the subject stored in the request
// context by TokenAuth. The subject is never read from request input.
func TaskScopeFromContext(c *gin.Context, userID int) TaskScope {
	var subject types.OrgSubject
	if c != nil {
		if value, ok := c.Get(string(constant.ContextKeyOrgSubject)); ok {
			subject, _ = value.(types.OrgSubject)
		}
	}
	return ReadTaskScope(subject, userID)
}

// orgTicketScopeContextKey holds the scope a verified v2 artifact ticket
// resolved to once its database recheck passed.
const orgTicketScopeContextKey = "org_artifact_scope"

// SetOrgTicketScope records the scope a rechecked v2 ticket resolved to.
func SetOrgTicketScope(c *gin.Context, scope TaskScope) { c.Set(orgTicketScopeContextKey, scope) }

// OrgTicketScopeFromContext returns the scope a rechecked v2 ticket resolved to.
func OrgTicketScopeFromContext(c *gin.Context) (TaskScope, bool) {
	value, ok := c.Get(orgTicketScopeContextKey)
	if !ok {
		return TaskScope{}, false
	}
	scope, ok := value.(TaskScope)
	return scope, ok && scope.Valid() && scope.IsOrg()
}

// IsOrg reports whether the scope reads organization rows.
func (s TaskScope) IsOrg() bool {
	return s.Kind != TaskScopeNone && s.Kind != TaskScopePersonal
}

// Valid reports whether the scope can match anything at all.
func (s TaskScope) Valid() bool { return s.Kind != TaskScopeNone }

// apply narrows a query over tasks or midjourneys. Both tables carry the same
// attribution columns.
func (s TaskScope) apply(tx *gorm.DB) *gorm.DB {
	switch s.Kind {
	case TaskScopePersonal:
		return tx.Where("user_id = ? AND org_id = 0", s.UserID)
	case TaskScopeOrgMember:
		return tx.Where("org_id = ? AND workspace_id = ? AND owner_type = ? AND actor_user_id = ?",
			s.OrgID, s.WorkspaceID, types.TokenOwnerMember, s.ActorUserID)
	case TaskScopeOrgSystem:
		return tx.Where("org_id = ? AND workspace_id = ? AND owner_type = ? AND access_principal_id = ?",
			s.OrgID, s.WorkspaceID, types.TokenOwnerWorkspace, s.AccessPrincipalID)
	case TaskScopeOrgWorkspace:
		return tx.Where("org_id = ? AND workspace_id = ?", s.OrgID, s.WorkspaceID)
	case TaskScopeOrgSelf:
		return tx.Where("org_id = ? AND workspace_id = ? AND owner_type = ? AND actor_user_id = ?",
			s.OrgID, s.WorkspaceID, types.TokenOwnerMember, s.ActorUserID)
	case TaskScopeOrgPlatform:
		tx = tx.Where("org_id = ?", s.OrgID)
		if s.WorkspaceID > 0 {
			tx = tx.Where("workspace_id = ?", s.WorkspaceID)
		}
		if s.ActorUserID > 0 {
			tx = tx.Where("actor_user_id = ?", s.ActorUserID)
		}
		return tx
	}
	return tx.Where("1 = 0")
}

// ApplyOrgSubject stamps the trusted attribution snapshot on a task being
// submitted. Polling, refunds and settlement logs read it back from the row, so
// they never depend on the key still existing. The subject comes from the
// TokenAuth-written context, never from request input. billing_operation_id is
// left for the billing session to fill.
func (t *Task) ApplyOrgSubject(subject types.OrgSubject) {
	if t == nil || subject.OrgID <= 0 {
		return
	}
	t.OrgId, t.WorkspaceId, t.ActorUserId = subject.OrgID, subject.WorkspaceID, subject.ActorUserID
	t.OwnerType, t.AccessPrincipalId = subject.OwnerType, subject.AccessPrincipalID
}

// ApplyOrgSubject is Task.ApplyOrgSubject for a legacy Midjourney row.
func (m *Midjourney) ApplyOrgSubject(subject types.OrgSubject) {
	if m == nil || subject.OrgID <= 0 {
		return
	}
	m.OrgId, m.WorkspaceId, m.ActorUserId = subject.OrgID, subject.WorkspaceID, subject.ActorUserID
	m.OwnerType, m.AccessPrincipalId = subject.OwnerType, subject.AccessPrincipalID
}

// GetTaskInScope returns one task the scope may read. A task outside the scope
// is indistinguishable from a missing one.
func GetTaskInScope(scope TaskScope, taskID string) (*Task, bool, error) {
	if taskID == "" || !scope.Valid() {
		return nil, false, nil
	}
	var task *Task
	err := scope.apply(DB).Where("task_id = ?", taskID).First(&task).Error
	exist, err := RecordExist(err)
	if err != nil {
		return nil, false, err
	}
	return task, exist, nil
}

// GetTasksInScopeForPlatforms is the batched form of GetTaskInScope, limited to
// the given platforms.
func GetTasksInScopeForPlatforms(scope TaskScope, platforms []constant.TaskPlatform, taskIDs []string) ([]*Task, error) {
	if len(platforms) == 0 || len(taskIDs) == 0 || !scope.Valid() {
		return nil, nil
	}
	var tasks []*Task
	if err := scope.apply(DB).Where("platform IN ? AND task_id IN ?", platforms, taskIDs).Find(&tasks).Error; err != nil {
		return nil, err
	}
	return tasks, nil
}

// GetTaskInScopeForObservation reloads one task for a long-lived protocol
// observer through the same scope.
func GetTaskInScopeForObservation(ctx context.Context, scope TaskScope, platform constant.TaskPlatform, taskID string) (*Task, bool, error) {
	if taskID == "" || !scope.Valid() {
		return nil, false, nil
	}
	var task Task
	err := scope.apply(DB.WithContext(ctx)).Where("platform = ? AND task_id = ?", platform, taskID).First(&task).Error
	exists, err := RecordExist(err)
	if err != nil || !exists {
		return nil, exists, err
	}
	return &task, true, nil
}

func (q SyncTaskQueryParams) applyToScope(tx *gorm.DB) *gorm.DB {
	if q.TaskID != "" {
		tx = tx.Where("task_id = ?", q.TaskID)
	}
	if q.Action != "" {
		tx = tx.Where("action = ?", q.Action)
	}
	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
	}
	if q.Platform != "" {
		tx = tx.Where("platform = ?", q.Platform)
	}
	if q.StartTimestamp != 0 {
		tx = tx.Where("submit_time >= ?", q.StartTimestamp)
	}
	if q.EndTimestamp != 0 {
		tx = tx.Where("submit_time <= ?", q.EndTimestamp)
	}
	return tx
}

// ListTasksInScope pages tasks the scope may read, newest first. Like every
// task list it omits the persisted upstream snapshot.
func ListTasksInScope(scope TaskScope, startIdx, num int, query SyncTaskQueryParams) ([]*Task, error) {
	if !scope.Valid() {
		return []*Task{}, nil
	}
	var tasks []*Task
	err := query.applyToScope(scope.apply(DB)).Omit("channel_id", "data").Order("id desc").Limit(num).Offset(startIdx).Find(&tasks).Error
	if err != nil {
		return nil, err
	}
	return tasks, nil
}

// CountTasksInScope counts what ListTasksInScope pages over.
func CountTasksInScope(scope TaskScope, query SyncTaskQueryParams) (int64, error) {
	if !scope.Valid() {
		return 0, nil
	}
	var total int64
	err := query.applyToScope(scope.apply(DB.Model(&Task{}))).Count(&total).Error
	return total, err
}

// GetMJInScope returns one Midjourney task the scope may read, or nil.
func GetMJInScope(scope TaskScope, mjID string) *Midjourney {
	if mjID == "" || !scope.Valid() {
		return nil
	}
	var mj *Midjourney
	if err := scope.apply(DB).Where("mj_id = ?", mjID).First(&mj).Error; err != nil {
		return nil
	}
	return mj
}

// GetMJsInScope is the batched form of GetMJInScope.
func GetMJsInScope(scope TaskScope, mjIDs []string) []*Midjourney {
	if len(mjIDs) == 0 || !scope.Valid() {
		return nil
	}
	var mj []*Midjourney
	if err := scope.apply(DB).Where("mj_id IN ?", mjIDs).Find(&mj).Error; err != nil {
		return nil
	}
	return mj
}

func (q TaskQueryParams) applyToScope(tx *gorm.DB) *gorm.DB {
	if q.MjID != "" {
		tx = tx.Where("mj_id = ?", q.MjID)
	}
	if q.StartTimestamp != "" {
		tx = tx.Where("submit_time >= ?", q.StartTimestamp)
	}
	if q.EndTimestamp != "" {
		tx = tx.Where("submit_time <= ?", q.EndTimestamp)
	}
	return tx
}

// ListMJInScope pages Midjourney tasks the scope may read, newest first.
func ListMJInScope(scope TaskScope, startIdx, num int, query TaskQueryParams) ([]*Midjourney, error) {
	if !scope.Valid() {
		return []*Midjourney{}, nil
	}
	var tasks []*Midjourney
	err := query.applyToScope(scope.apply(DB)).Order("id desc").Limit(num).Offset(startIdx).Find(&tasks).Error
	if err != nil {
		return nil, err
	}
	return tasks, nil
}

// CountMJInScope counts what ListMJInScope pages over.
func CountMJInScope(scope TaskScope, query TaskQueryParams) (int64, error) {
	if !scope.Valid() {
		return 0, nil
	}
	var total int64
	err := query.applyToScope(scope.apply(DB.Model(&Midjourney{}))).Count(&total).Error
	return total, err
}
