package model

import (
	"context"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func orgTaskDialects() []string { return []string{"sqlite", "mysql", "postgres"} }

// newOrgTaskFixture adds the task, Midjourney, log and aggregation tables to the
// shared organization fixture and points the log database at the main one.
func newOrgTaskFixture(t *testing.T, dialect string) (*gorm.DB, orgFixture) {
	t.Helper()
	db := openOrgMigrationDB(t, dialect)
	if dialect == "mysql" {
		// MySQL keeps its tables between runs and the shared harness drops only the
		// organization tables and users; these would carry rows over.
		dropRows := func() {
			for _, m := range []any{&Task{}, &Midjourney{}, &Log{}, &QuotaData{}, &Token{}} {
				require.NoError(t, db.Migrator().DropTable(m))
			}
		}
		dropRows()
		t.Cleanup(dropRows)
	}
	f := newOrgFixture(t, db)
	require.NoError(t, db.AutoMigrate(&Task{}, &Midjourney{}, &Log{}, &QuotaData{}))
	previousLog := LOG_DB
	LOG_DB = db
	t.Cleanup(func() { LOG_DB = previousLog })
	return db, f
}

// submitTask stores a task the way the submit path does: attribution comes from
// the RelayInfo subject through InitTask.
func submitTask(t *testing.T, db *gorm.DB, subject types.OrgSubject, userID int, taskID string) *Task {
	t.Helper()
	task := InitTask(constant.TaskPlatform("plugin"), &relaycommon.RelayInfo{
		OrgSubject: subject, UserId: userID, ChannelMeta: &relaycommon.ChannelMeta{ChannelId: 1}})
	task.TaskID = taskID
	require.NoError(t, db.Create(task).Error)
	return task
}

func TestOrgTaskScope(t *testing.T) {
	for _, dialect := range orgTaskDialects() {
		t.Run(dialect, func(t *testing.T) {
			db, f := newOrgTaskFixture(t, dialect)
			peer := User{Username: "member-b", Password: "password-123", Role: common.RoleCommonUser,
				Status: common.UserStatusEnabled, AffCode: "mem-b"}
			require.NoError(t, db.Create(&peer).Error)
			mine, system := subjectOf(t, f.memberKey), subjectOf(t, f.systemKey)
			theirs := mine
			theirs.ActorUserID = peer.Id

			t.Run("submit stamps the trusted subject and leaves personal tasks unmarked", func(t *testing.T) {
				task := submitTask(t, db, mine, f.wallet.Id, "task_mine")
				assert.Equal(t, mine.OrgID, task.OrgId)
				assert.Equal(t, mine.WorkspaceID, task.WorkspaceId)
				assert.Equal(t, mine.ActorUserID, task.ActorUserId)
				assert.Equal(t, types.TokenOwnerMember, task.OwnerType)
				assert.Equal(t, "prn-member", task.AccessPrincipalId)
				assert.Empty(t, task.BillingOperationId, "the billing session fills the operation id")
				personal := submitTask(t, db, types.OrgSubject{}, f.member.Id, "task_personal")
				assert.Zero(t, personal.OrgId)
				assert.Empty(t, personal.OwnerType)

				legacy := &Midjourney{MjId: "mj_mine", UserId: f.wallet.Id}
				legacy.ApplyOrgSubject(mine)
				require.NoError(t, db.Create(legacy).Error)
				assert.Equal(t, mine.ActorUserID, legacy.ActorUserId)
				var stored Midjourney
				require.NoError(t, db.Where("mj_id = ?", "mj_mine").First(&stored).Error)
				assert.Equal(t, mine.OrgID, stored.OrgId)
				assert.Equal(t, types.TokenOwnerMember, stored.OwnerType)
			})

			submitTask(t, db, theirs, f.wallet.Id, "task_peer")
			submitTask(t, db, system, f.wallet.Id, "task_system")
			elsewhere := mine
			elsewhere.WorkspaceID += 100
			submitTask(t, db, elsewhere, f.wallet.Id, "task_other_ws")
			foreign := mine
			foreign.OrgID += 100
			submitTask(t, db, foreign, f.wallet.Id, "task_other_org")
			ids := []string{"task_mine", "task_peer", "task_system", "task_other_ws", "task_other_org", "task_personal"}
			visible := func(scope TaskScope) []string {
				var seen []string
				for _, id := range ids {
					if _, ok, err := GetTaskInScope(scope, id); err == nil && ok {
						seen = append(seen, id)
					}
				}
				return seen
			}

			t.Run("a member key reads only its own actor in its own workspace", func(t *testing.T) {
				assert.Equal(t, []string{"task_mine"}, visible(TaskScopeForOrgSubject(mine)))
				assert.Equal(t, []string{"task_peer"}, visible(TaskScopeForOrgSubject(theirs)))
			})

			t.Run("a system key reads by principal, so a rotated key keeps the history", func(t *testing.T) {
				assert.Equal(t, []string{"task_system"}, visible(TaskScopeForOrgSubject(system)))
				rotated := system
				rotated.TokenID += 50
				assert.Equal(t, []string{"task_system"}, visible(TaskScopeForOrgSubject(rotated)))
				fresh := system
				fresh.AccessPrincipalID = "prn-other"
				assert.Empty(t, visible(TaskScopeForOrgSubject(fresh)), "a newly created system key is a different principal")
			})

			t.Run("console readers are bounded by their standing", func(t *testing.T) {
				assert.Equal(t, []string{"task_mine", "task_peer", "task_system"}, visible(WorkspaceTaskScope(mine.OrgID, mine.WorkspaceID)))
				assert.Equal(t, []string{"task_mine"}, visible(WorkspaceSelfTaskScope(mine.OrgID, mine.WorkspaceID, f.member.Id)))
				assert.Equal(t, []string{"task_peer"}, visible(WorkspaceSelfTaskScope(mine.OrgID, mine.WorkspaceID, peer.Id)))
				assert.Equal(t, []string{"task_mine", "task_peer", "task_system", "task_other_ws"},
					visible(PlatformTaskScope(mine.OrgID, 0, 0)))
				assert.Equal(t, []string{"task_peer"}, visible(PlatformTaskScope(mine.OrgID, mine.WorkspaceID, peer.Id)))
			})

			t.Run("an incomplete scope reads nothing", func(t *testing.T) {
				for name, scope := range map[string]TaskScope{
					"zero":              {},
					"no actor":          TaskScopeForOrgSubject(types.OrgSubject{OrgID: mine.OrgID, WorkspaceID: mine.WorkspaceID, OwnerType: types.TokenOwnerMember}),
					"no principal":      TaskScopeForOrgSubject(types.OrgSubject{OrgID: mine.OrgID, WorkspaceID: mine.WorkspaceID, OwnerType: types.TokenOwnerWorkspace}),
					"no workspace":      TaskScopeForOrgSubject(types.OrgSubject{OrgID: mine.OrgID, ActorUserID: mine.ActorUserID, OwnerType: types.TokenOwnerMember}),
					"unknown owner":     TaskScopeForOrgSubject(types.OrgSubject{OrgID: mine.OrgID, WorkspaceID: mine.WorkspaceID, ActorUserID: 1}),
					"workspace no ws":   WorkspaceTaskScope(mine.OrgID, 0),
					"self no actor":     WorkspaceSelfTaskScope(mine.OrgID, mine.WorkspaceID, 0),
					"personal no user":  PersonalTaskScope(0),
					"platform no org":   PlatformTaskScope(0, 0, 0),
					"context key wrong": ReadTaskScope(types.OrgSubject{OrgID: mine.OrgID}, f.wallet.Id),
				} {
					assert.False(t, scope.Valid() && len(visible(scope)) > 0, name)
				}
			})

			t.Run("the shared wallet id never owns an organization task", func(t *testing.T) {
				assert.Equal(t, []string{"task_personal"}, visible(PersonalTaskScope(f.member.Id)))
				assert.Empty(t, visible(PersonalTaskScope(f.wallet.Id)), "scoped to the wallet user id")
				for _, id := range ids {
					_, ok, err := GetByTaskId(f.wallet.Id, id)
					require.NoError(t, err)
					assert.False(t, ok, "the legacy lookup by wallet id must not reach %s", id)
				}
				_, ok, err := GetByOnlyTaskId("task_mine")
				require.NoError(t, err)
				assert.False(t, ok)
				_, ok, err = GetUniqueByOnlyTaskId("task_mine")
				require.NoError(t, err)
				assert.False(t, ok)
				found, err := GetByTaskIdsForPlatforms(f.wallet.Id, []constant.TaskPlatform{"plugin"}, ids)
				require.NoError(t, err)
				assert.Empty(t, found)
				_, ok, err = GetTaskForProtocolObservation(context.Background(), f.wallet.Id, "plugin", "task_mine")
				require.NoError(t, err)
				assert.False(t, ok)
				assert.Empty(t, TaskGetAllUserTask(f.wallet.Id, 0, 50, SyncTaskQueryParams{}))
				assert.EqualValues(t, 0, TaskCountAllUserTask(f.wallet.Id, SyncTaskQueryParams{}))
				for _, task := range TaskGetAllTasks(0, 50, SyncTaskQueryParams{}) {
					assert.Zero(t, task.OrgId, "the platform task table lists personal tasks only")
				}
				assert.EqualValues(t, 1, TaskCountAllTasks(SyncTaskQueryParams{}))
				_, ok, err = GetTaskForProtocolObservation(context.Background(), f.member.Id, "plugin", "task_personal")
				require.NoError(t, err)
				assert.True(t, ok, "personal tasks are unchanged")
			})

			t.Run("lists and counts use the same boundary", func(t *testing.T) {
				scope := WorkspaceTaskScope(mine.OrgID, mine.WorkspaceID)
				page, err := ListTasksInScope(scope, 0, 2, SyncTaskQueryParams{})
				require.NoError(t, err)
				assert.Len(t, page, 2)
				total, err := CountTasksInScope(scope, SyncTaskQueryParams{})
				require.NoError(t, err)
				assert.EqualValues(t, 3, total)
				total, err = CountTasksInScope(WorkspaceSelfTaskScope(mine.OrgID, mine.WorkspaceID, peer.Id), SyncTaskQueryParams{})
				require.NoError(t, err)
				assert.EqualValues(t, 1, total)
				none, err := ListTasksInScope(TaskScope{}, 0, 10, SyncTaskQueryParams{})
				require.NoError(t, err)
				assert.Empty(t, none)
			})

			t.Run("midjourney reads follow the same scopes", func(t *testing.T) {
				for id, subject := range map[string]types.OrgSubject{"mj_peer": theirs, "mj_system": system} {
					row := &Midjourney{MjId: id, UserId: f.wallet.Id}
					row.ApplyOrgSubject(subject)
					require.NoError(t, db.Create(row).Error)
				}
				require.NoError(t, db.Create(&Midjourney{MjId: "mj_personal", UserId: f.member.Id}).Error)
				assert.NotNil(t, GetMJInScope(TaskScopeForOrgSubject(mine), "mj_mine"))
				assert.Nil(t, GetMJInScope(TaskScopeForOrgSubject(mine), "mj_peer"))
				assert.Nil(t, GetMJInScope(TaskScopeForOrgSubject(mine), "mj_system"))
				assert.NotNil(t, GetMJInScope(TaskScopeForOrgSubject(system), "mj_system"))
				assert.Len(t, GetMJsInScope(WorkspaceTaskScope(mine.OrgID, mine.WorkspaceID), []string{"mj_mine", "mj_peer", "mj_system", "mj_personal"}), 3)
				assert.Nil(t, GetByMJId(f.wallet.Id, "mj_mine"), "legacy lookup by wallet id")
				assert.Empty(t, GetByMJIds(f.wallet.Id, []string{"mj_mine", "mj_peer"}))
				assert.Empty(t, GetAllUserTask(f.wallet.Id, 0, 10, TaskQueryParams{}))
				assert.EqualValues(t, 0, CountAllUserTask(f.wallet.Id, TaskQueryParams{}))
				assert.EqualValues(t, 1, CountAllTasks(TaskQueryParams{}))
				assert.NotNil(t, GetByMJId(f.member.Id, "mj_personal"))
				total, err := CountMJInScope(WorkspaceSelfTaskScope(mine.OrgID, mine.WorkspaceID, peer.Id), TaskQueryParams{})
				require.NoError(t, err)
				assert.EqualValues(t, 1, total)
			})

			t.Run("deleting the key keeps the history and its attribution", func(t *testing.T) {
				require.NoError(t, db.Delete(&Token{}, f.memberKey.Id).Error)
				task, ok, err := GetTaskInScope(TaskScopeForOrgSubject(mine), "task_mine")
				require.NoError(t, err)
				require.True(t, ok)
				assert.Equal(t, mine.ActorUserID, task.ActorUserId)

				// A settlement log is attributed from the task row, not from the key.
				RecordTaskBillingLog(RecordTaskBillingLogParams{OrgId: task.OrgId, WorkspaceId: task.WorkspaceId, ActorUserId: task.ActorUserId,
					UserId: task.UserId, LogType: LogTypeRefund, ModelName: "m", Quota: 5, TokenId: f.memberKey.Id, Other: NewLogOther()})
				var log Log
				require.NoError(t, db.Order("id DESC").First(&log).Error)
				assert.Equal(t, mine.OrgID, log.OrgId)
				assert.Equal(t, mine.WorkspaceID, log.WorkspaceId)
				assert.Equal(t, mine.ActorUserID, log.ActorUserId)
			})
		})
	}
}

func TestOrgUsageQueryScope(t *testing.T) {
	for _, dialect := range orgTaskDialects() {
		t.Run(dialect, func(t *testing.T) {
			db, f := newOrgTaskFixture(t, dialect)
			org, ws, other := f.org.Id, f.workspace.Id, f.member.Id+1000
			rows := []Log{
				{OrgId: org, WorkspaceId: ws, ActorUserId: f.member.Id, UserId: f.wallet.Id, Quota: 10, ModelName: "a", Type: LogTypeConsume, CreatedAt: 100},
				{OrgId: org, WorkspaceId: ws, ActorUserId: other, UserId: f.wallet.Id, Quota: 20, ModelName: "a", Type: LogTypeConsume, CreatedAt: 101},
				{OrgId: org, WorkspaceId: ws + 1, ActorUserId: f.member.Id, UserId: f.wallet.Id, Quota: 40, ModelName: "b", Type: LogTypeConsume, CreatedAt: 102},
				{OrgId: org + 1, WorkspaceId: ws, ActorUserId: f.member.Id, UserId: f.wallet.Id + 1, Quota: 80, ModelName: "a", Type: LogTypeConsume, CreatedAt: 103},
				{UserId: f.member.Id, Quota: 160, ModelName: "a", Type: LogTypeConsume, CreatedAt: 104},
			}
			require.NoError(t, db.Create(&rows).Error)
			quotas := []QuotaData{
				{OrgID: org, WorkspaceID: ws, ActorUserID: f.member.Id, ModelName: "a", CreatedAt: 3600, Count: 1, Quota: 10, TokenUsed: 3},
				{OrgID: org, WorkspaceID: ws, ActorUserID: other, ModelName: "a", CreatedAt: 3600, Count: 2, Quota: 20, TokenUsed: 5},
				{OrgID: org, WorkspaceID: ws + 1, ActorUserID: f.member.Id, ModelName: "b", CreatedAt: 3600, Count: 4, Quota: 40},
				{OrgID: org + 1, WorkspaceID: ws, ActorUserID: f.member.Id, ModelName: "a", CreatedAt: 3600, Count: 8, Quota: 80},
				{ModelName: "a", CreatedAt: 3600, Count: 16, Quota: 160},
			}
			require.NoError(t, db.Create(&quotas).Error)

			sum := func(scope OrgUsageScope) (logQuota, usageQuota int, logs int64) {
				page, total, err := GetOrgLogs(scope, LogFilter{}, 0, 50)
				require.NoError(t, err)
				for _, row := range page {
					logQuota += row.Quota
				}
				stat, err := GetOrgUsage(scope, 0, 10000)
				require.NoError(t, err)
				for _, row := range stat {
					usageQuota += row.Quota
				}
				var exported int
				require.NoError(t, StreamOrgLogs(context.Background(), scope, LogFilter{}, func(*Log) error { exported++; return nil }))
				assert.EqualValues(t, total, exported, "the export covers what the list counts")
				return logQuota, usageQuota, total
			}

			t.Run("list, statistics and export share one boundary", func(t *testing.T) {
				logQ, useQ, n := sum(OrgUsageScope{OrgID: org})
				assert.Equal(t, 70, logQ)
				assert.Equal(t, 70, useQ)
				assert.EqualValues(t, 3, n)
				logQ, useQ, n = sum(OrgUsageScope{OrgID: org, WorkspaceID: ws})
				assert.Equal(t, 30, logQ)
				assert.Equal(t, 30, useQ)
				assert.EqualValues(t, 2, n)
				logQ, useQ, n = sum(OrgUsageScope{OrgID: org, WorkspaceID: ws, ActorUserID: f.member.Id})
				assert.Equal(t, 10, logQ)
				assert.Equal(t, 10, useQ)
				assert.EqualValues(t, 1, n)
				logQ, useQ, n = sum(OrgUsageScope{OrgID: org, ActorUserID: f.member.Id})
				assert.Equal(t, 50, logQ, "a member sees their own rows across workspaces")
				assert.Equal(t, 50, useQ)
				assert.EqualValues(t, 2, n)
			})

			t.Run("a scope without an organization reads nothing", func(t *testing.T) {
				logQ, useQ, n := sum(OrgUsageScope{})
				assert.Zero(t, logQ)
				assert.Zero(t, useQ)
				assert.Zero(t, n)
				_, _, err := ListOrgAuditLogs(OrgUsageScope{}, OrgAuditFilter{}, 0, 10)
				require.NoError(t, err)
			})

			t.Run("audit rows are scoped, redacted and safe to put in a spreadsheet", func(t *testing.T) {
				audit := []OrgAuditLog{
					{OrgId: org, WorkspaceId: 0, ActorUserId: f.member.Id, Action: "member.join", CreatedAt: 1,
						Detail: `{"role":"member","token":"abc","nested":{"api_key":"k"},"note":"sk-ABCDEFGH12345678"}`, CredentialRef: "hash123"},
					{OrgId: org, WorkspaceId: ws, ActorUserId: other, Action: "=cmd|' /C calc'!A0", CreatedAt: 2, Detail: `not json`},
					{OrgId: org + 1, ActorUserId: other, Action: "foreign", CreatedAt: 3},
				}
				require.NoError(t, db.Create(&audit).Error)
				listed, total, err := ListOrgAuditLogs(OrgUsageScope{OrgID: org}, OrgAuditFilter{}, 0, 10)
				require.NoError(t, err)
				assert.EqualValues(t, 2, total)
				require.Len(t, listed, 2)
				for _, row := range listed {
					assert.Empty(t, row.CredentialRef)
					assert.NotContains(t, row.Detail, "abc")
					assert.NotContains(t, row.Detail, "ABCDEFGH")
				}
				assert.JSONEq(t, `{"role":"member","token":"[redacted]","nested":{"api_key":"[redacted]"},"note":"[redacted]"}`, listed[1].Detail)
				assert.Equal(t, "[redacted]", listed[0].Detail, "an unparsable detail is never passed through")

				mine, _, err := ListOrgAuditLogs(OrgUsageScope{OrgID: org, ActorUserID: f.member.Id}, OrgAuditFilter{}, 0, 10)
				require.NoError(t, err)
				require.Len(t, mine, 1)
				assert.Equal(t, "member.join", mine[0].Action)
				inWs, _, err := ListOrgAuditLogs(OrgUsageScope{OrgID: org, WorkspaceID: ws}, OrgAuditFilter{}, 0, 10)
				require.NoError(t, err)
				assert.Len(t, inWs, 1, "organization-level rows are not workspace rows")

				previous := orgAuditStreamBatch
				orgAuditStreamBatch = 1
				t.Cleanup(func() { orgAuditStreamBatch = previous })
				var streamed []int
				require.NoError(t, StreamOrgAuditLogs(context.Background(), OrgUsageScope{OrgID: org}, OrgAuditFilter{}, func(row OrgAuditLog) error {
					streamed = append(streamed, row.Id)
					assert.Empty(t, row.CredentialRef)
					return nil
				}))
				assert.Len(t, streamed, 2, "batched streaming returns every row once")
				assert.NotEqual(t, streamed[0], streamed[1])

				assert.Equal(t, "'=1+1", CSVSafe("=1+1"))
				assert.Equal(t, "'-2", CSVSafe("-2"))
				assert.Equal(t, "'@x", CSVSafe("@x"))
				assert.Equal(t, "plain", CSVSafe("plain"))
				assert.Empty(t, CSVSafe(""))
			})
		})
	}
}
