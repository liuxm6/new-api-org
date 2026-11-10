package model

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/clickhouse"
	"gorm.io/gorm"
)

// TestOrgLogsOnClickHouse reads the organization log list and export through a
// real ClickHouse log database (TEST_CLICKHOUSE_DSN). The financial tables stay
// in the main database; only operational logs move.
func TestOrgLogsOnClickHouse(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_DSN is not configured")
	}
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	require.True(t, net.ParseIP(parsed.Hostname()).IsLoopback(), "database tests only permit loopback instances")

	name := fmt.Sprintf("newapi_org_logs_%d", time.Now().UnixNano())
	admin, err := gorm.Open(clickhouse.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE DATABASE "+name).Error)
	t.Cleanup(func() {
		assert.NoError(t, admin.Exec("DROP DATABASE IF EXISTS "+name).Error)
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	parsed.Path = "/" + name
	t.Setenv("LOG_SQL_DSN", parsed.String())

	previousLogDB, previousLogType, previousMaster := LOG_DB, common.LogDatabaseType(), common.IsMasterNode
	common.IsMasterNode = true
	t.Cleanup(func() {
		if sqlDB, err := LOG_DB.DB(); err == nil {
			_ = sqlDB.Close()
		}
		LOG_DB, common.IsMasterNode = previousLogDB, previousMaster
		common.SetLogDatabaseType(previousLogType)
		initCol()
	})
	require.NoError(t, InitLogDB())
	require.True(t, common.UsingLogDatabase(common.DatabaseTypeClickHouse), "the log database is ClickHouse")

	var version string
	require.NoError(t, LOG_DB.Raw("SELECT version()").Scan(&version).Error)
	t.Logf("log database: clickhouse %s", version)

	now := time.Now().Unix()
	row := func(org, ws, actor int, requestID, text string, at int64) Log {
		return Log{UserId: 1, Username: "u", CreatedAt: at, Type: LogTypeConsume, Content: text, ModelName: "gpt-x",
			Quota: 10, RequestId: requestID, OrgId: org, WorkspaceId: ws, ActorUserId: actor,
			Other: `{"admin_info":{"use_channel":[1]},"model_ratio":1}`}
	}
	logs := []Log{
		row(1, 10, 100, "a-1", "org1 ws10 actor100", now-30),
		row(1, 10, 101, "a-2", "org1 ws10 actor101", now-20),
		row(1, 11, 100, "a-3", "org1 ws11 actor100", now-10),
		row(2, 20, 200, "b-1", "org2", now-5),
		row(0, 0, 0, "p-1", "personal", now-1),
	}
	for i := range logs {
		require.NoError(t, LOG_DB.Create(&logs[i]).Error)
	}

	list := func(scope OrgUsageScope) ([]*Log, int64) {
		page, total, err := GetOrgLogs(scope, LogFilter{}, 0, 50)
		require.NoError(t, err)
		return page, total
	}
	contents := func(page []*Log) []string {
		out := []string{}
		for _, l := range page {
			out = append(out, l.Content)
		}
		return out
	}

	t.Run("an organization sees only its own logs", func(t *testing.T) {
		page, total := list(OrgUsageScope{OrgID: 1})
		assert.EqualValues(t, 3, total)
		assert.ElementsMatch(t, []string{"org1 ws10 actor100", "org1 ws10 actor101", "org1 ws11 actor100"}, contents(page))
		page, total = list(OrgUsageScope{OrgID: 2})
		assert.EqualValues(t, 1, total)
		assert.Equal(t, []string{"org2"}, contents(page))
	})

	t.Run("a workspace and a member narrow the scope", func(t *testing.T) {
		_, total := list(OrgUsageScope{OrgID: 1, WorkspaceID: 10})
		assert.EqualValues(t, 2, total)
		_, total = list(OrgUsageScope{OrgID: 1, WorkspaceID: 10, ActorUserID: 101})
		assert.EqualValues(t, 1, total)
		_, total = list(OrgUsageScope{OrgID: 1, ActorUserID: 100})
		assert.EqualValues(t, 2, total)
	})

	t.Run("no organization means no rows, never every row", func(t *testing.T) {
		page, total := list(OrgUsageScope{})
		assert.Zero(t, total)
		assert.Empty(t, page)
		_, total = list(OrgUsageScope{OrgID: 999})
		assert.Zero(t, total)
	})

	t.Run("the list is newest first and hides internal channel data", func(t *testing.T) {
		page, _ := list(OrgUsageScope{OrgID: 1})
		require.Len(t, page, 3)
		assert.Equal(t, "org1 ws11 actor100", page[0].Content)
		for _, l := range page {
			assert.Empty(t, l.ChannelName)
			assert.NotContains(t, l.Other, "admin_info")
		}
	})

	t.Run("filters work inside the scope", func(t *testing.T) {
		page, total, err := GetOrgLogs(OrgUsageScope{OrgID: 1}, LogFilter{RequestId: "a-2"}, 0, 50)
		require.NoError(t, err)
		assert.EqualValues(t, 1, total)
		assert.Equal(t, []string{"org1 ws10 actor101"}, contents(page))
		_, total, err = GetOrgLogs(OrgUsageScope{OrgID: 1}, LogFilter{RequestId: "b-1"}, 0, 50)
		require.NoError(t, err)
		assert.Zero(t, total, "another organization's request id finds nothing")
	})

	t.Run("paging", func(t *testing.T) {
		page, total, err := GetOrgLogs(OrgUsageScope{OrgID: 1}, LogFilter{}, 1, 1)
		require.NoError(t, err)
		assert.EqualValues(t, 3, total)
		require.Len(t, page, 1)
		assert.Equal(t, "org1 ws10 actor101", page[0].Content)
	})

	t.Run("the export streams the same rows", func(t *testing.T) {
		var streamed []string
		require.NoError(t, StreamOrgLogs(context.Background(), OrgUsageScope{OrgID: 1}, LogFilter{}, func(l *Log) error {
			streamed = append(streamed, l.Content)
			assert.NotContains(t, l.Other, "admin_info")
			return nil
		}))
		assert.ElementsMatch(t, []string{"org1 ws10 actor100", "org1 ws10 actor101", "org1 ws11 actor100"}, streamed)
	})
}
