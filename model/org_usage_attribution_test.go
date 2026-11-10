package model

import (
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetQuotaDataCache() {
	CacheQuotaDataLock.Lock()
	CacheQuotaData = make(map[string]*QuotaData)
	CacheQuotaDataLock.Unlock()
}

func TestOrgUsageAttribution(t *testing.T) {
	truncateTables(t)
	resetQuotaDataCache()
	require.NoError(t, DB.AutoMigrate(&Log{}, &QuotaData{}))

	base := QuotaDataLogParams{
		UserID: 7, Username: "org_wallet", ModelName: "gpt-a", CreatedAt: 3661,
		UseGroup: "default", TokenID: 11, ChannelID: 1, NodeName: "node-a",
	}
	log := func(orgID, workspaceID, actor, quota int) {
		params := base
		params.OrgID, params.WorkspaceID, params.ActorUserID, params.Quota = orgID, workspaceID, actor, quota
		LogQuotaData(params)
	}

	t.Run("same wallet, different workspaces and actors stay separate", func(t *testing.T) {
		log(5, 1, 100, 10)
		log(5, 1, 100, 10) // same bucket: merges
		log(5, 2, 100, 30) // other workspace
		log(5, 1, 101, 50) // other actor
		log(6, 1, 100, 70) // other organization, same wallet id is impossible in practice but must not merge
		SaveQuotaDataCache()

		var rows []QuotaData
		require.NoError(t, DB.Order("quota ASC").Find(&rows).Error)
		require.Len(t, rows, 4)
		got := map[[3]int]int{}
		for _, r := range rows {
			got[[3]int{r.OrgID, r.WorkspaceID, r.ActorUserID}] = r.Quota
		}
		assert.Equal(t, map[[3]int]int{{5, 1, 100}: 20, {5, 2, 100}: 30, {5, 1, 101}: 50, {6, 1, 100}: 70}, got)
	})

	t.Run("a second flush adds to the matching row only", func(t *testing.T) {
		resetQuotaDataCache()
		log(5, 2, 100, 5)
		SaveQuotaDataCache()
		var row QuotaData
		require.NoError(t, DB.Where("org_id = ? AND workspace_id = ? AND actor_user_id = ?", 5, 2, 100).First(&row).Error)
		assert.Equal(t, 35, row.Quota)
		var other QuotaData
		require.NoError(t, DB.Where("org_id = ? AND workspace_id = ? AND actor_user_id = ?", 5, 1, 101).First(&other).Error)
		assert.Equal(t, 50, other.Quota, "other buckets are untouched")
	})

	t.Run("personal usage keeps merging as before", func(t *testing.T) {
		resetQuotaDataCache()
		log(0, 0, 0, 40)
		log(0, 0, 0, 60)
		SaveQuotaDataCache()
		var rows []QuotaData
		require.NoError(t, DB.Where("org_id = 0 AND workspace_id = 0 AND actor_user_id = 0").Find(&rows).Error)
		require.Len(t, rows, 1)
		assert.Equal(t, 100, rows[0].Quota)
		assert.Zero(t, rows[0].OrgID)
	})
}

func TestOrgConsumeLogAttribution(t *testing.T) {
	truncateTables(t)
	resetQuotaDataCache()
	require.NoError(t, DB.AutoMigrate(&Log{}, &QuotaData{}, &User{}))
	previousLogDB := LOG_DB
	LOG_DB = DB
	t.Cleanup(func() { LOG_DB = previousLogDB })
	previousExport := common.DataExportEnabled
	common.DataExportEnabled = false
	t.Cleanup(func() { common.DataExportEnabled = previousExport })

	record := func(setup func(*gin.Context)) Log {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest("POST", "/v1/chat/completions?org_id=999", nil)
		c.Request.Header.Set("X-Org-Id", "999")
		setup(c)
		DB.Exec("DELETE FROM logs")
		RecordConsumeLog(c, 7, RecordConsumeLogParams{ModelName: "gpt-a", Quota: 10, Other: &LogOther{}})
		var stored Log
		require.NoError(t, DB.Order("id DESC").First(&stored).Error)
		return stored
	}

	t.Run("organization request is attributed from the trusted subject", func(t *testing.T) {
		stored := record(func(c *gin.Context) {
			c.Set(string(constant.ContextKeyOrgSubject), types.OrgSubject{OrgID: 5, WorkspaceID: 2, ActorUserID: 100})
		})
		assert.Equal(t, 5, stored.OrgId)
		assert.Equal(t, 2, stored.WorkspaceId)
		assert.Equal(t, 100, stored.ActorUserId)
	})

	t.Run("request input never sets attribution", func(t *testing.T) {
		stored := record(func(c *gin.Context) {})
		assert.Zero(t, stored.OrgId)
		assert.Zero(t, stored.WorkspaceId)
		assert.Zero(t, stored.ActorUserId)
	})

	t.Run("a wrongly typed context value is ignored", func(t *testing.T) {
		stored := record(func(c *gin.Context) { c.Set(string(constant.ContextKeyOrgSubject), "5") })
		assert.Zero(t, stored.OrgId)
	})
}
