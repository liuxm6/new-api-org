package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestOrgArtifactTicketAdmissionOrder proves the order the design fixes for a v2
// ticket: signature and expiry first with no database read, then the anonymous
// limiter, then the database recheck of the key and its organization.
func TestOrgArtifactTicketAdmissionOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)
	f := setupOrgAuthTest(t)
	previousSecret := common.CryptoSecret
	common.CryptoSecret = "org-ticket-admission-secret"
	t.Cleanup(func() { common.CryptoSecret = previousSecret })

	var reads atomic.Int64
	require.NoError(t, model.DB.Callback().Query().Before("gorm:query").Register("count_reads", func(*gorm.DB) { reads.Add(1) }))
	t.Cleanup(func() { _ = model.DB.Callback().Query().Remove("count_reads") })

	previousLimiter := taskArtifactAnonymousLimiter
	t.Cleanup(func() { taskArtifactAnonymousLimiter = previousLimiter })
	freshLimiter := func(invalid int) {
		taskArtifactAnonymousLimiter = newTaskArtifactAccessLimiter(system_setting.TaskArtifactAccessLimits{
			InvalidRatePerMinute: invalid, GlobalConcurrency: 8, IPConcurrency: 8, ObjectConcurrency: 8})
	}

	router := gin.New()
	router.Use(redactTaskArtifactAccessQuery())
	var reached atomic.Int64
	router.GET("/v1/tasks/:key/artifacts/:artifact_key/content", TokenOrTaskArtifactAccessAuth("key", "artifact_key"),
		func(c *gin.Context) {
			reached.Add(1)
			scope, ok := model.OrgTicketScopeFromContext(c)
			assert.True(t, ok)
			assert.Equal(t, model.TaskScopeOrgMember, scope.Kind)
			c.Status(http.StatusNoContent)
		})
	call := func(ticket string) int {
		request := httptest.NewRequest(http.MethodGet, "/v1/tasks/task_a/artifacts/video/content?access="+ticket, nil)
		request.RemoteAddr = "192.0.2.77:1234"
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		return recorder.Code
	}
	subject, ok := model.OrgSubjectFromToken(&f.memberKey)
	require.True(t, ok)
	claims, ok := service.OrgArtifactClaimsForSubject(subject, f.org.PolicyVersion)
	require.True(t, ok)
	issue := func(at time.Time) string {
		ticket, err := service.IssueOrgArtifactTicket(claims, "task_a", "video", at)
		require.NoError(t, err)
		return ticket
	}

	t.Run("a forged or expired ticket is refused without reading the database", func(t *testing.T) {
		freshLimiter(60)
		reads.Store(0)
		valid := issue(time.Now())
		assert.Equal(t, http.StatusNotFound, call(valid[:len(valid)-2]+"AA"), "bad signature")
		assert.Equal(t, http.StatusNotFound, call(issue(time.Now().Add(-2*time.Hour))), "expired")
		assert.Equal(t, http.StatusNotFound, call("o2.e30.AAAA"), "garbage")
		assert.Zero(t, reads.Load(), "no state is read before the signature and expiry pass")
		assert.Zero(t, reached.Load())
	})

	t.Run("the invalid-attempt budget is spent by forgeries, not by genuine expired tickets", func(t *testing.T) {
		freshLimiter(2)
		expired := issue(time.Now().Add(-2 * time.Hour))
		for range 5 {
			assert.Equal(t, http.StatusNotFound, call(expired), "an expired genuine ticket never locks its holder out")
		}
		valid := issue(time.Now())
		forged := valid[:len(valid)-2] + "AA"
		assert.Equal(t, http.StatusNotFound, call(forged))
		assert.Equal(t, http.StatusNotFound, call(forged))
		assert.Equal(t, http.StatusTooManyRequests, call(forged), "forgeries are limited per address")
	})

	t.Run("the limiter runs before the recheck", func(t *testing.T) {
		freshLimiter(60)
		taskArtifactAnonymousLimiter.limits.GlobalConcurrency = 0
		reads.Store(0)
		assert.Equal(t, http.StatusTooManyRequests, call(issue(time.Now())))
		assert.Zero(t, reads.Load(), "a rejected-by-limiter request never reaches the database")
	})

	t.Run("a valid ticket is rechecked against the database and then served", func(t *testing.T) {
		freshLimiter(60)
		reads.Store(0)
		reached.Store(0)
		assert.Equal(t, http.StatusNoContent, call(issue(time.Now())))
		assert.Positive(t, reads.Load())
		assert.EqualValues(t, 1, reached.Load())
	})

	t.Run("suspension, key changes and a moved policy refuse a ticket that is still signed and unexpired", func(t *testing.T) {
		freshLimiter(60)
		ticket := issue(time.Now())
		restore := func(model any, id int, column string, value any) func() {
			return func() { require.NoError(t, f.db().Model(model).Where("id = ?", id).Update(column, value).Error) }
		}
		cases := []struct {
			name   string
			break_ func()
			fix    func()
		}{
			{"organization suspended", func() {
				require.NoError(t, f.db().Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("status", types.OrgStatusSuspended).Error)
			}, restore(&model.Organization{}, f.org.Id, "status", types.OrgStatusActive)},
			{"workspace suspended", func() {
				require.NoError(t, f.db().Model(&model.Workspace{}).Where("id = ?", f.workspace.Id).Update("status", types.WorkspaceStatusSuspended).Error)
			}, restore(&model.Workspace{}, f.workspace.Id, "status", types.WorkspaceStatusActive)},
			{"key disabled", func() {
				require.NoError(t, f.db().Model(&model.Token{}).Where("id = ?", f.memberKey.Id).Update("status", common.TokenStatusDisabled).Error)
			}, restore(&model.Token{}, f.memberKey.Id, "status", common.TokenStatusEnabled)},
			{"member disabled", func() {
				require.NoError(t, f.db().Model(&model.User{}).Where("id = ?", f.member.Id).Update("status", common.UserStatusDisabled).Error)
			}, restore(&model.User{}, f.member.Id, "status", common.UserStatusEnabled)},
			{"policy moved on", func() {
				require.NoError(t, f.db().Model(&model.Organization{}).Where("id = ?", f.org.Id).Update("policy_version", f.org.PolicyVersion+1).Error)
			}, restore(&model.Organization{}, f.org.Id, "policy_version", f.org.PolicyVersion)},
			{"key deleted", func() { require.NoError(t, f.db().Delete(&model.Token{}, f.memberKey.Id).Error) }, func() {
				require.NoError(t, f.db().Unscoped().Model(&model.Token{}).Where("id = ?", f.memberKey.Id).Update("deleted_at", nil).Error)
			}},
		}
		require.Equal(t, http.StatusNoContent, call(ticket), "the ticket is good before any change")
		for _, tc := range cases {
			tc.break_()
			assert.Equal(t, http.StatusNotFound, call(ticket), tc.name)
			tc.fix()
		}
		assert.Equal(t, http.StatusNoContent, call(ticket), "and good again once everything is restored")
	})
}
