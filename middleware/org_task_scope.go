package middleware

import (
	"time"

	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

// TaskArtifactURLBuilder returns the artifact content URL builder for one task
// read with an API key. A personal task keeps the permanent capability URL. An
// organization task gets a v2 ticket bound to this key's organization,
// workspace and subject; if the key is not the task's organization the builder
// fails closed rather than minting a personal URL.
func TaskArtifactURLBuilder(c *gin.Context, task *model.Task) func(taskID, artifactKey string) (string, error) {
	if task == nil || task.OrgId == 0 {
		return service.BuildTaskArtifactContentURL
	}
	subject, ok := OrgSubjectFromContext(c)
	if !ok || subject.OrgID != task.OrgId {
		return func(string, string) (string, error) { return "", service.ErrOrgArtifactTicketInvalid }
	}
	claims, ok := service.OrgArtifactClaimsForSubject(subject, c.GetInt64(string(constant.ContextKeyOrgPolicyVersion)))
	if !ok {
		return func(string, string) (string, error) { return "", service.ErrOrgArtifactTicketInvalid }
	}
	return func(taskID, artifactKey string) (string, error) {
		return service.BuildOrgTaskArtifactContentURL(claims, taskID, artifactKey)
	}
}

// OrgMidjourneyImageTicket admits a v2 organization ticket on the public
// Midjourney image route. Without an access value the request passes through
// untouched, so personal images keep working; the handler itself refuses an
// organization task that arrived without a rechecked ticket scope.
func OrgMidjourneyImageTicket() gin.HandlerFunc {
	return func(c *gin.Context) {
		rawAccess := c.GetString(taskArtifactAccessRawContextKey)
		present := c.GetBool(taskArtifactAccessPresentContextKey)
		invalid := c.GetBool(taskArtifactAccessInvalidContextKey)
		if queryAccess, queryPresent, queryInvalid := popTaskArtifactAccessQuery(c.Request); queryPresent {
			present, rawAccess, invalid = true, queryAccess, invalid || queryInvalid
		}
		if !present {
			c.Next()
			return
		}
		ip := c.ClientIP()
		if ip == "" {
			ip = "unknown"
		}
		if invalid || !service.IsOrgArtifactTicket(rawAccess) {
			if !taskArtifactAnonymousLimiter.invalidAttempt(time.Now(), ip) {
				writeTaskArtifactAccessLimited(c)
				return
			}
			writeTaskArtifactAccessNotFound(c)
			return
		}
		authorizeOrgArtifactTicket(c, rawAccess, c.Param("id"), service.OrgMidjourneyImageArtifactKey, ip)
	}
}
