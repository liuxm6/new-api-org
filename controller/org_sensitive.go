package controller

import (
	"slices"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/middleware"

	"github.com/gin-gonic/gin"
)

// Resource strings bind a proof to the exact thing it authorizes. They are
// built here from validated server-side values, never taken from the client.

func credentialGrantResource(kind string, scopes []string, expiresAt int64) string {
	sorted := slices.Clone(scopes)
	for i := range sorted {
		sorted[i] = strings.TrimSpace(sorted[i])
	}
	slices.Sort(sorted)
	return "grant:" + kind + ":" + strconv.FormatInt(expiresAt, 10) + ":" + strings.Join(slices.Compact(sorted), ",")
}

func credentialResource(id int) string  { return "credential:" + strconv.Itoa(id) }
func ownershipResource(user int) string { return "user:" + strconv.Itoa(user) }
func orgDeleteResource(slug string) string {
	return "slug:" + slug
}
func ssoResource(orgID int) string { return "sso:" + strconv.Itoa(orgID) }

// requireSensitive is the one call every irreversible organization action
// makes after it validated its input and before it changes anything. It never
// runs for a management credential: those routes are not mounted for them.
func requireSensitive(c *gin.Context, action string, orgID int, resource string) bool {
	return middleware.RequireOrgSensitiveProof(c, action, orgID, resource)
}

// transferResource binds a transfer proof to the exact organization, amount and
// idempotency key it authorizes, so a proof for one transfer cannot move another.
func transferResource(orgID, quota int, key string) string {
	return "transfer:" + strconv.Itoa(orgID) + ":" + strconv.Itoa(quota) + ":" + key
}
