package middleware

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	managementPrincipalContextKey = "management_principal"
	scimOrgContextKey             = "scim_org_id"
)

// ManagementPrincipalFromContext returns the credential standing ManagementAuth proved.
func ManagementPrincipalFromContext(c *gin.Context) (*orgsvc.ManagementPrincipal, bool) {
	value, ok := c.Get(managementPrincipalContextKey)
	if !ok {
		return nil, false
	}
	principal, ok := value.(*orgsvc.ManagementPrincipal)
	return principal, ok && principal != nil
}

func bearerValue(c *gin.Context) string {
	header := strings.TrimSpace(c.GetHeader("Authorization"))
	if len(header) > 7 && strings.EqualFold(header[:7], "Bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
}

// ManagementAuth authenticates a personal management credential for the :org
// path parameter and requires scope. Every request re-reads the primary
// database (hash, status, expiry, organization, creator, live role), so a
// demoted, removed or disabled creator loses the credential at once. The
// request then runs as the creator capped at administrator, and the credential
// id is stamped on every audit row written for it. A credential for another
// organization answers exactly like an unknown one.
//
// It is mounted only on the /api/mgmt tree: the session-only routes (credential
// administration, ownership, deletion, SSO, billing writes) are not on it.
func ManagementAuth(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, err := orgsvc.AuthenticateCredential(c.Request.Context(), bearerValue(c), types.OrgAccessTokenPersonalManagement)
		if err != nil {
			abortWithOrgError(c, err)
			return
		}
		org, err := model.GetOrganizationByRef(model.DB, c.Param("org"))
		if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && org.Id != principal.Org.Id) {
			abortWithOrgError(c, types.NewOrgAccessError(types.OrgErrNotFound))
			return
		}
		if err != nil {
			abortWithOrgError(c, types.NewOrgAccessError(types.OrgErrStateUnavailable))
			return
		}
		if !principal.HasScope(scope) {
			abortWithOrgError(c, types.NewOrgAccessError(types.OrgErrForbidden))
			return
		}
		model.TouchOrgAccessToken(model.DB, &principal.Token, c.ClientIP())
		c.Request = c.Request.WithContext(orgsvc.WithManagementCredential(c.Request.Context(), principal.Token.Id))
		c.Set("id", principal.ActorUserID)
		c.Set(sessionOrgIDContextKey, principal.Org.Id)
		c.Set(orgAccessContextKey, principal.Access)
		c.Set(managementPrincipalContextKey, principal)
		c.Next()
	}
}

// ScimErrorSchema is the SCIM 2.0 error message schema URN.
const ScimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"

// WriteScimError renders a SCIM error response and aborts.
func WriteScimError(c *gin.Context, status int, scimType, detail string) {
	body := gin.H{"schemas": []string{ScimErrorSchema}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	c.Header("Content-Type", "application/scim+json")
	c.AbortWithStatusJSON(status, body)
}

// ScimAuth authenticates a scim_service credential on the /scim/v2 tree and
// nothing else. The credential carries only the scim scope and does not depend
// on its creator, but organization state, expiry and revocation apply on every
// request. A personal management credential, an inference key and an
// organization session all fail here the same way.
func ScimAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/scim/v2/") && c.Request.URL.Path != "/scim/v2" {
			WriteScimError(c, http.StatusForbidden, "", "The credential is not valid for this route")
			return
		}
		principal, err := orgsvc.AuthenticateCredential(c.Request.Context(), bearerValue(c), types.OrgAccessTokenSCIMService)
		if err != nil {
			response := orgsvc.ConsoleError(err)
			status := http.StatusUnauthorized
			if response.Code == types.OrgErrSuspended {
				status = http.StatusForbidden
			}
			WriteScimError(c, status, "", "Authentication failed")
			return
		}
		model.TouchOrgAccessToken(model.DB, &principal.Token, c.ClientIP())
		c.Set(scimOrgContextKey, principal.Org.Id)
		c.Request = c.Request.WithContext(orgsvc.WithManagementCredential(c.Request.Context(), principal.Token.Id))
		c.Next()
	}
}

// ScimOrgID is the organization the SCIM credential belongs to.
func ScimOrgID(c *gin.Context) int { return c.GetInt(scimOrgContextKey) }

// RequireOrgSensitiveProof consumes the single-use proof for one organization
// action. It binds the proof to the session (inside ConsumeOperationProof), to
// the session's own auth scope (read from the session, never from the client),
// to the organization and to the exact resource. It writes the refusal and
// returns false when the proof is missing, stale, spent or for something else.
func RequireOrgSensitiveProof(c *gin.Context, action string, orgID int, resource string) bool {
	authScope := c.GetString(sessionAuthScopeContextKey)
	if authScope == "" {
		authScope = types.AuthScopeGlobal
	}
	context, err := service.OrgSensitiveContextJSON(orgID, authScope, resource)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return false
	}
	return RequireSecurityProof(c, service.VerificationOperation{Scope: action, Context: context}) != nil
}

// SessionAuthScope is the auth scope of the dashboard session that passed
// UserAuth for this request: global or org.
func SessionAuthScope(c *gin.Context) string {
	if scope := c.GetString(sessionAuthScopeContextKey); scope != "" {
		return scope
	}
	return types.AuthScopeGlobal
}
