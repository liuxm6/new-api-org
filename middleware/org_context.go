package middleware

import (
	"errors"
	"fmt"

	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	relaytypes "github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// OrgSubjectFromContext returns the trusted organization subject that TokenAuth
// stored for this request. ok is false for personal and legacy keys. The subject
// is never read from a request body or header.
func OrgSubjectFromContext(c *gin.Context) (types.OrgSubject, bool) {
	value, exists := c.Get(string(constant.ContextKeyOrgSubject))
	if !exists {
		return types.OrgSubject{}, false
	}
	subject, ok := value.(types.OrgSubject)
	return subject, ok && subject.OrgID > 0
}

// RateLimitSubject names the principal that rate limits count against. An
// organization key counts per member inside its organization, a system key per
// workspace, so one wallet shared by many members does not share one bucket and
// two organizations never share a bucket. Personal keys keep the user id.
func RateLimitSubject(c *gin.Context) string {
	subject, ok := OrgSubjectFromContext(c)
	if !ok {
		return fmt.Sprintf("%d", c.GetInt("id"))
	}
	if subject.ActorUserID > 0 {
		return fmt.Sprintf("org:%d:user:%d", subject.OrgID, subject.ActorUserID)
	}
	return fmt.Sprintf("org:%d:ws:%d", subject.OrgID, subject.WorkspaceID)
}

// applyOrgTokenContext proves the organization state of a key and records the
// subject. It returns false after writing the refusal. A failure to read the
// primary database refuses the request; it is never read as a personal key.
func applyOrgTokenContext(c *gin.Context, token *model.Token) bool {
	subject, isOrg := model.OrgSubjectFromToken(token)
	if !isOrg {
		return true
	}
	state, err := model.LoadOrgRequestState(c.Request.Context(), subject)
	if err != nil {
		var accessErr *types.OrgAccessError
		if !errors.As(err, &accessErr) {
			accessErr = types.NewOrgAccessError(types.OrgErrStateUnavailable)
		}
		abortWithOpenAiMessage(c, accessErr.Status, orgAccessMessage(accessErr.Code), relaytypes.ErrorCode(accessErr.Code))
		return false
	}
	c.Set(string(constant.ContextKeyOrgSubject), subject)
	c.Set(string(constant.ContextKeyOrgPolicyVersion), state.PolicyVersion)
	c.Set(string(constant.ContextKeyOrgRecoveryRequired), state.RecoveryRequired)
	return true
}

// orgAccessMessage is the client-facing text for an organization refusal. It
// carries no internal identifiers.
func orgAccessMessage(code string) string {
	switch code {
	case types.OrgErrSuspended:
		return "The organization is suspended"
	case types.OrgErrWorkspaceSuspended:
		return "The workspace is suspended"
	case types.OrgErrMemberSuspended:
		return "The member is suspended"
	case types.OrgErrForbidden:
		return "This key is not permitted to perform the request"
	case types.OrgErrStateUnavailable:
		return "The organization state could not be verified, retry later"
	default:
		return "Invalid token"
	}
}
