package service

import (
	"context"
	"errors"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"
)

// ErrOrgArtifactTicketRevoked means a correctly signed, unexpired ticket no
// longer authorizes its reader: the organization, workspace, key or person was
// suspended or changed, or the policy moved on. The reader reads the task again
// to get a fresh URL.
var ErrOrgArtifactTicketRevoked = errors.New("organization artifact ticket is no longer authorized")

// ResolveOrgArtifactTicketScope is the database half of a v2 ticket. The
// signature and expiry have already been checked without reading state; this
// proves the ticket's reader is still allowed now and returns the scope they
// read through. Any gap, including a database failure, refuses.
func ResolveOrgArtifactTicketScope(ctx context.Context, claims OrgArtifactTicketClaims) (model.TaskScope, error) {
	revoked := func(err error) (model.TaskScope, error) {
		var refusal *types.OrgAccessError
		if err != nil && !errors.As(err, &refusal) {
			common.SysError(common.LogText("organization artifact ticket recheck failed: %v", err))
		}
		return model.TaskScope{}, ErrOrgArtifactTicketRevoked
	}

	if claims.Kind == OrgArtifactSubjectHuman {
		var user model.User
		if err := model.DB.WithContext(ctx).Select("id", "status", "kind").Where("id = ?", claims.UserID).Take(&user).Error; err != nil {
			return revoked(err)
		}
		if user.Status != common.UserStatusEnabled || user.IsBillingAccount() {
			return revoked(nil)
		}
		access, err := orgsvc.ResolveWorkspaceAccess(ctx, claims.UserID, strconv.Itoa(claims.OrgID), strconv.Itoa(claims.WorkspaceID), 0)
		if err != nil {
			return revoked(err)
		}
		if access.Org.PolicyVersion != claims.PolicyVersion {
			return revoked(nil)
		}
		scope := orgsvc.TaskScopeForWorkspaceAccess(access, claims.UserID)
		if !scope.Valid() {
			return revoked(nil)
		}
		return scope, nil
	}

	token, err := model.GetTokenById(claims.TokenID)
	if err != nil {
		return revoked(err)
	}
	subject, isOrg := model.OrgSubjectFromToken(token)
	if !isOrg || subject.OrgID != claims.OrgID || subject.WorkspaceID != claims.WorkspaceID {
		return revoked(nil)
	}
	switch claims.Kind {
	case OrgArtifactSubjectMemberKey:
		if subject.OwnerType != types.TokenOwnerMember || subject.ActorUserID != claims.UserID {
			return revoked(nil)
		}
	case OrgArtifactSubjectSystemKey:
		if subject.OwnerType != types.TokenOwnerWorkspace || OrgArtifactPrincipalDigest(subject.AccessPrincipalID) != claims.PrincipalHash {
			return revoked(nil)
		}
	default:
		return revoked(nil)
	}
	state, err := model.LoadOrgRequestState(ctx, subject)
	if err != nil {
		return revoked(err)
	}
	if state.PolicyVersion != claims.PolicyVersion {
		return revoked(nil)
	}
	scope := model.TaskScopeForOrgSubject(subject)
	if !scope.Valid() {
		return revoked(nil)
	}
	return scope, nil
}

// OrgArtifactClaimsForSubject builds the ticket claims for an organization key.
func OrgArtifactClaimsForSubject(subject types.OrgSubject, policyVersion int64) (OrgArtifactTicketClaims, bool) {
	claims := OrgArtifactTicketClaims{OrgID: subject.OrgID, WorkspaceID: subject.WorkspaceID, TokenID: subject.TokenID, PolicyVersion: policyVersion}
	switch subject.OwnerType {
	case types.TokenOwnerMember:
		claims.Kind, claims.UserID = OrgArtifactSubjectMemberKey, subject.ActorUserID
	case types.TokenOwnerWorkspace:
		claims.Kind, claims.PrincipalHash = OrgArtifactSubjectSystemKey, OrgArtifactPrincipalDigest(subject.AccessPrincipalID)
	default:
		return OrgArtifactTicketClaims{}, false
	}
	return claims, claims.wellFormed()
}

// OrgArtifactClaimsForHuman builds the ticket claims for a console reader.
func OrgArtifactClaimsForHuman(orgID, workspaceID, userID int, policyVersion int64) OrgArtifactTicketClaims {
	return OrgArtifactTicketClaims{OrgID: orgID, WorkspaceID: workspaceID, Kind: OrgArtifactSubjectHuman, UserID: userID, PolicyVersion: policyVersion}
}
