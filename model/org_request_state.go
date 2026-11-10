package model

import (
	"context"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// OrgRequestState is the authorization snapshot of one organization request,
// read from the primary database. Redis is never the basis for admitting an
// organization key.
type OrgRequestState struct {
	Subject       types.OrgSubject
	BillingUserId int
	PolicyVersion int64
	// RecoveryRequired counts operations of this organization waiting for a
	// platform decision; the billing layer compares it with platform thresholds.
	RecoveryRequired int64
}

// LoadOrgRequestState proves that a key's organization, workspace, key row and
// (for member keys) human owner are all live. Any gap returns an
// *types.OrgAccessError; a database failure returns OrgErrStateUnavailable. It
// never reports an organization key as a personal key.
func LoadOrgRequestState(ctx context.Context, subject types.OrgSubject) (*OrgRequestState, error) {
	if subject.OrgID <= 0 || subject.WorkspaceID <= 0 || subject.TokenID <= 0 {
		return nil, types.NewOrgAccessError(types.OrgErrNotFound)
	}
	unavailable := func(err error) error {
		common.SysError(common.LogText("organization request state unavailable: %v", err))
		return types.NewOrgAccessError(types.OrgErrStateUnavailable)
	}
	db := DB.WithContext(ctx)

	var token Token
	err := db.Select("id", "user_id", "status", "org_id", "workspace_id", "created_by", "owner_type", "access_principal_id").
		Where("id = ?", subject.TokenID).Take(&token).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, types.NewOrgAccessError(types.OrgErrNotFound)
	}
	if err != nil {
		return nil, unavailable(err)
	}
	// The cached subject must agree with the row; a mismatch means a stale or
	// forged cache entry and the request is refused.
	if token.OrgId != subject.OrgID || token.WorkspaceId != subject.WorkspaceID ||
		token.OwnerType != subject.OwnerType || token.AccessPrincipalId != subject.AccessPrincipalID ||
		token.CreatedBy != subject.ActorUserID {
		return nil, types.NewOrgAccessError(types.OrgErrNotFound)
	}
	if token.Status != common.TokenStatusEnabled {
		return nil, types.NewOrgAccessError(types.OrgErrForbidden)
	}

	var org Organization
	err = db.Select("id", "status", "billing_user_id", "policy_version").Where("id = ?", subject.OrgID).Take(&org).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, types.NewOrgAccessError(types.OrgErrNotFound)
	}
	if err != nil {
		return nil, unavailable(err)
	}
	if org.BillingUserId != token.UserId {
		return nil, types.NewOrgAccessError(types.OrgErrNotFound)
	}
	if org.Status != types.OrgStatusActive {
		return nil, types.NewOrgAccessError(types.OrgErrSuspended)
	}

	var workspace Workspace
	err = db.Select("id", "org_id", "status").Where("id = ? AND org_id = ?", subject.WorkspaceID, subject.OrgID).Take(&workspace).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, types.NewOrgAccessError(types.OrgErrWorkspaceNotFound)
	}
	if err != nil {
		return nil, unavailable(err)
	}
	if workspace.Status != types.WorkspaceStatusActive {
		return nil, types.NewOrgAccessError(types.OrgErrWorkspaceSuspended)
	}

	// The wallet itself must be an enabled organization wallet.
	var wallet User
	err = db.Select("id", "status", "kind").Where("id = ?", org.BillingUserId).Take(&wallet).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, types.NewOrgAccessError(types.OrgErrNotFound)
		}
		return nil, unavailable(err)
	}
	if !wallet.IsBillingAccount() || wallet.Status != common.UserStatusEnabled {
		return nil, types.NewOrgAccessError(types.OrgErrSuspended)
	}

	// Member keys also need their human owner enabled. Revocation disables the
	// key in the same transaction, so membership is not joined on the hot path.
	if subject.OwnerType == types.TokenOwnerMember {
		var human User
		err = db.Select("id", "status", "kind").Where("id = ?", subject.ActorUserID).Take(&human).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, types.NewOrgAccessError(types.OrgErrMemberSuspended)
		}
		if err != nil {
			return nil, unavailable(err)
		}
		if human.Status != common.UserStatusEnabled || human.IsBillingAccount() {
			return nil, types.NewOrgAccessError(types.OrgErrMemberSuspended)
		}
	}

	state := &OrgRequestState{Subject: subject, BillingUserId: org.BillingUserId, PolicyVersion: org.PolicyVersion}
	if err := db.Model(&OrgBillingOperation{}).
		Where("org_id = ? AND state = ?", subject.OrgID, types.OrgOpStateRecoveryRequired).
		Count(&state.RecoveryRequired).Error; err != nil {
		return nil, unavailable(err)
	}
	return state, nil
}

// OrgSubjectFromToken builds the trusted subject from a token row that came
// from the database or from a MAC-verified cache entry. Personal and legacy
// tokens (OrgId == 0) return ok = false.
func OrgSubjectFromToken(token *Token) (types.OrgSubject, bool) {
	if token == nil || token.OrgId <= 0 {
		return types.OrgSubject{}, false
	}
	return types.OrgSubject{
		OrgID:             token.OrgId,
		WorkspaceID:       token.WorkspaceId,
		ActorUserID:       token.CreatedBy,
		TokenID:           token.Id,
		AccessPrincipalID: token.AccessPrincipalId,
		OwnerType:         token.OwnerType,
	}, true
}
