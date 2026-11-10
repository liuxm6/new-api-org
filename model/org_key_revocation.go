package model

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// KeyRevocation is the set of keys disabled by one transaction. The database
// write happens inside the caller's transaction; Publish raises the mutation
// fence and drops the Redis copies once it has committed, so every instance
// stops serving the old state at once instead of after a cache TTL.
type KeyRevocation struct {
	TokenIDs []int
	keys     []string
}

// Count is the number of keys disabled.
func (r *KeyRevocation) Count() int {
	if r == nil {
		return 0
	}
	return len(r.TokenIDs)
}

// Publish invalidates the cached copies of the revoked keys. It is safe on a
// nil revocation and best effort by design: organization keys are checked
// against the primary database on every request (LoadOrgRequestState), so a
// failed cache purge cannot extend a revoked key's life, and the periodic
// sweeper repeats it.
func (r *KeyRevocation) Publish() {
	if r == nil {
		return
	}
	for _, key := range r.keys {
		if err := invalidateTokenCacheForMutation(key); err != nil {
			common.SysLog(common.LogText("failed to purge revoked key cache: %s", err.Error()))
		}
	}
}

// OrgKeyScope selects organization keys to disable. OrgID is required. A zero
// WorkspaceID spans every workspace. OwnerType and ActorUserID narrow to one
// kind of key or one member's keys; ExceptWorkspaceIDs keeps keys in the
// listed workspaces.
type OrgKeyScope struct {
	OrgID              int
	WorkspaceID        int
	OwnerType          string
	ActorUserID        int
	ExceptWorkspaceIDs []int
	ExceptTokenIDs     []int
}

// DisableOrgKeysTx disables every matching key that is not disabled yet. The
// fence is raised before the write so a concurrent reader cannot re-publish
// the old enabled state, and again from Publish after commit.
func DisableOrgKeysTx(tx *gorm.DB, scope OrgKeyScope) (*KeyRevocation, error) {
	if scope.OrgID <= 0 {
		return nil, types.NewOrgAccessError(types.OrgErrInvalidInput)
	}
	query := tx.Model(&Token{}).Where("org_id = ? AND status <> ?", scope.OrgID, common.TokenStatusDisabled)
	if scope.WorkspaceID > 0 {
		query = query.Where("workspace_id = ?", scope.WorkspaceID)
	}
	if scope.OwnerType != "" {
		query = query.Where("owner_type = ?", scope.OwnerType)
	}
	if scope.ActorUserID > 0 {
		query = query.Where("created_by = ?", scope.ActorUserID)
	}
	if len(scope.ExceptWorkspaceIDs) > 0 {
		query = query.Where("workspace_id NOT IN ?", scope.ExceptWorkspaceIDs)
	}
	if len(scope.ExceptTokenIDs) > 0 {
		query = query.Where("id NOT IN ?", scope.ExceptTokenIDs)
	}
	return disableTokensTx(tx, query)
}

// DisableUserOrgKeysEverywhereTx disables the member keys one person holds in
// every organization and every personal management credential they created.
// Global account disable and deletion call it, so a person cannot keep
// spending an organization's wallet after their account is shut off.
func DisableUserOrgKeysEverywhereTx(tx *gorm.DB, userID int) (*KeyRevocation, error) {
	if userID <= 0 {
		return nil, types.NewOrgAccessError(types.OrgErrInvalidInput)
	}
	query := tx.Model(&Token{}).Where("org_id > 0 AND owner_type = ? AND created_by = ? AND status <> ?",
		types.TokenOwnerMember, userID, common.TokenStatusDisabled)
	revocation, err := disableTokensTx(tx, query)
	if err != nil {
		return nil, err
	}
	return revocation, DisableManagementTokensTx(tx, 0, userID)
}

// DisableManagementTokensTx disables the personal management credentials a
// person created, in one organization (orgID > 0) or in all of them.
func DisableManagementTokensTx(tx *gorm.DB, orgID, userID int) error {
	query := tx.Model(&OrgAccessToken{}).Where("created_by = ? AND kind = ? AND status = ?",
		userID, types.OrgAccessTokenPersonalManagement, 1)
	if orgID > 0 {
		query = query.Where("org_id = ?", orgID)
	}
	return query.Updates(map[string]any{"status": 2, "updated_at": common.GetTimestamp()}).Error
}

func disableTokensTx(tx *gorm.DB, selector *gorm.DB) (*KeyRevocation, error) {
	var rows []Token
	if err := selector.Session(&gorm.Session{}).Find(&rows).Error; err != nil {
		return nil, err
	}
	revocation := &KeyRevocation{}
	if len(rows) == 0 {
		return revocation, nil
	}
	for _, row := range rows {
		revocation.TokenIDs = append(revocation.TokenIDs, row.Id)
		revocation.keys = append(revocation.keys, row.Key)
		// Best effort: a revoked key is refused by the primary-database check on
		// every request, so an unreachable Redis must not block the revocation.
		if err := invalidateTokenCacheForMutation(row.Key); err != nil {
			common.SysLog(common.LogText("failed to fence revoked key cache: %s", err.Error()))
		}
	}
	if err := tx.Model(&Token{}).Where("id IN ?", revocation.TokenIDs).Update("status", common.TokenStatusDisabled).Error; err != nil {
		return nil, err
	}
	return revocation, nil
}
