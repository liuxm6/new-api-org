package model

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// LockOrgKeyTx reads one organization key under a row lock, scoped to its
// organization and workspace so an id from anywhere else is "not found". With
// ownerID > 0 it also requires the key to be that member's own. Soft-deleted
// keys are not returned.
func LockOrgKeyTx(tx *gorm.DB, orgID, workspaceID, keyID, ownerID int) (*Token, error) {
	query := lockForUpdate(tx).Where("id = ? AND org_id = ? AND workspace_id = ?", keyID, orgID, workspaceID)
	if ownerID > 0 {
		query = query.Where("owner_type = ? AND created_by = ?", types.TokenOwnerMember, ownerID)
	}
	var tokens []Token
	if err := query.Limit(1).Find(&tokens).Error; err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &tokens[0], nil
}

// CountWorkspaceKeysTx counts a workspace's live (not deleted) keys, whatever
// their status, so the per-workspace limit cannot be dodged by disabling keys.
func CountWorkspaceKeysTx(tx *gorm.DB, orgID, workspaceID int) (int64, error) {
	var n int64
	err := tx.Model(&Token{}).Where("org_id = ? AND workspace_id = ?", orgID, workspaceID).Count(&n).Error
	return n, err
}

// FenceOrgKeysTx raises the token-cache mutation fence for the given keys
// before the transaction writes them, and returns the handle whose Publish
// repeats the purge after commit. A key write without it could let a reader
// re-publish the old state to Redis.
func FenceOrgKeysTx(keys ...Token) (*KeyRevocation, error) {
	revocation := &KeyRevocation{}
	for _, key := range keys {
		revocation.TokenIDs = append(revocation.TokenIDs, key.Id)
		revocation.keys = append(revocation.keys, key.Key)
		if err := invalidateTokenCacheForMutation(key.Key); err != nil {
			return nil, err
		}
	}
	return revocation, nil
}

// DisableOrgKeysByIDTx disables exactly the listed keys of one organization.
func DisableOrgKeysByIDTx(tx *gorm.DB, orgID int, keyIDs []int) (*KeyRevocation, error) {
	if orgID <= 0 || len(keyIDs) == 0 {
		return &KeyRevocation{}, nil
	}
	return disableTokensTx(tx, tx.Model(&Token{}).Where("org_id = ? AND id IN ? AND status <> ?", orgID, keyIDs, common.TokenStatusDisabled))
}
