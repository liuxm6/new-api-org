package model

import (
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// ErrOrgOwnerMustTransfer blocks deleting an account that still owns an
// organization. Ownership is handed over (or the owner demoted) first, so an
// organization is never left without anyone who can govern it.
var ErrOrgOwnerMustTransfer = common.NewMessage("Transfer ownership of your organizations before deleting this account")

// RevokeUserOrgAccessTx is called from the account disable, delete and hard
// delete paths, in the same transaction. Disabling revokes what the person can
// spend or manage in every organization (member keys, personal management
// credentials) and leaves the memberships in place, so enabling the account
// again restores the membership but never the keys. With leaving = true (the
// account is being deleted) it also ends every membership, drops all
// workspace grants and frees the seats, after refusing when the person is the
// primary or the last active owner of a live organization.
//
// The caller publishes the cache purge after commit with
// PurgeUserOrgKeyCaches.
func RevokeUserOrgAccessTx(tx *gorm.DB, userID int, leaving bool) error {
	if userID <= 0 {
		return nil
	}
	if _, err := DisableUserOrgKeysEverywhereTx(tx, userID); err != nil {
		return err
	}
	if !leaving {
		return nil
	}
	var memberships []OrganizationMember
	if err := tx.Where("user_id = ? AND status <> ?", userID, types.OrgMemberStatusRemoved).Find(&memberships).Error; err != nil {
		return err
	}
	for _, member := range memberships {
		var orgs []Organization
		if err := tx.Where("id = ?", member.OrgId).Limit(1).Find(&orgs).Error; err != nil {
			return err
		}
		if len(orgs) == 0 {
			continue
		}
		if member.Role == types.OrgRoleOwner && member.Status == types.OrgMemberStatusActive {
			var otherOwners int64
			if err := tx.Model(&OrganizationMember{}).Where("org_id = ? AND role = ? AND status = ? AND user_id <> ?",
				member.OrgId, types.OrgRoleOwner, types.OrgMemberStatusActive, userID).Count(&otherOwners).Error; err != nil {
				return err
			}
			if orgs[0].OwnerUserId == userID || otherOwners == 0 {
				return ErrOrgOwnerMustTransfer
			}
		}
		if err := SetOrganizationMemberStatusTx(tx, member.OrgId, userID, types.OrgMemberStatusRemoved); err != nil {
			return err
		}
		if err := DeleteAllWorkspaceGrantsOfUserTx(tx, member.OrgId, userID); err != nil {
			return err
		}
		if err := RecordOrgAuditTx(tx, OrgAuditEntry{OrgId: member.OrgId, ActorKind: "system", Action: "member.account_removed",
			TargetType: "member", TargetId: strconv.Itoa(userID)}); err != nil {
			return err
		}
	}
	return nil
}

// PurgeUserOrgKeyCaches drops the Redis copies of every organization key the
// person created, after the revoking transaction committed. Organization keys
// are checked against the primary database on each request, so this narrows
// the window for the plain token cache rather than being the revocation.
func PurgeUserOrgKeyCaches(userID int) {
	if !common.RedisEnabled || userID <= 0 {
		return
	}
	var tokens []Token
	if err := DB.Unscoped().Select("id", commonKeyCol).Where("org_id > 0 AND created_by = ?", userID).Find(&tokens).Error; err != nil {
		common.SysLog(common.LogText("failed to list organization keys for cache purge: %s", err.Error()))
		return
	}
	if err := invalidateTokensCache(tokens); err != nil {
		common.SysLog(common.LogText("failed to purge organization key cache: %s", err.Error()))
	}
}
