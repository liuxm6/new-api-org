package org

import (
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// ReconcileMemberKeysTx disables every member key of one person in one
// organization that their current standing no longer justifies. It is the
// single rule behind removal, suspension, demotion and grant changes:
//
//   - no live membership: every key and personal management credential goes;
//   - owner or admin: implicit admin everywhere, all member keys stay;
//   - any other role: keys stay only in workspaces where the projected
//     workspace role is admin or member (auditors are read-only and may not
//     spend), and personal management credentials go because they require
//     owner or admin.
//
// A disabled key is never re-enabled here: reactivation or re-granting does
// not revive old keys, a new key must be created. The caller publishes the
// returned revocation after commit.
func ReconcileMemberKeysTx(tx *gorm.DB, orgID, userID int, reason string) (*model.KeyRevocation, error) {
	member, err := model.GetOrganizationMember(tx, orgID, userID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	scope := model.OrgKeyScope{OrgID: orgID, OwnerType: types.TokenOwnerMember, ActorUserID: userID}
	live := err == nil && member.Status == types.OrgMemberStatusActive
	switch {
	case !live:
		// everything of this person in this organization
	case model.OrgRoleAtLeast(member.Role, types.OrgRoleAdmin):
		return &model.KeyRevocation{}, nil
	default:
		var spendable []int
		if err := tx.Model(&model.WorkspaceMember{}).
			Where("org_id = ? AND user_id = ? AND status = ? AND role IN ?", orgID, userID,
				model.WorkspaceMemberStatusActive, []string{types.WorkspaceRoleAdmin, types.WorkspaceRoleMember}).
			Pluck("workspace_id", &spendable).Error; err != nil {
			return nil, err
		}
		scope.ExceptWorkspaceIDs = spendable
	}
	revocation, err := model.DisableOrgKeysTx(tx, scope)
	if err != nil {
		return nil, err
	}
	if !live || !model.OrgRoleAtLeast(member.Role, types.OrgRoleAdmin) {
		if err := model.DisableManagementTokensTx(tx, orgID, userID); err != nil {
			return nil, err
		}
	}
	if revocation.Count() > 0 {
		err = model.RecordOrgAuditTx(tx, model.OrgAuditEntry{OrgId: orgID, ActorKind: "system", Action: "key.revoked",
			TargetType: "member", TargetId: itoa(userID),
			Detail: map[string]any{"reason": reason, "count": revocation.Count(), "at": common.GetTimestamp()}})
	}
	return revocation, err
}
