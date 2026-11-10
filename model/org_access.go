package model

import (
	"errors"
	"strconv"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// Organization and workspace references in URLs are either a numeric id or a
// slug. Slugs may never be all digits (see service/org slug rules), so the two
// forms cannot collide.

// GetOrganizationByRef resolves an id or slug. Soft-deleted organizations are
// not returned; a missing row is gorm.ErrRecordNotFound.
func GetOrganizationByRef(db *gorm.DB, ref string) (*Organization, error) {
	var org Organization
	query := db.Where("slug = ?", ref)
	if id, err := strconv.Atoi(ref); err == nil {
		query = db.Where("id = ?", id)
	}
	result := query.Limit(1).Find(&org)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &org, nil
}

// GetWorkspaceByRef resolves a workspace inside one organization. A workspace
// of another organization is indistinguishable from a missing one.
func GetWorkspaceByRef(db *gorm.DB, orgID int, ref string) (*Workspace, error) {
	var workspace Workspace
	query := db.Where("org_id = ? AND slug = ?", orgID, ref)
	if id, err := strconv.Atoi(ref); err == nil {
		query = db.Where("org_id = ? AND id = ?", orgID, id)
	}
	result := query.Limit(1).Find(&workspace)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &workspace, nil
}

// GetOrganizationMember returns the membership row in any status.
func GetOrganizationMember(db *gorm.DB, orgID, userID int) (*OrganizationMember, error) {
	var member OrganizationMember
	// Find, not Take: a stranger probing an organization is routine and must not
	// write a "record not found" line to the database log each time.
	result := db.Where("org_id = ? AND user_id = ?", orgID, userID).Limit(1).Find(&member)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &member, nil
}

// GetWorkspaceMember returns the projected workspace role row in any status.
func GetWorkspaceMember(db *gorm.DB, workspaceID, userID int) (*WorkspaceMember, error) {
	var member WorkspaceMember
	result := db.Where("workspace_id = ? AND user_id = ?", workspaceID, userID).Limit(1).Find(&member)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &member, nil
}

// LockOrganizationTx takes the organization row lock. It is the first lock of
// every organization-scoped write so seat counts, ownership and policy version
// changes are serialized per organization.
func LockOrganizationTx(tx *gorm.DB, orgID int) (*Organization, error) {
	var org Organization
	if err := lockForUpdate(tx).Where("id = ?", orgID).Take(&org).Error; err != nil {
		return nil, err
	}
	return &org, nil
}

// LockOrganizationMemberTx re-reads a membership under a row lock so a write
// never trusts a role that came from a cache.
func LockOrganizationMemberTx(tx *gorm.DB, orgID, userID int) (*OrganizationMember, error) {
	var member OrganizationMember
	if err := lockForUpdate(tx).Where("org_id = ? AND user_id = ?", orgID, userID).Take(&member).Error; err != nil {
		return nil, err
	}
	return &member, nil
}

// BumpOrgPolicyVersionTx advances the organization's policy_version. Every
// write to a role, a membership or workspace status, a grant or a policy goes
// through it in the same transaction, so cached authorization keyed by the old
// version can never be read again.
func BumpOrgPolicyVersionTx(tx *gorm.DB, orgID int) error {
	result := tx.Model(&Organization{}).Where("id = ?", orgID).
		Updates(map[string]any{"policy_version": gorm.Expr("policy_version + 1"), "updated_at": common.GetTimestamp()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// SetOrganizationMemberRoleTx changes a role and bumps policy_version.
func SetOrganizationMemberRoleTx(tx *gorm.DB, orgID, userID int, role string) error {
	result := tx.Model(&OrganizationMember{}).Where("org_id = ? AND user_id = ?", orgID, userID).
		Updates(map[string]any{"role": role, "updated_at": common.GetTimestamp()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return BumpOrgPolicyVersionTx(tx, orgID)
}

// SetOrganizationMemberStatusTx changes a membership status and bumps
// policy_version.
func SetOrganizationMemberStatusTx(tx *gorm.DB, orgID, userID, status int) error {
	result := tx.Model(&OrganizationMember{}).Where("org_id = ? AND user_id = ?", orgID, userID).
		Updates(map[string]any{"status": status, "updated_at": common.GetTimestamp()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return BumpOrgPolicyVersionTx(tx, orgID)
}

// SetOrganizationStatusTx changes the organization status and bumps
// policy_version.
func SetOrganizationStatusTx(tx *gorm.DB, orgID, status int) error {
	if err := tx.Model(&Organization{}).Where("id = ?", orgID).
		Updates(map[string]any{"status": status, "updated_at": common.GetTimestamp()}).Error; err != nil {
		return err
	}
	return BumpOrgPolicyVersionTx(tx, orgID)
}

// SetWorkspaceStatusTx changes the workspace status and bumps the parent
// organization's policy_version.
func SetWorkspaceStatusTx(tx *gorm.DB, orgID, workspaceID, status int) error {
	result := tx.Model(&Workspace{}).Where("id = ? AND org_id = ?", workspaceID, orgID).
		Updates(map[string]any{"status": status, "updated_at": common.GetTimestamp()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return BumpOrgPolicyVersionTx(tx, orgID)
}

// IsOrgNotFound reports whether err means the row does not exist.
func IsOrgNotFound(err error) bool { return errors.Is(err, gorm.ErrRecordNotFound) }

// OrgRoleAtLeast ranks organization roles for comparisons that are linear. The
// billing role is deliberately outside the ladder: it grants financial access
// only and is compared by exact match.
func OrgRoleAtLeast(role, floor string) bool {
	rank := map[string]int{types.OrgRoleMember: 1, types.OrgRoleAdmin: 2, types.OrgRoleOwner: 3}
	return rank[role] >= rank[floor] && rank[role] > 0
}
