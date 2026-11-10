package org

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// SCIM groups never create authority on their own. A group is a row in
// scim_group_mappings; it grants a workspace role only when an administrator
// mapped it to a workspace (workspace_id > 0). Its members get one grant each
// of source "scim" and source_ref = the group name, so revoking a group
// leaves manual grants and other groups' grants in force. The organization
// role is never touched: there is no path from a group to owner or admin.

// ScimGroupView is one group as SCIM shows it.
type ScimGroupView struct {
	ID          int
	DisplayName string
	// Members are the identity ids that hold this group's grant.
	Members []int
}

// MappingView is the administrators' view of a group mapping.
type MappingView struct {
	Id          int    `json:"id"`
	IdpGroup    string `json:"idp_group"`
	WorkspaceId int    `json:"workspace_id"`
	WsRole      string `json:"ws_role"`
}

func validMappingRole(role string) bool { return model.ValidWorkspaceRole(role) }

func groupMembersTx(tx *gorm.DB, mapping model.ScimGroupMapping) ([]int, error) {
	if mapping.WorkspaceId == 0 {
		return []int{}, nil
	}
	var userIDs []int
	if err := tx.Model(&model.WorkspaceMemberGrant{}).
		Where("org_id = ? AND workspace_id = ? AND source = ? AND source_ref = ?", mapping.OrgId, mapping.WorkspaceId, model.GrantSourceSCIM, mapping.IdpGroup).
		Pluck("user_id", &userIDs).Error; err != nil {
		return nil, err
	}
	members := []int{}
	if len(userIDs) == 0 {
		return members, nil
	}
	if err := tx.Model(&model.OrgIdentity{}).Where("org_id = ? AND user_id IN ? AND status = ?", mapping.OrgId, userIDs, types.OrgIdentityActive).
		Order("id").Pluck("id", &members).Error; err != nil {
		return nil, err
	}
	return members, nil
}

func groupViewTx(tx *gorm.DB, mapping model.ScimGroupMapping) (ScimGroupView, error) {
	members, err := groupMembersTx(tx, mapping)
	return ScimGroupView{ID: mapping.Id, DisplayName: mapping.IdpGroup, Members: members}, err
}

func mappingByIDTx(tx *gorm.DB, orgID, id int) (*model.ScimGroupMapping, error) {
	var rows []model.ScimGroupMapping
	if err := lockedMapping(tx).Where("org_id = ? AND id = ?", orgID, id).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, scimErr(http.StatusNotFound, "", "Group not found")
	}
	return &rows[0], nil
}

// lockedMapping reads mapping rows inside a transaction that already holds the
// organization row lock, which is what serializes mapping and grant changes.
func lockedMapping(tx *gorm.DB) *gorm.DB { return tx.Model(&model.ScimGroupMapping{}) }

// grantMemberTx gives one identity's person the mapping's grant, when that
// person is an active member. Others are skipped: a grant cannot outlive or
// precede membership.
func grantMemberTx(tx *gorm.DB, mapping model.ScimGroupMapping, identityID int, revocations *[]*model.KeyRevocation) error {
	identity, err := model.GetOrgIdentityByID(tx, mapping.OrgId, identityID)
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && identity.Status == types.OrgIdentityRemoved) {
		return scimErr(http.StatusBadRequest, "invalidValue", "Unknown group member")
	}
	if err != nil {
		return err
	}
	if mapping.WorkspaceId == 0 || identity.Status != types.OrgIdentityActive {
		return nil
	}
	member, err := model.GetOrganizationMember(tx, mapping.OrgId, identity.UserId)
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && member.Status != types.OrgMemberStatusActive) {
		return nil
	}
	if err != nil {
		return err
	}
	revocation, err := ApplyGrantTx(tx, mapping.OrgId, mapping.WorkspaceId, identity.UserId, model.GrantSourceSCIM, mapping.IdpGroup, mapping.WsRole, 0)
	*revocations = append(*revocations, revocation)
	return err
}

func revokeMemberTx(tx *gorm.DB, mapping model.ScimGroupMapping, userID int, revocations *[]*model.KeyRevocation) error {
	if mapping.WorkspaceId == 0 {
		return nil
	}
	revocation, err := RevokeGrantTx(tx, mapping.OrgId, mapping.WorkspaceId, userID, model.GrantSourceSCIM, mapping.IdpGroup, 0)
	*revocations = append(*revocations, revocation)
	return err
}

func publishAll(revocations []*model.KeyRevocation) {
	for _, revocation := range revocations {
		revocation.Publish()
	}
}

// setGroupMembersTx makes the group's members exactly the given identities.
func setGroupMembersTx(tx *gorm.DB, mapping model.ScimGroupMapping, identityIDs []int, revocations *[]*model.KeyRevocation) error {
	current, err := groupMembersTx(tx, mapping)
	if err != nil {
		return err
	}
	for _, id := range identityIDs {
		if err := grantMemberTx(tx, mapping, id, revocations); err != nil {
			return err
		}
	}
	for _, id := range current {
		if slices.Contains(identityIDs, id) {
			continue
		}
		identity, err := model.GetOrgIdentityByID(tx, mapping.OrgId, id)
		if err != nil {
			return err
		}
		if err := revokeMemberTx(tx, mapping, identity.UserId, revocations); err != nil {
			return err
		}
	}
	return nil
}

// CreateScimGroup registers a group. An unmapped group is a registry row only
// and grants nothing, whatever members the IdP sends.
func CreateScimGroup(ctx context.Context, orgID int, displayName string, members []int) (ScimGroupView, error) {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || len(displayName) > 191 || !validScimText(displayName, 191) {
		return ScimGroupView{}, scimErr(http.StatusBadRequest, "invalidValue", "displayName is required")
	}
	var view ScimGroupView
	var revocations []*model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := scimOrgTx(tx, orgID); err != nil {
			return err
		}
		var existing int64
		if err := tx.Model(&model.ScimGroupMapping{}).Where("org_id = ? AND idp_group = ?", orgID, displayName).Count(&existing).Error; err != nil {
			return err
		}
		if existing > 0 {
			return scimErr(http.StatusConflict, "uniqueness", "A group with this displayName already exists")
		}
		now := common.GetTimestamp()
		mapping := model.ScimGroupMapping{OrgId: orgID, IdpGroup: displayName, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&mapping).Error; err != nil {
			return err
		}
		if err := setGroupMembersTx(tx, mapping, members, &revocations); err != nil {
			return err
		}
		var err error
		view, err = groupViewTx(tx, mapping)
		if err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorKind: "scim", Action: "scim.group_create",
			TargetType: "group", TargetId: strconv.Itoa(mapping.Id)})
	})
	if err != nil {
		return ScimGroupView{}, err
	}
	publishAll(revocations)
	return view, nil
}

// GetScimGroup returns one group of this organization.
func GetScimGroup(ctx context.Context, orgID, id int) (ScimGroupView, error) {
	db := model.DB.WithContext(ctx)
	var rows []model.ScimGroupMapping
	if err := db.Where("org_id = ? AND id = ?", orgID, id).Limit(1).Find(&rows).Error; err != nil {
		return ScimGroupView{}, err
	}
	if len(rows) == 0 {
		return ScimGroupView{}, scimErr(http.StatusNotFound, "", "Group not found")
	}
	return groupViewTx(db, rows[0])
}

// ListScimGroups pages through the groups, optionally filtered by displayName.
func ListScimGroups(ctx context.Context, orgID int, filter string, startIndex, count int) ([]ScimGroupView, int, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	count = min(max(count, 0), ScimPageMax)
	db := model.DB.WithContext(ctx)
	query := db.Model(&model.ScimGroupMapping{}).Where("org_id = ?", orgID)
	if strings.TrimSpace(filter) != "" {
		match := regexpDisplayName.FindStringSubmatch(filter)
		if match == nil {
			return nil, 0, scimErr(http.StatusBadRequest, "invalidFilter", "Only displayName eq filters are supported")
		}
		query = query.Where("idp_group = ?", match[1])
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []model.ScimGroupMapping
	if count > 0 {
		if err := query.Order("id").Offset(startIndex - 1).Limit(count).Find(&rows).Error; err != nil {
			return nil, 0, err
		}
	}
	views := make([]ScimGroupView, 0, len(rows))
	for _, row := range rows {
		view, err := groupViewTx(db, row)
		if err != nil {
			return nil, 0, err
		}
		views = append(views, view)
	}
	return views, int(total), nil
}

// ScimGroupChange is one normalized member operation of a group PATCH.
type ScimGroupChange struct {
	Op      string // add, remove, replace
	Members []int
}

// PatchScimGroup applies member operations.
func PatchScimGroup(ctx context.Context, orgID, id int, changes []ScimGroupChange) (ScimGroupView, error) {
	return updateGroup(ctx, orgID, id, func(tx *gorm.DB, mapping model.ScimGroupMapping, revocations *[]*model.KeyRevocation) error {
		for _, change := range changes {
			switch change.Op {
			case "add":
				for _, member := range change.Members {
					if err := grantMemberTx(tx, mapping, member, revocations); err != nil {
						return err
					}
				}
			case "remove":
				for _, member := range change.Members {
					identity, err := model.GetOrgIdentityByID(tx, orgID, member)
					if errors.Is(err, gorm.ErrRecordNotFound) {
						continue
					}
					if err != nil {
						return err
					}
					if err := revokeMemberTx(tx, mapping, identity.UserId, revocations); err != nil {
						return err
					}
				}
			case "replace":
				if err := setGroupMembersTx(tx, mapping, change.Members, revocations); err != nil {
					return err
				}
			default:
				return scimErr(http.StatusBadRequest, "invalidValue", "Unsupported group operation")
			}
		}
		return nil
	})
}

// ReplaceScimGroupMembers is PUT: the member list becomes exactly the given one.
func ReplaceScimGroupMembers(ctx context.Context, orgID, id int, members []int) (ScimGroupView, error) {
	return PatchScimGroup(ctx, orgID, id, []ScimGroupChange{{Op: "replace", Members: members}})
}

func updateGroup(ctx context.Context, orgID, id int,
	apply func(*gorm.DB, model.ScimGroupMapping, *[]*model.KeyRevocation) error) (ScimGroupView, error) {
	var view ScimGroupView
	var revocations []*model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := scimOrgTx(tx, orgID); err != nil {
			return err
		}
		mapping, err := mappingByIDTx(tx, orgID, id)
		if err != nil {
			return err
		}
		if err := apply(tx, *mapping, &revocations); err != nil {
			return err
		}
		if view, err = groupViewTx(tx, *mapping); err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorKind: "scim", Action: "scim.group_update",
			TargetType: "group", TargetId: strconv.Itoa(mapping.Id)})
	})
	if err != nil {
		return ScimGroupView{}, err
	}
	publishAll(revocations)
	return view, nil
}

// revokeWholeGroupTx removes every grant the mapping's group has handed out.
func revokeWholeGroupTx(tx *gorm.DB, mapping model.ScimGroupMapping, revocations *[]*model.KeyRevocation) error {
	if mapping.WorkspaceId == 0 {
		return nil
	}
	var userIDs []int
	if err := tx.Model(&model.WorkspaceMemberGrant{}).
		Where("org_id = ? AND workspace_id = ? AND source = ? AND source_ref = ?", mapping.OrgId, mapping.WorkspaceId, model.GrantSourceSCIM, mapping.IdpGroup).
		Pluck("user_id", &userIDs).Error; err != nil {
		return err
	}
	for _, userID := range userIDs {
		if err := revokeMemberTx(tx, mapping, userID, revocations); err != nil {
			return err
		}
	}
	return nil
}

// DeleteScimGroup removes the group and every SCIM grant it handed out. Manual
// grants and other groups' grants stay.
func DeleteScimGroup(ctx context.Context, orgID, id int) error {
	var revocations []*model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := scimOrgTx(tx, orgID); err != nil {
			return err
		}
		mapping, err := mappingByIDTx(tx, orgID, id)
		if err != nil {
			return err
		}
		if err := revokeWholeGroupTx(tx, *mapping, &revocations); err != nil {
			return err
		}
		if err := tx.Delete(&model.ScimGroupMapping{}, mapping.Id).Error; err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorKind: "scim", Action: "scim.group_delete",
			TargetType: "group", TargetId: strconv.Itoa(mapping.Id)})
	})
	if err != nil {
		return err
	}
	publishAll(revocations)
	return nil
}

// ---- administrators' mapping API ----

func mappingView(row model.ScimGroupMapping) MappingView {
	return MappingView{Id: row.Id, IdpGroup: row.IdpGroup, WorkspaceId: row.WorkspaceId, WsRole: row.WsRole}
}

// ListMappings returns the organization's group mappings.
func ListMappings(ctx context.Context, orgID int) ([]MappingView, error) {
	var rows []model.ScimGroupMapping
	if err := model.DB.WithContext(ctx).Where("org_id = ?", orgID).Order("id").Limit(1000).Find(&rows).Error; err != nil {
		return nil, err
	}
	views := make([]MappingView, 0, len(rows))
	for _, row := range rows {
		views = append(views, mappingView(row))
	}
	return views, nil
}

func requireMappingTarget(tx *gorm.DB, orgID, workspaceID int, role string) error {
	if !validMappingRole(role) {
		// Organization roles (owner, admin, billing, member) are not workspace
		// roles; a mapping can never reach them.
		return refuse(types.OrgErrInvalidInput)
	}
	var count int64
	if err := tx.Model(&model.Workspace{}).Where("id = ? AND org_id = ? AND status = ?", workspaceID, orgID, types.WorkspaceStatusActive).
		Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return refuse(types.OrgErrWorkspaceNotFound)
	}
	return nil
}

// regroupTx moves every member of the group from the old target to the new one.
func regroupTx(tx *gorm.DB, old, updated model.ScimGroupMapping, revocations *[]*model.KeyRevocation) error {
	if old.WorkspaceId == 0 {
		return nil
	}
	var userIDs []int
	if err := tx.Model(&model.WorkspaceMemberGrant{}).
		Where("org_id = ? AND workspace_id = ? AND source = ? AND source_ref = ?", old.OrgId, old.WorkspaceId, model.GrantSourceSCIM, old.IdpGroup).
		Pluck("user_id", &userIDs).Error; err != nil {
		return err
	}
	for _, userID := range userIDs {
		if err := revokeMemberTx(tx, old, userID, revocations); err != nil {
			return err
		}
		revocation, err := ApplyGrantTx(tx, updated.OrgId, updated.WorkspaceId, userID, model.GrantSourceSCIM, updated.IdpGroup, updated.WsRole, 0)
		*revocations = append(*revocations, revocation)
		if err != nil {
			return err
		}
	}
	return nil
}

// SaveMapping creates a mapping, or points a registered but ungranted group at
// a workspace role. An already-mapped group is changed with UpdateMapping.
func SaveMapping(ctx context.Context, actorID, orgID int, idpGroup string, workspaceID int, role string) (MappingView, error) {
	idpGroup = strings.TrimSpace(idpGroup)
	if idpGroup == "" || len(idpGroup) > 191 {
		return MappingView{}, refuse(types.OrgErrInvalidInput)
	}
	var view MappingView
	var revocations []*model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		if err := requireMappingTarget(tx, orgID, workspaceID, role); err != nil {
			return err
		}
		var rows []model.ScimGroupMapping
		if err := tx.Where("org_id = ? AND idp_group = ?", orgID, idpGroup).Limit(1).Find(&rows).Error; err != nil {
			return err
		}
		now := common.GetTimestamp()
		if len(rows) == 1 && rows[0].WorkspaceId != 0 {
			return refuse(types.OrgErrConflict)
		}
		if len(rows) == 0 {
			row := model.ScimGroupMapping{OrgId: orgID, IdpGroup: idpGroup, WorkspaceId: workspaceID, WsRole: role, CreatedAt: now, UpdatedAt: now}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
			view = mappingView(row)
		} else {
			if err := tx.Model(&model.ScimGroupMapping{}).Where("id = ?", rows[0].Id).
				Updates(map[string]any{"workspace_id": workspaceID, "ws_role": role, "updated_at": now}).Error; err != nil {
				return err
			}
			rows[0].WorkspaceId, rows[0].WsRole = workspaceID, role
			view = mappingView(rows[0])
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "scim.mapping_save",
			TargetType: "mapping", TargetId: strconv.Itoa(view.Id), Detail: map[string]any{"workspace_id": workspaceID, "ws_role": role}})
	})
	if err != nil {
		return MappingView{}, err
	}
	publishAll(revocations)
	return view, nil
}

// UpdateMapping retargets a mapping. Existing members are moved to the new
// workspace role in the same transaction, through grant changes only.
func UpdateMapping(ctx context.Context, actorID, orgID, id, workspaceID int, role string) (MappingView, error) {
	var view MappingView
	var revocations []*model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		if err := requireMappingTarget(tx, orgID, workspaceID, role); err != nil {
			return err
		}
		mapping, err := mappingByIDTx(tx, orgID, id)
		if err != nil {
			return refuse(types.OrgErrKeyNotFound)
		}
		updated := *mapping
		updated.WorkspaceId, updated.WsRole = workspaceID, role
		if err := tx.Model(&model.ScimGroupMapping{}).Where("id = ?", mapping.Id).
			Updates(map[string]any{"workspace_id": workspaceID, "ws_role": role, "updated_at": common.GetTimestamp()}).Error; err != nil {
			return err
		}
		if err := regroupTx(tx, *mapping, updated, &revocations); err != nil {
			return err
		}
		view = mappingView(updated)
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "scim.mapping_update",
			TargetType: "mapping", TargetId: strconv.Itoa(id), Detail: map[string]any{"workspace_id": workspaceID, "ws_role": role}})
	})
	if err != nil {
		return MappingView{}, err
	}
	publishAll(revocations)
	return view, nil
}

// DeleteMapping removes a mapping and every grant its group handed out.
func DeleteMapping(ctx context.Context, actorID, orgID, id int) error {
	var revocations []*model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		mapping, err := mappingByIDTx(tx, orgID, id)
		if err != nil {
			return refuse(types.OrgErrKeyNotFound)
		}
		if err := revokeWholeGroupTx(tx, *mapping, &revocations); err != nil {
			return err
		}
		if err := tx.Delete(&model.ScimGroupMapping{}, mapping.Id).Error; err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "scim.mapping_delete",
			TargetType: "mapping", TargetId: strconv.Itoa(id)})
	})
	if err != nil {
		return err
	}
	publishAll(revocations)
	return nil
}

var regexpDisplayName = regexp.MustCompile(`^\s*(?i:displayName)\s+(?i:eq)\s+"([^"\\]*)"\s*$`)
