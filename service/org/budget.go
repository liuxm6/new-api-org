package org

import (
	"context"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// BudgetTarget names whose budget a request reads or writes. WorkspaceID is set
// for workspace and key budgets, UserID for member budgets, TokenID for keys.
type BudgetTarget struct {
	OrgID       int
	WorkspaceID int
	Scope       string
	SubjectID   int
}

// authorizeBudgetTx proves the actor may read or write the budget of a target,
// inside the transaction, and says whether the write may only tighten.
//
//   - org and member budgets: organization owners and admins write; billing
//     members read; a member reads their own.
//   - workspace budgets: workspace admins (owners and admins implicitly).
//   - key budgets: workspace admins write; the key's own creator may only
//     tighten, never loosen or switch a period off.
//
// A workspace admin therefore can never change an organization member's budget.
func authorizeBudgetTx(tx *gorm.DB, target BudgetTarget, actorID int, write bool) (tightenOnly bool, err error) {
	switch target.Scope {
	case types.BudgetScopeOrg, types.BudgetScopeMember:
		roles := []string{types.OrgRoleOwner, types.OrgRoleAdmin}
		if !write {
			roles = append(roles, types.OrgRoleBilling)
		}
		_, member, err := RequireOrgRoleTx(tx, target.OrgID, actorID)
		if err != nil {
			return false, err
		}
		if roleAllowed(member.Role, roles) {
			return false, nil
		}
		if !write && target.Scope == types.BudgetScopeMember && target.SubjectID == actorID {
			return false, nil // a member reads their own
		}
		return false, refuse(types.OrgErrForbidden)
	case types.BudgetScopeWorkspace:
		roles := []string{types.WorkspaceRoleAdmin}
		if !write {
			roles = append(roles, types.WorkspaceRoleAuditor)
		}
		_, _, err := RequireWorkspaceRoleTx(tx, target.OrgID, target.SubjectID, actorID, false, roles...)
		return false, err
	case types.BudgetScopeKey:
		_, role, err := RequireWorkspaceRoleTx(tx, target.OrgID, target.WorkspaceID, actorID, false)
		if err != nil {
			return false, err
		}
		if role == types.WorkspaceRoleAdmin || (!write && role == types.WorkspaceRoleAuditor) {
			return false, nil
		}
		key, err := keyInWorkspaceTx(tx, target.OrgID, target.WorkspaceID, target.SubjectID)
		if err != nil {
			return false, err
		}
		if key.OwnerType == types.TokenOwnerMember && key.CreatedBy == actorID {
			return write, nil // the creator reads, and may only tighten
		}
		return false, refuse(types.OrgErrForbidden)
	}
	return false, refuse(types.OrgErrInvalidInput)
}

func keyInWorkspaceTx(tx *gorm.DB, orgID, workspaceID, tokenID int) (*model.Token, error) {
	var keys []model.Token
	if err := tx.Where("id = ? AND org_id = ? AND workspace_id = ?", tokenID, orgID, workspaceID).Limit(1).Find(&keys).Error; err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, refuse(types.OrgErrKeyNotFound)
	}
	return &keys[0], nil
}

// subjectExistsTx checks that the subject belongs to the organization, so a
// budget can never be attached to another tenant's member, workspace or key.
func subjectExistsTx(tx *gorm.DB, target BudgetTarget) error {
	var count int64
	var err error
	switch target.Scope {
	case types.BudgetScopeOrg:
		if target.SubjectID != target.OrgID {
			return refuse(types.OrgErrNotFound)
		}
		return nil
	case types.BudgetScopeMember:
		err = tx.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ? AND status = ?",
			target.OrgID, target.SubjectID, types.OrgMemberStatusActive).Count(&count).Error
		if err == nil && count == 0 {
			return refuse(types.OrgErrMemberNotFound)
		}
	case types.BudgetScopeWorkspace:
		err = tx.Model(&model.Workspace{}).Where("id = ? AND org_id = ?", target.SubjectID, target.OrgID).Count(&count).Error
		if err == nil && count == 0 {
			return refuse(types.OrgErrWorkspaceNotFound)
		}
	}
	return err
}

// GetBudgets reads a subject's whole budget set after proving the actor may.
func GetBudgets(ctx context.Context, actorID int, target BudgetTarget) (model.OrgBudgetSet, error) {
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := authorizeBudgetTx(tx, target, actorID, false); err != nil {
			return err
		}
		return subjectExistsTx(tx, target)
	})
	if err != nil {
		return model.OrgBudgetSet{}, err
	}
	return model.GetOrgBudgetSet(ctx, target.OrgID, target.Scope, target.SubjectID)
}

// PutBudgets replaces a subject's whole budget set. Authorization is proved in
// its own transaction first and the write re-proves nothing it does not need:
// the replacement itself runs with the subject locked, and the organization's
// policy version moves with every period it changes.
func PutBudgets(ctx context.Context, actorID int, target BudgetTarget, periods []model.OrgBudgetPeriodInput,
	expectedVersion int64) (model.OrgBudgetSet, error) {
	var tighten bool
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		if tighten, err = authorizeBudgetTx(tx, target, actorID, true); err != nil {
			return err
		}
		return subjectExistsTx(tx, target)
	})
	if err != nil {
		return model.OrgBudgetSet{}, err
	}
	set, err := model.ReplaceOrgBudgetSet(ctx, target.OrgID, target.Scope, target.SubjectID, periods, expectedVersion, tighten)
	if err != nil {
		return set, err
	}
	err = model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: target.OrgID, WorkspaceId: target.WorkspaceID, ActorUserId: actorID,
			Action: "budget.update", TargetType: target.Scope, TargetId: itoa(target.SubjectID),
			Detail: map[string]any{"periods": len(periods), "tighten_only": tighten}})
	})
	return set, err
}
