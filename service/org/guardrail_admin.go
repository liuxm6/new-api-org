package org

import (
	"context"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

const maxGuardrailsPerOrg = 500

const (
	guardrailStatusActive   = 1
	guardrailStatusDisabled = 2
)

// GuardrailInput is what a client may choose when writing a guardrail. The
// scope (organization or one workspace) comes from the route, never the body.
type GuardrailInput struct {
	Name       string
	TargetType string
	TargetID   int
	// Config is the raw JSON object. It is validated by ParseGuardrailConfig and
	// stored as given, so an explicit empty allow list keeps meaning "deny all".
	Config   string
	Disabled bool
}

// GuardrailScope says where a guardrail is managed. WorkspaceID == 0 is the
// organization scope.
type GuardrailScope struct {
	OrgID       int
	WorkspaceID int
}

// authorizeGuardrailScopeTx proves the actor may manage guardrails in a scope:
// organization owners and admins for the organization scope, workspace admins
// (organization owners and admins count implicitly) for a workspace scope.
func authorizeGuardrailScopeTx(tx *gorm.DB, scope GuardrailScope, actorID int, write bool) error {
	if scope.WorkspaceID == 0 {
		_, _, err := RequireOrgRoleTx(tx, scope.OrgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin)
		return err
	}
	roles := []string{types.WorkspaceRoleAdmin}
	if !write {
		roles = append(roles, types.WorkspaceRoleAuditor)
	}
	_, _, err := RequireWorkspaceRoleTx(tx, scope.OrgID, scope.WorkspaceID, actorID, false, roles...)
	return err
}

// validateGuardrailInputTx checks the target type against the scope and, for
// member and key targets, that the target really belongs here.
func validateGuardrailInputTx(tx *gorm.DB, scope GuardrailScope, in *GuardrailInput) error {
	name, err := validateName(in.Name)
	if err != nil {
		return err
	}
	in.Name = name
	if _, err := ParseGuardrailConfig(in.Config); err != nil {
		return refuse(types.OrgErrInvalidInput)
	}
	switch in.TargetType {
	case types.GuardrailTargetOrgDefault:
		// Organization-wide default: organization scope only, no target.
		if scope.WorkspaceID != 0 || in.TargetID != 0 {
			return refuse(types.OrgErrInvalidInput)
		}
	case types.GuardrailTargetWorkspaceDefault:
		if scope.WorkspaceID == 0 || in.TargetID != 0 {
			return refuse(types.OrgErrInvalidInput)
		}
	case types.GuardrailTargetMember:
		if in.TargetID <= 0 {
			return refuse(types.OrgErrInvalidInput)
		}
		var members int64
		if err := tx.Model(&model.OrganizationMember{}).
			Where("org_id = ? AND user_id = ? AND status = ?", scope.OrgID, in.TargetID, types.OrgMemberStatusActive).
			Count(&members).Error; err != nil {
			return err
		}
		if members == 0 {
			return refuse(types.OrgErrMemberNotFound)
		}
	case types.GuardrailTargetKey:
		// A key guardrail belongs to a workspace; organization scope has no keys.
		if scope.WorkspaceID == 0 || in.TargetID <= 0 {
			return refuse(types.OrgErrInvalidInput)
		}
		var keys int64
		if err := tx.Model(&model.Token{}).
			Where("id = ? AND org_id = ? AND workspace_id = ?", in.TargetID, scope.OrgID, scope.WorkspaceID).
			Count(&keys).Error; err != nil {
			return err
		}
		if keys == 0 {
			return refuse(types.OrgErrKeyNotFound)
		}
	default:
		return refuse(types.OrgErrInvalidInput)
	}
	return nil
}

// ListGuardrails returns the guardrails stored in one scope. A workspace
// listing also reports the organization-level rules that apply to it, read-only.
func ListGuardrails(ctx context.Context, actorID int, scope GuardrailScope) (own, inherited []model.Guardrail, err error) {
	err = model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := authorizeGuardrailScopeTx(tx, scope, actorID, false); err != nil {
			return err
		}
		if err := tx.Where("org_id = ? AND workspace_id = ?", scope.OrgID, scope.WorkspaceID).
			Order("id ASC").Find(&own).Error; err != nil {
			return err
		}
		if scope.WorkspaceID == 0 {
			return nil
		}
		return tx.Where("org_id = ? AND workspace_id = 0 AND target_type = ?", scope.OrgID, types.GuardrailTargetOrgDefault).
			Order("id ASC").Find(&inherited).Error
	})
	return own, inherited, err
}

// CreateGuardrail stores a guardrail in a scope. The change and its audit row
// commit together with the policy_version bump that invalidates cached policies.
func CreateGuardrail(ctx context.Context, actorID int, scope GuardrailScope, in GuardrailInput) (*model.Guardrail, error) {
	var created model.Guardrail
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := authorizeGuardrailScopeTx(tx, scope, actorID, true); err != nil {
			return err
		}
		if err := validateGuardrailInputTx(tx, scope, &in); err != nil {
			return err
		}
		var total int64
		if err := tx.Model(&model.Guardrail{}).Where("org_id = ?", scope.OrgID).Count(&total).Error; err != nil {
			return err
		}
		if total >= maxGuardrailsPerOrg {
			return refuse(types.OrgErrInvalidInput)
		}
		now := common.GetTimestamp()
		created = model.Guardrail{OrgId: scope.OrgID, WorkspaceId: scope.WorkspaceID, Name: in.Name,
			TargetType: in.TargetType, TargetId: in.TargetID, Config: strings.TrimSpace(in.Config),
			Status: statusOf(in.Disabled), CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&created).Error; err != nil {
			return err
		}
		if err := model.BumpOrgPolicyVersionTx(tx, scope.OrgID); err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: scope.OrgID, WorkspaceId: scope.WorkspaceID, ActorUserId: actorID,
			Action: "guardrail.create", TargetType: "guardrail", TargetId: itoa(created.Id),
			Detail: map[string]any{"target_type": in.TargetType, "target_id": in.TargetID}})
	})
	if err != nil {
		return nil, err
	}
	return &created, nil
}

func statusOf(disabled bool) int {
	if disabled {
		return guardrailStatusDisabled
	}
	return guardrailStatusActive
}

// loadGuardrailInScopeTx finds a guardrail that lives in exactly this scope. A
// row of another organization, or of the organization scope when a workspace is
// asked for, is reported as missing.
func loadGuardrailInScopeTx(tx *gorm.DB, scope GuardrailScope, id int) (*model.Guardrail, error) {
	row, err := model.LockGuardrailInScopeTx(tx, scope.OrgID, scope.WorkspaceID, id)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, refuse(types.OrgErrGuardrailNotFound)
	}
	return row, nil
}

// UpdateGuardrail replaces a guardrail's name, config and enabled state. The
// target cannot change: delete and create instead.
func UpdateGuardrail(ctx context.Context, actorID int, scope GuardrailScope, id int, in GuardrailInput) (*model.Guardrail, error) {
	var updated *model.Guardrail
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := authorizeGuardrailScopeTx(tx, scope, actorID, true); err != nil {
			return err
		}
		row, err := loadGuardrailInScopeTx(tx, scope, id)
		if err != nil {
			return err
		}
		if in.TargetType != "" && (in.TargetType != row.TargetType || in.TargetID != row.TargetId) {
			return refuse(types.OrgErrInvalidInput)
		}
		in.TargetType, in.TargetID = row.TargetType, row.TargetId
		if err := validateGuardrailInputTx(tx, scope, &in); err != nil {
			return err
		}
		row.Name, row.Config, row.Status, row.UpdatedAt = in.Name, strings.TrimSpace(in.Config), statusOf(in.Disabled), common.GetTimestamp()
		if err := tx.Save(row).Error; err != nil {
			return err
		}
		if err := model.BumpOrgPolicyVersionTx(tx, scope.OrgID); err != nil {
			return err
		}
		updated = row
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: scope.OrgID, WorkspaceId: scope.WorkspaceID, ActorUserId: actorID,
			Action: "guardrail.update", TargetType: "guardrail", TargetId: itoa(id)})
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// DeleteGuardrail removes a guardrail. Removing a rule can only widen access, so
// it is audited and invalidates cached policies like any other change.
func DeleteGuardrail(ctx context.Context, actorID int, scope GuardrailScope, id int) error {
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := authorizeGuardrailScopeTx(tx, scope, actorID, true); err != nil {
			return err
		}
		row, err := loadGuardrailInScopeTx(tx, scope, id)
		if err != nil {
			return err
		}
		if err := tx.Delete(row).Error; err != nil {
			return err
		}
		if err := model.BumpOrgPolicyVersionTx(tx, scope.OrgID); err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: scope.OrgID, WorkspaceId: scope.WorkspaceID, ActorUserId: actorID,
			Action: "guardrail.delete", TargetType: "guardrail", TargetId: itoa(id)})
	})
}
