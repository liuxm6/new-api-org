package org

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

const (
	// DefaultBillingGroup is the pricing group of every organization wallet. It
	// is a platform decision (changed by a platform admin, Task 16), never the
	// creator's personal group: a VIP user must not hand VIP prices to a team.
	DefaultBillingGroup = "default"
	DefaultSeatLimit    = 10
	DefaultPlan         = "team"

	orgNameMaxRunes = 120
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,31}$`)

// reservedSlugs can never name an organization or workspace: they collide with
// routes, platform concepts or the generated default workspace.
var reservedSlugs = map[string]bool{
	"admin": true, "api": true, "app": true, "auth": true, "billing": true, "console": true,
	"dashboard": true, "default": true, "docs": true, "invite": true, "invites": true,
	"login": true, "logout": true, "me": true, "new": true, "null": true, "org": true,
	"orgs": true, "organization": true, "organizations": true, "platform": true, "root": true,
	"scim": true, "self": true, "settings": true, "status": true, "support": true, "system": true,
	"undefined": true, "user": true, "users": true, "workspace": true, "workspaces": true, "www": true,
}

// ValidateSlug applies the slug rules of design section 3.1. All-digit slugs
// are rejected because URLs accept an id or a slug and the two must never
// collide. The reserved-word check applies to organization slugs only for
// workspaces other than the generated "default" (see CreateWorkspace).
func ValidateSlug(slug string) error {
	if !slugPattern.MatchString(slug) {
		return refuse(types.OrgErrInvalidInput)
	}
	if strings.Trim(slug, "0123456789") == "" {
		return refuse(types.OrgErrInvalidInput)
	}
	if reservedSlugs[slug] {
		return refuse(types.OrgErrSlugReserved)
	}
	return nil
}

func validateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > orgNameMaxRunes {
		return "", refuse(types.OrgErrInvalidInput)
	}
	return name, nil
}

// CreateOrganizationInput is everything a client may choose. The billing group,
// plan, seat limit and status are platform decisions.
type CreateOrganizationInput struct {
	Name string
	Slug string
}

type CreateOrganizationResult struct {
	Org              model.Organization
	DefaultWorkspace model.Workspace
}

// createFaultHook lets tests fail a creation after a chosen step to prove the
// whole transaction rolls back. It is nil in production.
var createFaultHook func(step string) error

// CreateOrganization creates the billing wallet, the organization, its
// default workspace, the owner membership, the owner's manual workspace grant
// and the audit row in one transaction. Any failure leaves nothing behind.
// When email verification is enabled the actor needs an email address:
// addresses enter users.email only through a verification code, an
// email-binding flow or a trusted OAuth provider.
func CreateOrganization(ctx context.Context, actorID int, input CreateOrganizationInput) (*CreateOrganizationResult, error) {
	name, err := validateName(input.Name)
	if err != nil {
		return nil, err
	}
	slug := strings.TrimSpace(input.Slug)
	if err := ValidateSlug(slug); err != nil {
		return nil, err
	}
	var result *CreateOrganizationResult
	err = model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var actor model.User
		if err := tx.Select("id", "email", "status", "kind").Where("id = ?", actorID).Take(&actor).Error; err != nil {
			return err
		}
		if actor.Status != common.UserStatusEnabled || actor.IsBillingAccount() {
			return refuse(types.OrgErrForbidden)
		}
		// The email is required only when the platform verifies addresses. With
		// email verification off there is no way to attach one, so requiring it
		// would block every account from creating an organization.
		if common.EmailVerificationEnabled && strings.TrimSpace(actor.Email) == "" {
			return refuse(types.OrgErrEmailNotVerified)
		}
		var taken int64
		// Unscoped: a deleted organization keeps its slug for good.
		if err := tx.Unscoped().Model(&model.Organization{}).Where("slug = ?", slug).Count(&taken).Error; err != nil {
			return err
		}
		if taken > 0 {
			return refuse(types.OrgErrSlugTaken)
		}
		wallet, err := model.CreateBillingAccountTx(tx, DefaultBillingGroup)
		if err != nil {
			return err
		}
		now := common.GetTimestamp()
		org := model.Organization{Slug: slug, Name: name, OwnerUserId: actorID, BillingUserId: wallet.Id,
			Plan: DefaultPlan, SeatLimit: DefaultSeatLimit, Status: types.OrgStatusActive, PolicyVersion: 1,
			BillingGroup: DefaultBillingGroup, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&org).Error; err != nil {
			return err
		}
		workspace := model.Workspace{OrgId: org.Id, Slug: "default", Name: "Default", IsDefault: true,
			Status: types.WorkspaceStatusActive, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&workspace).Error; err != nil {
			return err
		}
		if err := tx.Create(&model.OrganizationMember{OrgId: org.Id, UserId: actorID, Role: types.OrgRoleOwner,
			Status: types.OrgMemberStatusActive, Source: types.OrgMemberSourceManual, JoinedAt: now,
			CreatedAt: now, UpdatedAt: now}).Error; err != nil {
			return err
		}
		if createFaultHook != nil {
			if err := createFaultHook("after_owner"); err != nil {
				return err
			}
		}
		if _, err := model.UpsertWorkspaceGrantTx(tx, org.Id, workspace.Id, actorID,
			model.GrantSourceManual, "", types.WorkspaceRoleAdmin); err != nil {
			return err
		}
		if err := recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: org.Id, ActorUserId: actorID, Action: "org.create",
			TargetType: "organization", TargetId: slug, Detail: map[string]any{"slug": slug}}); err != nil {
			return err
		}
		result = &CreateOrganizationResult{Org: org, DefaultWorkspace: workspace}
		return nil
	})
	if err == nil {
		return result, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, refuse(types.OrgErrNotFound)
	}
	if isUniqueViolation(err) {
		// Two requests raced for the same slug and the other one won.
		return nil, refuse(types.OrgErrSlugTaken)
	}
	return nil, err
}

// isUniqueViolation recognizes a unique-key failure on SQLite, MySQL (1062) and
// PostgreSQL (23505) without importing the drivers.
func isUniqueViolation(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "unique constraint") || strings.Contains(text, "duplicate entry") ||
		strings.Contains(text, "duplicate key") || strings.Contains(text, "sqlstate 23505") ||
		strings.Contains(text, "error 1062")
}

// UpdateOrganizationInput carries the owner-editable fields. A nil field is
// left unchanged. Seat limit, plan, billing group and status are platform
// fields and are deliberately absent.
type UpdateOrganizationInput struct {
	Name            *string
	DisplayTimezone *string
}

// UpdateOrganization is the owner-only PATCH of organization settings. The
// owner role is re-proven inside the transaction.
func UpdateOrganization(ctx context.Context, actorID, orgID int, input UpdateOrganizationInput) (*model.Organization, error) {
	var updated model.Organization
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner)
		if err != nil {
			return err
		}
		updates := map[string]any{"updated_at": common.GetTimestamp()}
		changed := []string{}
		if input.Name != nil {
			name, err := validateName(*input.Name)
			if err != nil {
				return err
			}
			updates["name"] = name
			changed = append(changed, "name")
		}
		if input.DisplayTimezone != nil {
			if _, err := time.LoadLocation(*input.DisplayTimezone); err != nil || *input.DisplayTimezone == "" {
				return refuse(types.OrgErrInvalidInput)
			}
			settings := map[string]any{}
			if org.Settings != "" {
				if err := common.UnmarshalJsonStr(org.Settings, &settings); err != nil {
					return err
				}
			}
			settings["display_timezone"] = *input.DisplayTimezone
			data, err := common.Marshal(settings)
			if err != nil {
				return err
			}
			updates["settings"] = string(data)
			changed = append(changed, "display_timezone")
		}
		if len(changed) == 0 {
			return refuse(types.OrgErrInvalidInput)
		}
		if err := tx.Model(&model.Organization{}).Where("id = ?", orgID).Updates(updates).Error; err != nil {
			return err
		}
		if err := model.BumpOrgPolicyVersionTx(tx, orgID); err != nil {
			return err
		}
		if err := recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "org.update",
			TargetType: "organization", TargetId: org.Slug, Detail: map[string]any{"fields": changed}}); err != nil {
			return err
		}
		return tx.Where("id = ?", orgID).Take(&updated).Error
	})
	if err != nil {
		return nil, err
	}
	return &updated, nil
}

// TransferOwnership hands the primary ownership to another active member. The
// target becomes owner, the former primary owner becomes admin, and
// organizations.owner_user_id follows, all in one transaction. Only the
// primary owner can transfer.
func TransferOwnership(ctx context.Context, actorID, orgID, targetUserID int) error {
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner)
		if err != nil {
			return err
		}
		if org.OwnerUserId != actorID || targetUserID == actorID {
			return refuse(types.OrgErrOwnerRole)
		}
		target, err := model.LockOrganizationMemberTx(tx, orgID, targetUserID)
		if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && target.Status != types.OrgMemberStatusActive) {
			return refuse(types.OrgErrMemberNotFound)
		}
		if err != nil {
			return err
		}
		if err := tx.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", orgID, targetUserID).
			Updates(map[string]any{"role": types.OrgRoleOwner, "updated_at": common.GetTimestamp()}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", orgID, actorID).
			Updates(map[string]any{"role": types.OrgRoleAdmin, "updated_at": common.GetTimestamp()}).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.Organization{}).Where("id = ?", orgID).
			Update("owner_user_id", targetUserID).Error; err != nil {
			return err
		}
		if err := model.BumpOrgPolicyVersionTx(tx, orgID); err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "org.transfer_ownership",
			TargetType: "member", TargetId: itoa(targetUserID), Detail: map[string]any{"from": actorID, "to": targetUserID}})
	})
}
