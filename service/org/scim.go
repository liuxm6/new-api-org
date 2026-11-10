package org

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// ScimError is a SCIM 2.0 failure (RFC 7644 section 3.12). The controller
// renders it; no field ever carries IdP-controlled text or a secret.
type ScimError struct {
	Status   int
	ScimType string
	Detail   string
}

func (e *ScimError) Error() string { return e.Detail }

func scimErr(status int, scimType, detail string) *ScimError {
	return &ScimError{Status: status, ScimType: scimType, Detail: detail}
}

// AsScimError converts any service failure into a SCIM error.
func AsScimError(err error) *ScimError {
	var scim *ScimError
	if errors.As(err, &scim) {
		return scim
	}
	var access *types.OrgAccessError
	if errors.As(err, &access) {
		switch access.Code {
		case types.OrgErrSeatLimitReached:
			return scimErr(http.StatusConflict, "", "The organization has no free seats")
		case types.OrgErrOwnerRole, types.OrgErrLastOwner:
			return scimErr(http.StatusForbidden, "", "Organization owners are not managed through SCIM")
		case types.OrgErrSuspended, types.OrgErrForbidden, types.OrgErrMemberSuspended:
			return scimErr(http.StatusForbidden, "", "The request is not permitted")
		case types.OrgErrNotFound, types.OrgErrMemberNotFound, types.OrgErrWorkspaceNotFound:
			return scimErr(http.StatusNotFound, "", "Resource not found")
		case types.OrgErrConflict:
			return scimErr(http.StatusConflict, "uniqueness", "The resource conflicts with an existing one")
		case types.OrgErrInvalidInput:
			return scimErr(http.StatusBadRequest, "invalidValue", "Invalid value")
		}
	}
	common.SysError(common.LogText("scim request failed: %v", err))
	return scimErr(http.StatusInternalServerError, "", "Internal error")
}

const (
	scimMaxUserName   = 255
	scimMaxExternalID = 191
	scimMaxDisplay    = 120
	// ScimPageMax bounds the page size of a list response.
	ScimPageMax = 200
)

// ScimUserInput is a create request after the controller parsed the SCIM JSON.
type ScimUserInput struct {
	UserName    string
	ExternalID  string
	OIDCSub     string
	DisplayName string
	Active      bool
}

// ScimUserView is the organization-scoped representation of one identity.
type ScimUserView struct {
	ID          int
	ExternalID  string
	UserName    string
	DisplayName string
	Active      bool
	Created     int64
	Modified    int64
}

// ScimUserChanges is a normalized PATCH. Nil fields are untouched.
type ScimUserChanges struct {
	Active      *bool
	DisplayName *string
	UserName    *string
	ExternalID  *string
}

func scimOrgTx(tx *gorm.DB, orgID int) (*model.Organization, error) {
	org, err := model.LockOrganizationTx(tx, orgID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, refuse(types.OrgErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	if org.Status != types.OrgStatusActive {
		return nil, refuse(types.OrgErrSuspended)
	}
	return org, nil
}

// scimProviderTx is the IdP identities are provisioned against. Without one
// there is no issuer to bind a subject to, which SCIM reports as invalidValue.
func scimProviderTx(tx *gorm.DB, orgID int) (*model.CustomOAuthProvider, error) {
	provider, err := OrgSSOProvider(tx, orgID)
	var access *types.OrgAccessError
	if errors.As(err, &access) {
		return nil, scimErr(http.StatusBadRequest, "invalidValue", "The organization has no identity provider to provision against")
	}
	return provider, err
}

// scimSubject is the OIDC sub a provisioned user will sign in with: the
// explicit extension value, or the externalId when the platform confirmed
// that mode. Anything else is refused; no email-based guess is made.
func scimSubject(org *model.Organization, in ScimUserInput) (string, error) {
	switch {
	case in.OIDCSub != "":
		return in.OIDCSub, nil
	case in.ExternalID != "" && LoadSSOSettings(org).ExternalIDIsSub:
		return in.ExternalID, nil
	}
	return "", scimErr(http.StatusBadRequest, "invalidValue",
		"A subject mapping is required: send the oidcSub extension or have the platform enable externalId-as-sub")
}

func validScimText(value string, limit int) bool {
	return len(value) <= limit && !strings.ContainsAny(value, "\x00\r\n")
}

func scimViewTx(tx *gorm.DB, identity model.OrgIdentity) (ScimUserView, error) {
	view := ScimUserView{ID: identity.Id, UserName: identity.ClaimEmail, Created: identity.CreatedAt, Modified: identity.UpdatedAt}
	if identity.ScimExternalId != nil {
		view.ExternalID = *identity.ScimExternalId
	}
	var users []model.User
	if err := tx.Select("id", "display_name").Where("id = ?", identity.UserId).Limit(1).Find(&users).Error; err != nil {
		return view, err
	}
	if len(users) == 1 {
		view.DisplayName = users[0].DisplayName
	}
	member, err := model.GetOrganizationMember(tx, identity.OrgId, identity.UserId)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return view, err
	}
	view.Active = identity.Status == types.OrgIdentityActive && err == nil && member.Status == types.OrgMemberStatusActive
	return view, nil
}

// CreateScimUser provisions a person. A replay of the same externalId and sub
// returns the same identity (created = false). The same externalId with
// another sub, or the same sub under another externalId, is a 409: a binding is
// never moved by a provisioning call. An identity that exists because of JIT is
// taken over (SCIM becomes its source). A previously removed identity is
// restored.
func CreateScimUser(ctx context.Context, orgID int, in ScimUserInput) (ScimUserView, bool, error) {
	in.UserName, in.ExternalID, in.OIDCSub = strings.TrimSpace(in.UserName), strings.TrimSpace(in.ExternalID), strings.TrimSpace(in.OIDCSub)
	if in.UserName == "" || !validScimText(in.UserName, scimMaxUserName) || !validScimText(in.ExternalID, scimMaxExternalID) ||
		!validScimText(in.OIDCSub, scimMaxExternalID) || !validScimText(in.DisplayName, scimMaxDisplay) {
		return ScimUserView{}, false, scimErr(http.StatusBadRequest, "invalidValue", "userName is required and values must be short plain text")
	}
	var view ScimUserView
	var created bool
	var revocation *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, err := scimOrgTx(tx, orgID)
		if err != nil {
			return err
		}
		provider, err := scimProviderTx(tx, orgID)
		if err != nil {
			return err
		}
		sub, err := scimSubject(org, in)
		if err != nil {
			return err
		}
		bySub, err := model.GetOrgIdentityBySubject(tx, orgID, provider.Id, sub)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var byExt *model.OrgIdentity
		if in.ExternalID != "" {
			byExt, err = model.GetOrgIdentityByExternalID(tx, orgID, provider.Id, in.ExternalID)
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
		}
		existing := bySub
		if existing == nil {
			existing = byExt
		}
		if existing != nil {
			if (bySub != nil && byExt != nil && bySub.Id != byExt.Id) || existing.Subject != sub ||
				(existing.ScimExternalId != nil && *existing.ScimExternalId != in.ExternalID && in.ExternalID != "") {
				return scimErr(http.StatusConflict, "uniqueness", "The subject or externalId is already bound to another user")
			}
			revocation, created, err = adoptIdentityTx(ctx, tx, org, existing, in)
			if err != nil {
				return err
			}
			fresh, err := model.GetOrgIdentityByID(tx, orgID, existing.Id)
			if err != nil {
				return err
			}
			view, err = scimViewTx(tx, *fresh)
			return err
		}
		if _, err := model.OrgIdentityByUserNameTx(tx, orgID, provider.Id, in.UserName, 0); err == nil {
			return scimErr(http.StatusConflict, "uniqueness", "userName is already in use")
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		user, err := model.CreateOrgPlaceholderUserTx(tx, in.DisplayName, org.BillingGroup)
		if err != nil {
			return err
		}
		now := common.GetTimestamp()
		identity := model.OrgIdentity{OrgId: orgID, ProviderId: provider.Id, Issuer: provider.Issuer, Subject: sub, UserId: user.Id,
			ClaimEmail: in.UserName, Source: types.OrgIdentitySourceSCIM, Status: types.OrgIdentityActive, CreatedAt: now, UpdatedAt: now}
		if in.ExternalID != "" {
			identity.ScimExternalId = &in.ExternalID
		}
		if !in.Active {
			identity.Status = types.OrgIdentityDisabled
		}
		if err := tx.Create(&identity).Error; err != nil {
			return err
		}
		if in.Active {
			if _, err := AdmitMemberTx(tx, AdmitInput{OrgID: orgID, UserID: user.Id, OrgRole: types.OrgRoleMember, Source: types.OrgMemberSourceSCIM}); err != nil {
				return err
			}
			if in.ExternalID != "" {
				if err := tx.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", orgID, user.Id).
					Update("external_id", in.ExternalID).Error; err != nil {
					return err
				}
			}
		}
		created = true
		if err := recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorKind: "scim", Action: "scim.user_create",
			TargetType: "identity", TargetId: strconv.Itoa(identity.Id), Detail: map[string]any{"active": in.Active}}); err != nil {
			return err
		}
		view, err = scimViewTx(tx, identity)
		return err
	})
	if err != nil {
		return ScimUserView{}, false, err
	}
	revocation.Publish()
	return view, created, nil
}

// adoptIdentityTx handles a create that matched an existing identity: SCIM
// takes over a JIT identity, restores a removed one and reconciles active.
func adoptIdentityTx(ctx context.Context, tx *gorm.DB, org *model.Organization, identity *model.OrgIdentity,
	in ScimUserInput) (*model.KeyRevocation, bool, error) {
	updates := map[string]any{"updated_at": common.GetTimestamp()}
	restored := identity.Status == types.OrgIdentityRemoved
	taken := identity.Source != types.OrgIdentitySourceSCIM
	if taken {
		updates["source"], updates["claim_email"] = types.OrgIdentitySourceSCIM, in.UserName
	}
	if identity.ScimExternalId == nil && in.ExternalID != "" {
		updates["scim_external_id"] = in.ExternalID
	}
	if len(updates) > 1 {
		if err := tx.Model(&model.OrgIdentity{}).Where("id = ?", identity.Id).Updates(updates).Error; err != nil {
			return nil, false, err
		}
	}
	if taken || in.ExternalID != "" {
		memberUpdates := map[string]any{"updated_at": common.GetTimestamp()}
		if taken {
			memberUpdates["source"] = types.OrgMemberSourceSCIM
		}
		if in.ExternalID != "" {
			memberUpdates["external_id"] = in.ExternalID
		}
		if err := tx.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ? AND status <> ?", org.Id, identity.UserId,
			types.OrgMemberStatusRemoved).Updates(memberUpdates).Error; err != nil {
			return nil, false, err
		}
	}
	revocation, err := setIdentityActiveTx(ctx, tx, org, identity.Id, in.Active)
	return revocation, restored, err
}

// setIdentityActiveTx makes the identity and its membership agree with the IdP
// "active" flag. Deactivation suspends (keys, credentials and org sessions go);
// activation restores only what SCIM itself stopped.
func setIdentityActiveTx(ctx context.Context, tx *gorm.DB, org *model.Organization, identityID int, active bool) (*model.KeyRevocation, error) {
	identity, err := model.LockOrgIdentityTx(tx, org.Id, identityID)
	if err != nil {
		return nil, err
	}
	now := common.GetTimestamp()
	member, err := model.LockOrganizationMemberTx(tx, org.Id, identity.UserId)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	live := err == nil && member.Status != types.OrgMemberStatusRemoved
	if !active {
		if live && member.Role == types.OrgRoleOwner {
			return nil, refuse(types.OrgErrOwnerRole)
		}
		if err := tx.Model(&model.OrgIdentity{}).Where("id = ?", identity.Id).
			Updates(map[string]any{"status": types.OrgIdentityDisabled, "updated_at": now}).Error; err != nil {
			return nil, err
		}
		if !live || member.Status != types.OrgMemberStatusActive {
			return &model.KeyRevocation{}, nil
		}
		if err := model.SetOrganizationMemberStatusTx(tx, org.Id, identity.UserId, types.OrgMemberStatusSuspended); err != nil {
			return nil, err
		}
		revocation, err := ReconcileMemberKeysTx(tx, org.Id, identity.UserId, "scim_deactivated")
		if err != nil {
			return nil, err
		}
		return revocation, recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: org.Id, ActorKind: "scim", Action: "scim.user_deactivate",
			TargetType: "identity", TargetId: strconv.Itoa(identity.Id)})
	}
	// The identity status records who stopped the person: only SCIM ever sets it
	// to disabled or removed. A member suspended or removed while the identity is
	// still active was stopped by an administrator, and the IdP's "active" flag
	// does not overrule that.
	switch {
	case live && member.Status == types.OrgMemberStatusSuspended && identity.Status == types.OrgIdentityDisabled:
		if err := model.SetOrganizationMemberStatusTx(tx, org.Id, identity.UserId, types.OrgMemberStatusActive); err != nil {
			return nil, err
		}
	case live && member.Status == types.OrgMemberStatusSuspended:
		return nil, refuse(types.OrgErrMemberSuspended)
	case !live && err == nil && identity.Status != types.OrgIdentityRemoved:
		return nil, refuse(types.OrgErrMemberSuspended)
	case !live:
		if _, err := AdmitMemberTx(tx, AdmitInput{OrgID: org.Id, UserID: identity.UserId, OrgRole: types.OrgRoleMember, Source: types.OrgMemberSourceSCIM}); err != nil {
			return nil, err
		}
	}
	if err := tx.Model(&model.OrgIdentity{}).Where("id = ?", identity.Id).
		Updates(map[string]any{"status": types.OrgIdentityActive, "updated_at": now}).Error; err != nil {
		return nil, err
	}
	return &model.KeyRevocation{}, recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: org.Id, ActorKind: "scim", Action: "scim.user_activate",
		TargetType: "identity", TargetId: strconv.Itoa(identity.Id)})
}

// GetScimUser returns one identity of this organization.
func GetScimUser(ctx context.Context, orgID, id int) (ScimUserView, error) {
	db := model.DB.WithContext(ctx)
	identity, err := model.GetOrgIdentityByID(db, orgID, id)
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && identity.Status == types.OrgIdentityRemoved) {
		return ScimUserView{}, scimErr(http.StatusNotFound, "", "User not found")
	}
	if err != nil {
		return ScimUserView{}, err
	}
	return scimViewTx(db, *identity)
}

var scimFilterPattern = regexp.MustCompile(`^\s*(?i:(userName|externalId))\s+(?i:eq)\s+"([^"\\]*)"\s*$`)

// ListScimUsers pages through the organization's identities. Only
// `userName eq "x"` and `externalId eq "x"` filters exist; any other filter
// is refused rather than ignored, so a client never receives an unfiltered
// list by mistake. startIndex is 1-based.
func ListScimUsers(ctx context.Context, orgID int, filter string, startIndex, count int) ([]ScimUserView, int, error) {
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 0
	}
	count = min(count, ScimPageMax)
	db := model.DB.WithContext(ctx)
	query := db.Model(&model.OrgIdentity{}).Where("org_id = ? AND status <> ?", orgID, types.OrgIdentityRemoved)
	if strings.TrimSpace(filter) != "" {
		match := scimFilterPattern.FindStringSubmatch(filter)
		if match == nil {
			return nil, 0, scimErr(http.StatusBadRequest, "invalidFilter", "Only userName eq and externalId eq filters are supported")
		}
		if strings.EqualFold(match[1], "userName") {
			query = query.Where("claim_email = ?", match[2])
		} else {
			query = query.Where("scim_external_id = ?", match[2])
		}
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []model.OrgIdentity
	if count > 0 {
		if err := query.Order("id").Offset(startIndex - 1).Limit(count).Find(&rows).Error; err != nil {
			return nil, 0, err
		}
	}
	views := make([]ScimUserView, 0, len(rows))
	for _, row := range rows {
		view, err := scimViewTx(db, row)
		if err != nil {
			return nil, 0, err
		}
		views = append(views, view)
	}
	return views, int(total), nil
}

// ScimPatchOp is one RFC 7644 PATCH operation.
type ScimPatchOp struct {
	Op    string
	Path  string
	Value any
}

func scimBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func scimString(value any) (string, bool) {
	text, ok := value.(string)
	return strings.TrimSpace(text), ok
}

// ParseScimPatch normalizes PATCH operations (replace/add of active,
// displayName, userName, externalId and name.formatted, with or without a path)
// into one change set. Anything else is invalidPath/invalidValue.
func ParseScimPatch(ops []ScimPatchOp) (ScimUserChanges, error) {
	var changes ScimUserChanges
	if len(ops) == 0 {
		return changes, scimErr(http.StatusBadRequest, "invalidSyntax", "At least one operation is required")
	}
	apply := func(path string, value any) error {
		switch strings.ToLower(path) {
		case "active":
			active, ok := scimBool(value)
			if !ok {
				return scimErr(http.StatusBadRequest, "invalidValue", "active must be a boolean")
			}
			changes.Active = &active
		case "displayname", "name.formatted":
			text, ok := scimString(value)
			if !ok || !validScimText(text, scimMaxDisplay) {
				return scimErr(http.StatusBadRequest, "invalidValue", "displayName must be short plain text")
			}
			changes.DisplayName = &text
		case "username":
			text, ok := scimString(value)
			if !ok || text == "" || !validScimText(text, scimMaxUserName) {
				return scimErr(http.StatusBadRequest, "invalidValue", "userName must be non-empty plain text")
			}
			changes.UserName = &text
		case "externalid":
			text, ok := scimString(value)
			if !ok || text == "" || !validScimText(text, scimMaxExternalID) {
				return scimErr(http.StatusBadRequest, "invalidValue", "externalId must be non-empty plain text")
			}
			changes.ExternalID = &text
		default:
			return scimErr(http.StatusBadRequest, "invalidPath", "Unsupported attribute")
		}
		return nil
	}
	for _, op := range ops {
		switch strings.ToLower(op.Op) {
		case "replace", "add":
		default:
			return changes, scimErr(http.StatusBadRequest, "invalidValue", "Only add and replace are supported")
		}
		if op.Path != "" {
			if err := apply(op.Path, op.Value); err != nil {
				return changes, err
			}
			continue
		}
		object, ok := op.Value.(map[string]any)
		if !ok || len(object) == 0 {
			return changes, scimErr(http.StatusBadRequest, "invalidSyntax", "A pathless operation needs an object value")
		}
		for key, value := range object {
			if err := apply(key, value); err != nil {
				return changes, err
			}
		}
	}
	return changes, nil
}

// PatchScimUser applies a change set atomically.
func PatchScimUser(ctx context.Context, orgID, id int, changes ScimUserChanges) (ScimUserView, error) {
	var view ScimUserView
	var revocation *model.KeyRevocation
	var sessionUser int
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, err := scimOrgTx(tx, orgID)
		if err != nil {
			return err
		}
		identity, err := model.LockOrgIdentityTx(tx, orgID, id)
		if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && identity.Status == types.OrgIdentityRemoved) {
			return scimErr(http.StatusNotFound, "", "User not found")
		}
		if err != nil {
			return err
		}
		updates := map[string]any{}
		if changes.UserName != nil && *changes.UserName != identity.ClaimEmail {
			if _, err := model.OrgIdentityByUserNameTx(tx, orgID, identity.ProviderId, *changes.UserName, identity.Id); err == nil {
				return scimErr(http.StatusConflict, "uniqueness", "userName is already in use")
			} else if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			updates["claim_email"] = *changes.UserName
		}
		if changes.ExternalID != nil {
			switch {
			case identity.ScimExternalId != nil && *identity.ScimExternalId == *changes.ExternalID:
			case identity.ScimExternalId != nil:
				return scimErr(http.StatusConflict, "mutability", "externalId cannot be rebound")
			default:
				if _, err := model.GetOrgIdentityByExternalID(tx, orgID, identity.ProviderId, *changes.ExternalID); err == nil {
					return scimErr(http.StatusConflict, "uniqueness", "externalId is already in use")
				} else if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				updates["scim_external_id"] = *changes.ExternalID
			}
		}
		if len(updates) > 0 {
			updates["updated_at"] = common.GetTimestamp()
			if err := tx.Model(&model.OrgIdentity{}).Where("id = ?", identity.Id).Updates(updates).Error; err != nil {
				return err
			}
		}
		if changes.DisplayName != nil {
			if err := tx.Model(&model.User{}).Where("id = ?", identity.UserId).Update("display_name", *changes.DisplayName).Error; err != nil {
				return err
			}
		}
		if changes.Active != nil {
			if revocation, err = setIdentityActiveTx(ctx, tx, org, identity.Id, *changes.Active); err != nil {
				return err
			}
			if !*changes.Active {
				sessionUser = identity.UserId
			}
		}
		fresh, err := model.GetOrgIdentityByID(tx, orgID, identity.Id)
		if err != nil {
			return err
		}
		view, err = scimViewTx(tx, *fresh)
		return err
	})
	if err != nil {
		return ScimUserView{}, err
	}
	revocation.Publish()
	if sessionUser > 0 {
		endOrgSessions(sessionUser, orgID, "scim_deactivated")
	}
	return view, nil
}

func endOrgSessions(userID, orgID int, reason string) {
	if err := model.RevokeOrgScopedSessions(userID, orgID, reason); err != nil {
		common.SysLog(common.LogText("failed to revoke organization sessions: %s", err.Error()))
	}
}

// DeleteScimUser removes the person from this organization only: the
// membership ends, grants and keys go, and the identity is kept as removed so a
// replayed create restores the same binding. The global account is untouched.
func DeleteScimUser(ctx context.Context, orgID, id int) error {
	var revocation *model.KeyRevocation
	var userID int
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, err := scimOrgTx(tx, orgID)
		if err != nil {
			return err
		}
		identity, err := model.LockOrgIdentityTx(tx, orgID, id)
		if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && identity.Status == types.OrgIdentityRemoved) {
			return scimErr(http.StatusNotFound, "", "User not found")
		}
		if err != nil {
			return err
		}
		member, err := model.LockOrganizationMemberTx(tx, org.Id, identity.UserId)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil && member.Status != types.OrgMemberStatusRemoved {
			if member.Role == types.OrgRoleOwner {
				return refuse(types.OrgErrOwnerRole)
			}
			if err := model.SetOrganizationMemberStatusTx(tx, org.Id, identity.UserId, types.OrgMemberStatusRemoved); err != nil {
				return err
			}
			if err := model.DeleteAllWorkspaceGrantsOfUserTx(tx, org.Id, identity.UserId); err != nil {
				return err
			}
			if revocation, err = ReconcileMemberKeysTx(tx, org.Id, identity.UserId, "scim_removed"); err != nil {
				return err
			}
		}
		if err := tx.Model(&model.OrgIdentity{}).Where("id = ?", identity.Id).
			Updates(map[string]any{"status": types.OrgIdentityRemoved, "updated_at": common.GetTimestamp()}).Error; err != nil {
			return err
		}
		userID = identity.UserId
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorKind: "scim", Action: "scim.user_delete",
			TargetType: "identity", TargetId: strconv.Itoa(identity.Id)})
	})
	if err != nil {
		return err
	}
	revocation.Publish()
	endOrgSessions(userID, orgID, "scim_removed")
	return nil
}
