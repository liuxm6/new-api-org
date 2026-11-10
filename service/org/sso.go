package org

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// SSOClaims is what a verified ID Token proved. The caller (the OIDC relying
// party) has already checked signature, issuer, audience, nonce and expiry;
// this package never sees a token. Identity is Issuer + Subject. Email is a
// claim for display and for the verified-email gate, never a lookup key.
type SSOClaims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// SSOSettings are the organization-level SSO switches stored in
// organizations.settings under "sso".
type SSOSettings struct {
	JITEnabled         bool `json:"jit_enabled"`
	DefaultWorkspaceID int  `json:"default_workspace_id"`
	// ExternalIDIsSub is the platform-confirmed mode in which a SCIM externalId
	// is the OIDC sub. Organizations cannot set it themselves.
	ExternalIDIsSub bool `json:"external_id_is_sub"`
}

// LoadSSOSettings reads the "sso" block of the organization settings.
func LoadSSOSettings(org *model.Organization) SSOSettings {
	var all struct {
		SSO SSOSettings `json:"sso"`
	}
	if org.Settings != "" {
		_ = common.UnmarshalJsonStr(org.Settings, &all)
	}
	return all.SSO
}

func saveSSOSettingsTx(tx *gorm.DB, org *model.Organization, settings SSOSettings) error {
	all := map[string]any{}
	if org.Settings != "" {
		if err := common.UnmarshalJsonStr(org.Settings, &all); err != nil {
			all = map[string]any{}
		}
	}
	all["sso"] = settings
	encoded, err := common.Marshal(all)
	if err != nil {
		return err
	}
	return tx.Model(&model.Organization{}).Where("id = ?", org.Id).
		Updates(map[string]any{"settings": string(encoded), "updated_at": common.GetTimestamp()}).Error
}

// ssoProviderTx loads the organization's IdP and proves it is the provider the
// ceremony ran against: same organization, enabled, and the issuer the ID Token
// carried. A provider edited since (or one of another organization) is refused.
func ssoProviderTx(tx *gorm.DB, orgID, providerID int, issuer string) (*model.CustomOAuthProvider, error) {
	var providers []model.CustomOAuthProvider
	if err := tx.Where("id = ?", providerID).Limit(1).Find(&providers).Error; err != nil {
		return nil, err
	}
	if len(providers) == 0 || providers[0].OrgId != orgID || !providers[0].Enabled ||
		providers[0].Issuer == "" || providers[0].Issuer != issuer {
		return nil, refuse(types.OrgErrSSONotConfigured)
	}
	return &providers[0], nil
}

// OrgSSOProvider returns the single IdP bound to an organization.
func OrgSSOProvider(db *gorm.DB, orgID int) (*model.CustomOAuthProvider, error) {
	var providers []model.CustomOAuthProvider
	if err := db.Where("org_id = ?", orgID).Order("id").Limit(1).Find(&providers).Error; err != nil {
		return nil, err
	}
	if len(providers) == 0 {
		return nil, refuse(types.OrgErrSSONotConfigured)
	}
	return &providers[0], nil
}

func normalizeClaimEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	if len(email) > 255 {
		email = email[:255]
	}
	return email
}

// defaultWorkspaceTx is the workspace a newly joined person lands in: the
// configured one when it is still an active workspace of this organization,
// otherwise the organization's default workspace.
func defaultWorkspaceTx(tx *gorm.DB, orgID, configured int) (*model.Workspace, error) {
	query := tx.Where("org_id = ? AND status = ?", orgID, types.WorkspaceStatusActive)
	if configured > 0 {
		query = query.Where("id = ?", configured)
	} else {
		query = query.Where("is_default = ?", true)
	}
	var rows []model.Workspace
	if err := query.Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

func joinDefaultWorkspaceTx(tx *gorm.DB, org *model.Organization, userID int) (*model.KeyRevocation, error) {
	workspace, err := defaultWorkspaceTx(tx, org.Id, LoadSSOSettings(org).DefaultWorkspaceID)
	if err != nil || workspace == nil {
		return &model.KeyRevocation{}, err
	}
	return ApplyGrantTx(tx, org.Id, workspace.Id, userID, ssoGrantSource, "", types.WorkspaceRoleMember, 0)
}

// ssoGrantSource labels the default-workspace grant of a JIT or linked join,
// so it is distinguishable from manual and SCIM grants.
const ssoGrantSource = "sso"

// SSOLoginResult names who signed in and whether this login created them.
type SSOLoginResult struct {
	UserID    int
	OrgID     int
	Joined    bool
	Placehold bool
}

// ResolveSSOLogin turns a verified tenant identity into the human it
// belongs to, creating nothing unless every JIT gate passes:
//
//   - the organization is active and the provider is its own, enabled IdP;
//   - an existing (org, provider, subject) identity wins over everything; it
//     must be active, its user an enabled human and its membership active.
//     Suspended and removed members are never revived by signing in, whoever
//     removed them;
//   - a new subject joins only when the organization allows JIT and the IdP
//     claims a verified email. A placeholder human is created (no email, no
//     bonus), admitted through the shared seat transaction and added to the
//     default workspace.
//
// Denials are audited with a fixed reason code, never with claim text.
func ResolveSSOLogin(ctx context.Context, orgID, providerID int, claims SSOClaims) (*SSOLoginResult, error) {
	var result *SSOLoginResult
	var revocation *model.KeyRevocation
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, err := model.LockOrganizationTx(tx, orgID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return refuse(types.OrgErrNotFound)
		}
		if err != nil {
			return err
		}
		if org.Status != types.OrgStatusActive {
			return refuse(types.OrgErrSuspended)
		}
		if claims.Subject == "" {
			return refuse(types.OrgErrInvalidInput)
		}
		if _, err := ssoProviderTx(tx, orgID, providerID, claims.Issuer); err != nil {
			return err
		}
		identity, err := model.GetOrgIdentityBySubject(tx, orgID, providerID, claims.Subject)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err == nil {
			result, err = signInExistingTx(tx, org, identity, claims)
			return err
		}
		return joinNewIdentityTx(ctx, tx, org, providerID, claims, &result, &revocation)
	})
	if err != nil {
		auditSSODenied(ctx, orgID, err)
		return nil, err
	}
	revocation.Publish()
	return result, nil
}

func signInExistingTx(tx *gorm.DB, org *model.Organization, identity *model.OrgIdentity, claims SSOClaims) (*SSOLoginResult, error) {
	if identity.Status != types.OrgIdentityActive {
		return nil, refuse(types.OrgErrIdentityDisabled)
	}
	var users []model.User
	if err := tx.Select("id", "status", "kind").Where("id = ?", identity.UserId).Limit(1).Find(&users).Error; err != nil {
		return nil, err
	}
	if len(users) == 0 || users[0].Status != common.UserStatusEnabled || users[0].IsBillingAccount() {
		return nil, refuse(types.OrgErrForbidden)
	}
	member, err := model.LockOrganizationMemberTx(tx, org.Id, identity.UserId)
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && member.Status == types.OrgMemberStatusRemoved) {
		return nil, refuse(types.OrgErrMemberSuspended)
	}
	if err != nil {
		return nil, err
	}
	if member.Status != types.OrgMemberStatusActive {
		return nil, refuse(types.OrgErrMemberSuspended)
	}
	// SCIM owns the userName of a provisioned identity; a JIT identity follows
	// the IdP's current address claim.
	if email := normalizeClaimEmail(claims.Email); identity.Source == types.OrgIdentitySourceSSO && email != "" && email != identity.ClaimEmail {
		if err := tx.Model(&model.OrgIdentity{}).Where("id = ?", identity.Id).
			Updates(map[string]any{"claim_email": email, "updated_at": common.GetTimestamp()}).Error; err != nil {
			return nil, err
		}
	}
	return &SSOLoginResult{UserID: identity.UserId, OrgID: org.Id}, nil
}

func joinNewIdentityTx(ctx context.Context, tx *gorm.DB, org *model.Organization, providerID int, claims SSOClaims,
	result **SSOLoginResult, revocation **model.KeyRevocation) error {
	if !LoadSSOSettings(org).JITEnabled {
		return refuse(types.OrgErrJITDisabled)
	}
	email := normalizeClaimEmail(claims.Email)
	if !claims.EmailVerified || email == "" {
		return refuse(types.OrgErrEmailNotVerified)
	}
	user, err := model.CreateOrgPlaceholderUserTx(tx, claims.Name, org.BillingGroup)
	if err != nil {
		return err
	}
	now := common.GetTimestamp()
	identity := model.OrgIdentity{OrgId: org.Id, ProviderId: providerID, Issuer: claims.Issuer, Subject: claims.Subject,
		UserId: user.Id, ClaimEmail: email, Source: types.OrgIdentitySourceSSO, Status: types.OrgIdentityActive,
		CreatedAt: now, UpdatedAt: now}
	if err := tx.Create(&identity).Error; err != nil {
		return err
	}
	if _, err := AdmitMemberTx(tx, AdmitInput{OrgID: org.Id, UserID: user.Id, OrgRole: types.OrgRoleMember, Source: types.OrgMemberSourceSSO}); err != nil {
		return err
	}
	revoked, err := joinDefaultWorkspaceTx(tx, org, user.Id)
	if err != nil {
		return err
	}
	*revocation = revoked
	*result = &SSOLoginResult{UserID: user.Id, OrgID: org.Id, Joined: true, Placehold: true}
	return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: org.Id, ActorUserId: user.Id, ActorKind: "sso", Action: "sso.jit_join",
		TargetType: "member", TargetId: strconv.Itoa(user.Id), Detail: map[string]any{"provider_id": providerID}})
}

// ssoDenialCode is the fixed, secret-free reason an audit row records.
func ssoDenialCode(err error) string {
	var access *types.OrgAccessError
	if errors.As(err, &access) {
		return access.Code
	}
	return "unavailable"
}

func auditSSODenied(ctx context.Context, orgID int, err error) {
	if orgID <= 0 {
		return
	}
	if auditErr := recordAudit(ctx, model.DB.WithContext(ctx), model.OrgAuditEntry{OrgId: orgID, ActorKind: "sso",
		Action: "sso.login_denied", TargetType: "sso", Detail: map[string]any{"reason": ssoDenialCode(err)}}); auditErr != nil {
		common.SysLog(common.LogText("failed to audit sso denial: %s", auditErr.Error()))
	}
}

// LinkResult reports what a global-account link did.
type LinkResult struct {
	Joined   bool
	Replaced bool
	// AuthVersions are committed auth versions of disabled placeholders; the
	// caller publishes them after commit through PublishLinkResult.
	replacedUser    int
	replacedVersion int64
	revocation      *model.KeyRevocation
}

// PublishLinkResult finishes the post-commit side effects of LinkGlobalAccount.
func PublishLinkResult(result *LinkResult, orgID int) {
	if result == nil || result.replacedUser == 0 {
		return
	}
	model.PublishCommittedAuthVersion(result.replacedUser, result.replacedVersion)
	if err := model.RevokeOrgScopedSessions(result.replacedUser, orgID, "identity_replaced"); err != nil {
		common.SysLog(common.LogText("failed to revoke replaced placeholder sessions: %s", err.Error()))
	}
	result.revocation.Publish()
}

// LinkGlobalAccount ties a freshly proven tenant identity to an existing global
// account. The caller must already hold two proofs: the global account (its
// own authenticated, security-verified session) and the organization identity
// (a fresh ceremony against the organization's IdP, giving claims). Neither
// alone links anything, and an email match is never consulted.
//
// If the identity already belongs to an emptied placeholder, the placeholder
// is replaced by the global account. Any business fact on the placeholder
// (keys, tasks, billed operations, spend, credentials, budgets), an owner
// role, a suspended membership, or any existing membership of the global
// account in this organization refuses with a conflict instead: financial
// history is never migrated, and two people are never merged silently.
func LinkGlobalAccount(ctx context.Context, globalUserID, orgID, providerID int, claims SSOClaims) (*LinkResult, error) {
	result := &LinkResult{}
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, err := model.LockOrganizationTx(tx, orgID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return refuse(types.OrgErrNotFound)
		}
		if err != nil {
			return err
		}
		if org.Status != types.OrgStatusActive {
			return refuse(types.OrgErrSuspended)
		}
		if claims.Subject == "" {
			return refuse(types.OrgErrInvalidInput)
		}
		if _, err := ssoProviderTx(tx, orgID, providerID, claims.Issuer); err != nil {
			return err
		}
		var users []model.User
		if err := tx.Select("id", "status", "kind").Where("id = ?", globalUserID).Limit(1).Find(&users).Error; err != nil {
			return err
		}
		if len(users) == 0 || users[0].Status != common.UserStatusEnabled || users[0].IsBillingAccount() {
			return refuse(types.OrgErrForbidden)
		}
		mine, err := model.GetOrganizationMember(tx, orgID, globalUserID)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		identity, err := model.GetOrgIdentityBySubject(tx, orgID, providerID, claims.Subject)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		known := err == nil
		if known && identity.UserId == globalUserID && mine != nil && mine.Status == types.OrgMemberStatusActive {
			return nil // already linked: replay is a no-op
		}
		if mine != nil {
			return refuse(types.OrgErrConflict) // any other standing needs a person to untangle
		}
		if known {
			return replacePlaceholderTx(ctx, tx, org, identity, globalUserID, result)
		}
		return linkNewIdentityTx(ctx, tx, org, providerID, claims, globalUserID, result)
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func linkNewIdentityTx(ctx context.Context, tx *gorm.DB, org *model.Organization, providerID int, claims SSOClaims,
	globalUserID int, result *LinkResult) error {
	if !LoadSSOSettings(org).JITEnabled {
		return refuse(types.OrgErrJITDisabled)
	}
	email := normalizeClaimEmail(claims.Email)
	if !claims.EmailVerified || email == "" {
		return refuse(types.OrgErrEmailNotVerified)
	}
	now := common.GetTimestamp()
	identity := model.OrgIdentity{OrgId: org.Id, ProviderId: providerID, Issuer: claims.Issuer, Subject: claims.Subject,
		UserId: globalUserID, ClaimEmail: email, Source: types.OrgIdentitySourceSSO, Status: types.OrgIdentityActive,
		GlobalLinkVerifiedAt: now, CreatedAt: now, UpdatedAt: now}
	if err := tx.Create(&identity).Error; err != nil {
		return err
	}
	if _, err := AdmitMemberTx(tx, AdmitInput{OrgID: org.Id, UserID: globalUserID, OrgRole: types.OrgRoleMember, Source: types.OrgMemberSourceSSO}); err != nil {
		return err
	}
	revoked, err := joinDefaultWorkspaceTx(tx, org, globalUserID)
	if err != nil {
		return err
	}
	result.Joined, result.revocation = true, revoked
	return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: org.Id, ActorUserId: globalUserID, Action: "identity.link",
		TargetType: "member", TargetId: strconv.Itoa(globalUserID), Detail: map[string]any{"provider_id": identity.ProviderId, "replaced": false}})
}

func replacePlaceholderTx(ctx context.Context, tx *gorm.DB, org *model.Organization, identity *model.OrgIdentity,
	globalUserID int, result *LinkResult) error {
	if identity.Status != types.OrgIdentityActive {
		return refuse(types.OrgErrIdentityDisabled)
	}
	placeholderID := identity.UserId
	if placeholderID == globalUserID || identity.GlobalLinkVerifiedAt > 0 {
		return refuse(types.OrgErrConflict) // already bound to a global account
	}
	var holders []model.User
	if err := tx.Select("id", "email", "kind").Where("id = ?", placeholderID).Limit(1).Find(&holders).Error; err != nil {
		return err
	}
	if len(holders) == 0 || holders[0].Email != "" || holders[0].Kind != types.UserKindHuman {
		return refuse(types.OrgErrConflict) // only an email-less placeholder is ever replaced
	}
	old, err := model.LockOrganizationMemberTx(tx, org.Id, placeholderID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return refuse(types.OrgErrConflict)
	}
	if err != nil {
		return err
	}
	if old.Status != types.OrgMemberStatusActive || old.Role == types.OrgRoleOwner {
		return refuse(types.OrgErrConflict)
	}
	facts, err := model.OrgUserBusinessFactsTx(tx, org.Id, placeholderID)
	if err != nil {
		return err
	}
	if len(facts) > 0 {
		return refuse(types.OrgErrConflict)
	}
	var grants []model.WorkspaceMemberGrant
	if err := tx.Where("org_id = ? AND user_id = ?", org.Id, placeholderID).Find(&grants).Error; err != nil {
		return err
	}
	if err := model.SetOrganizationMemberStatusTx(tx, org.Id, placeholderID, types.OrgMemberStatusRemoved); err != nil {
		return err
	}
	if err := model.DeleteAllWorkspaceGrantsOfUserTx(tx, org.Id, placeholderID); err != nil {
		return err
	}
	source := old.Source
	if source != types.OrgMemberSourceSCIM {
		source = types.OrgMemberSourceSSO
	}
	if _, err := AdmitMemberTx(tx, AdmitInput{OrgID: org.Id, UserID: globalUserID, OrgRole: old.Role, Source: source}); err != nil {
		return err
	}
	for _, grant := range grants {
		if _, err := ApplyGrantTx(tx, org.Id, grant.WorkspaceId, globalUserID, grant.Source, grant.SourceRef, grant.Role, 0); err != nil {
			return err
		}
	}
	now := common.GetTimestamp()
	if err := tx.Model(&model.OrgIdentity{}).Where("id = ?", identity.Id).
		Updates(map[string]any{"user_id": globalUserID, "global_link_verified_at": now, "updated_at": now}).Error; err != nil {
		return err
	}
	version, err := model.DisableUserForReplacementTx(tx, placeholderID)
	if err != nil {
		return err
	}
	result.replacedUser, result.replacedVersion = placeholderID, version
	revoked, err := ReconcileMemberKeysTx(tx, org.Id, placeholderID, "identity_replaced")
	if err != nil {
		return err
	}
	result.Joined, result.Replaced, result.revocation = true, true, revoked
	return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: org.Id, ActorUserId: globalUserID, Action: "identity.link",
		TargetType: "member", TargetId: strconv.Itoa(globalUserID),
		Detail: map[string]any{"provider_id": identity.ProviderId, "replaced": true, "replaced_user_id": placeholderID}})
}

// ConfirmExternalIDIsSub is the platform-only switch that lets SCIM externalId
// stand for the OIDC sub. It has no organization-facing route.
func ConfirmExternalIDIsSub(ctx context.Context, orgID, platformActorID int, enabled bool) error {
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, err := model.LockOrganizationTx(tx, orgID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return refuse(types.OrgErrNotFound)
		}
		if err != nil {
			return err
		}
		settings := LoadSSOSettings(org)
		settings.ExternalIDIsSub = enabled
		if err := saveSSOSettingsTx(tx, org, settings); err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: platformActorID, ActorKind: "platform",
			Action: "sso.external_id_is_sub", TargetType: "organization", TargetId: org.Slug, Detail: map[string]any{"enabled": enabled}})
	})
}

// SSOConfigView is the owner's view of the organization's SSO. The client
// secret is never returned.
type SSOConfigView struct {
	Configured         bool     `json:"configured"`
	ProviderID         int      `json:"provider_id"`
	Issuer             string   `json:"issuer"`
	ClientID           string   `json:"client_id"`
	HasSecret          bool     `json:"has_secret"`
	Scopes             []string `json:"scopes"`
	Enabled            bool     `json:"enabled"`
	JITEnabled         bool     `json:"jit_enabled"`
	DefaultWorkspaceID int      `json:"default_workspace_id"`
	ExternalIDIsSub    bool     `json:"external_id_is_sub"`
}

func ssoConfigView(org *model.Organization, provider *model.CustomOAuthProvider) SSOConfigView {
	settings := LoadSSOSettings(org)
	view := SSOConfigView{JITEnabled: settings.JITEnabled, DefaultWorkspaceID: settings.DefaultWorkspaceID,
		ExternalIDIsSub: settings.ExternalIDIsSub, Scopes: []string{}}
	if provider != nil {
		view.Configured, view.ProviderID, view.Issuer, view.ClientID = true, provider.Id, provider.Issuer, provider.ClientId
		view.HasSecret, view.Enabled = provider.ClientSecret != "", provider.Enabled
		view.Scopes = strings.Fields(provider.Scopes)
	}
	return view
}

// GetSSOConfig returns the organization's SSO settings for its owner.
func GetSSOConfig(ctx context.Context, org *model.Organization) (SSOConfigView, error) {
	provider, err := OrgSSOProvider(model.DB.WithContext(ctx), org.Id)
	var access *types.OrgAccessError
	if errors.As(err, &access) {
		return ssoConfigView(org, nil), nil
	}
	if err != nil {
		return SSOConfigView{}, err
	}
	return ssoConfigView(org, provider), nil
}

// SSOConfigInput is everything the owner may set. Nil means "leave unchanged".
type SSOConfigInput struct {
	Issuer             *string
	ClientID           *string
	ClientSecret       *string
	Scopes             *string
	Enabled            *bool
	JITEnabled         *bool
	DefaultWorkspaceID *int
}

// UpdateSSOConfig creates or edits the organization's IdP. The issuer is set
// once: changing it later is refused, because identities are keyed to it.
// A tenant provider carries no endpoints; discovery supplies them (design 8.1).
func UpdateSSOConfig(ctx context.Context, actorID, orgID int, input SSOConfigInput) (SSOConfigView, error) {
	var view SSOConfigView
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner)
		if err != nil {
			return err
		}
		var providers []model.CustomOAuthProvider
		if err := tx.Where("org_id = ?", orgID).Order("id").Limit(1).Find(&providers).Error; err != nil {
			return err
		}
		var provider *model.CustomOAuthProvider
		if len(providers) == 1 {
			provider = &providers[0]
		}
		if provider == nil {
			if input.Issuer == nil || input.ClientID == nil || input.ClientSecret == nil {
				return refuse(types.OrgErrInvalidInput)
			}
			provider = &model.CustomOAuthProvider{Name: "SSO " + org.Slug, Slug: "org-" + strconv.Itoa(orgID) + "-sso",
				OrgId: orgID, Issuer: strings.TrimSpace(*input.Issuer), ClientId: strings.TrimSpace(*input.ClientID),
				ClientSecret: *input.ClientSecret, Enabled: true}
			if input.Scopes != nil {
				provider.Scopes = *input.Scopes
			}
			if input.Enabled != nil {
				provider.Enabled = *input.Enabled
			}
			if err := model.CreateCustomOAuthProviderTx(tx, provider); err != nil {
				return refuse(types.OrgErrInvalidInput)
			}
		} else {
			if input.Issuer != nil && strings.TrimSpace(*input.Issuer) != provider.Issuer {
				return refuse(types.OrgErrConflict)
			}
			if input.ClientID != nil {
				provider.ClientId = strings.TrimSpace(*input.ClientID)
			}
			if input.ClientSecret != nil && *input.ClientSecret != "" {
				provider.ClientSecret = *input.ClientSecret
			}
			if input.Scopes != nil {
				provider.Scopes = *input.Scopes
			}
			if input.Enabled != nil {
				provider.Enabled = *input.Enabled
			}
			if err := model.UpdateCustomOAuthProviderTx(tx, provider); err != nil {
				return refuse(types.OrgErrInvalidInput)
			}
		}
		settings := LoadSSOSettings(org)
		if input.JITEnabled != nil {
			settings.JITEnabled = *input.JITEnabled
		}
		if input.DefaultWorkspaceID != nil {
			if *input.DefaultWorkspaceID > 0 {
				workspace, err := defaultWorkspaceTx(tx, orgID, *input.DefaultWorkspaceID)
				if err != nil {
					return err
				}
				if workspace == nil {
					return refuse(types.OrgErrWorkspaceNotFound)
				}
			}
			settings.DefaultWorkspaceID = *input.DefaultWorkspaceID
		}
		if err := saveSSOSettingsTx(tx, org, settings); err != nil {
			return err
		}
		if err := model.BumpOrgPolicyVersionTx(tx, orgID); err != nil {
			return err
		}
		fresh, err := model.LockOrganizationTx(tx, orgID)
		if err != nil {
			return err
		}
		view = ssoConfigView(fresh, provider)
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "sso.update",
			TargetType: "sso", TargetId: strconv.Itoa(provider.Id),
			Detail: map[string]any{"enabled": provider.Enabled, "jit_enabled": settings.JITEnabled}})
	})
	return view, err
}

// SessionLive is the refresh-time check of an org-restricted session: the
// organization is active, the person is an enabled human and an active member,
// and their identity at the session's provider is active. It reads the primary
// database and fails closed.
func SessionLive(userID, orgID, providerID int) bool {
	db := model.DB
	var orgs []model.Organization
	if err := db.Select("id", "status").Where("id = ?", orgID).Limit(1).Find(&orgs).Error; err != nil || len(orgs) == 0 ||
		orgs[0].Status != types.OrgStatusActive {
		return false
	}
	var users []model.User
	if err := db.Select("id", "status", "kind").Where("id = ?", userID).Limit(1).Find(&users).Error; err != nil || len(users) == 0 ||
		users[0].Status != common.UserStatusEnabled || users[0].IsBillingAccount() {
		return false
	}
	member, err := model.GetOrganizationMember(db, orgID, userID)
	if err != nil || member.Status != types.OrgMemberStatusActive {
		return false
	}
	identity, err := model.GetOrgIdentityByUser(db, orgID, userID)
	return err == nil && identity.Status == types.OrgIdentityActive && identity.ProviderId == providerID
}

// AuditSSOEvent records an SSO event (sign-in, failure, proof issued, link).
// detail holds fixed codes and ids only; callers never pass claim text, tokens
// or cookies.
func AuditSSOEvent(ctx context.Context, orgID, userID int, action string, detail map[string]any) {
	if orgID <= 0 {
		return
	}
	if err := recordAudit(ctx, model.DB.WithContext(ctx), model.OrgAuditEntry{OrgId: orgID, ActorUserId: userID, ActorKind: "sso",
		Action: action, TargetType: "sso", Detail: detail}); err != nil {
		common.SysLog(common.LogText("failed to audit sso event: %s", err.Error()))
	}
}
