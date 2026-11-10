package org

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// Management credentials (design section 7) are organization control-plane
// bearer tokens. They are not inference keys: the sk- path never resolves
// them, the plaintext is shown once, and only its SHA-256 is stored.

const (
	maxManagementCredentials = 50
	maxCredentialLifetime    = 366 * 24 * 3600
	credentialNameMaxRunes   = 64
)

// managementScopes is the closed scope vocabulary. An unknown scope is a
// refusal, never ignored: a typo must not silently narrow or widen a grant.
var managementScopes = []string{
	types.MgmtScopeKeysRead, types.MgmtScopeKeysWrite, types.MgmtScopeMembersRead, types.MgmtScopeMembersWrite,
	types.MgmtScopeUsageRead, types.MgmtScopeBillingRead, types.MgmtScopeAuditRead, types.MgmtScopeGuardrailsWrite,
	types.MgmtScopeSCIM,
}

// ValidManagementScope reports whether scope is in the vocabulary.
func ValidManagementScope(scope string) bool { return slices.Contains(managementScopes, scope) }

// roleScopes are the scopes a standing can use. Both administrator roles hold
// every personal-management scope; the intersection with the credential's own
// scopes is taken on every request, so the live role is what limits it.
func roleScopes(role string) []string {
	switch role {
	case types.OrgRoleOwner, types.OrgRoleAdmin:
		return slices.DeleteFunc(slices.Clone(managementScopes), func(scope string) bool { return scope == types.MgmtScopeSCIM })
	}
	return nil
}

type mgmtContextKey struct{}

// WithManagementCredential marks ctx as acting through a management
// credential. Organization role checks then cap the actor at administrator,
// credential administration refuses, and audit rows name the credential.
func WithManagementCredential(ctx context.Context, tokenID int) context.Context {
	return context.WithValue(ctx, mgmtContextKey{}, "mk_"+strconv.Itoa(tokenID))
}

func managementCredentialFrom(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	ref, ok := ctx.Value(mgmtContextKey{}).(string)
	return ref, ok
}

// CredentialView is the client representation of a credential. It never holds
// the plaintext or the stored hash.
type CredentialView struct {
	Id         int      `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Scopes     []string `json:"scopes"`
	TokenHint  string   `json:"token_hint"`
	CreatedBy  int      `json:"created_by"`
	ExpiresAt  int64    `json:"expires_at"`
	LastUsedAt int64    `json:"last_used_at"`
	Status     int      `json:"status"`
	CreatedAt  int64    `json:"created_at"`
}

func credentialView(token model.OrgAccessToken) CredentialView {
	scopes := []string{}
	_ = common.UnmarshalJsonStr(token.Scopes, &scopes)
	return CredentialView{Id: token.Id, Name: token.Name, Kind: token.Kind, Scopes: scopes, TokenHint: token.TokenHint,
		CreatedBy: token.CreatedBy, ExpiresAt: token.ExpiresAt, LastUsedAt: token.LastUsedAt, Status: token.Status, CreatedAt: token.CreatedAt}
}

// CreateCredentialInput is everything a client may choose.
type CreateCredentialInput struct {
	Name      string
	Kind      string
	Scopes    []string
	ExpiresAt int64
}

// CreatedCredential carries the plaintext exactly once.
type CreatedCredential struct {
	Credential CredentialView
	Plaintext  string
}

func normalizeScopes(kind string, scopes []string) ([]string, error) {
	seen := map[string]bool{}
	clean := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !ValidManagementScope(scope) {
			return nil, refuse(types.OrgErrInvalidInput)
		}
		if !seen[scope] {
			seen[scope] = true
			clean = append(clean, scope)
		}
	}
	if len(clean) == 0 {
		return nil, refuse(types.OrgErrInvalidInput)
	}
	slices.Sort(clean)
	hasSCIM := slices.Contains(clean, types.MgmtScopeSCIM)
	switch kind {
	case types.OrgAccessTokenSCIMService:
		// A SCIM credential is the scim scope and nothing else.
		if !hasSCIM || len(clean) != 1 {
			return nil, refuse(types.OrgErrInvalidInput)
		}
	case types.OrgAccessTokenPersonalManagement:
		if hasSCIM {
			return nil, refuse(types.OrgErrInvalidInput)
		}
	default:
		return nil, refuse(types.OrgErrInvalidInput)
	}
	return clean, nil
}

// CreateCredential issues a credential. The actor must be a live owner or
// admin; a management credential cannot issue another one, so no credential
// can create a more powerful successor.
func CreateCredential(ctx context.Context, actorID, orgID int, input CreateCredentialInput) (*CreatedCredential, error) {
	if _, viaCredential := managementCredentialFrom(ctx); viaCredential {
		return nil, refuse(types.OrgErrForbidden)
	}
	name := strings.TrimSpace(input.Name)
	if name == "" || utf8.RuneCountInString(name) > credentialNameMaxRunes {
		return nil, refuse(types.OrgErrInvalidInput)
	}
	scopes, err := normalizeScopes(input.Kind, input.Scopes)
	if err != nil {
		return nil, err
	}
	now := common.GetTimestamp()
	if input.ExpiresAt <= now || input.ExpiresAt > now+maxCredentialLifetime {
		return nil, refuse(types.OrgErrInvalidInput)
	}
	encoded, err := common.Marshal(scopes)
	if err != nil {
		return nil, err
	}
	prefix := types.ManagementKeyPrefix
	if input.Kind == types.OrgAccessTokenSCIMService {
		prefix = types.SCIMTokenPrefix
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	plaintext := prefix + hex.EncodeToString(secret)
	var created model.OrgAccessToken
	err = model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		var active int64
		if err := tx.Model(&model.OrgAccessToken{}).Where("org_id = ? AND status = ?", orgID, types.OrgAccessTokenActive).Count(&active).Error; err != nil {
			return err
		}
		if active >= maxManagementCredentials {
			return refuse(types.OrgErrConflict)
		}
		created = model.OrgAccessToken{OrgId: orgID, Name: name, TokenHash: model.HashOrgAccessToken(plaintext),
			TokenHint: plaintext[len(plaintext)-4:], Scopes: string(encoded), CreatedBy: actorID, Kind: input.Kind,
			ExpiresAt: input.ExpiresAt, Status: types.OrgAccessTokenActive, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&created).Error; err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "management_key.create",
			TargetType: "management_key", TargetId: strconv.Itoa(created.Id),
			Detail: map[string]any{"kind": input.Kind, "scopes": scopes, "expires_at": input.ExpiresAt}})
	})
	if err != nil {
		return nil, err
	}
	return &CreatedCredential{Credential: credentialView(created), Plaintext: plaintext}, nil
}

// ListCredentials returns the organization's credentials, newest first.
func ListCredentials(ctx context.Context, orgID int) ([]CredentialView, error) {
	var rows []model.OrgAccessToken
	if err := model.DB.WithContext(ctx).Where("org_id = ?", orgID).Order("id DESC").Limit(200).Find(&rows).Error; err != nil {
		return nil, err
	}
	views := make([]CredentialView, 0, len(rows))
	for _, row := range rows {
		views = append(views, credentialView(row))
	}
	return views, nil
}

// RenameCredential changes the display name only. Scopes and expiry never
// change in place: a wider grant is a new credential with its own proof.
func RenameCredential(ctx context.Context, actorID, orgID, credentialID int, name string) error {
	if _, viaCredential := managementCredentialFrom(ctx); viaCredential {
		return refuse(types.OrgErrForbidden)
	}
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > credentialNameMaxRunes {
		return refuse(types.OrgErrInvalidInput)
	}
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		result := tx.Model(&model.OrgAccessToken{}).Where("id = ? AND org_id = ?", credentialID, orgID).
			Updates(map[string]any{"name": name, "updated_at": common.GetTimestamp()})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return refuse(types.OrgErrKeyNotFound)
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "management_key.rename",
			TargetType: "management_key", TargetId: strconv.Itoa(credentialID)})
	})
}

// RevokeCredential ends a credential for good.
func RevokeCredential(ctx context.Context, actorID, orgID, credentialID int) error {
	if _, viaCredential := managementCredentialFrom(ctx); viaCredential {
		return refuse(types.OrgErrForbidden)
	}
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		locked, err := model.LockOrgAccessTokenTx(tx, orgID, credentialID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return refuse(types.OrgErrKeyNotFound)
		}
		if err != nil {
			return err
		}
		if locked.Status == types.OrgAccessTokenRevoked {
			return nil
		}
		if err := tx.Model(&model.OrgAccessToken{}).Where("id = ?", credentialID).
			Updates(map[string]any{"status": types.OrgAccessTokenRevoked, "updated_at": common.GetTimestamp()}).Error; err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "management_key.revoke",
			TargetType: "management_key", TargetId: strconv.Itoa(credentialID)})
	})
}

// ManagementPrincipal is the standing a valid credential proves right now.
type ManagementPrincipal struct {
	Token model.OrgAccessToken
	Org   *model.Organization
	// ActorUserID is the credential's creator for personal_management and 0 for
	// scim_service, whose creator is recorded for audit only.
	ActorUserID int
	// Role is the creator's live role capped at administrator.
	Role   string
	Scopes []string
	// Access is the organization standing handed to organization handlers.
	Access *OrgAccess
}

// HasScope reports whether the principal may use scope.
func (p *ManagementPrincipal) HasScope(scope string) bool { return slices.Contains(p.Scopes, scope) }

func invalidCredential() error { return refuse(types.OrgErrCredentialInvalid) }

// AuthenticateCredential resolves a bearer value to a principal for the wanted
// kind. Every failure before the organization is known is the same refusal.
//
//   - hash, status, expiry and kind are checked on every request;
//   - the organization must be active;
//   - personal_management also needs its creator to be an enabled human account
//     and a live owner or admin of this organization, and the usable scopes
//     are the intersection of the credential's scopes and that role's;
//   - scim_service needs exactly the scim scope and does not look at its creator.
func AuthenticateCredential(ctx context.Context, plaintext, wantKind string) (*ManagementPrincipal, error) {
	prefix := types.ManagementKeyPrefix
	if wantKind == types.OrgAccessTokenSCIMService {
		prefix = types.SCIMTokenPrefix
	}
	if !strings.HasPrefix(plaintext, prefix) || len(plaintext) > 128 {
		return nil, invalidCredential()
	}
	db := model.DB.WithContext(ctx)
	token, err := model.GetOrgAccessTokenByHash(db, model.HashOrgAccessToken(plaintext))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, invalidCredential()
	}
	if err != nil {
		return nil, unavailable(err)
	}
	if token.Kind != wantKind || token.Status != types.OrgAccessTokenActive ||
		(token.ExpiresAt > 0 && token.ExpiresAt <= common.GetTimestamp()) {
		return nil, invalidCredential()
	}
	var scopes []string
	if err := common.UnmarshalJsonStr(token.Scopes, &scopes); err != nil || len(scopes) == 0 {
		return nil, invalidCredential()
	}
	for _, scope := range scopes {
		if !ValidManagementScope(scope) {
			return nil, invalidCredential()
		}
	}
	var orgs []model.Organization
	if err := db.Where("id = ?", token.OrgId).Limit(1).Find(&orgs).Error; err != nil {
		return nil, unavailable(err)
	}
	if len(orgs) == 0 || orgs[0].Status == types.OrgStatusDeleted {
		return nil, invalidCredential()
	}
	org := &orgs[0]
	if org.Status != types.OrgStatusActive {
		return nil, refuse(types.OrgErrSuspended)
	}
	principal := &ManagementPrincipal{Token: *token, Org: org}
	if wantKind == types.OrgAccessTokenSCIMService {
		if len(scopes) != 1 || scopes[0] != types.MgmtScopeSCIM {
			return nil, invalidCredential()
		}
		principal.Scopes = scopes
		return principal, nil
	}
	if slices.Contains(scopes, types.MgmtScopeSCIM) {
		return nil, invalidCredential()
	}
	var users []model.User
	if err := db.Select("id", "status", "kind").Where("id = ?", token.CreatedBy).Limit(1).Find(&users).Error; err != nil {
		return nil, unavailable(err)
	}
	if len(users) == 0 || users[0].Status != common.UserStatusEnabled || users[0].IsBillingAccount() {
		return nil, invalidCredential()
	}
	member, err := model.GetOrganizationMember(db, org.Id, token.CreatedBy)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, invalidCredential()
	}
	if err != nil {
		return nil, unavailable(err)
	}
	if member.Status != types.OrgMemberStatusActive || !model.OrgRoleAtLeast(member.Role, types.OrgRoleAdmin) {
		return nil, invalidCredential()
	}
	allowed := roleScopes(member.Role)
	for _, scope := range scopes {
		if slices.Contains(allowed, scope) {
			principal.Scopes = append(principal.Scopes, scope)
		}
	}
	capped := *member
	capped.Role = types.OrgRoleAdmin
	principal.ActorUserID, principal.Role = token.CreatedBy, types.OrgRoleAdmin
	principal.Access = &OrgAccess{Org: org, Member: capped}
	return principal, nil
}
