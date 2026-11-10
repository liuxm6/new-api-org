package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// ErrOrgIdentityConflict is returned when a subject, an externalId or a
// userName is already bound to a different person in the same provider scope.
var ErrOrgIdentityConflict = errors.New("organization identity is already bound to another user")

// CreateOrgPlaceholderUserTx creates the human account behind a tenant IdP
// identity inside the caller's transaction. Like CreateBillingAccountTx it
// bypasses User.Insert and finishInsert: the account has no email (the IdP's
// claim lives on org_identities only, so password recovery and automatic OAuth
// binding can never reach it), a random password nobody knows, zero quota, no
// sign-up bonus and no invitation reward. The caller owns commit and rollback.
func CreateOrgPlaceholderUserTx(tx *gorm.DB, displayName, group string) (*User, error) {
	if tx == nil {
		return nil, errors.New("transaction is required")
	}
	if group == "" {
		group = "default"
	}
	password, err := common.HashAccountPassword(common.GetRandomString(32))
	if err != nil {
		return nil, err
	}
	user := &User{
		Username: "sso_" + common.GetRandomString(12),
		Password: password,
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
		Group:    group,
		AffCode:  common.GetRandomString(12),
		Quota:    0,
		Kind:     types.UserKindHuman,
	}
	displayName = strings.TrimSpace(displayName)
	if utf8.RuneCountInString(displayName) > 20 {
		displayName = string([]rune(displayName)[:20])
	}
	if displayName == "" {
		displayName = user.Username
	}
	user.DisplayName = displayName
	if err := tx.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

// GetOrgIdentityBySubject returns the identity of (org, provider, subject) in
// any status. A missing row is gorm.ErrRecordNotFound.
func GetOrgIdentityBySubject(tx *gorm.DB, orgID, providerID int, subject string) (*OrgIdentity, error) {
	return findOrgIdentity(tx, "org_id = ? AND provider_id = ? AND subject = ?", orgID, providerID, subject)
}

// GetOrgIdentityByExternalID looks an identity up by its SCIM externalId in
// one organization and provider. Isolation by org and provider is part of the
// key, so another organization's externalId is never visible here.
func GetOrgIdentityByExternalID(tx *gorm.DB, orgID, providerID int, externalID string) (*OrgIdentity, error) {
	return findOrgIdentity(tx, "org_id = ? AND provider_id = ? AND scim_external_id = ?", orgID, providerID, externalID)
}

// GetOrgIdentityByID returns one identity of one organization.
func GetOrgIdentityByID(tx *gorm.DB, orgID, id int) (*OrgIdentity, error) {
	return findOrgIdentity(tx, "org_id = ? AND id = ?", orgID, id)
}

// GetOrgIdentityByUser returns the identity a user holds in one organization.
func GetOrgIdentityByUser(tx *gorm.DB, orgID, userID int) (*OrgIdentity, error) {
	return findOrgIdentity(tx, "org_id = ? AND user_id = ? AND status <> ?", orgID, userID, types.OrgIdentityRemoved)
}

func findOrgIdentity(tx *gorm.DB, query string, args ...any) (*OrgIdentity, error) {
	var rows []OrgIdentity
	if err := tx.Where(query, args...).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &rows[0], nil
}

// OrgIdentityByUserNameTx finds a live identity of the provider whose
// claim_email (the SCIM userName) equals userName, other than excludeID.
func OrgIdentityByUserNameTx(tx *gorm.DB, orgID, providerID int, userName string, excludeID int) (*OrgIdentity, error) {
	query := tx.Where("org_id = ? AND provider_id = ? AND claim_email = ? AND status <> ?", orgID, providerID, userName, types.OrgIdentityRemoved)
	if excludeID > 0 {
		query = query.Where("id <> ?", excludeID)
	}
	var rows []OrgIdentity
	if err := query.Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &rows[0], nil
}

// OrgUserBusinessFactsTx lists, in non-secret words, what the user has done in
// the organization: keys, tasks, billed operations, spend, management
// credentials and budgets. Linking an IdP identity to a different global
// account refuses when any exist, because financial history is never migrated.
func OrgUserBusinessFactsTx(tx *gorm.DB, orgID, userID int) ([]string, error) {
	checks := []struct {
		reason string
		model  any
		where  string
		args   []any
	}{
		{"keys", &Token{}, "org_id = ? AND created_by = ?", []any{orgID, userID}},
		{"tasks", &Task{}, "org_id = ? AND actor_user_id = ?", []any{orgID, userID}},
		{"midjourney_tasks", &Midjourney{}, "org_id = ? AND actor_user_id = ?", []any{orgID, userID}},
		{"spend_events", &OrgSpendEvent{}, "org_id = ? AND actor_user_id = ?", []any{orgID, userID}},
		{"billing_operations", &OrgBillingOperation{}, "org_id = ? AND actor_user_id = ?", []any{orgID, userID}},
		{"management_credentials", &OrgAccessToken{}, "org_id = ? AND created_by = ?", []any{orgID, userID}},
		{"budgets", &Budget{}, "org_id = ? AND scope = ? AND subject_id = ?", []any{orgID, types.BudgetScopeMember, userID}},
		{"budget_usage", &OrgBudgetUsage{}, "org_id = ? AND scope = ? AND subject_id = ?", []any{orgID, types.BudgetScopeMember, userID}},
	}
	var reasons []string
	for _, check := range checks {
		var n int64
		if err := tx.Unscoped().Model(check.model).Where(check.where, check.args...).Count(&n).Error; err != nil {
			return nil, err
		}
		if n > 0 {
			reasons = append(reasons, check.reason)
		}
	}
	return reasons, nil
}

// DisableUserForReplacementTx disables an emptied placeholder account and
// advances its auth version so any session it still holds dies. It returns the
// new version for PublishCommittedAuthVersion.
func DisableUserForReplacementTx(tx *gorm.DB, userID int) (int64, error) {
	if err := tx.Model(&User{}).Where("id = ?", userID).Update("status", common.UserStatusDisabled).Error; err != nil {
		return 0, err
	}
	return IncrementUserAuthVersionWithTx(tx, userID)
}

// PublishCommittedAuthVersion exposes an auth version committed by a service
// transaction to the cache layer. Call it after the transaction committed.
func PublishCommittedAuthVersion(userID int, version int64) {
	if version <= 0 {
		return
	}
	if err := publishCommittedUserAuthVersion(userID, version); err != nil {
		common.SysLog(common.LogText("failed to publish auth version: %s", err.Error()))
	}
}

// RevokeOrgScopedSessions revokes every active session the user holds that is
// restricted to the organization. Global sessions are left alone: membership
// loss ends the tenant session, not the person's own account. Sessions are
// fenced through the same path as every other bulk revoke.
func RevokeOrgScopedSessions(userID, orgID int, reason string) error {
	if userID <= 0 || orgID <= 0 {
		return nil
	}
	now := time.Now().Unix()
	var sessions []UserSession
	if err := DB.Where("user_id = ? AND auth_scope = ? AND org_id = ? AND status = ? AND expires_at > ?",
		userID, types.AuthScopeOrg, orgID, UserSessionStatusActive, now).Find(&sessions).Error; err != nil {
		return err
	}
	for i := range sessions {
		if _, err := RevokeUserSession(userID, sessions[i].SID, reason); err != nil {
			return err
		}
	}
	return nil
}

// HashOrgAccessToken is the stored form of a management or SCIM credential.
// The plaintext carries 256 bits of randomness, so one SHA-256 round is the
// right construction (a slow password hash would only add a login-time cost);
// it matches UserAccessToken.
func HashOrgAccessToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// GetOrgAccessTokenByHash finds a credential by the hash of its plaintext, in
// any status. A missing row is gorm.ErrRecordNotFound.
func GetOrgAccessTokenByHash(db *gorm.DB, hash string) (*OrgAccessToken, error) {
	var rows []OrgAccessToken
	if err := db.Where("token_hash = ?", hash).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &rows[0], nil
}

// TouchOrgAccessToken records use at most once a minute, so a busy integration
// does not turn every request into a write.
func TouchOrgAccessToken(db *gorm.DB, token *OrgAccessToken, ip string) {
	now := common.GetTimestamp()
	if now-token.LastUsedAt < 60 {
		return
	}
	_ = db.Model(&OrgAccessToken{}).Where("id = ?", token.Id).
		Updates(map[string]any{"last_used_at": now, "last_used_ip": truncateString(ip, 64)}).Error
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// LockOrgAccessTokenTx reads one credential of one organization under a row
// lock. A missing row is gorm.ErrRecordNotFound.
func LockOrgAccessTokenTx(tx *gorm.DB, orgID, id int) (*OrgAccessToken, error) {
	var rows []OrgAccessToken
	if err := lockForUpdate(tx).Where("id = ? AND org_id = ?", id, orgID).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &rows[0], nil
}

// LockOrgIdentityTx reads one identity of one organization under a row lock.
func LockOrgIdentityTx(tx *gorm.DB, orgID, id int) (*OrgIdentity, error) {
	var rows []OrgIdentity
	if err := lockForUpdate(tx).Where("org_id = ? AND id = ?", orgID, id).Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &rows[0], nil
}
