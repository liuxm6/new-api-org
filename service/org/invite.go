package org

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

const (
	// InviteTTL is how long an invitation stays valid; a resend starts it again.
	InviteTTL = 7 * 24 * time.Hour

	inviteTokenBytes = 32 // 256 bits
	inviteEmailMax   = 254
)

// HashInviteToken is the only form of a token that is stored or compared.
func HashInviteToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newInviteToken returns a 256-bit URL-safe random token and its hash.
func newInviteToken() (token, hash string, err error) {
	raw := make([]byte, inviteTokenBytes)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashInviteToken(token), nil
}

// NormalizeInviteEmail lower-cases and validates an address. It must be a bare
// address with a dotted domain; display names and comments are refused.
func NormalizeInviteEmail(email string) (string, bool) {
	email = model.NormalizeEmail(email)
	if email == "" || len(email) > inviteEmailMax {
		return "", false
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email {
		return "", false
	}
	_, domain, _ := strings.Cut(email, "@")
	return email, strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".")
}

// CreateInviteInput is an invitation request. WorkspaceID 0 invites to the
// organization (and its default workspace); otherwise to that workspace.
type CreateInviteInput struct {
	Email         string
	OrgRole       string
	WorkspaceID   int
	WorkspaceRole string
}

// InviteIssued carries the one and only copy of the plaintext token. The
// caller (controller or parent service) puts it in the email or the response;
// nothing here stores or logs it.
type InviteIssued struct {
	Invite  model.Invite
	Token   string
	Rotated bool
}

// CreateInvite issues an invitation, or re-issues the pending one for the same
// address: a resend rotates the token, restarts the seven days and takes the
// latest roles, so there is never more than one pending invitation per
// organization and address and the old link stops working. A pending
// invitation holds a seat unless the address already belongs to a member.
func CreateInvite(ctx context.Context, actorID, orgID int, in CreateInviteInput) (*InviteIssued, error) {
	var issued *InviteIssued
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		org, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin)
		if err != nil {
			return err
		}
		email, ok := NormalizeInviteEmail(in.Email)
		if !ok {
			return refuse(types.OrgErrInvalidInput)
		}
		orgRole, wsRole := in.OrgRole, in.WorkspaceRole
		if orgRole == "" {
			orgRole = types.OrgRoleMember
		}
		if wsRole == "" {
			wsRole = types.WorkspaceRoleMember
		}
		if !validOrgRole(orgRole) || !model.ValidWorkspaceRole(wsRole) {
			return refuse(types.OrgErrInvalidInput)
		}
		if orgRole == types.OrgRoleOwner {
			return refuse(types.OrgErrOwnerRole)
		}
		if in.WorkspaceID > 0 {
			var workspaces int64
			if err := tx.Model(&model.Workspace{}).Where("id = ? AND org_id = ? AND status = ?",
				in.WorkspaceID, orgID, types.WorkspaceStatusActive).Count(&workspaces).Error; err != nil {
				return err
			}
			if workspaces == 0 {
				return refuse(types.OrgErrWorkspaceNotFound)
			}
		}
		_, memberErr := model.OrgMemberByEmail(tx, orgID, email)
		if memberErr != nil && !errors.Is(memberErr, gorm.ErrRecordNotFound) {
			return memberErr
		}
		alreadyMember := memberErr == nil
		if alreadyMember && in.WorkspaceID == 0 {
			return refuse(types.OrgErrConflict)
		}
		if !alreadyMember {
			seats, err := model.CountOrgSeats(tx, orgID, email, true)
			if err != nil {
				return err
			}
			if seats >= org.SeatLimit {
				return refuse(types.OrgErrSeatLimitReached)
			}
		}

		token, hash, err := newInviteToken()
		if err != nil {
			return err
		}
		now := common.GetTimestamp()
		expires := time.Now().Add(InviteTTL).Unix()
		var pending []model.Invite
		if err := tx.Where("org_id = ? AND email = ? AND status = ?", orgID, email, types.InviteStatusPending).
			Limit(1).Find(&pending).Error; err != nil {
			return err
		}
		action := "invite.create"
		if len(pending) == 1 {
			action = "invite.resend"
			if err := tx.Model(&model.Invite{}).Where("id = ?", pending[0].Id).Updates(map[string]any{
				"token_hash": hash, "expires_at": expires, "org_role": orgRole, "ws_role": wsRole,
				"workspace_id": in.WorkspaceID, "invited_by": actorID}).Error; err != nil {
				return err
			}
			pending[0].TokenHash, pending[0].ExpiresAt, pending[0].OrgRole, pending[0].WsRole = hash, expires, orgRole, wsRole
			pending[0].WorkspaceId, pending[0].InvitedBy = in.WorkspaceID, actorID
			issued = &InviteIssued{Invite: pending[0], Token: token, Rotated: true}
		} else {
			invite := model.Invite{OrgId: orgID, WorkspaceId: in.WorkspaceID, Email: email, OrgRole: orgRole, WsRole: wsRole,
				TokenHash: hash, Status: types.InviteStatusPending, InvitedBy: actorID, ExpiresAt: expires, CreatedAt: now}
			if err := tx.Create(&invite).Error; err != nil {
				return err
			}
			issued = &InviteIssued{Invite: invite, Token: token}
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: action, TargetType: "invite",
			TargetId: itoa(issued.Invite.Id), Detail: map[string]any{"email": email, "org_role": orgRole, "workspace_id": in.WorkspaceID}})
	})
	if err != nil {
		return nil, err
	}
	return issued, nil
}

// AcceptResult reports what accepting an invitation did.
type AcceptResult struct {
	Org         model.Organization
	Joined      bool
	WorkspaceID int
}

// AcceptInvite redeems a token for the signed-in person. The checks run in a
// fixed order inside one transaction under the organization lock:
// unknown token, already used, revoked, expired, then the address match. When
// email verification is enabled the address of the signed-in account must
// equal the invited address, and the account must hold one (addresses reach
// users.email only through a verification code, email binding or a trusted
// OAuth provider). When it is disabled, holding the link is enough. A mismatch
// does not burn the invitation. Success consumes it exactly once; a second
// redemption, concurrent or later, fails.
func AcceptInvite(ctx context.Context, userID int, token string) (*AcceptResult, error) {
	hash := HashInviteToken(token)
	var result *AcceptResult
	// The unlocked read only finds which organization to lock first, so the lock
	// order is always organization, then invitation.
	probe, err := model.GetInviteByTokenHash(model.DB.WithContext(ctx), hash)
	if token == "" || errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, refuse(types.OrgErrInviteNotFound)
	}
	if err != nil {
		return nil, err
	}
	err = model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, err := model.LockOrganizationTx(tx, probe.OrgId); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return refuse(types.OrgErrNotFound)
			}
			return err
		}
		invite, err := model.LockInviteByTokenHashTx(tx, hash)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return refuse(types.OrgErrInviteNotFound)
		}
		if err != nil {
			return err
		}
		switch {
		case invite.Status == types.InviteStatusAccepted:
			return refuse(types.OrgErrInviteUsed)
		case invite.Status == types.InviteStatusRevoked:
			return refuse(types.OrgErrInviteRevoked)
		case invite.Status != types.InviteStatusPending, invite.ExpiresAt <= time.Now().Unix():
			return refuse(types.OrgErrInviteExpired)
		}
		var user model.User
		if err := tx.Select("id", "email", "status", "kind").Where("id = ?", userID).Take(&user).Error; err != nil {
			return refuse(types.OrgErrForbidden)
		}
		// Without email verification no account can hold a trusted address, so
		// holding the link is the proof and the address is not compared.
		if common.EmailVerificationEnabled && model.NormalizeEmail(user.Email) != invite.Email {
			return refuse(types.OrgErrInviteEmailMismatch)
		}
		admitted, err := AdmitMemberTx(tx, AdmitInput{OrgID: invite.OrgId, UserID: userID, OrgRole: invite.OrgRole,
			Source: types.OrgMemberSourceInvite, InvitedBy: invite.InvitedBy})
		if err != nil {
			return err
		}
		workspaceID := invite.WorkspaceId
		if workspaceID == 0 && admitted.Joined {
			var defaults []model.Workspace
			if err := tx.Where("org_id = ? AND is_default = ?", invite.OrgId, true).Limit(1).Find(&defaults).Error; err != nil {
				return err
			}
			if len(defaults) == 1 {
				workspaceID = defaults[0].Id
			}
		}
		if workspaceID > 0 {
			if _, err := model.UpsertWorkspaceGrantTx(tx, invite.OrgId, workspaceID, userID,
				model.GrantSourceManual, "", invite.WsRole); err != nil {
				return err
			}
		}
		consumed := tx.Model(&model.Invite{}).Where("id = ? AND status = ?", invite.Id, types.InviteStatusPending).
			Updates(map[string]any{"status": types.InviteStatusAccepted, "accepted_by": userID, "accepted_at": common.GetTimestamp()})
		if consumed.Error != nil {
			return consumed.Error
		}
		if consumed.RowsAffected != 1 {
			return refuse(types.OrgErrInviteUsed)
		}
		if err := recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: invite.OrgId, ActorUserId: userID, Action: "invite.accept",
			TargetType: "invite", TargetId: itoa(invite.Id), Detail: map[string]any{"joined": admitted.Joined, "workspace_id": workspaceID}}); err != nil {
			return err
		}
		result = &AcceptResult{Org: *admitted.Org, Joined: admitted.Joined, WorkspaceID: workspaceID}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RevokeInvite withdraws a pending invitation, which frees its seat at once.
// Revoking an already revoked invitation is a no-op; an accepted one cannot be
// revoked.
func RevokeInvite(ctx context.Context, actorID, orgID, inviteID int) error {
	return model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if _, _, err := RequireOrgRoleTx(tx, orgID, actorID, types.OrgRoleOwner, types.OrgRoleAdmin); err != nil {
			return err
		}
		var invites []model.Invite
		if err := tx.Where("id = ? AND org_id = ?", inviteID, orgID).Limit(1).Find(&invites).Error; err != nil {
			return err
		}
		if len(invites) == 0 {
			return refuse(types.OrgErrInviteNotFound)
		}
		switch invites[0].Status {
		case types.InviteStatusRevoked:
			return nil
		case types.InviteStatusAccepted:
			return refuse(types.OrgErrInviteUsed)
		}
		if err := tx.Model(&model.Invite{}).Where("id = ? AND status = ?", inviteID, types.InviteStatusPending).
			Update("status", types.InviteStatusRevoked).Error; err != nil {
			return err
		}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, ActorUserId: actorID, Action: "invite.revoke",
			TargetType: "invite", TargetId: itoa(inviteID)})
	})
}

// InviteView is the list representation of an invitation. It has no token or
// hash: the plaintext exists only in the issuing response and the email.
type InviteView struct {
	Id          int    `json:"id"`
	Email       string `json:"email"`
	OrgRole     string `json:"org_role"`
	WsRole      string `json:"ws_role"`
	WorkspaceId int    `json:"workspace_id"`
	// State is pending, expired, accepted or revoked; expiry is derived from the
	// clock so no background job has to flip a row.
	State     string `json:"state"`
	InvitedBy int    `json:"invited_by"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
}

// ListInvites returns the organization's invitations, newest first.
func ListInvites(ctx context.Context, orgID int) ([]InviteView, error) {
	var rows []model.Invite
	if err := model.DB.WithContext(ctx).Where("org_id = ?", orgID).Order("id DESC").Limit(500).Find(&rows).Error; err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	views := make([]InviteView, 0, len(rows))
	for _, row := range rows {
		state := map[int]string{types.InviteStatusPending: "pending", types.InviteStatusAccepted: "accepted",
			types.InviteStatusRevoked: "revoked", types.InviteStatusExpired: "expired"}[row.Status]
		if row.Status == types.InviteStatusPending && row.ExpiresAt <= now {
			state = "expired"
		}
		views = append(views, InviteView{Id: row.Id, Email: row.Email, OrgRole: row.OrgRole, WsRole: row.WsRole,
			WorkspaceId: row.WorkspaceId, State: state, InvitedBy: row.InvitedBy, ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt})
	}
	return views, nil
}
