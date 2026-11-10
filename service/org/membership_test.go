package org

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func admit(db *gorm.DB, orgID, userID int, source string) (*AdmitResult, error) {
	var result *AdmitResult
	err := db.Transaction(func(tx *gorm.DB) error {
		var err error
		result, err = AdmitMemberTx(tx, AdmitInput{OrgID: orgID, UserID: userID, OrgRole: types.OrgRoleMember, Source: source})
		return err
	})
	return result, err
}

func setSeatLimit(t *testing.T, db *gorm.DB, orgID, limit int) {
	t.Helper()
	require.NoError(t, db.Model(&model.Organization{}).Where("id = ?", orgID).Update("seat_limit", limit).Error)
}

func TestOrgSeatAdmission(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()

		t.Run("ten people race for five free seats and exactly five get one", func(t *testing.T) {
			org, _ := orgWithMembers(t, db, "race10", nil)
			setSeatLimit(t, db, org.Id, 6) // the creator holds one
			var users []*model.User
			for i := range 10 {
				users = append(users, newUser(t, db, fmt.Sprintf("racer%d", i), fmt.Sprintf("racer%d@example.com", i)))
			}
			var ok, full atomic.Int32
			var wg sync.WaitGroup
			for _, user := range users {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := admit(db, org.Id, user.Id, types.OrgMemberSourceInvite)
					switch {
					case err == nil:
						ok.Add(1)
					case isRefusal(err, types.OrgErrSeatLimitReached):
						full.Add(1)
					default:
						t.Errorf("unexpected error: %v", err)
					}
				}()
			}
			wg.Wait()
			assert.EqualValues(t, 5, ok.Load())
			assert.EqualValues(t, 5, full.Load())
			used, err := SeatsInUse(db, org.Id)
			require.NoError(t, err)
			assert.Equal(t, 6, used)
			assert.EqualValues(t, 6, count(t, db, &model.OrganizationMember{}, "org_id = ? AND status = ?", org.Id, types.OrgMemberStatusActive))
		})

		t.Run("pending invitations hold seats until they expire or are revoked", func(t *testing.T) {
			org, u := orgWithMembers(t, db, "pending", nil)
			setSeatLimit(t, db, org.Id, 3)
			first, err := CreateInvite(ctx, u["creator"].Id, org.Id, CreateInviteInput{Email: "a@example.com", OrgRole: types.OrgRoleMember})
			require.NoError(t, err)
			_, err = CreateInvite(ctx, u["creator"].Id, org.Id, CreateInviteInput{Email: "b@example.com", OrgRole: types.OrgRoleMember})
			require.NoError(t, err)
			_, err = CreateInvite(ctx, u["creator"].Id, org.Id, CreateInviteInput{Email: "c@example.com", OrgRole: types.OrgRoleMember})
			requireRefusal(t, err, types.OrgErrSeatLimitReached)
			late := newUser(t, db, "late", "late@example.com")
			_, err = admit(db, org.Id, late.Id, types.OrgMemberSourceManual)
			requireRefusal(t, err, types.OrgErrSeatLimitReached)

			require.NoError(t, RevokeInvite(ctx, u["creator"].Id, org.Id, first.Invite.Id))
			_, err = admit(db, org.Id, late.Id, types.OrgMemberSourceManual)
			require.NoError(t, err, "a revoked invitation frees its seat")

			require.NoError(t, db.Model(&model.Invite{}).Where("org_id = ? AND email = ?", org.Id, "b@example.com").
				Update("expires_at", time.Now().Unix()-1).Error)
			used, err := SeatsInUse(db, org.Id)
			require.NoError(t, err)
			assert.Equal(t, 2, used, "an expired invitation no longer holds a seat")
			another := newUser(t, db, "another", "another@example.com")
			_, err = admit(db, org.Id, another.Id, types.OrgMemberSourceManual)
			require.NoError(t, err)
		})

		t.Run("an existing member accepting a workspace invitation takes no extra seat", func(t *testing.T) {
			org, u := orgWithMembers(t, db, "wsonly", map[string]string{"member": types.OrgRoleMember})
			setSeatLimit(t, db, org.Id, 2) // full: creator + member
			second := model.Workspace{OrgId: org.Id, Slug: "second", Name: "Second", Status: types.WorkspaceStatusActive}
			require.NoError(t, db.Create(&second).Error)
			issued, err := CreateInvite(ctx, u["creator"].Id, org.Id, CreateInviteInput{
				Email: u["member"].Email, WorkspaceID: second.Id, WorkspaceRole: types.WorkspaceRoleMember})
			require.NoError(t, err, "a member's workspace invitation needs no seat")
			used, err := SeatsInUse(db, org.Id)
			require.NoError(t, err)
			assert.Equal(t, 2, used, "the pending workspace invitation is not counted")
			accepted, err := AcceptInvite(ctx, u["member"].Id, issued.Token)
			require.NoError(t, err)
			assert.False(t, accepted.Joined, "no new organization membership")
			projected, err := model.GetWorkspaceMember(db, second.Id, u["member"].Id)
			require.NoError(t, err)
			assert.Equal(t, types.WorkspaceRoleMember, projected.Role)
			used, _ = SeatsInUse(db, org.Id)
			assert.Equal(t, 2, used)
		})

		t.Run("a plain workspace invitation to a member who is already in is refused as redundant", func(t *testing.T) {
			org, u := orgWithMembers(t, db, "redundant", map[string]string{"member": types.OrgRoleMember})
			_, err := CreateInvite(ctx, u["creator"].Id, org.Id, CreateInviteInput{Email: u["member"].Email, OrgRole: types.OrgRoleMember})
			requireRefusal(t, err, types.OrgErrConflict)
		})

		t.Run("returning members follow the source rules", func(t *testing.T) {
			org, u := orgWithMembers(t, db, "returns", map[string]string{"manual": types.OrgRoleMember, "scim": types.OrgRoleMember, "paused": types.OrgRoleMember})
			setStatus := func(name string, status int, source string) {
				require.NoError(t, db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", org.Id, u[name].Id).
					Updates(map[string]any{"status": status, "source": source}).Error)
			}
			setStatus("manual", types.OrgMemberStatusRemoved, types.OrgMemberSourceManual)
			setStatus("scim", types.OrgMemberStatusRemoved, types.OrgMemberSourceSCIM)
			setStatus("paused", types.OrgMemberStatusSuspended, types.OrgMemberSourceManual)

			_, err := admit(db, org.Id, u["paused"].Id, types.OrgMemberSourceInvite)
			requireRefusal(t, err, types.OrgErrMemberSuspended)
			_, err = admit(db, org.Id, u["scim"].Id, types.OrgMemberSourceInvite)
			requireRefusal(t, err, types.OrgErrMemberSuspended)
			_, err = admit(db, org.Id, u["scim"].Id, types.OrgMemberSourceDomain)
			requireRefusal(t, err, types.OrgErrMemberSuspended)
			_, err = admit(db, org.Id, u["manual"].Id, types.OrgMemberSourceDomain)
			requireRefusal(t, err, types.OrgErrMemberSuspended)

			result, err := admit(db, org.Id, u["manual"].Id, types.OrgMemberSourceInvite)
			require.NoError(t, err)
			assert.True(t, result.Joined)
			assert.Equal(t, types.OrgMemberStatusActive, result.Member.Status)
			result, err = admit(db, org.Id, u["scim"].Id, types.OrgMemberSourceSCIM)
			require.NoError(t, err)
			assert.True(t, result.Joined, "SCIM may restore what SCIM removed")
		})

		t.Run("a suspended or deleted organization admits nobody", func(t *testing.T) {
			org, _ := orgWithMembers(t, db, "closed", nil)
			require.NoError(t, db.Model(&model.Organization{}).Where("id = ?", org.Id).Update("status", types.OrgStatusSuspended).Error)
			stranger := newUser(t, db, "stranger", "stranger@example.com")
			_, err := admit(db, org.Id, stranger.Id, types.OrgMemberSourceInvite)
			requireRefusal(t, err, types.OrgErrSuspended)
		})

		t.Run("a billing wallet and a disabled account cannot be admitted", func(t *testing.T) {
			org, _ := orgWithMembers(t, db, "badusers", nil)
			var wallet model.User
			require.NoError(t, db.Where("kind = ?", types.UserKindBilling).First(&wallet).Error)
			_, err := admit(db, org.Id, wallet.Id, types.OrgMemberSourceManual)
			requireRefusal(t, err, types.OrgErrForbidden)
			off := newUser(t, db, "offuser", "off@example.com")
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", off.Id).Update("status", common.UserStatusDisabled).Error)
			_, err = admit(db, org.Id, off.Id, types.OrgMemberSourceManual)
			requireRefusal(t, err, types.OrgErrForbidden)
		})
	})
}

func isRefusal(err error, code string) bool {
	var access *types.OrgAccessError
	return errors.As(err, &access) && access.Code == code
}

func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestOrgInviteLinkWithoutVerification(t *testing.T) {
	previous := common.EmailVerificationEnabled
	common.EmailVerificationEnabled = false
	t.Cleanup(func() { common.EmailVerificationEnabled = previous })
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		org, u := orgWithMembers(t, db, "linkonly", map[string]string{})
		invite := func(email string) *InviteIssued {
			issued, err := CreateInvite(ctx, u["creator"].Id, org.Id, CreateInviteInput{Email: email, OrgRole: types.OrgRoleMember})
			require.NoError(t, err)
			return issued
		}
		holder := newUser(t, db, "linkholder", "")
		other := newUser(t, db, "otheraddr", "otheraddr@example.com")
		issued := invite("someone-else@example.com")
		_, err := AcceptInvite(ctx, holder.Id, issued.Token)
		require.NoError(t, err, "an account with no address redeems by holding the link")
		assert.Equal(t, types.OrgRoleMember, memberRole(t, db, org.Id, holder.Id))
		_, err = AcceptInvite(ctx, other.Id, issued.Token)
		requireRefusal(t, err, types.OrgErrInviteUsed)
		second := invite("another@example.com")
		_, err = AcceptInvite(ctx, other.Id, second.Token)
		require.NoError(t, err, "a different address also redeems")
		assert.Equal(t, types.OrgRoleMember, memberRole(t, db, org.Id, other.Id))
	})
}

func TestOrgInviteSecurity(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		org, u := orgWithMembers(t, db, "invsec", map[string]string{"admin": types.OrgRoleAdmin, "member": types.OrgRoleMember})
		invite := func(email, role string) *InviteIssued {
			issued, err := CreateInvite(ctx, u["creator"].Id, org.Id, CreateInviteInput{Email: email, OrgRole: role})
			require.NoError(t, err)
			return issued
		}

		t.Run("token is 256 bits, only its SHA-256 is stored, and it expires in seven days", func(t *testing.T) {
			issued := invite("tok@example.com", types.OrgRoleMember)
			raw, err := base64.RawURLEncoding.DecodeString(issued.Token)
			require.NoError(t, err)
			assert.Len(t, raw, 32)
			var row model.Invite
			require.NoError(t, db.First(&row, issued.Invite.Id).Error)
			assert.Equal(t, hashOf(issued.Token), row.TokenHash)
			assert.Len(t, row.TokenHash, 64)
			assert.NotContains(t, row.TokenHash, issued.Token)
			assert.InDelta(t, time.Now().Add(7*24*time.Hour).Unix(), row.ExpiresAt, 5)
			second := invite("tok2@example.com", types.OrgRoleMember)
			assert.NotEqual(t, issued.Token, second.Token)
			var leaked int64
			require.NoError(t, db.Model(&model.OrgAuditLog{}).Where("detail LIKE ?", "%"+issued.Token+"%").Count(&leaked).Error)
			assert.Zero(t, leaked, "audit rows never carry the token")
			for _, audit := range auditRows(t, db, org.Id) {
				assert.NotContains(t, audit.Detail, issued.Token)
				assert.NotContains(t, audit.Detail, row.TokenHash)
			}
		})

		t.Run("success joins once, grants the default workspace, and replay is refused", func(t *testing.T) {
			joiner := newUser(t, db, "joiner", "joiner@example.com")
			issued := invite("JOINER@example.com", types.OrgRoleBilling)
			accepted, err := AcceptInvite(ctx, joiner.Id, issued.Token)
			require.NoError(t, err)
			assert.True(t, accepted.Joined)
			assert.Equal(t, types.OrgRoleBilling, memberRole(t, db, org.Id, joiner.Id))
			var defaultWs model.Workspace
			require.NoError(t, db.Where("org_id = ? AND is_default = ?", org.Id, true).First(&defaultWs).Error)
			projected, err := model.GetWorkspaceMember(db, defaultWs.Id, joiner.Id)
			require.NoError(t, err)
			assert.Equal(t, types.WorkspaceRoleMember, projected.Role)
			var row model.Invite
			require.NoError(t, db.First(&row, issued.Invite.Id).Error)
			assert.Equal(t, types.InviteStatusAccepted, row.Status)
			assert.Equal(t, joiner.Id, row.AcceptedBy)

			_, err = AcceptInvite(ctx, joiner.Id, issued.Token)
			requireRefusal(t, err, types.OrgErrInviteUsed)
			other := newUser(t, db, "replayer", "joiner@example.com")
			_, err = AcceptInvite(ctx, other.Id, issued.Token)
			requireRefusal(t, err, types.OrgErrInviteUsed)
			assert.EqualValues(t, 1, count(t, db, &model.OrganizationMember{}, "org_id = ? AND user_id = ?", org.Id, joiner.Id))
		})

		t.Run("two simultaneous accepts of one token produce one membership", func(t *testing.T) {
			racer := newUser(t, db, "racer", "racer@example.com")
			issued := invite("racer@example.com", types.OrgRoleMember)
			var ok atomic.Int32
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := AcceptInvite(ctx, racer.Id, issued.Token); err == nil {
						ok.Add(1)
					}
				}()
			}
			wg.Wait()
			assert.EqualValues(t, 1, ok.Load())
		})

		t.Run("resend rotates the token, keeps one pending row, and kills the old token", func(t *testing.T) {
			person := newUser(t, db, "rotatee", "rotatee@example.com")
			first := invite("rotatee@example.com", types.OrgRoleMember)
			second := invite("rotatee@example.com", types.OrgRoleAdmin)
			assert.NotEqual(t, first.Token, second.Token)
			assert.Equal(t, first.Invite.Id, second.Invite.Id)
			assert.True(t, second.Rotated)
			assert.EqualValues(t, 1, count(t, db, &model.Invite{}, "org_id = ? AND email = ? AND status = ?", org.Id, "rotatee@example.com", types.InviteStatusPending))
			_, err := AcceptInvite(ctx, person.Id, first.Token)
			requireRefusal(t, err, types.OrgErrInviteNotFound)
			_, err = AcceptInvite(ctx, person.Id, second.Token)
			require.NoError(t, err)
			assert.Equal(t, types.OrgRoleAdmin, memberRole(t, db, org.Id, person.Id), "the resend carries the latest role")
		})

		t.Run("failures are distinct and a failed accept leaves the invitation usable", func(t *testing.T) {
			previous := common.EmailVerificationEnabled
			common.EmailVerificationEnabled = true
			t.Cleanup(func() { common.EmailVerificationEnabled = previous })
			rightful := newUser(t, db, "rightful", "rightful@example.com")
			wrong := newUser(t, db, "wrongful", "wrongful@example.com")
			noMail := newUser(t, db, "nomail", "")
			issued := invite("rightful@example.com", types.OrgRoleMember)
			_, err := AcceptInvite(ctx, wrong.Id, issued.Token)
			requireRefusal(t, err, types.OrgErrInviteEmailMismatch)
			_, err = AcceptInvite(ctx, noMail.Id, issued.Token)
			requireRefusal(t, err, types.OrgErrInviteEmailMismatch)
			_, err = AcceptInvite(ctx, rightful.Id, "not-a-token")
			requireRefusal(t, err, types.OrgErrInviteNotFound)
			_, err = AcceptInvite(ctx, rightful.Id, "")
			requireRefusal(t, err, types.OrgErrInviteNotFound)
			assert.Zero(t, count(t, db, &model.OrganizationMember{}, "org_id = ? AND user_id IN ?", org.Id, []int{wrong.Id, noMail.Id}))
			_, err = AcceptInvite(ctx, rightful.Id, issued.Token)
			require.NoError(t, err, "a mismatch must not burn the invitation")
		})

		t.Run("expired and revoked invitations are refused", func(t *testing.T) {
			person := newUser(t, db, "latecomer", "latecomer@example.com")
			expired := invite("latecomer@example.com", types.OrgRoleMember)
			require.NoError(t, db.Model(&model.Invite{}).Where("id = ?", expired.Invite.Id).Update("expires_at", time.Now().Unix()-1).Error)
			_, err := AcceptInvite(ctx, person.Id, expired.Token)
			requireRefusal(t, err, types.OrgErrInviteExpired)
			revoked := invite("latecomer@example.com", types.OrgRoleMember) // resend revives the expired row
			require.NoError(t, RevokeInvite(ctx, u["creator"].Id, org.Id, revoked.Invite.Id))
			_, err = AcceptInvite(ctx, person.Id, revoked.Token)
			requireRefusal(t, err, types.OrgErrInviteRevoked)
		})

		t.Run("who may invite, and as what", func(t *testing.T) {
			_, err := CreateInvite(ctx, u["member"].Id, org.Id, CreateInviteInput{Email: "x@example.com", OrgRole: types.OrgRoleMember})
			requireRefusal(t, err, types.OrgErrForbidden)
			_, err = CreateInvite(ctx, u["admin"].Id, org.Id, CreateInviteInput{Email: "x@example.com", OrgRole: types.OrgRoleOwner})
			requireRefusal(t, err, types.OrgErrOwnerRole)
			_, err = CreateInvite(ctx, u["creator"].Id, org.Id, CreateInviteInput{Email: "x@example.com", OrgRole: types.OrgRoleOwner})
			requireRefusal(t, err, types.OrgErrOwnerRole)
			for _, bad := range []string{"", "not-an-email", "a@b", strings.Repeat("x", 300) + "@example.com"} {
				_, err = CreateInvite(ctx, u["admin"].Id, org.Id, CreateInviteInput{Email: bad, OrgRole: types.OrgRoleMember})
				requireRefusal(t, err, types.OrgErrInvalidInput)
			}
			_, err = CreateInvite(ctx, u["admin"].Id, org.Id, CreateInviteInput{Email: "x@example.com", OrgRole: "root"})
			requireRefusal(t, err, types.OrgErrInvalidInput)
			_, err = CreateInvite(ctx, u["admin"].Id, org.Id, CreateInviteInput{Email: "y@example.com", OrgRole: types.OrgRoleMember, WorkspaceID: 99999})
			requireRefusal(t, err, types.OrgErrWorkspaceNotFound)
		})

		t.Run("a suspended organization cannot be joined through an old invitation", func(t *testing.T) {
			org2, v := orgWithMembers(t, db, "invsusp", nil)
			person := newUser(t, db, "suspjoin", "suspjoin@example.com")
			issued, err := CreateInvite(ctx, v["creator"].Id, org2.Id, CreateInviteInput{Email: "suspjoin@example.com", OrgRole: types.OrgRoleMember})
			require.NoError(t, err)
			require.NoError(t, db.Model(&model.Organization{}).Where("id = ?", org2.Id).Update("status", types.OrgStatusSuspended).Error)
			_, err = AcceptInvite(ctx, person.Id, issued.Token)
			requireRefusal(t, err, types.OrgErrSuspended)
		})

		t.Run("listing never exposes token material", func(t *testing.T) {
			list, err := ListInvites(ctx, org.Id)
			require.NoError(t, err)
			require.NotEmpty(t, list)
			encoded, err := common.Marshal(list)
			require.NoError(t, err)
			assert.NotContains(t, string(encoded), "token", "the list view has no token field of any kind")
		})
	})
}

func auditRows(t *testing.T, db *gorm.DB, orgID int) []model.OrgAuditLog {
	t.Helper()
	var rows []model.OrgAuditLog
	require.NoError(t, db.Where("org_id = ?", orgID).Find(&rows).Error)
	return rows
}
