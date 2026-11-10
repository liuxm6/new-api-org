package org

import (
	"context"
	"sync"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func (o *scimOrg) claims(sub, email string) SSOClaims {
	return SSOClaims{Issuer: o.provider.Issuer, Subject: sub, Email: email, EmailVerified: true, Name: email}
}

// TestOrgLinkStore exercises the account-link transaction on every database:
// row locks, the placeholder swap and the conflicts that must leave both
// principals untouched.
func TestOrgLinkStore(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		o := newScimOrg(t, db, "linkstore", true)
		login := func(sub string) int {
			result, err := o.login(sub, sub+"@corp.example", true)
			require.NoError(t, err)
			return result.UserID
		}

		t.Run("a clean placeholder is replaced and its access moves", func(t *testing.T) {
			placeholder := login("sub-a")
			global := newUser(t, db, "linkstore-a", "a@home.example")
			result, err := LinkGlobalAccount(ctx, global.Id, o.org.Id, o.provider.Id, o.claims("sub-a", "a@corp.example"))
			require.NoError(t, err)
			PublishLinkResult(result, o.org.Id)
			assert.True(t, result.Replaced)
			old, _ := model.GetOrganizationMember(db, o.org.Id, placeholder)
			assert.Equal(t, types.OrgMemberStatusRemoved, old.Status)
			now, err := model.GetOrganizationMember(db, o.org.Id, global.Id)
			require.NoError(t, err)
			assert.Equal(t, types.OrgMemberStatusActive, now.Status)
			identity, _ := model.GetOrgIdentityBySubject(db, o.org.Id, o.provider.Id, "sub-a")
			assert.Equal(t, global.Id, identity.UserId)
			assert.NotZero(t, identity.GlobalLinkVerifiedAt)
			var emptied model.User
			require.NoError(t, db.First(&emptied, placeholder).Error)
			assert.Equal(t, common.UserStatusDisabled, emptied.Status)
			seats, _ := SeatsInUse(db, o.org.Id)
			assert.Equal(t, 4, seats, "owner, admin, plain and the linked person: the swap freed and took one seat")

			again, err := LinkGlobalAccount(ctx, global.Id, o.org.Id, o.provider.Id, o.claims("sub-a", "a@corp.example"))
			require.NoError(t, err)
			assert.False(t, again.Replaced, "a replay is a no-op")
		})

		t.Run("each kind of business fact refuses with a conflict and changes nothing", func(t *testing.T) {
			facts := map[string]func(userID int) any{
				"key": func(u int) any {
					return &model.Token{UserId: o.wallet, Key: "lk-key-" + common.GetRandomString(12), Name: "k", Status: 1, ExpiredTime: -1, UnlimitedQuota: true, OrgId: o.org.Id, WorkspaceId: o.main.Id, CreatedBy: u, OwnerType: types.TokenOwnerMember, AccessPrincipalId: "p-" + common.GetRandomString(8)}
				},
				"task": func(u int) any {
					return &model.Task{OrgId: o.org.Id, ActorUserId: u, TaskID: "lk-task-" + common.GetRandomString(8)}
				},
				"spend": func(u int) any {
					return &model.OrgSpendEvent{OrgId: o.org.Id, ActorUserId: u, OperationId: "op-" + common.GetRandomString(10), EventKind: "capture", Revision: 1, DeltaQuota: 1}
				},
				"operation": func(u int) any {
					return &model.OrgBillingOperation{OrgId: o.org.Id, ActorUserId: u, OperationId: "bo-" + common.GetRandomString(10)}
				},
				"credential": func(u int) any {
					return &model.OrgAccessToken{OrgId: o.org.Id, CreatedBy: u, TokenHash: "h-" + common.GetRandomString(20), Kind: types.OrgAccessTokenPersonalManagement, Status: 2}
				},
				"budget": func(u int) any {
					return &model.Budget{OrgId: o.org.Id, Scope: types.BudgetScopeMember, SubjectId: u, Period: types.BudgetPeriodMonthly, LimitQuota: 10}
				},
			}
			for name, make := range facts {
				sub := "sub-fact-" + name
				placeholder := login(sub)
				require.NoError(t, db.Create(make(placeholder)).Error, name)
				global := newUser(t, db, "linkstore-"+name, name+"@home.example")
				_, err := LinkGlobalAccount(ctx, global.Id, o.org.Id, o.provider.Id, o.claims(sub, sub+"@corp.example"))
				requireRefusal(t, err, types.OrgErrConflict)
				member, _ := model.GetOrganizationMember(db, o.org.Id, placeholder)
				assert.Equal(t, types.OrgMemberStatusActive, member.Status, name)
				_, err = model.GetOrganizationMember(db, o.org.Id, global.Id)
				assert.ErrorIs(t, err, gorm.ErrRecordNotFound, name)
				identity, _ := model.GetOrgIdentityBySubject(db, o.org.Id, o.provider.Id, sub)
				assert.Equal(t, placeholder, identity.UserId, name)
				assert.Zero(t, identity.GlobalLinkVerifiedAt, name)
			}
		})

		t.Run("an account already linked to someone else, an owner and a standing member are conflicts", func(t *testing.T) {
			linked := login("sub-linked")
			real := newUser(t, db, "linkstore-real", "real@home.example")
			_, err := LinkGlobalAccount(ctx, real.Id, o.org.Id, o.provider.Id, o.claims("sub-linked", "l@corp.example"))
			require.NoError(t, err)
			thief := newUser(t, db, "linkstore-thief", "thief@home.example")
			_, err = LinkGlobalAccount(ctx, thief.Id, o.org.Id, o.provider.Id, o.claims("sub-linked", "l@corp.example"))
			requireRefusal(t, err, types.OrgErrConflict)
			identity, _ := model.GetOrgIdentityBySubject(db, o.org.Id, o.provider.Id, "sub-linked")
			assert.Equal(t, real.Id, identity.UserId)
			_ = linked

			boss := login("sub-boss")
			require.NoError(t, db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", o.org.Id, boss).Update("role", types.OrgRoleOwner).Error)
			_, err = LinkGlobalAccount(ctx, newUser(t, db, "linkstore-b", "b@home.example").Id, o.org.Id, o.provider.Id, o.claims("sub-boss", "b@corp.example"))
			requireRefusal(t, err, types.OrgErrConflict)

			member := o.users["plain"]
			_, err = LinkGlobalAccount(ctx, member.Id, o.org.Id, o.provider.Id, o.claims("sub-nobody", "n@corp.example"))
			requireRefusal(t, err, types.OrgErrConflict)

			login("sub-suspended")
			susp := newUser(t, db, "linkstore-s", "s@home.example")
			require.NoError(t, db.Create(&model.OrganizationMember{OrgId: o.org.Id, UserId: susp.Id, Role: types.OrgRoleMember, Status: types.OrgMemberStatusSuspended, Source: types.OrgMemberSourceManual}).Error)
			_, err = LinkGlobalAccount(ctx, susp.Id, o.org.Id, o.provider.Id, o.claims("sub-suspended", "s@corp.example"))
			requireRefusal(t, err, types.OrgErrConflict)
		})

		t.Run("a global account without an email is still protected once linked", func(t *testing.T) {
			login("sub-noemail")
			owner := newUser(t, db, "linkstore-ne", "")
			_, err := LinkGlobalAccount(ctx, owner.Id, o.org.Id, o.provider.Id, o.claims("sub-noemail", "ne@corp.example"))
			require.NoError(t, err)
			thief := newUser(t, db, "linkstore-ne-thief", "nethief@home.example")
			_, err = LinkGlobalAccount(ctx, thief.Id, o.org.Id, o.provider.Id, o.claims("sub-noemail", "ne@corp.example"))
			requireRefusal(t, err, types.OrgErrConflict)
			identity, _ := model.GetOrgIdentityBySubject(db, o.org.Id, o.provider.Id, "sub-noemail")
			assert.Equal(t, owner.Id, identity.UserId, "the verified link, not the email, is what protects it")
		})

		t.Run("only an email-less placeholder is ever replaced", func(t *testing.T) {
			placeholder := login("sub-gotmail")
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", placeholder).Update("email", "got@home.example").Error)
			global := newUser(t, db, "linkstore-gm", "gm@home.example")
			_, err := LinkGlobalAccount(ctx, global.Id, o.org.Id, o.provider.Id, o.claims("sub-gotmail", "gm@corp.example"))
			requireRefusal(t, err, types.OrgErrConflict)
		})

		t.Run("an SSO or domain join never revives a removed or suspended member", func(t *testing.T) {
			removed := newUser(t, db, "linkstore-rm", "rm@home.example")
			require.NoError(t, db.Create(&model.OrganizationMember{OrgId: o.org.Id, UserId: removed.Id, Role: types.OrgRoleMember,
				Status: types.OrgMemberStatusRemoved, Source: types.OrgMemberSourceManual}).Error)
			for _, source := range []string{types.OrgMemberSourceSSO, types.OrgMemberSourceDomain} {
				err := db.Transaction(func(tx *gorm.DB) error {
					_, err := AdmitMemberTx(tx, AdmitInput{OrgID: o.org.Id, UserID: removed.Id, OrgRole: types.OrgRoleMember, Source: source})
					return err
				})
				requireRefusal(t, err, types.OrgErrMemberSuspended)
			}
			require.NoError(t, db.Transaction(func(tx *gorm.DB) error {
				_, err := AdmitMemberTx(tx, AdmitInput{OrgID: o.org.Id, UserID: removed.Id, OrgRole: types.OrgRoleMember, Source: types.OrgMemberSourceInvite})
				return err
			}), "an invitation still can")
		})

		t.Run("a provider or issuer that is not this organization's is refused", func(t *testing.T) {
			global := newUser(t, db, "linkstore-p", "p@home.example")
			bad := o.claims("sub-p", "p@corp.example")
			bad.Issuer = "https://evil.example.com"
			_, err := LinkGlobalAccount(ctx, global.Id, o.org.Id, o.provider.Id, bad)
			requireRefusal(t, err, types.OrgErrSSONotConfigured)
			_, err = LinkGlobalAccount(ctx, global.Id, o.org.Id, o.provider.Id+99, o.claims("sub-p", "p@corp.example"))
			requireRefusal(t, err, types.OrgErrSSONotConfigured)
			other := newScimOrg(t, db, "linkother", true)
			_, err = LinkGlobalAccount(ctx, global.Id, o.org.Id, other.provider.Id, other.claims("sub-p", "p@corp.example"))
			requireRefusal(t, err, types.OrgErrSSONotConfigured)
		})

		t.Run("concurrent links of one identity produce one winner", func(t *testing.T) {
			login("sub-race")
			accounts := []*model.User{newUser(t, db, "linkstore-r1", "r1@home.example"), newUser(t, db, "linkstore-r2", "r2@home.example")}
			var wg sync.WaitGroup
			errs := make([]error, len(accounts))
			for i, account := range accounts {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, errs[i] = LinkGlobalAccount(ctx, account.Id, o.org.Id, o.provider.Id, o.claims("sub-race", "r@corp.example"))
				}()
			}
			wg.Wait()
			wins := 0
			for _, err := range errs {
				if err == nil {
					wins++
				}
			}
			assert.Equal(t, 1, wins, "%v", errs)
			var active int64
			db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id IN ? AND status = ?", o.org.Id,
				[]int{accounts[0].Id, accounts[1].Id}, types.OrgMemberStatusActive).Count(&active)
			assert.Equal(t, int64(1), active)
		})
	})
}
