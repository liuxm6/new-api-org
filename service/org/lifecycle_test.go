package org

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// lifecycleOrg is an organization with people in the roles the lifecycle tests
// need, created through the real service so the tables hold exactly what
// production code writes.
type lifecycleOrg struct {
	db      *gorm.DB
	org     model.Organization
	wallet  int
	main    model.Workspace
	users   map[string]*model.User
	keySeq  int
	keyRows map[string]model.Token
}

func newLifecycleOrg(t *testing.T, db *gorm.DB, slug string, roles map[string]string) *lifecycleOrg {
	t.Helper()
	f := &lifecycleOrg{db: db, users: map[string]*model.User{}, keyRows: map[string]model.Token{}}
	mk := func(name string) *model.User {
		user := &model.User{Username: slug + "-" + name, Password: "password-123", Role: common.RoleCommonUser,
			Status: common.UserStatusEnabled, Group: "default", AffCode: "aff-" + slug + "-" + name,
			Email: slug + "-" + name + "@example.com", AuthVersion: 1}
		require.NoError(t, db.Create(user).Error)
		f.users[name] = user
		return user
	}
	owner := mk("owner")
	created, err := CreateOrganization(context.Background(), owner.Id, CreateOrganizationInput{Name: slug, Slug: slug})
	require.NoError(t, err)
	f.org, f.main, f.wallet = created.Org, created.DefaultWorkspace, created.Org.BillingUserId
	for name, role := range roles {
		user := mk(name)
		require.NoError(t, db.Create(&model.OrganizationMember{OrgId: f.org.Id, UserId: user.Id, Role: role,
			Status: types.OrgMemberStatusActive, Source: types.OrgMemberSourceManual, JoinedAt: common.GetTimestamp()}).Error)
	}
	return f
}

func (f *lifecycleOrg) workspace(t *testing.T, slug string) model.Workspace {
	t.Helper()
	workspace := model.Workspace{OrgId: f.org.Id, Slug: slug, Name: slug, Status: types.WorkspaceStatusActive}
	require.NoError(t, f.db.Create(&workspace).Error)
	return workspace
}

// grant gives a user a workspace role through the grant model.
func (f *lifecycleOrg) grant(t *testing.T, workspaceID int, user, source, ref, role string) {
	t.Helper()
	require.NoError(t, f.db.Transaction(func(tx *gorm.DB) error {
		_, err := model.UpsertWorkspaceGrantTx(tx, f.org.Id, workspaceID, f.users[user].Id, source, ref, role)
		return err
	}))
}

// key creates an enabled organization key. actor "" makes a system key.
func (f *lifecycleOrg) key(t *testing.T, name, actor string, workspaceID int) model.Token {
	t.Helper()
	f.keySeq++
	token := model.Token{UserId: f.wallet, Key: fmt.Sprintf("k-%s-%d-%s", f.org.Slug, f.keySeq, name), Name: name,
		Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true, OrgId: f.org.Id, WorkspaceId: workspaceID,
		AccessPrincipalId: "prn-" + name, OwnerType: types.TokenOwnerWorkspace}
	if actor != "" {
		token.CreatedBy, token.OwnerType = f.users[actor].Id, types.TokenOwnerMember
	}
	require.NoError(t, f.db.Create(&token).Error)
	f.keyRows[name] = token
	return token
}

func (f *lifecycleOrg) status(t *testing.T, name string) int {
	t.Helper()
	var status int
	require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", f.keyRows[name].Id).Select("status").Scan(&status).Error)
	return status
}

func (f *lifecycleOrg) requireKeys(t *testing.T, want map[string]int) {
	t.Helper()
	for name, status := range want {
		assert.Equal(t, status, f.status(t, name), "key %s", name)
	}
}

func (f *lifecycleOrg) admitted(t *testing.T, key string) error {
	t.Helper()
	_, err := model.LoadOrgRequestState(context.Background(), types.OrgSubject{
		OrgID: f.org.Id, WorkspaceID: f.keyRows[key].WorkspaceId, ActorUserID: f.keyRows[key].CreatedBy,
		TokenID: f.keyRows[key].Id, AccessPrincipalID: f.keyRows[key].AccessPrincipalId, OwnerType: f.keyRows[key].OwnerType})
	return err
}

const (
	enabled  = common.TokenStatusEnabled
	disabled = common.TokenStatusDisabled
)

func TestOrgWorkspaceLifecycle(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newLifecycleOrg(t, db, "life", map[string]string{"admin": types.OrgRoleAdmin, "member": types.OrgRoleMember})
		a, b := f.workspace(t, "alpha"), f.workspace(t, "beta")
		f.grant(t, a.Id, "member", model.GrantSourceManual, "", types.WorkspaceRoleMember)
		f.grant(t, b.Id, "member", model.GrantSourceManual, "", types.WorkspaceRoleMember)
		f.key(t, "a-member", "member", a.Id)
		f.key(t, "b-member", "member", b.Id)
		f.key(t, "a-system", "", a.Id)
		f.key(t, "b-system", "", b.Id)
		wallet := func() int {
			var quota int
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", f.wallet).Select("quota").Scan(&quota).Error)
			return quota
		}
		require.NoError(t, db.Model(&model.User{}).Where("id = ?", f.wallet).Update("quota", 5_000_000).Error)

		t.Run("creating workspaces", func(t *testing.T) {
			_, err := CreateWorkspace(ctx, f.users["member"].Id, f.org.Id, CreateWorkspaceInput{Name: "X", Slug: "xspace"})
			requireRefusal(t, err, types.OrgErrForbidden)
			_, err = CreateWorkspace(ctx, f.users["admin"].Id, f.org.Id, CreateWorkspaceInput{Name: "Default 2", Slug: "default"})
			requireRefusal(t, err, types.OrgErrSlugReserved)
			_, err = CreateWorkspace(ctx, f.users["admin"].Id, f.org.Id, CreateWorkspaceInput{Name: "Dup", Slug: "alpha"})
			requireRefusal(t, err, types.OrgErrSlugTaken)
			_, err = CreateWorkspace(ctx, f.users["admin"].Id, f.org.Id, CreateWorkspaceInput{Name: "", Slug: "emptyname"})
			requireRefusal(t, err, types.OrgErrInvalidInput)
			created, err := CreateWorkspace(ctx, f.users["admin"].Id, f.org.Id, CreateWorkspaceInput{Name: "Gamma", Slug: "gamma"})
			require.NoError(t, err)
			assert.False(t, created.IsDefault)
			assert.EqualValues(t, 1, count(t, db, &model.OrgAuditLog{}, "org_id = ? AND action = ?", f.org.Id, "workspace.create"))
		})

		t.Run("suspending A refuses its requests and leaves B and the wallet alone", func(t *testing.T) {
			before := orgVersion(t, db, f.org.Id)
			requireRefusal(t, SetWorkspaceStatus(ctx, f.users["member"].Id, f.org.Id, a.Id, types.WorkspaceStatusSuspended), types.OrgErrForbidden)
			require.NoError(t, SetWorkspaceStatus(ctx, f.users["admin"].Id, f.org.Id, a.Id, types.WorkspaceStatusSuspended))
			assert.Greater(t, orgVersion(t, db, f.org.Id), before)
			for _, key := range []string{"a-member", "a-system"} {
				requireRefusal(t, f.admitted(t, key), types.OrgErrWorkspaceSuspended)
			}
			for _, key := range []string{"b-member", "b-system"} {
				require.NoError(t, f.admitted(t, key), key)
			}
			assert.Equal(t, 5_000_000, wallet(), "the shared wallet is untouched")
			f.requireKeys(t, map[string]int{"a-member": enabled, "a-system": enabled})
		})

		t.Run("a suspended workspace refuses reads and writes of its own", func(t *testing.T) {
			_, err := ResolveWorkspaceAccess(ctx, f.users["member"].Id, "life", "alpha", 0)
			requireRefusal(t, err, types.OrgErrWorkspaceSuspended)
			_, err = ResolveWorkspaceAccess(ctx, f.users["admin"].Id, "life", "alpha", 0, types.WorkspaceRoleAdmin)
			requireRefusal(t, err, types.OrgErrWorkspaceSuspended) // even an implicit admin
			err = SetWorkspaceMemberRole(ctx, f.users["admin"].Id, f.org.Id, a.Id, f.users["member"].Id, types.WorkspaceRoleAuditor)
			requireRefusal(t, err, types.OrgErrWorkspaceSuspended)
		})

		t.Run("resume is a parent-organization action and does not revive a disabled key", func(t *testing.T) {
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", f.keyRows["a-system"].Id).Update("status", disabled).Error)
			requireRefusal(t, SetWorkspaceStatus(ctx, f.users["member"].Id, f.org.Id, a.Id, types.WorkspaceStatusActive), types.OrgErrForbidden)
			require.NoError(t, SetWorkspaceStatus(ctx, f.users["admin"].Id, f.org.Id, a.Id, types.WorkspaceStatusActive))
			require.NoError(t, f.admitted(t, "a-member"))
			f.requireKeys(t, map[string]int{"a-system": disabled, "a-member": enabled})
			require.Error(t, f.admitted(t, "a-system"), "a key disabled by hand stays disabled")
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", f.keyRows["a-system"].Id).Update("status", enabled).Error)
		})

		t.Run("organization suspension blocks even the parent route; only the platform resumes", func(t *testing.T) {
			require.NoError(t, SetOrganizationStatus(ctx, f.org.Id, types.OrgStatusSuspended, 0, "test"))
			err := SetWorkspaceStatus(ctx, f.users["admin"].Id, f.org.Id, a.Id, types.WorkspaceStatusSuspended)
			requireRefusal(t, err, types.OrgErrSuspended)
			requireRefusal(t, f.admitted(t, "b-member"), types.OrgErrSuspended)
			assert.Equal(t, 5_000_000, wallet())
			require.NoError(t, SetOrganizationStatus(ctx, f.org.Id, types.OrgStatusActive, 0, "test"))
			require.NoError(t, f.admitted(t, "b-member"))
			require.Error(t, SetOrganizationStatus(ctx, f.org.Id, types.OrgStatusDeleted, 0, "test"), "delete is not a status change")
		})

		t.Run("the default workspace cannot be deleted", func(t *testing.T) {
			err := DeleteWorkspace(ctx, f.users["admin"].Id, f.org.Id, f.main.Id)
			requireRefusal(t, err, types.OrgErrDefaultWorkspace)
			assert.EqualValues(t, 1, count(t, db, &model.Workspace{}, "id = ?", f.main.Id))
		})

		t.Run("deleting B disables its keys, hides it, keeps its slug, and spares A", func(t *testing.T) {
			_, err := CreateInvite(ctx, f.users["admin"].Id, f.org.Id, CreateInviteInput{Email: "pending@example.com", WorkspaceID: b.Id})
			require.NoError(t, err)
			requireRefusal(t, DeleteWorkspace(ctx, f.users["member"].Id, f.org.Id, b.Id), types.OrgErrForbidden)
			require.NoError(t, DeleteWorkspace(ctx, f.users["admin"].Id, f.org.Id, b.Id))
			f.requireKeys(t, map[string]int{"b-member": disabled, "b-system": disabled, "a-member": enabled, "a-system": enabled})
			_, err = ResolveWorkspaceAccess(ctx, f.users["admin"].Id, "life", "beta", 0)
			requireRefusal(t, err, types.OrgErrWorkspaceNotFound)
			_, err = CreateWorkspace(ctx, f.users["admin"].Id, f.org.Id, CreateWorkspaceInput{Name: "Again", Slug: "beta"})
			requireRefusal(t, err, types.OrgErrSlugTaken)
			assert.EqualValues(t, 0, count(t, db, &model.Invite{}, "workspace_id = ? AND status = ?", b.Id, types.InviteStatusPending))
			assert.EqualValues(t, 1, count(t, db, &model.Invite{}, "workspace_id = ? AND status = ?", b.Id, types.InviteStatusRevoked))
			assert.Equal(t, 5_000_000, wallet())
			require.NoError(t, f.admitted(t, "a-member"))
		})
	})
}

func TestOrgDeleteLifecycle(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newLifecycleOrg(t, db, "gone", map[string]string{"admin": types.OrgRoleAdmin})
		f.key(t, "member-key", "admin", f.main.Id)
		f.key(t, "system-key", "", f.main.Id)
		require.NoError(t, db.Model(&model.User{}).Where("id = ?", f.wallet).Update("quota", 1000).Error)

		t.Run("only the owner, and only with the slug typed back", func(t *testing.T) {
			requireRefusal(t, DeleteOrganization(ctx, f.users["admin"].Id, f.org.Id, "gone"), types.OrgErrForbidden)
			requireRefusal(t, DeleteOrganization(ctx, f.users["owner"].Id, f.org.Id, "wrong"), types.OrgErrInvalidInput)
			requireRefusal(t, DeleteOrganization(ctx, f.users["owner"].Id, f.org.Id, ""), types.OrgErrInvalidInput)
		})

		t.Run("blockers are reported together and nothing changes", func(t *testing.T) {
			require.NoError(t, db.Create(&model.OrgSpendFoldQueue{OrgId: f.org.Id, OperationId: "op-1", Kind: types.OrgFoldKindCapture}).Error)
			require.NoError(t, db.Create(&model.OrgBillingOperation{OperationId: "op-2", OrgId: f.org.Id, State: types.OrgOpStateRecoveryRequired}).Error)
			require.NoError(t, db.Create(&model.OrgQuotaLease{OrgId: f.org.Id, TargetType: types.OrgLeaseTargetWallet, TargetId: f.wallet,
				Status: types.OrgLeaseStatusActive, Amount: 10}).Error)
			require.NoError(t, db.Create(&model.Task{TaskID: "t-1", OrgId: f.org.Id, Status: model.TaskStatusInProgress}).Error)
			err := DeleteOrganization(ctx, f.users["owner"].Id, f.org.Id, "gone")
			requireRefusal(t, err, types.OrgErrDeleteBlocked)
			var blocked *DeleteBlockedError
			require.ErrorAs(t, err, &blocked)
			assert.ElementsMatch(t, []string{"balance", "leases", "billing_operations", "fold_queue", "tasks"}, blocked.Reasons)
			assert.EqualValues(t, 1, count(t, db, &model.Organization{}, "id = ?", f.org.Id))
			f.requireKeys(t, map[string]int{"member-key": enabled, "system-key": enabled})
		})

		t.Run("once settled the organization is deleted for good", func(t *testing.T) {
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", f.wallet).Update("quota", 0).Error)
			require.NoError(t, db.Model(&model.OrgSpendFoldQueue{}).Where("org_id = ?", f.org.Id).Delete(&model.OrgSpendFoldQueue{}).Error)
			require.NoError(t, db.Model(&model.OrgBillingOperation{}).Where("org_id = ?", f.org.Id).Update("state", types.OrgOpStateClosed).Error)
			require.NoError(t, db.Model(&model.OrgQuotaLease{}).Where("org_id = ?", f.org.Id).Update("status", types.OrgLeaseStatusClosed).Error)
			require.NoError(t, db.Model(&model.Task{}).Where("org_id = ?", f.org.Id).Update("status", model.TaskStatusSuccess).Error)
			_, err := CreateInvite(ctx, f.users["owner"].Id, f.org.Id, CreateInviteInput{Email: "late@example.com"})
			require.NoError(t, err)

			require.NoError(t, DeleteOrganization(ctx, f.users["owner"].Id, f.org.Id, "gone"))
			_, err = ResolveOrgAccess(ctx, f.users["owner"].Id, "gone", 0)
			requireRefusal(t, err, types.OrgErrNotFound)
			f.requireKeys(t, map[string]int{"member-key": disabled, "system-key": disabled})
			assert.EqualValues(t, 0, count(t, db, &model.Invite{}, "org_id = ? AND status = ?", f.org.Id, types.InviteStatusPending))
			// Financial facts and the wallet survive so background settlement, refunds and
			// statements keep working.
			assert.EqualValues(t, 1, count(t, db.Unscoped(), &model.Organization{}, "id = ?", f.org.Id))
			var wallet model.User
			require.NoError(t, db.First(&wallet, f.wallet).Error)
			assert.Equal(t, common.UserStatusEnabled, wallet.Status)
			assert.True(t, wallet.IsBillingAccount())
			assert.EqualValues(t, 0, count(t, db, &model.Workspace{}, "org_id = ?", f.org.Id))
			assert.EqualValues(t, 1, count(t, db.Unscoped(), &model.Workspace{}, "org_id = ?", f.org.Id))
			stranger, err := CreateOrganization(ctx, f.users["admin"].Id, CreateOrganizationInput{Name: "Reuse", Slug: "gone"})
			assert.Nil(t, stranger)
			requireRefusal(t, err, types.OrgErrSlugTaken)
		})
	})
}

func TestOrgMemberRevocation(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newLifecycleOrg(t, db, "rev", map[string]string{"admin": types.OrgRoleAdmin, "dev": types.OrgRoleMember, "other": types.OrgRoleMember})
		a, b := f.workspace(t, "alpha"), f.workspace(t, "beta")
		reset := func() {
			require.NoError(t, db.Model(&model.Token{}).Where("org_id = ?", f.org.Id).Update("status", enabled).Error)
			require.NoError(t, db.Model(&model.OrgAccessToken{}).Where("org_id = ?", f.org.Id).Update("status", 1).Error)
		}
		f.grant(t, a.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
		f.grant(t, b.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
		f.key(t, "dev-a", "dev", a.Id)
		f.key(t, "dev-b", "dev", b.Id)
		f.key(t, "other-a", "other", a.Id)
		f.key(t, "admin-a", "admin", a.Id)
		f.key(t, "system-a", "", a.Id)
		mgmt := model.OrgAccessToken{OrgId: f.org.Id, Name: "pm", TokenHash: "hash-admin-pm", CreatedBy: f.users["admin"].Id,
			Kind: types.OrgAccessTokenPersonalManagement, Status: 1}
		require.NoError(t, db.Create(&mgmt).Error)
		mgmtStatus := func() int {
			var status int
			require.NoError(t, db.Model(&model.OrgAccessToken{}).Where("id = ?", mgmt.Id).Select("status").Scan(&status).Error)
			return status
		}

		t.Run("leaving one workspace disables only the keys spent there", func(t *testing.T) {
			reset()
			require.NoError(t, RemoveWorkspaceMember(ctx, f.users["admin"].Id, f.org.Id, a.Id, f.users["dev"].Id))
			f.requireKeys(t, map[string]int{"dev-a": disabled, "dev-b": enabled, "other-a": enabled, "system-a": enabled})
			assert.Equal(t, 1, mgmtStatus(), "workspace changes leave the management credential alone")
			f.grant(t, a.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
			f.requireKeys(t, map[string]int{"dev-a": disabled})
		})

		t.Run("demotion to auditor disables that workspace's keys only", func(t *testing.T) {
			reset()
			require.NoError(t, SetWorkspaceMemberRole(ctx, f.users["admin"].Id, f.org.Id, b.Id, f.users["dev"].Id, types.WorkspaceRoleAuditor))
			f.requireKeys(t, map[string]int{"dev-b": disabled, "dev-a": enabled})
			requireRefusal(t, SetWorkspaceMemberRole(ctx, f.users["other"].Id, f.org.Id, b.Id, f.users["dev"].Id, types.WorkspaceRoleMember), types.OrgErrWorkspaceNotFound)
		})

		t.Run("suspending a member disables every member key and the management credential", func(t *testing.T) {
			reset()
			f.grant(t, b.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
			require.NoError(t, SetMemberStatus(ctx, f.users["admin"].Id, f.org.Id, f.users["dev"].Id, types.OrgMemberStatusSuspended))
			f.requireKeys(t, map[string]int{"dev-a": disabled, "dev-b": disabled, "other-a": enabled, "admin-a": enabled, "system-a": enabled})
			require.Error(t, f.admitted(t, "dev-a"))
			require.NoError(t, SetMemberStatus(ctx, f.users["admin"].Id, f.org.Id, f.users["dev"].Id, types.OrgMemberStatusActive))
			f.requireKeys(t, map[string]int{"dev-a": disabled, "dev-b": disabled})
		})

		t.Run("suspending an admin also kills their management credential, for good", func(t *testing.T) {
			reset()
			require.NoError(t, SetMemberStatus(ctx, f.users["owner"].Id, f.org.Id, f.users["admin"].Id, types.OrgMemberStatusSuspended))
			f.requireKeys(t, map[string]int{"admin-a": disabled, "dev-a": enabled})
			assert.Equal(t, 2, mgmtStatus())
			require.NoError(t, SetMemberStatus(ctx, f.users["owner"].Id, f.org.Id, f.users["admin"].Id, types.OrgMemberStatusActive))
			assert.Equal(t, 2, mgmtStatus(), "reactivation never revives credentials")
			f.requireKeys(t, map[string]int{"admin-a": disabled})
		})

		t.Run("removing a member frees the seat and ends every grant", func(t *testing.T) {
			reset()
			before, err := SeatsInUse(db, f.org.Id)
			require.NoError(t, err)
			require.NoError(t, RemoveMember(ctx, f.users["admin"].Id, f.org.Id, f.users["dev"].Id))
			after, err := SeatsInUse(db, f.org.Id)
			require.NoError(t, err)
			assert.Equal(t, before-1, after)
			assert.EqualValues(t, 0, count(t, db, &model.WorkspaceMemberGrant{}, "org_id = ? AND user_id = ?", f.org.Id, f.users["dev"].Id))
			assert.EqualValues(t, 0, count(t, db, &model.WorkspaceMember{}, "org_id = ? AND user_id = ? AND status = ?", f.org.Id, f.users["dev"].Id, model.WorkspaceMemberStatusActive))
			f.requireKeys(t, map[string]int{"dev-a": disabled, "dev-b": disabled, "other-a": enabled})
			_, err = ResolveOrgAccess(ctx, f.users["dev"].Id, "rev", 0)
			requireRefusal(t, err, types.OrgErrNotFound)
		})

		t.Run("members may leave; admins cannot remove owners; the last owner stays", func(t *testing.T) {
			require.NoError(t, RemoveMember(ctx, f.users["other"].Id, f.org.Id, f.users["other"].Id), "self-leave needs no role")
			requireRefusal(t, RemoveMember(ctx, f.users["admin"].Id, f.org.Id, f.users["owner"].Id), types.OrgErrOwnerRole)
			requireRefusal(t, RemoveMember(ctx, f.users["owner"].Id, f.org.Id, f.users["owner"].Id), types.OrgErrLastOwner)
			requireRefusal(t, RemoveMember(ctx, f.users["admin"].Id, f.org.Id, 424242), types.OrgErrMemberNotFound)
		})

		t.Run("demoting an admin ends the implicit access to every workspace", func(t *testing.T) {
			reset()
			require.NoError(t, ChangeMemberRole(ctx, f.users["owner"].Id, f.org.Id, f.users["admin"].Id, types.OrgRoleMember))
			f.requireKeys(t, map[string]int{"admin-a": disabled, "system-a": enabled})
			assert.Equal(t, 2, mgmtStatus(), "no longer an admin, so no management credential")
		})
	})
}

func TestOrgGlobalDisableAndDelete(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		one := newLifecycleOrg(t, db, "gone-one", map[string]string{"dev": types.OrgRoleMember})
		// The same person is a member of a second organization.
		two := newLifecycleOrg(t, db, "gone-two", nil)
		dev := one.users["dev"]
		require.NoError(t, db.Create(&model.OrganizationMember{OrgId: two.org.Id, UserId: dev.Id, Role: types.OrgRoleMember,
			Status: types.OrgMemberStatusActive}).Error)
		two.users["dev"] = dev
		one.key(t, "one-dev", "dev", one.main.Id)
		two.key(t, "two-dev", "dev", two.main.Id)
		two.key(t, "two-system", "", two.main.Id)

		t.Run("disabling the account disables the member keys in every organization", func(t *testing.T) {
			fresh := *dev
			fresh.Status = common.UserStatusDisabled
			require.NoError(t, fresh.Update(false))
			one.requireKeys(t, map[string]int{"one-dev": disabled})
			two.requireKeys(t, map[string]int{"two-dev": disabled, "two-system": enabled})
			var member model.OrganizationMember
			require.NoError(t, db.Where("org_id = ? AND user_id = ?", one.org.Id, dev.Id).First(&member).Error)
			assert.Equal(t, types.OrgMemberStatusActive, member.Status, "memberships stay; only the credentials go")
		})

		t.Run("re-enabling does not revive anything", func(t *testing.T) {
			fresh := *dev
			fresh.Status = common.UserStatusEnabled
			require.NoError(t, fresh.Update(false))
			one.requireKeys(t, map[string]int{"one-dev": disabled})
		})

		t.Run("an organization owner must transfer before the account can be deleted", func(t *testing.T) {
			owner := one.users["owner"]
			_, err := owner.Delete()
			require.ErrorIs(t, err, model.ErrOrgOwnerMustTransfer)
			var still model.User
			require.NoError(t, db.First(&still, owner.Id).Error, "the account survives the refusal")
			_, err = (&model.User{Id: owner.Id}).HardDelete()
			require.ErrorIs(t, err, model.ErrOrgOwnerMustTransfer)

			require.NoError(t, TransferOwnership(ctx, owner.Id, one.org.Id, dev.Id))
			one.key(t, "owner-key", "owner", one.main.Id)
			before, err := SeatsInUse(db, one.org.Id)
			require.NoError(t, err)
			_, err = (&model.User{Id: owner.Id}).Delete()
			require.NoError(t, err)
			one.requireKeys(t, map[string]int{"owner-key": disabled})
			after, err := SeatsInUse(db, one.org.Id)
			require.NoError(t, err)
			assert.Equal(t, before-1, after, "deleting the account frees its seat")
			assert.EqualValues(t, 0, count(t, db, &model.WorkspaceMemberGrant{}, "org_id = ? AND user_id = ?", one.org.Id, owner.Id))
		})
	})
}

func TestOrgGrantSources(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newLifecycleOrg(t, db, "grants", map[string]string{"admin": types.OrgRoleAdmin, "dev": types.OrgRoleMember, "ghost": types.OrgRoleMember})
		a := f.workspace(t, "alpha")
		dev := f.users["dev"].Id
		effective := func() string {
			projected, err := model.GetWorkspaceMember(db, a.Id, dev)
			if err != nil || projected.Status != model.WorkspaceMemberStatusActive {
				return ""
			}
			return projected.Role
		}
		scim := func(ref, role string) error {
			return db.Transaction(func(tx *gorm.DB) error {
				return applyGrant(tx, f.org.Id, a.Id, dev, model.GrantSourceSCIM, ref, role, 0)
			})
		}
		revoke := func(source, ref string) error {
			return db.Transaction(func(tx *gorm.DB) error { return revokeGrant(tx, f.org.Id, a.Id, dev, source, ref, 0) })
		}

		require.NoError(t, scim("group-readers", types.WorkspaceRoleAuditor))
		assert.Equal(t, types.WorkspaceRoleAuditor, effective())
		f.key(t, "dev-a", "dev", a.Id) // an auditor cannot hold a spending key, so it is made afterwards

		t.Run("manual and several SCIM sources coexist and the highest one wins", func(t *testing.T) {
			require.NoError(t, SetWorkspaceMemberRole(ctx, f.users["admin"].Id, f.org.Id, a.Id, dev, types.WorkspaceRoleMember))
			require.NoError(t, scim("group-admins", types.WorkspaceRoleAdmin))
			assert.Equal(t, types.WorkspaceRoleAdmin, effective())
			assert.EqualValues(t, 3, count(t, db, &model.WorkspaceMemberGrant{}, "workspace_id = ? AND user_id = ?", a.Id, dev))
			assert.EqualValues(t, 1, count(t, db, &model.WorkspaceMember{}, "workspace_id = ? AND user_id = ?", a.Id, dev), "one projection row")
		})

		t.Run("revoking one source falls back to the next and never erases the others", func(t *testing.T) {
			require.NoError(t, revoke(model.GrantSourceSCIM, "group-admins"))
			assert.Equal(t, types.WorkspaceRoleMember, effective(), "the manual grant remains")
			f.requireKeys(t, map[string]int{"dev-a": enabled})
			require.NoError(t, revoke(model.GrantSourceSCIM, "group-readers"))
			assert.Equal(t, types.WorkspaceRoleMember, effective())
			assert.EqualValues(t, 1, count(t, db, &model.WorkspaceMemberGrant{}, "workspace_id = ? AND user_id = ?", a.Id, dev))
		})

		t.Run("losing the spending grant disables the keys; an auditor grant cannot spend", func(t *testing.T) {
			require.NoError(t, scim("group-readers", types.WorkspaceRoleAuditor))
			require.NoError(t, RemoveWorkspaceMember(ctx, f.users["admin"].Id, f.org.Id, a.Id, dev))
			assert.Equal(t, types.WorkspaceRoleAuditor, effective(), "the SCIM auditor grant survives a manual removal")
			f.requireKeys(t, map[string]int{"dev-a": disabled})
			require.NoError(t, revoke(model.GrantSourceSCIM, "group-readers"))
			assert.Equal(t, "", effective())
		})

		t.Run("every workspace member must be an active organization member", func(t *testing.T) {
			outsider := newUser(t, db, "grants-outsider", "grants-outsider@example.com")
			err := db.Transaction(func(tx *gorm.DB) error {
				return applyGrant(tx, f.org.Id, a.Id, outsider.Id, model.GrantSourceSCIM, "g", types.WorkspaceRoleMember, 0)
			})
			requireRefusal(t, err, types.OrgErrMemberNotFound)
			require.NoError(t, SetMemberStatus(ctx, f.users["admin"].Id, f.org.Id, f.users["ghost"].Id, types.OrgMemberStatusSuspended))
			err = db.Transaction(func(tx *gorm.DB) error {
				return applyGrant(tx, f.org.Id, a.Id, f.users["ghost"].Id, model.GrantSourceSCIM, "g", types.WorkspaceRoleMember, 0)
			})
			requireRefusal(t, err, types.OrgErrMemberNotFound)
			other := newLifecycleOrg(t, db, "grants-other", nil)
			err = db.Transaction(func(tx *gorm.DB) error {
				return applyGrant(tx, f.org.Id, other.main.Id, dev, model.GrantSourceSCIM, "g", types.WorkspaceRoleMember, 0)
			})
			requireRefusal(t, err, types.OrgErrWorkspaceNotFound)
			err = db.Transaction(func(tx *gorm.DB) error {
				return applyGrant(tx, f.org.Id, a.Id, dev, model.GrantSourceSCIM, "g", "owner", 0)
			})
			requireRefusal(t, err, types.OrgErrInvalidInput)
		})

		t.Run("grants and projections never drift apart", func(t *testing.T) {
			require.NoError(t, scim("g1", types.WorkspaceRoleMember))
			require.NoError(t, scim("g2", types.WorkspaceRoleAuditor))
			require.NoError(t, revoke(model.GrantSourceSCIM, "g1"))
			var projections []model.WorkspaceMember
			require.NoError(t, db.Where("org_id = ?", f.org.Id).Find(&projections).Error)
			for _, projection := range projections {
				var grants []model.WorkspaceMemberGrant
				require.NoError(t, db.Where("workspace_id = ? AND user_id = ?", projection.WorkspaceId, projection.UserId).Find(&grants).Error)
				best := ""
				for _, grant := range grants {
					if model.WorkspaceRoleRank(grant.Role) > model.WorkspaceRoleRank(best) {
						best = grant.Role
					}
				}
				if best == "" {
					assert.Equal(t, model.WorkspaceMemberStatusRemoved, projection.Status, "no grant, no access")
				} else {
					assert.Equal(t, best, projection.Role)
					assert.Equal(t, model.WorkspaceMemberStatusActive, projection.Status)
				}
			}
		})

		t.Run("every change advances policy_version in its own transaction", func(t *testing.T) {
			before := orgVersion(t, db, f.org.Id)
			require.NoError(t, scim("g3", types.WorkspaceRoleMember))
			mid := orgVersion(t, db, f.org.Id)
			require.NoError(t, revoke(model.GrantSourceSCIM, "g3"))
			assert.Greater(t, mid, before)
			assert.Greater(t, orgVersion(t, db, f.org.Id), mid)
			failing := db.Transaction(func(tx *gorm.DB) error {
				if err := applyGrant(tx, f.org.Id, a.Id, dev, model.GrantSourceSCIM, "g4", types.WorkspaceRoleMember, 0); err != nil {
					return err
				}
				return fmt.Errorf("roll back")
			})
			require.Error(t, failing)
			assert.EqualValues(t, 0, count(t, db, &model.WorkspaceMemberGrant{}, "source_ref = ?", "g4"))
		})
	})
}

func TestOrgStaleAuthorizationDoesNotWrite(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newLifecycleOrg(t, db, "stale", map[string]string{"admin": types.OrgRoleAdmin, "dev": types.OrgRoleMember})
		// Prime the read cache with the admin's standing.
		_, err := ResolveOrgAccess(ctx, f.users["admin"].Id, "stale", 0, types.OrgRoleAdmin)
		require.NoError(t, err)
		// The role is lowered behind the cache's back (no version bump), as a race
		// between a request admitted earlier and a concurrent demotion would do.
		require.NoError(t, db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", f.org.Id, f.users["admin"].Id).
			Update("role", types.OrgRoleMember).Error)
		_, err = ResolveOrgAccess(ctx, f.users["admin"].Id, "stale", 0, types.OrgRoleAdmin)
		require.NoError(t, err, "the cache still believes the old role, which is the point of this test")
		requireRefusal(t, ChangeMemberRole(ctx, f.users["admin"].Id, f.org.Id, f.users["dev"].Id, types.OrgRoleBilling), types.OrgErrForbidden)
		requireRefusal(t, SetMemberStatus(ctx, f.users["admin"].Id, f.org.Id, f.users["dev"].Id, types.OrgMemberStatusSuspended), types.OrgErrForbidden)
		_, err = CreateInvite(ctx, f.users["admin"].Id, f.org.Id, CreateInviteInput{Email: "x@example.com"})
		requireRefusal(t, err, types.OrgErrForbidden)
		assert.Equal(t, types.OrgRoleMember, memberRole(t, db, f.org.Id, f.users["dev"].Id), "no write got through")
	})
}

// applyGrant and revokeGrant drop the revocation handle: these tests read the
// database, and the cache purge has its own test.
func applyGrant(tx *gorm.DB, orgID, wsID, userID int, source, ref, role string, actor int) error {
	_, err := ApplyGrantTx(tx, orgID, wsID, userID, source, ref, role, actor)
	return err
}

func revokeGrant(tx *gorm.DB, orgID, wsID, userID int, source, ref string, actor int) error {
	_, err := RevokeGrantTx(tx, orgID, wsID, userID, source, ref, actor)
	return err
}

func TestOrgRevocationWithRedisDown(t *testing.T) {
	db := openOrgTestDB(t, "sqlite")
	redisServer := miniredis.RunT(t)
	previous := common.RDB
	common.RDB = redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	common.RedisEnabled = true
	t.Cleanup(func() { _ = common.RDB.Close(); common.RDB = previous; common.RedisEnabled = false })

	ctx := context.Background()
	f := newLifecycleOrg(t, db, "redisdown", map[string]string{"admin": types.OrgRoleAdmin, "dev": types.OrgRoleMember})
	f.grant(t, f.main.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
	key := f.key(t, "dev-key", "dev", f.main.Id)

	cached, err := model.GetTokenByKey(key.Key, false)
	require.NoError(t, err)
	require.Equal(t, enabled, cached.Status)
	require.NoError(t, f.admitted(t, "dev-key"))
	require.NotEmpty(t, redisServer.Keys(), "the key is cached before Redis goes down")

	redisServer.Close()

	require.NoError(t, RemoveMember(ctx, f.users["admin"].Id, f.org.Id, f.users["dev"].Id),
		"a failed cache purge must not fail or undo the revocation")
	f.requireKeys(t, map[string]int{"dev-key": disabled})

	t.Run("the revoked key is refused although its cached copy could not be purged", func(t *testing.T) {
		assert.Error(t, f.admitted(t, "dev-key"), "organization keys are checked against the database on every request")
	})
	t.Run("reading the key falls back to the database while Redis is down", func(t *testing.T) {
		got, err := model.GetTokenByKey(key.Key, false)
		require.NoError(t, err)
		assert.Equal(t, disabled, got.Status)
	})
}

func TestOrgRevocationFence(t *testing.T) {
	db := openOrgTestDB(t, "sqlite")
	redisServer := miniredis.RunT(t)
	previous := common.RDB
	common.RDB = redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	common.RedisEnabled = true
	t.Cleanup(func() { _ = common.RDB.Close(); common.RDB = previous; common.RedisEnabled = false })

	ctx := context.Background()
	f := newLifecycleOrg(t, db, "fence", map[string]string{"admin": types.OrgRoleAdmin, "dev": types.OrgRoleMember})
	f.grant(t, f.main.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
	key := f.key(t, "dev-key", "dev", f.main.Id)

	// Another instance has the key hot in Redis, enabled.
	cached, err := model.GetTokenByKey(key.Key, false)
	require.NoError(t, err)
	require.Equal(t, enabled, cached.Status)
	require.NotEmpty(t, redisServer.Keys(), "the key is cached")

	require.NoError(t, RemoveMember(ctx, f.users["admin"].Id, f.org.Id, f.users["dev"].Id))

	t.Run("every instance reads the disabled state right after commit", func(t *testing.T) {
		got, err := model.GetTokenByKey(key.Key, false)
		require.NoError(t, err)
		assert.Equal(t, disabled, got.Status, "the stale enabled copy must be gone")
	})
	t.Run("a fence stops a late reader from re-publishing the old state", func(t *testing.T) {
		var fences []string
		for _, name := range redisServer.Keys() {
			if strings.Contains(name, "fence") {
				fences = append(fences, name)
			}
		}
		assert.NotEmpty(t, fences, "the mutation fence is raised for the revoked key")
		for _, name := range fences {
			assert.Positive(t, redisServer.TTL(name), "the fence expires by itself")
		}
	})
}
