package org

import (
	"context"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func loadKey(t *testing.T, db *gorm.DB, id int) model.Token {
	t.Helper()
	var token model.Token
	require.NoError(t, db.Unscoped().First(&token, id).Error)
	return token
}

func TestOrgKeyOwnership(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newLifecycleOrg(t, db, "keys", map[string]string{"admin": types.OrgRoleAdmin, "dev": types.OrgRoleMember,
			"dev2": types.OrgRoleMember, "audit": types.OrgRoleMember, "plain": types.OrgRoleMember})
		a := f.workspace(t, "alpha")
		f.grant(t, a.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
		f.grant(t, a.Id, "dev2", model.GrantSourceManual, "", types.WorkspaceRoleMember)
		f.grant(t, a.Id, "audit", model.GrantSourceManual, "", types.WorkspaceRoleAuditor)
		create := func(actor, owner, name string) (*KeyIssued, error) {
			return CreateWorkspaceKey(ctx, f.users[actor].Id, f.org.Id, a.Id, CreateKeyInput{Name: name, Owner: owner})
		}

		t.Run("the server writes ownership; the plaintext appears once", func(t *testing.T) {
			issued, err := create("dev", "me", "dev-key")
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(issued.Plaintext, "sk-"))
			row := loadKey(t, db, issued.Key.Id)
			assert.Equal(t, f.wallet, row.UserId, "billed to the wallet, never to the person")
			assert.Equal(t, f.org.Id, row.OrgId)
			assert.Equal(t, a.Id, row.WorkspaceId)
			assert.Equal(t, f.users["dev"].Id, row.CreatedBy)
			assert.Equal(t, types.TokenOwnerMember, row.OwnerType)
			assert.NotEmpty(t, row.AccessPrincipalId)
			assert.True(t, row.UnlimitedQuota, "member keys default to unlimited; budgets control spend")
			assert.False(t, row.AllowUserQuotaQuery, "an organization key can never probe the pool")
			assert.Equal(t, "sk-"+row.Key, issued.Plaintext)
			assert.NotContains(t, issued.Key.Masked, row.Key)
			listed, err := ListWorkspaceKeys(ctx, f.org.Id, a.Id, f.users["dev"].Id, types.WorkspaceRoleMember)
			require.NoError(t, err)
			encoded, err := common.Marshal(listed)
			require.NoError(t, err)
			assert.NotContains(t, string(encoded), row.Key, "listings are masked")
		})

		t.Run("system keys are workspace-admin only, with no human actor and a fresh principal", func(t *testing.T) {
			_, err := create("dev", "workspace", "nope")
			requireRefusal(t, err, types.OrgErrWorkspaceForbidden)
			one, err := create("admin", "workspace", "svc-1")
			require.NoError(t, err)
			two, err := create("admin", "workspace", "svc-2")
			require.NoError(t, err)
			r1, r2 := loadKey(t, db, one.Key.Id), loadKey(t, db, two.Key.Id)
			assert.Zero(t, r1.CreatedBy, "the creator is not the consuming actor")
			assert.Equal(t, types.TokenOwnerWorkspace, r1.OwnerType)
			assert.NotEqual(t, r1.AccessPrincipalId, r2.AccessPrincipalId)
			assert.EqualValues(t, 1, count(t, db, &model.OrgAuditLog{}, "org_id = ? AND action = ? AND target_id = ? AND actor_user_id = ?",
				f.org.Id, "key.create", itoa(one.Key.Id), f.users["admin"].Id),
				"creation is audited with the human creator, even though the key has no consuming actor")
		})

		t.Run("who can create, see and change what", func(t *testing.T) {
			_, err := create("audit", "me", "x")
			requireRefusal(t, err, types.OrgErrWorkspaceForbidden)
			_, err = create("plain", "me", "x")
			requireRefusal(t, err, types.OrgErrWorkspaceNotFound)
			_, err = create("dev", "", "x")
			requireRefusal(t, err, types.OrgErrInvalidInput)
			_, err = create("dev", "me", "")
			requireRefusal(t, err, types.OrgErrInvalidInput)
			_, err = create("dev", "me", strings.Repeat("n", 51))
			requireRefusal(t, err, types.OrgErrInvalidInput)

			mine, err := ListWorkspaceKeys(ctx, f.org.Id, a.Id, f.users["dev"].Id, types.WorkspaceRoleMember)
			require.NoError(t, err)
			for _, k := range mine {
				assert.Equal(t, f.users["dev"].Id, k.CreatedBy, "a member sees only their own keys")
			}
			all, err := ListWorkspaceKeys(ctx, f.org.Id, a.Id, f.users["admin"].Id, types.WorkspaceRoleAdmin)
			require.NoError(t, err)
			assert.Greater(t, len(all), len(mine))
			viewed, err := ListWorkspaceKeys(ctx, f.org.Id, a.Id, f.users["audit"].Id, types.WorkspaceRoleAuditor)
			require.NoError(t, err)
			assert.Len(t, viewed, len(all), "an auditor sees the masked list of all keys")

			devKey := mine[0].Id
			name := "renamed"
			_, err = UpdateWorkspaceKey(ctx, f.users["dev2"].Id, f.org.Id, a.Id, devKey, UpdateKeyInput{Name: &name})
			requireRefusal(t, err, types.OrgErrKeyNotFound)
			_, err = UpdateWorkspaceKey(ctx, f.users["audit"].Id, f.org.Id, a.Id, devKey, UpdateKeyInput{Name: &name})
			requireRefusal(t, err, types.OrgErrWorkspaceForbidden)
			updated, err := UpdateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, a.Id, devKey, UpdateKeyInput{Name: &name})
			require.NoError(t, err)
			assert.Equal(t, "renamed", updated.Name)
			requireRefusal(t, DeleteWorkspaceKey(ctx, f.users["dev2"].Id, f.org.Id, a.Id, devKey), types.OrgErrKeyNotFound)
			require.NoError(t, DeleteWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, devKey), "an admin manages every key")
			assert.EqualValues(t, 0, count(t, db, &model.Token{}, "id = ?", devKey))
			assert.EqualValues(t, 1, count(t, db.Unscoped(), &model.Token{}, "id = ?", devKey), "soft delete keeps the row for refunds")
		})

		t.Run("a key id from another workspace or organization is not found", func(t *testing.T) {
			b := f.workspace(t, "beta")
			f.grant(t, b.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
			other, err := CreateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, b.Id, CreateKeyInput{Name: "in-beta", Owner: "me"})
			require.NoError(t, err)
			name := "x"
			_, err = UpdateWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, other.Key.Id, UpdateKeyInput{Name: &name})
			requireRefusal(t, err, types.OrgErrKeyNotFound)
			requireRefusal(t, DeleteWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, other.Key.Id), types.OrgErrKeyNotFound)
			_, err = RotateWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, other.Key.Id)
			requireRefusal(t, err, types.OrgErrKeyNotFound)
		})

		t.Run("limits: key count per workspace and quota bounds", func(t *testing.T) {
			g := f.workspace(t, "limited")
			f.grant(t, g.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
			previous := WorkspaceKeyLimit
			WorkspaceKeyLimit = 2
			t.Cleanup(func() { WorkspaceKeyLimit = previous })
			restore := func() { WorkspaceKeyLimit = previous }
			for i := range 2 {
				_, err := CreateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, g.Id, CreateKeyInput{Name: "k" + itoa(i), Owner: "me"})
				require.NoError(t, err)
			}
			_, err := CreateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, g.Id, CreateKeyInput{Name: "k3", Owner: "me"})
			requireRefusal(t, err, types.OrgErrKeyLimit)
			restore()
			limited, err := CreateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, a.Id, CreateKeyInput{Name: "capped", Owner: "me", QuotaLimit: 1000})
			require.NoError(t, err)
			row := loadKey(t, db, limited.Key.Id)
			assert.False(t, row.UnlimitedQuota)
			assert.Equal(t, 1000, row.RemainQuota)
			_, err = CreateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, a.Id, CreateKeyInput{Name: "neg", Owner: "me", QuotaLimit: -5})
			requireRefusal(t, err, types.OrgErrInvalidInput)
		})

		t.Run("a suspended workspace or organization takes no key writes", func(t *testing.T) {
			require.NoError(t, SetWorkspaceStatus(ctx, f.users["admin"].Id, f.org.Id, a.Id, types.WorkspaceStatusSuspended))
			_, err := create("dev", "me", "late")
			requireRefusal(t, err, types.OrgErrWorkspaceSuspended)
			require.NoError(t, SetWorkspaceStatus(ctx, f.users["admin"].Id, f.org.Id, a.Id, types.WorkspaceStatusActive))
		})

		t.Run("re-enabling a key is allowed only while its owner can still spend", func(t *testing.T) {
			issued, err := create("dev", "me", "revive")
			require.NoError(t, err)
			off, on := common.TokenStatusDisabled, common.TokenStatusEnabled
			_, err = UpdateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, a.Id, issued.Key.Id, UpdateKeyInput{Status: &off})
			require.NoError(t, err)
			_, err = UpdateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, a.Id, issued.Key.Id, UpdateKeyInput{Status: &on})
			require.NoError(t, err, "the owner may turn their own key back on")
			require.NoError(t, RemoveWorkspaceMember(ctx, f.users["admin"].Id, f.org.Id, a.Id, f.users["dev"].Id))
			assert.Equal(t, common.TokenStatusDisabled, loadKey(t, db, issued.Key.Id).Status, "removal disabled it")
			_, err = UpdateWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, issued.Key.Id, UpdateKeyInput{Status: &on})
			requireRefusal(t, err, types.OrgErrConflict)
			assert.Equal(t, common.TokenStatusDisabled, loadKey(t, db, issued.Key.Id).Status, "an admin cannot revive a revoked member's key")
		})
	})
}

func TestOrgKeyRotation(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newLifecycleOrg(t, db, "rot", map[string]string{"admin": types.OrgRoleAdmin, "dev": types.OrgRoleMember, "dev2": types.OrgRoleMember})
		a := f.workspace(t, "alpha")
		f.grant(t, a.Id, "dev", model.GrantSourceManual, "", types.WorkspaceRoleMember)
		f.grant(t, a.Id, "dev2", model.GrantSourceManual, "", types.WorkspaceRoleMember)

		system, err := CreateWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, CreateKeyInput{Name: "svc", Owner: "workspace", QuotaLimit: 5000})
		require.NoError(t, err)
		old := loadKey(t, db, system.Key.Id)
		require.NoError(t, db.Create(&model.Task{TaskID: "hist-1", OrgId: f.org.Id, WorkspaceId: a.Id, AccessPrincipalId: old.AccessPrincipalId,
			OwnerType: types.TokenOwnerWorkspace, PrivateData: model.TaskPrivateData{TokenId: old.Id}, Status: model.TaskStatusSuccess}).Error)

		t.Run("a system key rotates atomically and the successor inherits the principal", func(t *testing.T) {
			rotated, err := RotateWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, old.Id)
			require.NoError(t, err)
			successor := loadKey(t, db, rotated.Key.Id)
			assert.NotEqual(t, old.Id, successor.Id)
			assert.NotEqual(t, old.Key, successor.Key)
			assert.Equal(t, old.AccessPrincipalId, successor.AccessPrincipalId, "the lineage keeps reading its own history")
			assert.Equal(t, types.TokenOwnerWorkspace, successor.OwnerType)
			assert.Zero(t, successor.CreatedBy)
			assert.Equal(t, old.RemainQuota, successor.RemainQuota)
			assert.Equal(t, common.TokenStatusEnabled, successor.Status)
			assert.Equal(t, common.TokenStatusDisabled, loadKey(t, db, old.Id).Status, "the old key is disabled in the same transaction")
			var history model.Task
			require.NoError(t, db.Where("task_id = ?", "hist-1").First(&history).Error)
			assert.Equal(t, old.Id, history.PrivateData.TokenId, "history keeps the original token id")
			assert.Equal(t, old.AccessPrincipalId, history.AccessPrincipalId)
			assert.EqualValues(t, 1, count(t, db, &model.OrgAuditLog{}, "org_id = ? AND action = ?", f.org.Id, "key.rotate"))
			encoded, err := common.Marshal(rotated)
			require.NoError(t, err)
			assert.Contains(t, string(encoded), "sk-", "the new plaintext is returned once")
			assert.NotContains(t, string(encoded), old.Key)
		})

		t.Run("a brand-new system key never inherits that principal", func(t *testing.T) {
			fresh, err := CreateWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, CreateKeyInput{Name: "svc-new", Owner: "workspace"})
			require.NoError(t, err)
			assert.NotEqual(t, old.AccessPrincipalId, loadKey(t, db, fresh.Key.Id).AccessPrincipalId)
		})

		t.Run("members rotate their own keys only; the rotation does not reopen a closed door", func(t *testing.T) {
			mine, err := CreateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, a.Id, CreateKeyInput{Name: "mine", Owner: "me"})
			require.NoError(t, err)
			_, err = RotateWorkspaceKey(ctx, f.users["dev2"].Id, f.org.Id, a.Id, mine.Key.Id)
			requireRefusal(t, err, types.OrgErrKeyNotFound)
			rotated, err := RotateWorkspaceKey(ctx, f.users["dev"].Id, f.org.Id, a.Id, mine.Key.Id)
			require.NoError(t, err)
			assert.Equal(t, f.users["dev"].Id, loadKey(t, db, rotated.Key.Id).CreatedBy)
			// A key that is already disabled (for example by a revocation) cannot be rotated into a live one.
			require.NoError(t, RemoveWorkspaceMember(ctx, f.users["admin"].Id, f.org.Id, a.Id, f.users["dev"].Id))
			_, err = RotateWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, rotated.Key.Id)
			requireRefusal(t, err, types.OrgErrConflict)
			assert.Equal(t, common.TokenStatusDisabled, loadKey(t, db, rotated.Key.Id).Status)
			// Rotating twice in a row fails on the second attempt: the old key is gone.
			_, err = RotateWorkspaceKey(ctx, f.users["admin"].Id, f.org.Id, a.Id, old.Id)
			requireRefusal(t, err, types.OrgErrConflict)
		})
	})
}

func TestOrgKeySweeper(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newLifecycleOrg(t, db, "sweep", map[string]string{"dev": types.OrgRoleMember, "gone": types.OrgRoleMember, "idle": types.OrgRoleMember})
		a := f.workspace(t, "alpha")
		for _, name := range []string{"dev", "gone", "idle"} {
			f.grant(t, a.Id, name, model.GrantSourceManual, "", types.WorkspaceRoleMember)
		}
		keep := f.key(t, "keep", "dev", a.Id)
		system := f.key(t, "system", "", a.Id)
		orphanDisabledUser := f.key(t, "disabled-user", "gone", a.Id)
		noGrant := f.key(t, "no-grant", "idle", a.Id)
		// Simulate what a missed revocation leaves behind: the standing is gone but the key is not.
		require.NoError(t, db.Model(&model.User{}).Where("id = ?", f.users["gone"].Id).Update("status", common.UserStatusDisabled).Error)
		require.NoError(t, db.Exec("DELETE FROM workspace_member_grants WHERE user_id = ?", f.users["idle"].Id).Error)
		require.NoError(t, db.Exec("UPDATE workspace_members SET status = ? WHERE user_id = ?", model.WorkspaceMemberStatusRemoved, f.users["idle"].Id).Error)

		disabledCount, err := SweepOrphanKeys(ctx)
		require.NoError(t, err)
		assert.Equal(t, 2, disabledCount)
		f.requireKeys(t, map[string]int{"keep": enabled, "system": enabled, "disabled-user": disabled, "no-grant": disabled})
		_, _ = keep, system
		_, _ = orphanDisabledUser, noGrant
		again, err := SweepOrphanKeys(ctx)
		require.NoError(t, err)
		assert.Zero(t, again, "a second sweep finds nothing")
		assert.EqualValues(t, 1, count(t, db, &model.OrgAuditLog{}, "org_id = ? AND action = ?", f.org.Id, "key.orphan_disabled"))
	})
}
