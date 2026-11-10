package org

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// orgDialects are the databases these tests run on. SQLite always runs;
// MySQL and PostgreSQL run when TEST_MYSQL_DSN / TEST_POSTGRES_DSN are set and
// are skipped, visibly, otherwise.
var orgDialects = []string{"sqlite", "mysql", "postgres"}

var orgTestModels = []any{
	&model.User{}, &model.UserSession{}, &model.Token{}, &model.Option{}, &model.Checkin{},
	&model.Task{}, &model.Midjourney{}, &model.TwoFA{}, &model.TwoFABackupCode{}, &model.PasskeyCredential{},
	&model.UserAccessToken{}, &model.AuthFlow{}, &model.ExternalIdentityClaim{}, &model.UserOAuthBinding{},
	&model.CustomOAuthProvider{},
}

// openOrgTestDB points model.DB at a clean database of the given dialect and
// creates every table the organization service touches.
func openOrgTestDB(t *testing.T, dialect string) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.Init())
	var driver gorm.Dialector
	switch dialect {
	case "sqlite":
		driver = sqlite.Open("file:" + t.Name() + "?mode=memory&cache=shared")
	case "mysql":
		dsn := os.Getenv("TEST_MYSQL_DSN")
		if dsn == "" {
			t.Skip("TEST_MYSQL_DSN is not configured")
		}
		driver = mysql.Open(dsn)
	case "postgres":
		dsn := os.Getenv("TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("TEST_POSTGRES_DSN is not configured")
		}
		driver = postgres.Open(dsn)
	}
	db, err := gorm.Open(driver, &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	if dialect == "sqlite" {
		sqlDB.SetMaxOpenConns(1)
	} else {
		sqlDB.SetMaxOpenConns(16)
	}
	previousDB, previousLog, previousType := model.DB, model.LOG_DB, common.MainDatabaseType()
	previousRedis := common.RedisEnabled
	model.DB, model.LOG_DB = db, db
	common.SetMainDatabaseType(common.DatabaseType(dialect))
	common.RedisEnabled = false
	model.InitColumnNames()
	dropOrgTestTables(t, db)
	require.NoError(t, db.AutoMigrate(orgTestModels...))
	require.NoError(t, model.MigrateOrgTables())
	resetAccessCache()
	t.Cleanup(func() {
		dropOrgTestTables(t, db)
		model.DB, model.LOG_DB = previousDB, previousLog
		common.SetMainDatabaseType(previousType)
		common.RedisEnabled = previousRedis
		model.InitColumnNames()
		_ = sqlDB.Close()
	})
	return db
}

func dropOrgTestTables(t *testing.T, db *gorm.DB) {
	t.Helper()
	if db.Dialector.Name() == "sqlite" {
		return
	}
	for _, m := range slices.Backward(model.OrgModels()) {
		require.NoError(t, db.Migrator().DropTable(m))
	}
	for _, m := range slices.Backward(orgTestModels) {
		require.NoError(t, db.Migrator().DropTable(m))
	}
}

func eachDialect(t *testing.T, run func(t *testing.T, db *gorm.DB)) {
	t.Helper()
	for _, dialect := range orgDialects {
		t.Run(dialect, func(t *testing.T) { run(t, openOrgTestDB(t, dialect)) })
	}
}

func newUser(t *testing.T, db *gorm.DB, name, email string) *model.User {
	t.Helper()
	user := &model.User{Username: name, Password: "password-123", Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, Group: "default", AffCode: "aff-" + name, Email: email, AuthVersion: 1}
	require.NoError(t, db.Create(user).Error)
	return user
}

func requireRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var access *types.OrgAccessError
	require.ErrorAs(t, err, &access, "expected %s, got %v", code, err)
	assert.Equal(t, code, access.Code)
}

func count(t *testing.T, db *gorm.DB, table any, query string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(table).Where(query, args...).Count(&n).Error)
	return n
}

func TestOrgCreateTransaction(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		alice := newUser(t, db, "alice", "alice@example.com")

		t.Run("one transaction creates wallet, org, default workspace, owner, grant and audit", func(t *testing.T) {
			created, err := CreateOrganization(ctx, alice.Id, CreateOrganizationInput{Name: "Acme Inc", Slug: "acme"})
			require.NoError(t, err)
			org := created.Org
			assert.Equal(t, "acme", org.Slug)
			assert.Equal(t, alice.Id, org.OwnerUserId)
			assert.Equal(t, types.OrgStatusActive, org.Status)

			var wallet model.User
			require.NoError(t, db.First(&wallet, org.BillingUserId).Error)
			assert.True(t, wallet.IsBillingAccount())
			assert.Zero(t, wallet.Quota, "no sign-up bonus on a billing account")
			assert.Empty(t, wallet.Email)
			assert.Equal(t, DefaultBillingGroup, wallet.Group)

			var workspace model.Workspace
			require.NoError(t, db.Where("org_id = ?", org.Id).Take(&workspace).Error)
			assert.True(t, workspace.IsDefault)
			assert.Equal(t, "default", workspace.Slug)
			assert.Equal(t, created.DefaultWorkspace.Id, workspace.Id)

			member, err := model.GetOrganizationMember(db, org.Id, alice.Id)
			require.NoError(t, err)
			assert.Equal(t, types.OrgRoleOwner, member.Role)
			assert.Equal(t, types.OrgMemberStatusActive, member.Status)

			var grant model.WorkspaceMemberGrant
			require.NoError(t, db.Where("workspace_id = ? AND user_id = ?", workspace.Id, alice.Id).Take(&grant).Error)
			assert.Equal(t, "manual", grant.Source)
			assert.Equal(t, types.WorkspaceRoleAdmin, grant.Role)
			projected, err := model.GetWorkspaceMember(db, workspace.Id, alice.Id)
			require.NoError(t, err)
			assert.Equal(t, types.WorkspaceRoleAdmin, projected.Role, "workspace_members is the projection of the grant")

			var audit model.OrgAuditLog
			require.NoError(t, db.Where("org_id = ? AND action = ?", org.Id, "org.create").Take(&audit).Error)
			assert.Equal(t, alice.Id, audit.ActorUserId)
		})

		t.Run("without email verification an account with no email can create one", func(t *testing.T) {
			previous := common.EmailVerificationEnabled
			common.EmailVerificationEnabled = false
			t.Cleanup(func() { common.EmailVerificationEnabled = previous })
			dana := newUser(t, db, "dana", "")
			result, err := CreateOrganization(ctx, dana.Id, CreateOrganizationInput{Name: "Dana Co", Slug: "danaco"})
			require.NoError(t, err)
			assert.Equal(t, dana.Id, result.Org.OwnerUserId)
		})

		t.Run("an unverified email is refused and nothing is created", func(t *testing.T) {
			previous := common.EmailVerificationEnabled
			common.EmailVerificationEnabled = true
			t.Cleanup(func() { common.EmailVerificationEnabled = previous })
			bob := newUser(t, db, "bob", "")
			before := count(t, db, &model.User{}, "kind = ?", types.UserKindBilling)
			_, err := CreateOrganization(ctx, bob.Id, CreateOrganizationInput{Name: "Bob Co", Slug: "bobco"})
			requireRefusal(t, err, types.OrgErrEmailNotVerified)
			assert.Equal(t, before, count(t, db, &model.User{}, "kind = ?", types.UserKindBilling))
			assert.Zero(t, count(t, db, &model.Organization{}, "slug = ?", "bobco"))
		})

		t.Run("duplicate and reserved slugs are 409 and leave no orphan wallet", func(t *testing.T) {
			carol := newUser(t, db, "carol", "carol@example.com")
			wallets := count(t, db, &model.User{}, "kind = ?", types.UserKindBilling)
			_, err := CreateOrganization(ctx, carol.Id, CreateOrganizationInput{Name: "Again", Slug: "acme"})
			requireRefusal(t, err, types.OrgErrSlugTaken)
			for _, slug := range []string{"admin", "api", "new", "default", "settings"} {
				_, err = CreateOrganization(ctx, carol.Id, CreateOrganizationInput{Name: "Reserved", Slug: slug})
				requireRefusal(t, err, types.OrgErrSlugReserved)
			}
			assert.Equal(t, wallets, count(t, db, &model.User{}, "kind = ?", types.UserKindBilling),
				"a failed creation must roll the wallet back")
		})

		t.Run("slug validation", func(t *testing.T) {
			dave := newUser(t, db, "dave", "dave@example.com")
			for _, slug := range []string{"ab", "Has-Upper", "-leading", "has space", "under_score", "12345", "x" + fmt.Sprintf("%040d", 1)} {
				_, err := CreateOrganization(ctx, dave.Id, CreateOrganizationInput{Name: "Bad", Slug: slug})
				requireRefusal(t, err, types.OrgErrInvalidInput)
			}
			for _, name := range []string{"", "   "} {
				_, err := CreateOrganization(ctx, dave.Id, CreateOrganizationInput{Name: name, Slug: "daveco"})
				requireRefusal(t, err, types.OrgErrInvalidInput)
			}
		})

		t.Run("the billing group is the platform group, never the creator's", func(t *testing.T) {
			vip := newUser(t, db, "vip", "vip@example.com")
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", vip.Id).Update("group", "vip").Error)
			created, err := CreateOrganization(ctx, vip.Id, CreateOrganizationInput{Name: "VIP Co", Slug: "vipco"})
			require.NoError(t, err)
			assert.Equal(t, DefaultBillingGroup, created.Org.BillingGroup)
			var wallet model.User
			require.NoError(t, db.First(&wallet, created.Org.BillingUserId).Error)
			assert.Equal(t, DefaultBillingGroup, wallet.Group)
		})

		t.Run("a failure after the wallet exists rolls everything back", func(t *testing.T) {
			erin := newUser(t, db, "erin", "erin@example.com")
			wallets := count(t, db, &model.User{}, "kind = ?", types.UserKindBilling)
			orgs := count(t, db, &model.Organization{}, "1 = 1")
			createFaultHook = func(step string) error {
				if step == "after_owner" {
					return errors.New("injected failure")
				}
				return nil
			}
			t.Cleanup(func() { createFaultHook = nil })
			_, err := CreateOrganization(ctx, erin.Id, CreateOrganizationInput{Name: "Fault", Slug: "faultco"})
			require.Error(t, err)
			assert.Equal(t, wallets, count(t, db, &model.User{}, "kind = ?", types.UserKindBilling))
			assert.Equal(t, orgs, count(t, db, &model.Organization{}, "1 = 1"))
			assert.Zero(t, count(t, db, &model.OrganizationMember{}, "user_id = ?", erin.Id))
			assert.Zero(t, count(t, db, &model.OrgAuditLog{}, "actor_user_id = ?", erin.Id))
		})
	})
}

// orgWithMembers creates an organization through the real service and adds the
// given members straight into the table (joining is Task 6's concern).
func orgWithMembers(t *testing.T, db *gorm.DB, slug string, roles map[string]string) (*model.Organization, map[string]*model.User) {
	t.Helper()
	users := map[string]*model.User{}
	creator := newUser(t, db, slug+"-creator", slug+"-creator@example.com")
	created, err := CreateOrganization(context.Background(), creator.Id, CreateOrganizationInput{Name: slug, Slug: slug})
	require.NoError(t, err)
	users["creator"] = creator
	for name, role := range roles {
		user := newUser(t, db, slug+"-"+name, slug+"-"+name+"@example.com")
		users[name] = user
		require.NoError(t, db.Create(&model.OrganizationMember{OrgId: created.Org.Id, UserId: user.Id, Role: role,
			Status: types.OrgMemberStatusActive, JoinedAt: common.GetTimestamp()}).Error)
	}
	return &created.Org, users
}

func ownerCount(t *testing.T, db *gorm.DB, orgID int) int64 {
	return count(t, db, &model.OrganizationMember{}, "org_id = ? AND role = ? AND status = ?", orgID, types.OrgRoleOwner, types.OrgMemberStatusActive)
}

func TestOrgOwnership(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		org, u := orgWithMembers(t, db, "own", map[string]string{"admin": types.OrgRoleAdmin, "second": types.OrgRoleOwner,
			"billing": types.OrgRoleBilling, "member": types.OrgRoleMember})
		name := "Renamed"

		t.Run("only an owner may change settings", func(t *testing.T) {
			for _, who := range []string{"admin", "billing", "member"} {
				_, err := UpdateOrganization(ctx, u[who].Id, org.Id, UpdateOrganizationInput{Name: &name})
				requireRefusal(t, err, types.OrgErrForbidden)
			}
			updated, err := UpdateOrganization(ctx, u["creator"].Id, org.Id, UpdateOrganizationInput{Name: &name})
			require.NoError(t, err)
			assert.Equal(t, "Renamed", updated.Name)
			zone := "Europe/Berlin"
			updated, err = UpdateOrganization(ctx, u["second"].Id, org.Id, UpdateOrganizationInput{DisplayTimezone: &zone})
			require.NoError(t, err)
			assert.Contains(t, updated.Settings, "Europe/Berlin")
			bad := "Mars/Olympus"
			_, err = UpdateOrganization(ctx, u["creator"].Id, org.Id, UpdateOrganizationInput{DisplayTimezone: &bad})
			requireRefusal(t, err, types.OrgErrInvalidInput)
			_, err = UpdateOrganization(ctx, u["creator"].Id, org.Id, UpdateOrganizationInput{})
			requireRefusal(t, err, types.OrgErrInvalidInput)
		})

		t.Run("an admin can neither grant, demote nor remove an owner", func(t *testing.T) {
			requireRefusal(t, ChangeMemberRole(ctx, u["admin"].Id, org.Id, u["member"].Id, types.OrgRoleOwner), types.OrgErrOwnerRole)
			requireRefusal(t, ChangeMemberRole(ctx, u["admin"].Id, org.Id, u["second"].Id, types.OrgRoleMember), types.OrgErrOwnerRole)
			requireRefusal(t, ChangeMemberRole(ctx, u["admin"].Id, org.Id, u["creator"].Id, types.OrgRoleAdmin), types.OrgErrOwnerRole)
			requireRefusal(t, ChangeMemberRole(ctx, u["member"].Id, org.Id, u["billing"].Id, types.OrgRoleAdmin), types.OrgErrForbidden)
			assert.EqualValues(t, 2, ownerCount(t, db, org.Id))
			require.NoError(t, ChangeMemberRole(ctx, u["admin"].Id, org.Id, u["member"].Id, types.OrgRoleBilling), "admins still manage the other roles")
		})

		t.Run("the primary owner is demoted only through a transfer", func(t *testing.T) {
			requireRefusal(t, ChangeMemberRole(ctx, u["second"].Id, org.Id, u["creator"].Id, types.OrgRoleAdmin), types.OrgErrOwnerRole)
			assert.Equal(t, types.OrgRoleOwner, memberRole(t, db, org.Id, u["creator"].Id))
		})

		t.Run("a non-primary owner can be demoted while another owner remains", func(t *testing.T) {
			require.NoError(t, ChangeMemberRole(ctx, u["creator"].Id, org.Id, u["second"].Id, types.OrgRoleAdmin))
			assert.EqualValues(t, 1, ownerCount(t, db, org.Id))
		})

		t.Run("the last owner cannot leave or be demoted", func(t *testing.T) {
			requireRefusal(t, ChangeMemberRole(ctx, u["creator"].Id, org.Id, u["creator"].Id, types.OrgRoleMember), types.OrgErrLastOwner)
			assert.EqualValues(t, 1, ownerCount(t, db, org.Id))
		})

		t.Run("transfer keeps owner_user_id and the active owner member in step", func(t *testing.T) {
			requireRefusal(t, TransferOwnership(ctx, u["admin"].Id, org.Id, u["second"].Id), types.OrgErrForbidden)
			requireRefusal(t, TransferOwnership(ctx, u["creator"].Id, org.Id, u["creator"].Id), types.OrgErrOwnerRole)
			requireRefusal(t, TransferOwnership(ctx, u["creator"].Id, org.Id, 424242), types.OrgErrMemberNotFound)
			require.NoError(t, db.Model(&model.OrganizationMember{}).Where("org_id = ? AND user_id = ?", org.Id, u["member"].Id).
				Update("status", types.OrgMemberStatusSuspended).Error)
			requireRefusal(t, TransferOwnership(ctx, u["creator"].Id, org.Id, u["member"].Id), types.OrgErrMemberNotFound)

			before := orgVersion(t, db, org.Id)
			require.NoError(t, TransferOwnership(ctx, u["creator"].Id, org.Id, u["second"].Id))
			var reloaded model.Organization
			require.NoError(t, db.First(&reloaded, org.Id).Error)
			assert.Equal(t, u["second"].Id, reloaded.OwnerUserId)
			assert.Equal(t, types.OrgRoleOwner, memberRole(t, db, org.Id, u["second"].Id))
			assert.Equal(t, types.OrgRoleAdmin, memberRole(t, db, org.Id, u["creator"].Id), "the former owner becomes admin")
			assert.EqualValues(t, 1, ownerCount(t, db, org.Id))
			assert.Greater(t, reloaded.PolicyVersion, before)
			assert.EqualValues(t, 1, count(t, db, &model.OrgAuditLog{}, "org_id = ? AND action = ?", org.Id, "org.transfer_ownership"))
			// The old owner is now an admin and may not touch settings.
			_, err := UpdateOrganization(ctx, u["creator"].Id, org.Id, UpdateOrganizationInput{Name: &name})
			requireRefusal(t, err, types.OrgErrForbidden)
		})

		t.Run("concurrent demotions are serialized on the organization lock and keep the primary owner", func(t *testing.T) {
			org2, v := orgWithMembers(t, db, "race", map[string]string{"b": types.OrgRoleOwner, "c": types.OrgRoleOwner})
			var wg sync.WaitGroup
			results := make([]error, 2)
			wg.Add(2)
			go func() {
				defer wg.Done()
				results[0] = ChangeMemberRole(ctx, v["b"].Id, org2.Id, v["c"].Id, types.OrgRoleMember)
			}()
			go func() {
				defer wg.Done()
				results[1] = ChangeMemberRole(ctx, v["c"].Id, org2.Id, v["b"].Id, types.OrgRoleMember)
			}()
			wg.Wait()
			assert.Equal(t, types.OrgRoleOwner, memberRole(t, db, org2.Id, v["creator"].Id))
			assert.GreaterOrEqual(t, ownerCount(t, db, org2.Id), int64(1))
			succeeded := 0
			for _, err := range results {
				if err == nil {
					succeeded++
				}
			}
			assert.GreaterOrEqual(t, succeeded, 1)
		})
	})
}

func memberRole(t *testing.T, db *gorm.DB, orgID, userID int) string {
	t.Helper()
	member, err := model.GetOrganizationMember(db, orgID, userID)
	require.NoError(t, err)
	return member.Role
}

func orgVersion(t *testing.T, db *gorm.DB, orgID int) int64 {
	t.Helper()
	var v int64
	require.NoError(t, db.Model(&model.Organization{}).Where("id = ?", orgID).Select("policy_version").Scan(&v).Error)
	return v
}
