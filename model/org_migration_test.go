package model

import (
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// expectedOrgTables is the full list required by the design (section 3.1).
// It is spelled out so adding or dropping a table fails this test.
var expectedOrgTables = []string{
	"organizations", "organization_members", "workspaces", "workspace_members",
	"workspace_member_grants", "invites", "org_identities", "scim_group_mappings",
	"budgets", "org_budget_usage", "guardrails", "org_access_tokens",
	"org_audit_logs", "org_billing_profiles", "org_invoices", "org_billing_ledger",
	"org_billing_operations", "org_spend_events", "org_spend_fold_queue",
	"org_fold_batches", "org_spend_rollups", "org_quota_leases",
	"org_writeoff_daily", "org_billing_jobs",
}

func openOrgMigrationDB(t *testing.T, dialect string) *gorm.DB {
	t.Helper()
	var driver gorm.Dialector
	switch dialect {
	case "sqlite":
		driver = sqlite.Open(":memory:")
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
	sqlDB.SetMaxOpenConns(1)

	previousDB, previousType := DB, common.MainDatabaseType()
	DB = db
	common.SetMainDatabaseType(common.DatabaseType(dialect))
	initCol()
	t.Cleanup(func() {
		DB = previousDB
		common.SetMainDatabaseType(previousType)
		initCol()
		assert.NoError(t, sqlDB.Close())
	})

	if dialect == "postgres" {
		// Isolate in a throwaway schema inside a transaction that is rolled back.
		tx := db.Begin()
		require.NoError(t, tx.Error)
		t.Cleanup(func() { assert.NoError(t, tx.Rollback().Error) })
		schema := fmt.Sprintf("org_migration_test_%d", time.Now().UnixNano())
		require.NoError(t, tx.Exec("CREATE SCHEMA ?", clause.Table{Name: schema}).Error)
		require.NoError(t, tx.Exec("SET LOCAL search_path TO ?", clause.Table{Name: schema}).Error)
		DB = tx
		return tx
	}
	// MySQL needs a clean slate; the tables are dropped again afterwards.
	if dialect == "mysql" {
		dropOrgTables(t, db)
		t.Cleanup(func() { dropOrgTables(t, db) })
	}
	return db
}

// createExpectingConflict inserts a row that is supposed to violate a unique
// key. PostgreSQL aborts the surrounding transaction on any error, and these
// tests run inside one, so the attempt is wrapped in a savepoint there. Other
// dialects need no wrapper.
func createExpectingConflict(db *gorm.DB, value any) error {
	if !common.UsingMainDatabase(common.DatabaseTypePostgreSQL) {
		return db.Create(value).Error
	}
	if err := db.SavePoint("expect_conflict").Error; err != nil {
		return err
	}
	err := db.Create(value).Error
	if err != nil {
		if rollbackErr := db.RollbackTo("expect_conflict").Error; rollbackErr != nil {
			return rollbackErr
		}
	}
	return err
}

func dropOrgTables(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, m := range slices.Backward(orgModels()) {
		require.NoError(t, db.Migrator().DropTable(m))
	}
	require.NoError(t, db.Migrator().DropTable(&User{}))
}

func TestOrgMigration(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			db := openOrgMigrationDB(t, dialect)

			// Existing tables first, as in production, then the org tables twice.
			require.NoError(t, db.AutoMigrate(&User{}))
			for range 2 {
				require.NoError(t, migrateOrgTables())
			}

			t.Run("every table exists", func(t *testing.T) {
				assert.Len(t, orgModels(), len(expectedOrgTables))
				for _, name := range expectedOrgTables {
					assert.True(t, db.Migrator().HasTable(name), name)
				}
			})

			t.Run("users wallet columns are 64-bit", func(t *testing.T) {
				if dialect == "sqlite" {
					t.Skip("sqlite integers are always 64-bit")
				}
				require.NoError(t, ensureUserQuotaColumns(db, common.DatabaseType(dialect)))
			})

			t.Run("a user defaults to a human account", func(t *testing.T) {
				user := User{Username: "org_mig_user", Password: "x"}
				require.NoError(t, db.Create(&user).Error)
				var kind int
				require.NoError(t, db.Model(&User{}).Where("id = ?", user.Id).Select("kind").Scan(&kind).Error)
				assert.Equal(t, 0, kind)
			})

			t.Run("budgets are independent per organization", func(t *testing.T) {
				for _, orgID := range []int{1, 2} {
					require.NoError(t, db.Create(&Budget{OrgId: orgID, Scope: "member", SubjectId: 7, Period: "monthly", LimitQuota: 100, Enabled: true}).Error)
				}
				err := createExpectingConflict(db, &Budget{OrgId: 1, Scope: "member", SubjectId: 7, Period: "monthly", LimitQuota: 5, Enabled: true})
				assert.Error(t, err, "same org, scope, subject and period must be unique")
			})

			t.Run("budget usage is keyed by window", func(t *testing.T) {
				base := OrgBudgetUsage{OrgId: 1, Scope: "org", SubjectId: 1, Period: "daily", WindowStart: 1000}
				require.NoError(t, db.Create(&base).Error)
				next := base
				next.Id = 0
				next.WindowStart = 2000
				require.NoError(t, db.Create(&next).Error)
				dup := base
				dup.Id = 0
				assert.Error(t, createExpectingConflict(db, &dup))
			})

			t.Run("business keys are unique", func(t *testing.T) {
				require.NoError(t, db.Create(&OrgSpendEvent{OrgId: 1, OperationId: "op1", EventKind: "capture", Revision: 1}).Error)
				assert.Error(t, createExpectingConflict(db, &OrgSpendEvent{OrgId: 1, OperationId: "op1", EventKind: "capture", Revision: 1}))
				require.NoError(t, db.Create(&OrgBillingOperation{OperationId: "op1", OrgId: 1}).Error)
				assert.Error(t, createExpectingConflict(db, &OrgBillingOperation{OperationId: "op1", OrgId: 1}))
				require.NoError(t, db.Create(&OrgBillingJob{OrgId: 1, Kind: "receipt", BusinessKey: "receipt:t1"}).Error)
				assert.Error(t, createExpectingConflict(db, &OrgBillingJob{OrgId: 1, Kind: "receipt", BusinessKey: "receipt:t1"}))
				require.NoError(t, db.Create(&OrgInvoice{OrgId: 1, Number: "INV-1-1", BusinessKey: "statement:2026-11"}).Error)
				assert.Error(t, createExpectingConflict(db, &OrgInvoice{OrgId: 1, Number: "INV-1-2", BusinessKey: "statement:2026-11"}))
				require.NoError(t, db.Create(&OrgBillingLedger{OrgId: 1, IdempotencyKey: "topup:1"}).Error)
				assert.Error(t, createExpectingConflict(db, &OrgBillingLedger{OrgId: 1, IdempotencyKey: "topup:1"}))
			})

			t.Run("rollup is unique per period key workspace and effective period", func(t *testing.T) {
				row := OrgSpendRollup{OrgId: 1, Period: "2026-11", RollupKey: "k", WorkspaceId: 1, EffectivePeriod: "2026-10"}
				require.NoError(t, db.Create(&row).Error)
				other := row
				other.Id = 0
				other.EffectivePeriod = "2026-11"
				require.NoError(t, db.Create(&other).Error)
				dup := row
				dup.Id = 0
				assert.Error(t, createExpectingConflict(db, &dup))
			})

			t.Run("workspace grants allow several sources for one user", func(t *testing.T) {
				manual := WorkspaceMemberGrant{OrgId: 1, WorkspaceId: 1, UserId: 5, Source: "manual", SourceRef: "", Role: "member"}
				scim := WorkspaceMemberGrant{OrgId: 1, WorkspaceId: 1, UserId: 5, Source: "scim", SourceRef: "grp-a", Role: "admin"}
				require.NoError(t, db.Create(&manual).Error)
				require.NoError(t, db.Create(&scim).Error)
				dup := scim
				dup.Id = 0
				assert.Error(t, createExpectingConflict(db, &dup))
			})

			t.Run("scim external id may be absent for many identities", func(t *testing.T) {
				for i := range 3 {
					require.NoError(t, db.Create(&OrgIdentity{OrgId: 1, ProviderId: 1, Subject: fmt.Sprintf("sub-%d", i), UserId: 10 + i}).Error)
				}
				ext := "ext-1"
				require.NoError(t, db.Create(&OrgIdentity{OrgId: 1, ProviderId: 1, Subject: "sub-x", UserId: 20, ScimExternalId: &ext}).Error)
				same := "ext-1"
				assert.Error(t, createExpectingConflict(db, &OrgIdentity{OrgId: 1, ProviderId: 1, Subject: "sub-y", UserId: 21, ScimExternalId: &same}))
				require.NoError(t, db.Create(&OrgIdentity{OrgId: 2, ProviderId: 1, Subject: "sub-y", UserId: 22, ScimExternalId: &same}).Error)
			})

			t.Run("migrating again keeps data", func(t *testing.T) {
				var before int64
				require.NoError(t, db.Model(&Budget{}).Count(&before).Error)
				require.NoError(t, migrateOrgTables())
				var after int64
				require.NoError(t, db.Model(&Budget{}).Count(&after).Error)
				assert.Equal(t, before, after)
			})
		})
	}
}

// TestOrgExistingTablesGainColumns checks the columns added to tables that
// already hold personal data, and that the defaults keep old rows personal.
func TestOrgExistingTablesGainColumns(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			db := openOrgMigrationDB(t, dialect)
			if dialect == "mysql" {
				t.Cleanup(func() {
					for _, m := range []any{&Token{}, &Task{}, &Midjourney{}, &QuotaData{}, &CustomOAuthProvider{}, &UserSession{}} {
						require.NoError(t, db.Migrator().DropTable(m))
					}
				})
			}
			require.NoError(t, db.AutoMigrate(&Token{}, &Task{}, &Midjourney{}, &QuotaData{}, &CustomOAuthProvider{}, &UserSession{}))

			want := map[any][]string{
				&Token{}:               {"org_id", "workspace_id", "created_by", "owner_type", "access_principal_id"},
				&Task{}:                {"org_id", "workspace_id", "actor_user_id", "owner_type", "access_principal_id", "billing_operation_id"},
				&Midjourney{}:          {"org_id", "workspace_id", "actor_user_id", "owner_type", "access_principal_id", "billing_operation_id"},
				&QuotaData{}:           {"org_id", "workspace_id", "actor_user_id"},
				&CustomOAuthProvider{}: {"org_id", "issuer"},
				&UserSession{}:         {"auth_scope", "org_id", "provider_id"},
			}
			for model, columns := range want {
				for _, column := range columns {
					assert.True(t, db.Migrator().HasColumn(model, column), "%T.%s", model, column)
				}
			}

			t.Run("old token rows stay personal", func(t *testing.T) {
				token := Token{UserId: 1, Key: "mig-key", Name: "t"}
				require.NoError(t, db.Create(&token).Error)
				var got Token
				require.NoError(t, db.First(&got, token.Id).Error)
				assert.Zero(t, got.OrgId)
				assert.Zero(t, got.WorkspaceId)
				assert.Equal(t, "", got.OwnerType)
				assert.Equal(t, "", got.AccessPrincipalId)
			})

			t.Run("old sessions stay global", func(t *testing.T) {
				session := UserSession{SID: "mig-sid", UserID: 1, Status: UserSessionStatusActive, RefreshHash: "h", LoginMethod: "password"}
				require.NoError(t, db.Create(&session).Error)
				var got UserSession
				require.NoError(t, db.First(&got, "sid = ?", "mig-sid").Error)
				assert.Equal(t, "global", got.AuthScope)
				assert.Zero(t, got.OrgID)
			})
		})
	}
}
