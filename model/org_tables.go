package model

// OrgModels returns every table of the organization feature, in dependency
// order. Packages outside model use it to create or drop the tables in tests.
func OrgModels() []any { return orgModels() }

// MigrateOrgTables creates the organization tables on the main database. It is
// the same migration startup runs and is idempotent.
func MigrateOrgTables() error { return migrateOrgTables() }
