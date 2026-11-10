#!/usr/bin/env bash
# Runs the organization tests against real SQLite, MySQL and PostgreSQL.
# It only calls existing tests and refuses to run without both DSNs; it never
# reads or stores credentials. Point the DSNs at disposable databases: the tests
# drop and recreate the organization tables.
set -euo pipefail

: "${TEST_MYSQL_DSN:?set TEST_MYSQL_DSN to a disposable MySQL database}"
: "${TEST_POSTGRES_DSN:?set TEST_POSTGRES_DSN to a disposable PostgreSQL database (postgres:// form)}"

cd "$(dirname "$0")/.."
log="$(mktemp)"
echo "go: $(go version)"
go test -p 1 -count=1 -v ./model ./service ./service/org ./middleware ./controller ./router -run '^TestOrg' >"$log" 2>&1 || true
grep -E '^(ok|FAIL|--- FAIL|panic)' "$log" || true
if grep -qE '^(FAIL|--- FAIL|panic)' "$log"; then
  echo "matrix failed; see $log" >&2
  exit 1
fi
# SQLite skips the cases that need row locks or fixed column types; a skipped
# MySQL or PostgreSQL case means that dialect did not prove the behavior.
if grep -E -- '--- SKIP' "$log" | grep -qE '/(mysql|postgres)(/|[ :])'; then
  echo "a MySQL or PostgreSQL case was skipped; the matrix is not proven; see $log" >&2
  exit 1
fi
echo "matrix passed on sqlite, mysql and postgres"
