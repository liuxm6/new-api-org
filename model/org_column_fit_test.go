package model

import (
	"testing"

	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/require"
)

// SQLite ignores varchar lengths, so a value longer than its column only fails
// on MySQL and PostgreSQL. This inserts every legal value of the enum-like
// columns through the real schema; the router tests run on SQLite and cannot
// see this class of mistake.
func TestOrgEnumValuesFitTheirColumns(t *testing.T) {
	for _, dialect := range orgTaskDialects() {
		t.Run(dialect, func(t *testing.T) {
			db := openOrgMigrationDB(t, dialect)
			require.NoError(t, db.AutoMigrate(&Guardrail{}, &OrgAccessToken{}))

			for _, target := range []string{types.GuardrailTargetOrgDefault, types.GuardrailTargetWorkspaceDefault, "member", "key"} {
				require.NoError(t, db.Create(&Guardrail{OrgId: 1, Name: "fit", TargetType: target, Config: "{}", Status: 1}).Error,
					"guardrail target %q must fit its column", target)
			}
			for _, kind := range []string{types.OrgAccessTokenPersonalManagement, types.OrgAccessTokenSCIMService} {
				require.NoError(t, db.Create(&OrgAccessToken{OrgId: 1, Name: "fit", TokenHash: "h-" + kind, TokenHint: "abcd", Scopes: "[]",
					Kind: kind, Status: types.OrgAccessTokenActive}).Error, "credential kind %q must fit its column", kind)
			}
		})
	}
}
