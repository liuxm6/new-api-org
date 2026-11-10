package router

import (
	"strconv"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrgRouteBudgets(t *testing.T) {
	f := setupOrgRoutes(t)
	for _, name := range []string{"owner", "admin", "biller", "wsadmin", "dev", "stranger"} {
		f.user(t, name, name+"@example.com")
	}
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)
	var acme model.Organization
	require.NoError(t, f.db.Where("slug = ?", "acme").First(&acme).Error)
	for name, role := range map[string]string{"admin": types.OrgRoleAdmin, "biller": types.OrgRoleBilling,
		"wsadmin": types.OrgRoleMember, "dev": types.OrgRoleMember} {
		require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: acme.Id, UserId: f.users[name].Id, Role: role,
			Status: types.OrgMemberStatusActive}).Error)
	}
	base := "/api/orgs/acme"
	require.Equal(t, 200, f.do(t, f.tokens["admin"], "POST", base+"/workspaces", `{"name":"Prod","slug":"prod"}`).Status)
	for name, role := range map[string]string{"wsadmin": "admin", "dev": "member"} {
		require.Equal(t, 200, f.do(t, f.tokens["admin"], "PUT",
			base+"/workspaces/prod/members/"+strconv.Itoa(f.users[name].Id), `{"role":"`+role+`"}`).Status)
	}
	var prod model.Workspace
	require.NoError(t, f.db.Where("slug = ?", "prod").First(&prod).Error)
	devKey := model.Token{UserId: acme.BillingUserId, Key: "devkey", Name: "dev", Status: common.TokenStatusEnabled, ExpiredTime: -1,
		UnlimitedQuota: true, OrgId: acme.Id, WorkspaceId: prod.Id, CreatedBy: f.users["dev"].Id, OwnerType: types.TokenOwnerMember, AccessPrincipalId: "p1"}
	require.NoError(t, f.db.Create(&devKey).Error)
	version := func(path, bearer string) int64 {
		return int64(f.do(t, f.tokens[bearer], "GET", path, "").data()["version"].(float64))
	}
	put := func(bearer, path, body string) routeReply { return f.do(t, f.tokens[bearer], "PUT", path, body) }
	budget := func(period string, limit int, enabled bool) string {
		return `{"period":"` + period + `","limit":` + strconv.Itoa(limit) + `,"enabled":` + strconv.FormatBool(enabled) + `}`
	}
	body := func(version int64, rows ...string) string {
		out := `{"version":` + strconv.FormatInt(version, 10) + `,"budgets":[`
		for i, row := range rows {
			if i > 0 {
				out += ","
			}
			out += row
		}
		return out + `]}`
	}
	memberPath := base + "/members/" + strconv.Itoa(f.users["dev"].Id) + "/budgets"
	keyPath := base + "/workspaces/prod/keys/" + strconv.Itoa(devKey.Id) + "/budgets"

	t.Run("organization budget: owners and admins write, billing reads, others do not", func(t *testing.T) {
		path := base + "/budgets"
		assert.Equal(t, 403, put("biller", path, body(0, budget("monthly", 1000, true))).Status)
		assert.Equal(t, 403, put("dev", path, body(0, budget("monthly", 1000, true))).Status)
		assert.Equal(t, 404, put("stranger", path, body(0, budget("monthly", 1000, true))).Status)
		reply := put("admin", path, body(0, budget("monthly", 1000, true), budget("daily", 100, true)))
		require.Equal(t, 200, reply.Status, reply.Raw)
		assert.Len(t, reply.data()["budgets"], 2)
		for _, name := range []string{"owner", "admin", "biller"} {
			assert.Equal(t, 200, f.do(t, f.tokens[name], "GET", path, "").Status, name)
		}
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "GET", path, "").Status)
	})

	t.Run("a workspace admin can never reach an organization member's budget", func(t *testing.T) {
		assert.Equal(t, 403, put("wsadmin", memberPath, body(0, budget("daily", 50, true))).Status)
		assert.Equal(t, 403, f.do(t, f.tokens["wsadmin"], "GET", memberPath, "").Status)
		assert.Equal(t, 403, put("biller", memberPath, body(0, budget("daily", 50, true))).Status)
		require.Equal(t, 200, put("admin", memberPath, body(0, budget("daily", 50, true))).Status)
		assert.Equal(t, 200, f.do(t, f.tokens["dev"], "GET", memberPath, "").Status, "a member reads their own")
		assert.Equal(t, 403, put("dev", memberPath, body(0, budget("daily", 1_000_000, true))).Status, "but cannot write it, even to raise it")
		assert.Contains(t, f.do(t, f.tokens["dev"], "GET", memberPath, "").Raw, `"limit":50`, "the budget is as the admin set it")
		assert.Equal(t, 404, put("admin", base+"/members/"+strconv.Itoa(f.users["stranger"].Id)+"/budgets",
			body(0, budget("daily", 50, true))).Status, "only organization members have a budget")
	})

	t.Run("workspace budget: workspace admins write", func(t *testing.T) {
		path := base + "/workspaces/prod/budgets"
		assert.Equal(t, 403, put("dev", path, body(0, budget("monthly", 500, true))).Status)
		require.Equal(t, 200, put("wsadmin", path, body(0, budget("monthly", 500, true))).Status)
		assert.Equal(t, 404, put("stranger", path, body(0, budget("monthly", 500, true))).Status)
	})

	t.Run("key budget: admins write, the creator may only tighten", func(t *testing.T) {
		require.Equal(t, 200, put("wsadmin", keyPath, body(0, budget("daily", 100, true), budget("monthly", 1000, true))).Status)
		v := version(keyPath, "wsadmin")
		assert.Equal(t, 200, put("dev", keyPath, body(v, budget("daily", 80, true), budget("monthly", 900, true))).Status, "lower limits")
		v = version(keyPath, "dev")
		assert.Equal(t, 403, put("dev", keyPath, body(v, budget("daily", 90, true), budget("monthly", 900, true))).Status, "raising a limit")
		assert.Equal(t, 403, put("dev", keyPath, body(v, budget("daily", 80, false), budget("monthly", 900, true))).Status, "switching a period off")
		assert.Equal(t, 403, put("dev", keyPath, body(v, budget("monthly", 900, true))).Status, "dropping a period")
		assert.Equal(t, 200, put("dev", keyPath, body(v, budget("daily", 80, true), budget("monthly", 900, true), budget("lifetime", 5000, true))).Status,
			"adding a period only tightens")
		assert.Equal(t, 404, put("stranger", keyPath, body(0, budget("daily", 1, true))).Status, "not a member of the organization")
		assert.Equal(t, 404, f.do(t, f.tokens["biller"], "GET", keyPath, "").Status, "billing is not in the workspace, so it is not there")
	})

	t.Run("a stale version is refused and writes nothing", func(t *testing.T) {
		path := base + "/budgets"
		v := version(path, "owner")
		require.Equal(t, 200, put("owner", path, body(v, budget("monthly", 2000, true), budget("daily", 100, true))).Status)
		stale := put("owner", path, body(v, budget("monthly", 9, true)))
		assert.Equal(t, 409, stale.Status)
		got := f.do(t, f.tokens["owner"], "GET", path, "")
		assert.Contains(t, got.Raw, `"limit":2000`, "the refused write changed nothing")
	})

	t.Run("a set is replaced as a whole: unlisted periods are switched off, not deleted", func(t *testing.T) {
		path := base + "/budgets"
		v := version(path, "owner")
		reply := put("owner", path, body(v, budget("monthly", 2000, true)))
		require.Equal(t, 200, reply.Status, reply.Raw)
		rows := reply.data()["budgets"].([]any)
		byPeriod := map[string]map[string]any{}
		for _, row := range rows {
			r := row.(map[string]any)
			byPeriod[r["period"].(string)] = r
		}
		assert.Equal(t, true, byPeriod["monthly"]["enabled"])
		assert.Equal(t, false, byPeriod["daily"]["enabled"], "daily was left out: off, with its history kept")
	})

	t.Run("limits must not shrink toward the longer period", func(t *testing.T) {
		path := base + "/budgets"
		v := version(path, "owner")
		assert.Equal(t, 400, put("owner", path, body(v, budget("monthly", 100, true), budget("lifetime", 50, true))).Status)
		assert.Equal(t, 400, put("owner", path, body(v, budget("daily", 500, true), budget("monthly", 100, true))).Status)
		assert.Equal(t, 200, put("owner", path, body(v, budget("daily", 50, false), budget("monthly", 100, true))).Status,
			"a disabled period does not take part in the ordering")
	})

	t.Run("bodies are strict", func(t *testing.T) {
		path := base + "/budgets"
		for _, raw := range []string{
			`{"budgets":[{"period":"yearly","limit":1}]}`,
			`{"budgets":[{"period":"daily","limit":-1}]}`,
			`{"budgets":[{"period":"daily","limit":1},{"period":"daily","limit":2}]}`,
			`{"budgets":[{"period":"daily","limit":1,"org_id":9}]}`,
			`{"budgets":[{"period":"daily"}]}`,
			`{"budgets":"x"}`,
			`{"budgets":[],"org_id":9}`,
			`{"version":-1,"budgets":[]}`,
		} {
			assert.Equal(t, 400, put("owner", path, raw).Status, raw)
		}
	})

	t.Run("a spent budget stays visible after it is switched off", func(t *testing.T) {
		path := base + "/members/" + strconv.Itoa(f.users["dev"].Id) + "/budgets"
		v := version(path, "owner")
		reply := put("owner", path, body(v))
		require.Equal(t, 200, reply.Status)
		for _, row := range reply.data()["budgets"].([]any) {
			assert.Equal(t, false, row.(map[string]any)["enabled"])
		}
	})
}
