package router

import (
	"strconv"
	"testing"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrgRouteGuardrails(t *testing.T) {
	f := setupOrgRoutes(t)
	require.NoError(t, f.db.AutoMigrate(&model.Guardrail{}))
	f.user(t, "owner", "owner@example.com")
	f.user(t, "admin", "admin@example.com")
	f.user(t, "wsadmin", "wsadmin@example.com")
	f.user(t, "auditor", "auditor@example.com")
	f.user(t, "dev", "dev@example.com")
	f.user(t, "stranger", "stranger@example.com")
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)
	var acme model.Organization
	require.NoError(t, f.db.Where("slug = ?", "acme").First(&acme).Error)
	for name, role := range map[string]string{"admin": types.OrgRoleAdmin, "wsadmin": types.OrgRoleMember,
		"auditor": types.OrgRoleMember, "dev": types.OrgRoleMember} {
		require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: acme.Id, UserId: f.users[name].Id, Role: role,
			Status: types.OrgMemberStatusActive}).Error)
	}
	base := "/api/orgs/acme"
	require.Equal(t, 200, f.do(t, f.tokens["admin"], "POST", base+"/workspaces", `{"name":"Prod","slug":"prod"}`).Status)
	other := f.do(t, f.tokens["admin"], "POST", base+"/workspaces", `{"name":"Dev","slug":"devws"}`)
	require.Equal(t, 200, other.Status)
	for name, role := range map[string]string{"wsadmin": "admin", "auditor": "auditor", "dev": "member"} {
		require.Equal(t, 200, f.do(t, f.tokens["admin"], "PUT",
			base+"/workspaces/prod/members/"+strconv.Itoa(f.users[name].Id), `{"role":"`+role+`"}`).Status)
	}
	version := func() int64 {
		var org model.Organization
		require.NoError(t, f.db.First(&org, acme.Id).Error)
		return org.PolicyVersion
	}
	body := func(target string, targetID int, config string) string {
		return `{"name":"rule","target_type":"` + target + `","target_id":` + strconv.Itoa(targetID) + `,"config":` + config + `}`
	}
	denyGPT := `{"denied_models":["gpt-4o"]}`

	t.Run("organization scope is for organization owners and admins", func(t *testing.T) {
		for _, name := range []string{"wsadmin", "auditor", "dev"} {
			assert.Equal(t, 403, f.do(t, f.tokens[name], "POST", base+"/guardrails", body("org_default", 0, denyGPT)).Status, name)
			assert.Equal(t, 403, f.do(t, f.tokens[name], "GET", base+"/guardrails", "").Status, name)
		}
		assert.Equal(t, 404, f.do(t, f.tokens["stranger"], "GET", base+"/guardrails", "").Status)
		before := version()
		created := f.do(t, f.tokens["admin"], "POST", base+"/guardrails", body("org_default", 0, denyGPT))
		require.Equal(t, 200, created.Status, created.Raw)
		assert.Greater(t, version(), before, "a guardrail write invalidates cached policies")
		list := f.do(t, f.tokens["owner"], "GET", base+"/guardrails", "")
		assert.Equal(t, 200, list.Status)
		assert.Contains(t, list.Raw, `"denied_models"`)
	})

	t.Run("workspace scope: admins write, auditors read, members neither", func(t *testing.T) {
		ws := base + "/workspaces/prod/guardrails"
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "GET", ws, "").Status)
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "POST", ws, body("workspace_default", 0, denyGPT)).Status)
		assert.Equal(t, 200, f.do(t, f.tokens["auditor"], "GET", ws, "").Status)
		assert.Equal(t, 403, f.do(t, f.tokens["auditor"], "POST", ws, body("workspace_default", 0, denyGPT)).Status)
		created := f.do(t, f.tokens["wsadmin"], "POST", ws, body("workspace_default", 0, `{"allowed_models":["gpt-*"]}`))
		require.Equal(t, 200, created.Status, created.Raw)
		listed := f.do(t, f.tokens["auditor"], "GET", ws, "")
		assert.Contains(t, listed.Raw, "inherited", "a workspace listing shows the inherited organization rules")
		assert.Contains(t, listed.Raw, `"gpt-4o"`)
	})

	t.Run("a workspace admin cannot reach organization rules or organization scope targets", func(t *testing.T) {
		ws := base + "/workspaces/prod/guardrails"
		assert.Equal(t, 400, f.do(t, f.tokens["wsadmin"], "POST", ws, body("org_default", 0, denyGPT)).Status,
			"org_default belongs to the organization route")
		var orgRule model.Guardrail
		require.NoError(t, f.db.Where("org_id = ? AND workspace_id = 0", acme.Id).First(&orgRule).Error)
		id := strconv.Itoa(orgRule.Id)
		assert.Equal(t, 404, f.do(t, f.tokens["wsadmin"], "PATCH", ws+"/"+id, body("org_default", 0, `{}`)).Status)
		assert.Equal(t, 404, f.do(t, f.tokens["wsadmin"], "DELETE", ws+"/"+id, "").Status)
		assert.Equal(t, 400, f.do(t, f.tokens["admin"], "POST", base+"/guardrails", body("workspace_default", 0, denyGPT)).Status,
			"workspace_default belongs to a workspace route")
		assert.Equal(t, 400, f.do(t, f.tokens["admin"], "POST", base+"/guardrails", body("key", 1, denyGPT)).Status,
			"the organization has no keys")
	})

	t.Run("targets must belong to the scope", func(t *testing.T) {
		ws := base + "/workspaces/prod/guardrails"
		assert.Equal(t, 200, f.do(t, f.tokens["wsadmin"], "POST", ws, body("member", f.users["dev"].Id, denyGPT)).Status)
		assert.Equal(t, 404, f.do(t, f.tokens["wsadmin"], "POST", ws, body("member", f.users["stranger"].Id, denyGPT)).Status,
			"only organization members can be targeted")
		assert.Equal(t, 404, f.do(t, f.tokens["wsadmin"], "POST", ws, body("key", 999999, denyGPT)).Status)
		foreign := model.Token{UserId: 1, Key: "foreign", Name: "f", Status: 1, ExpiredTime: -1, OrgId: acme.Id, WorkspaceId: 9999}
		require.NoError(t, f.db.Create(&foreign).Error)
		assert.Equal(t, 404, f.do(t, f.tokens["wsadmin"], "POST", ws, body("key", foreign.Id, denyGPT)).Status,
			"a key of another workspace cannot be targeted")
		assert.Equal(t, 400, f.do(t, f.tokens["wsadmin"], "POST", ws, body("member", 0, denyGPT)).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["wsadmin"], "POST", ws, body("galaxy", 0, denyGPT)).Status)
	})

	t.Run("configs are strict: no budgets, no unknown fields, object only", func(t *testing.T) {
		ws := base + "/workspaces/prod/guardrails"
		for _, config := range []string{`{"budget_refs":["b"]}`, `{"allowed_modles":["x"]}`, `{"allowed_models":"x"}`, `{"denied_models":[""]}`} {
			assert.Equal(t, 400, f.do(t, f.tokens["wsadmin"], "POST", ws, body("workspace_default", 0, config)).Status, config)
		}
		assert.Equal(t, 400, f.do(t, f.tokens["wsadmin"], "POST", ws,
			`{"name":"r","target_type":"workspace_default","config":["x"]}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["wsadmin"], "POST", ws,
			`{"name":"r","target_type":"workspace_default"}`).Status, "config is required")
		assert.Equal(t, 400, f.do(t, f.tokens["wsadmin"], "POST", ws,
			`{"name":"r","target_type":"workspace_default","config":{},"org_id":9}`).Status, "no smuggled fields")
	})

	t.Run("update keeps the target, delete audits, versions advance every time", func(t *testing.T) {
		ws := base + "/workspaces/prod/guardrails"
		created := f.do(t, f.tokens["wsadmin"], "POST", ws, body("member", f.users["dev"].Id, `{"denied_models":["a"]}`))
		require.Equal(t, 200, created.Status)
		id := strconv.Itoa(int(created.data()["id"].(float64)))
		before := version()
		assert.Equal(t, 400, f.do(t, f.tokens["wsadmin"], "PATCH", ws+"/"+id,
			body("member", f.users["auditor"].Id, `{"denied_models":["a"]}`)).Status, "the target cannot change")
		assert.Equal(t, before, version(), "a refused write changes nothing")
		upd := f.do(t, f.tokens["wsadmin"], "PATCH", ws+"/"+id, body("member", f.users["dev"].Id, `{"denied_models":["b"]}`))
		require.Equal(t, 200, upd.Status, upd.Raw)
		assert.Greater(t, version(), before)
		mid := version()
		assert.Equal(t, 200, f.do(t, f.tokens["wsadmin"], "DELETE", ws+"/"+id, "").Status)
		assert.Greater(t, version(), mid)
		assert.Equal(t, 404, f.do(t, f.tokens["wsadmin"], "DELETE", ws+"/"+id, "").Status, "already gone")
		var audits int64
		require.NoError(t, f.db.Model(&model.OrgAuditLog{}).Where("org_id = ? AND action LIKE ?", acme.Id, "guardrail.%").Count(&audits).Error)
		assert.GreaterOrEqual(t, audits, int64(3))
	})

	t.Run("a rule in another workspace is not reachable by id", func(t *testing.T) {
		require.Equal(t, 200, f.do(t, f.tokens["admin"], "POST", base+"/workspaces/devws/guardrails",
			body("workspace_default", 0, denyGPT)).Status)
		var row model.Guardrail
		require.NoError(t, f.db.Joins("JOIN workspaces w ON w.id = guardrails.workspace_id").Where("w.slug = ?", "devws").First(&row).Error)
		assert.Equal(t, 404, f.do(t, f.tokens["wsadmin"], "DELETE",
			base+"/workspaces/prod/guardrails/"+strconv.Itoa(row.Id), "").Status)
	})
}
