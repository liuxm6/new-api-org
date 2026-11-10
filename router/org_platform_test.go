package router

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrgRoutePlatform(t *testing.T) {
	f := setupOrgRoutes(t)
	for _, name := range []string{"owner", "root", "nobody"} {
		f.user(t, name, name+"@example.com")
	}
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["root"].Id).Update("role", common.RoleRootUser).Error)
	f.tokens["root"] = f.session(t, f.users["root"], types.AuthScopeGlobal, 0)
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)
	var acme model.Organization
	require.NoError(t, f.db.Where("slug = ?", "acme").First(&acme).Error)
	base := "/api/admin/orgs/acme"
	wallet := func() int64 {
		var q int64
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", acme.BillingUserId).Select("quota").Scan(&q).Error)
		return q
	}
	doAs := func(name, key, method, path, body string) routeReply {
		return f.doHeaders(t, f.tokens[name], map[string]string{"Idempotency-Key": key}, method, path, body)
	}

	t.Run("only a platform administrator gets in", func(t *testing.T) {
		for _, path := range []string{"/api/admin/orgs", base + "/billing-operations"} {
			assert.Equal(t, 200, f.do(t, f.tokens["root"], "GET", path, "").Status, path)
			assert.Equal(t, 403, f.do(t, f.tokens["owner"], "GET", path, "").Status, "an organization owner is not platform staff: "+path)
			assert.Equal(t, 403, f.do(t, f.tokens["nobody"], "GET", path, "").Status, path)
		}
		restricted := f.session(t, f.users["root"], types.AuthScopeOrg, acme.Id)
		assert.Equal(t, 403, f.do(t, restricted, "GET", "/api/admin/orgs", "").Status, "an org-restricted session never reaches the platform")
	})

	t.Run("the list finds organizations and shows the wallet", func(t *testing.T) {
		reply := f.do(t, f.tokens["root"], "GET", "/api/admin/orgs?keyword=acm", "")
		require.Equal(t, 200, reply.Status)
		assert.Contains(t, reply.Raw, `"slug":"acme"`)
		assert.NotContains(t, f.do(t, f.tokens["root"], "GET", "/api/admin/orgs?keyword=zzz", "").Raw, `"slug":"acme"`)
	})

	t.Run("suspending needs a reason, is audited, and can be undone from the platform", func(t *testing.T) {
		assert.Equal(t, 400, f.do(t, f.tokens["root"], "PATCH", base, `{"status":2}`).Status, "no reason")
		assert.Equal(t, 400, f.do(t, f.tokens["root"], "PATCH", base, `{"status":2,"reason":"  "}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["root"], "PATCH", base, `{"reason":"x","owner_user_id":1}`).Status, "no smuggled fields")
		require.Equal(t, 200, f.do(t, f.tokens["root"], "PATCH", base, `{"status":2,"reason":"abuse report"}`).Status)
		assert.Equal(t, 403, f.do(t, f.tokens["owner"], "GET", "/api/orgs/acme/billing", "").Status, "the tenant is locked out")
		require.Equal(t, 200, f.do(t, f.tokens["root"], "PATCH", base, `{"status":1,"reason":"cleared"}`).Status)
		assert.Equal(t, 200, f.do(t, f.tokens["owner"], "GET", "/api/orgs/acme/billing", "").Status)
		var audits int64
		require.NoError(t, f.db.Model(&model.OrgAuditLog{}).Where("org_id = ? AND actor_kind = ? AND action IN ?", acme.Id, "platform",
			[]string{"org.suspend", "org.resume"}).Count(&audits).Error)
		assert.EqualValues(t, 2, audits)
	})

	t.Run("settings: group and seats, with a reason", func(t *testing.T) {
		assert.Equal(t, 400, f.do(t, f.tokens["root"], "PATCH", base, `{"billing_group":"vip"}`).Status)
		require.Equal(t, 200, f.do(t, f.tokens["root"], "PATCH", base, `{"billing_group":"vip","seat_limit":25,"reason":"upgrade"}`).Status)
		var org model.Organization
		require.NoError(t, f.db.First(&org, acme.Id).Error)
		assert.Equal(t, "vip", org.BillingGroup)
		assert.Equal(t, 25, org.SeatLimit)
	})

	t.Run("an adjustment is idempotent, needs a reason, and cannot take leased money", func(t *testing.T) {
		before := wallet()
		assert.Equal(t, 400, doAs("root", "adj-1", "POST", base+"/adjust", `{"delta_quota":500}`).Status, "no reason")
		assert.Equal(t, 400, doAs("root", "", "POST", base+"/adjust", `{"delta_quota":500,"reason":"x"}`).Status, "no idempotency key")
		assert.Equal(t, 400, doAs("root", "adj-1", "POST", base+"/adjust", `{"delta_quota":0,"reason":"x"}`).Status)
		assert.Equal(t, 403, doAs("owner", "adj-1", "POST", base+"/adjust", `{"delta_quota":500,"reason":"x"}`).Status, "tenants cannot adjust")
		require.Equal(t, 200, doAs("root", "adj-1", "POST", base+"/adjust", `{"delta_quota":500,"reason":"goodwill"}`).Status)
		require.Equal(t, 200, doAs("root", "adj-1", "POST", base+"/adjust", `{"delta_quota":500,"reason":"goodwill"}`).Status)
		assert.Equal(t, before+500, wallet(), "a repeated key credits once")
		assert.Equal(t, 409, doAs("root", "adj-1", "POST", base+"/adjust", `{"delta_quota":600,"reason":"goodwill"}`).Status)
		assert.Equal(t, 409, doAs("root", "adj-2", "POST", base+"/adjust", `{"delta_quota":-99999999,"reason":"too much"}`).Status,
			"a debit larger than the free balance is refused as in use")
	})

	t.Run("a parked task is listed and resolved with evidence", func(t *testing.T) {
		require.NoError(t, f.db.Create(&model.Token{UserId: acme.BillingUserId, Key: "ptask", Name: "t", Status: 1, ExpiredTime: -1,
			UnlimitedQuota: true, OrgId: acme.Id, WorkspaceId: 1, CreatedBy: f.users["owner"].Id, OwnerType: types.TokenOwnerMember,
			AccessPrincipalId: "p"}).Error)
		var token model.Token
		require.NoError(t, f.db.Where("`key` = ?", "ptask").First(&token).Error)
		subject := types.OrgSubject{OrgID: acme.Id, WorkspaceID: 1, ActorUserID: f.users["owner"].Id, TokenID: token.Id,
			AccessPrincipalID: "p", OwnerType: types.TokenOwnerMember}
		_, err := model.ApplyOrgBilling(t.Context(), types.OrgBillingCommand{OperationID: "park-1", Subject: subject,
			Action: types.OrgBillingActionReserve, Bound: 100, ModelName: "m", SourceKind: types.OrgSourceTask, LeaseOwner: "x"})
		require.NoError(t, err)
		require.NoError(t, f.db.Model(&model.OrgBillingOperation{}).Where("operation_id = ?", "park-1").
			Update("state", types.OrgOpStateRecoveryRequired).Error)

		listed := f.do(t, f.tokens["root"], "GET", base+"/billing-operations?state=recovery_required", "")
		require.Equal(t, 200, listed.Status)
		assert.Contains(t, listed.Raw, `"operation_id":"park-1"`)
		path := base + "/billing-operations/park-1/resolve"
		assert.Equal(t, 403, f.do(t, f.tokens["owner"], "POST", path, `{"action":"cancel","reason":"x","expected_revision":0}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["root"], "POST", path, `{"action":"cancel","expected_revision":0}`).Status, "no reason")
		assert.Equal(t, 409, f.do(t, f.tokens["root"], "POST", path, `{"action":"cancel","reason":"x","expected_revision":5}`).Status)
		before := wallet()
		ok := f.do(t, f.tokens["root"], "POST", path, `{"action":"settle","target_quota":30,"evidence_ref":"ticket-7","reason":"upstream confirmed","expected_revision":0}`)
		require.Equal(t, 200, ok.Status, ok.Raw)
		assert.Equal(t, before+70, wallet(), "30 charged, 70 returned")
		again := f.do(t, f.tokens["root"], "POST", path, `{"action":"settle","target_quota":30,"evidence_ref":"ticket-7","reason":"upstream confirmed","expected_revision":0}`)
		assert.Equal(t, 200, again.Status)
		assert.Equal(t, before+70, wallet(), "a repeat moves nothing")
	})
}
