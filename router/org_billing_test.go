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

func TestOrgRouteBilling(t *testing.T) {
	f := setupOrgRoutes(t)
	require.NoError(t, f.db.AutoMigrate(&model.TopUp{}, &model.Redemption{}, &model.Log{}))
	for _, name := range []string{"owner", "admin", "biller", "dev", "stranger"} {
		f.user(t, name, name+"@example.com")
	}
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)
	var acme model.Organization
	require.NoError(t, f.db.Where("slug = ?", "acme").First(&acme).Error)
	for name, role := range map[string]string{"admin": types.OrgRoleAdmin, "biller": types.OrgRoleBilling, "dev": types.OrgRoleMember} {
		require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: acme.Id, UserId: f.users[name].Id, Role: role,
			Status: types.OrgMemberStatusActive}).Error)
	}
	base := "/api/orgs/acme"
	wallet := func() int64 {
		var quota int64
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", acme.BillingUserId).Select("quota").Scan(&quota).Error)
		return quota
	}
	code := func(key string, quota int) {
		require.NoError(t, f.db.Create(&model.Redemption{Key: key, Name: "c", Quota: quota,
			Status: common.RedemptionCodeStatusEnabled, CreatedTime: common.GetTimestamp(), UserId: f.users["owner"].Id}).Error)
	}

	t.Run("who can read the finance page", func(t *testing.T) {
		for _, name := range []string{"owner", "admin", "biller"} {
			reply := f.do(t, f.tokens[name], "GET", base+"/billing", "")
			require.Equal(t, 200, reply.Status, name)
			wallet := reply.data()["wallet"].(map[string]any)
			assert.EqualValues(t, 0, wallet["available_quota"])
			assert.GreaterOrEqual(t, wallet["held_quota"].(float64), float64(0), "there is no negative balance")
		}
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "GET", base+"/billing", "").Status)
		assert.Equal(t, 404, f.do(t, f.tokens["stranger"], "GET", base+"/billing", "").Status)
	})

	t.Run("a code tops up for owners and billing members only", func(t *testing.T) {
		code("ROUTE-1", 900)
		assert.Equal(t, 403, f.do(t, f.tokens["admin"], "POST", base+"/topup", `{"key":"ROUTE-1"}`).Status)
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "POST", base+"/topup", `{"key":"ROUTE-1"}`).Status)
		assert.EqualValues(t, 0, wallet())
		reply := f.do(t, f.tokens["biller"], "POST", base+"/topup", `{"key":"ROUTE-1"}`)
		require.Equal(t, 200, reply.Status, reply.Raw)
		assert.EqualValues(t, 900, wallet())
		assert.Equal(t, 400, f.do(t, f.tokens["owner"], "POST", base+"/topup", `{"key":"ROUTE-1"}`).Status, "a used code is refused")
		assert.Equal(t, 400, f.do(t, f.tokens["owner"], "POST", base+"/topup", `{"key":"NOPE"}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["owner"], "POST", base+"/topup", `{"key":" "}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["owner"], "POST", base+"/topup", `{"key":"x","org_id":9}`).Status)
		assert.EqualValues(t, 900, wallet())
	})

	t.Run("the ledger shows the credit, newest first, with the balance after it", func(t *testing.T) {
		code("ROUTE-2", 100)
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", base+"/topup", `{"key":"ROUTE-2"}`).Status)
		reply := f.do(t, f.tokens["owner"], "GET", base+"/billing", "")
		ledger := reply.data()["ledger"].(map[string]any)
		items := ledger["items"].([]any)
		require.Len(t, items, 2)
		assert.EqualValues(t, 2, ledger["total"])
		first := items[0].(map[string]any)
		assert.EqualValues(t, 100, first["amount_quota"])
		assert.EqualValues(t, 1000, first["balance_after"])
		assert.Equal(t, "redemption", first["ref_type"])
	})

	t.Run("a transfer moves personal money only with a bound proof on a global session", func(t *testing.T) {
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["biller"].Id).Update("quota", 5000).Error)
		body := `{"amount_quota":300}`
		resource := "transfer:" + strconv.Itoa(acme.Id) + ":300:key-1"
		headers := func(proof string) map[string]string {
			return map[string]string{"Idempotency-Key": "key-1", "X-Security-Proof": proof}
		}
		before := wallet()

		assert.Equal(t, 400, f.doHeaders(t, f.tokens["biller"], nil, "POST", base+"/credits/transfer", body).Status, "no idempotency key")
		noProof := f.doHeaders(t, f.tokens["biller"], map[string]string{"Idempotency-Key": "key-1"}, "POST", base+"/credits/transfer", body)
		assert.Equal(t, 403, noProof.Status)
		assert.Equal(t, "SECURITY_PROOF_REQUIRED", noProof.Body["code"])
		assert.Equal(t, before, wallet())

		wrong := f.proof(t, f.tokens["biller"], types.SensitiveCreditTransfer, acme.Id, "transfer:"+strconv.Itoa(acme.Id)+":999:key-1")
		mismatch := f.doHeaders(t, f.tokens["biller"], headers(wrong), "POST", base+"/credits/transfer", body)
		assert.Equal(t, 403, mismatch.Status, "a proof for another amount is useless")
		assert.Equal(t, before, wallet())

		assert.Equal(t, 403, f.doHeaders(t, f.tokens["dev"], headers("x"), "POST", base+"/credits/transfer", body).Status, "members cannot")
		assert.Equal(t, 403, f.doHeaders(t, f.tokens["admin"], headers("x"), "POST", base+"/credits/transfer", body).Status, "admins cannot")

		good := f.proof(t, f.tokens["biller"], types.SensitiveCreditTransfer, acme.Id, resource)
		reply := f.doHeaders(t, f.tokens["biller"], headers(good), "POST", base+"/credits/transfer", body)
		require.Equal(t, 200, reply.Status, reply.Raw)
		assert.Equal(t, before+300, wallet())
		var biller model.User
		require.NoError(t, f.db.First(&biller, f.users["biller"].Id).Error)
		assert.EqualValues(t, 4700, biller.Quota)

		again := f.doHeaders(t, f.tokens["biller"], headers(good), "POST", base+"/credits/transfer", body)
		assert.Equal(t, 403, again.Status, "a proof is single use")
		assert.Equal(t, before+300, wallet())
		replay := f.proof(t, f.tokens["biller"], types.SensitiveCreditTransfer, acme.Id, resource)
		same := f.doHeaders(t, f.tokens["biller"], headers(replay), "POST", base+"/credits/transfer", body)
		assert.Equal(t, 200, same.Status, "the same key and amount is a replay")
		assert.Equal(t, before+300, wallet(), "a replay moves nothing")
	})

	t.Run("an organization-restricted session can never spend personal money", func(t *testing.T) {
		restricted := f.session(t, f.users["biller"], types.AuthScopeOrg, acme.Id)
		reply := f.doHeaders(t, restricted, map[string]string{"Idempotency-Key": "key-9"}, "POST", base+"/credits/transfer", `{"amount_quota":10}`)
		assert.Equal(t, 403, reply.Status)
		assert.Equal(t, "session_scope_denied", reply.code(), "stopped by the session scope itself, not only by the missing proof")
		assert.Equal(t, 200, f.do(t, restricted, "GET", base+"/billing", "").Status, "it can still read its own organization")
	})

	t.Run("amounts are bounded", func(t *testing.T) {
		for _, body := range []string{`{"amount_quota":0}`, `{"amount_quota":-5}`, `{"amount_quota":99999999999}`, `{"amount_quota":"9"}`, `{}`} {
			reply := f.doHeaders(t, f.tokens["biller"], map[string]string{"Idempotency-Key": "k-bound"}, "POST", base+"/credits/transfer", body)
			assert.Equal(t, 400, reply.Status, body)
		}
	})
}

func TestOrgRouteInvoices(t *testing.T) {
	f := setupOrgRoutes(t)
	require.NoError(t, f.db.AutoMigrate(&model.TopUp{}, &model.Redemption{}, &model.Log{}))
	for _, name := range []string{"owner", "admin", "biller", "dev", "other"} {
		f.user(t, name, name+"@example.com")
	}
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)
	require.Equal(t, 200, f.do(t, f.tokens["other"], "POST", "/api/orgs", `{"name":"Other","slug":"other"}`).Status)
	var acme, other model.Organization
	require.NoError(t, f.db.Where("slug = ?", "acme").First(&acme).Error)
	require.NoError(t, f.db.Where("slug = ?", "other").First(&other).Error)
	for name, role := range map[string]string{"admin": types.OrgRoleAdmin, "biller": types.OrgRoleBilling, "dev": types.OrgRoleMember} {
		require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: acme.Id, UserId: f.users[name].Id, Role: role,
			Status: types.OrgMemberStatusActive}).Error)
	}
	base := "/api/orgs/acme"
	issue := func(orgID int, key string, quota int) model.OrgInvoice {
		code := model.Redemption{Key: "INV-" + key, Name: "c", Quota: quota, Status: common.RedemptionCodeStatusEnabled,
			CreatedTime: common.GetTimestamp(), UserId: f.users["owner"].Id}
		require.NoError(t, f.db.Create(&code).Error)
		var org model.Organization
		require.NoError(t, f.db.First(&org, orgID).Error)
		_, err := model.RedeemToOrganization(code.Key, org.BillingUserId, f.users["owner"].Id)
		require.NoError(t, err)
		invoice, err := model.IssueOrgReceipt(t.Context(), orgID, "redemption:"+strconv.Itoa(code.Id))
		require.NoError(t, err)
		return *invoice
	}
	mine := issue(acme.Id, "a", 1_000_000)
	theirs := issue(other.Id, "b", 2_000_000)

	t.Run("billing header: owners and billing members write, admins read, members cannot", func(t *testing.T) {
		put := `{"legal_name":"Acme Ltd","tax_id":"TX-9","address":"1 Main St","billing_email":"ap@acme.test"}`
		assert.Equal(t, 403, f.do(t, f.tokens["admin"], "PUT", base+"/billing-profile", put).Status)
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "PUT", base+"/billing-profile", put).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["biller"], "PUT", base+"/billing-profile", `{"legal_name":"x","org_id":9}`).Status)
		require.Equal(t, 200, f.do(t, f.tokens["biller"], "PUT", base+"/billing-profile", put).Status)
		for _, name := range []string{"owner", "admin", "biller"} {
			reply := f.do(t, f.tokens[name], "GET", base+"/billing-profile", "")
			require.Equal(t, 200, reply.Status, name)
			assert.Equal(t, "Acme Ltd", reply.data()["legal_name"])
		}
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "GET", base+"/billing-profile", "").Status)
	})

	t.Run("the list and detail show the server's amounts and never another organization's", func(t *testing.T) {
		list := f.do(t, f.tokens["admin"], "GET", base+"/invoices", "")
		require.Equal(t, 200, list.Status)
		assert.Contains(t, list.Raw, mine.Number)
		assert.NotContains(t, list.Raw, theirs.Number)
		assert.Equal(t, 403, f.do(t, f.tokens["dev"], "GET", base+"/invoices", "").Status)
		assert.Equal(t, 200, f.do(t, f.tokens["biller"], "GET", base+"/invoices?type=receipt", "").Status)

		detail := f.do(t, f.tokens["admin"], "GET", base+"/invoices/"+strconv.Itoa(mine.Id), "")
		require.Equal(t, 200, detail.Status)
		assert.EqualValues(t, 200, detail.data()["amount_cents"], "1,000,000 quota at 500,000 per dollar is $2.00")
		assert.NotEmpty(t, detail.data()["line_snapshot"])
		assert.Equal(t, 404, f.do(t, f.tokens["admin"], "GET", base+"/invoices/"+strconv.Itoa(theirs.Id), "").Status,
			"an invoice of another organization is not there")
	})

	t.Run("void: owners only, one way, no money moves", func(t *testing.T) {
		var before int64
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", acme.BillingUserId).Select("quota").Scan(&before).Error)
		path := base + "/invoices/" + strconv.Itoa(mine.Id) + "/void"
		for _, name := range []string{"admin", "biller", "dev"} {
			assert.Equal(t, 403, f.do(t, f.tokens[name], "POST", path, "").Status, name)
		}
		assert.Equal(t, 404, f.do(t, f.tokens["owner"], "POST", base+"/invoices/"+strconv.Itoa(theirs.Id)+"/void", "").Status)
		reply := f.do(t, f.tokens["owner"], "POST", path, "")
		require.Equal(t, 200, reply.Status)
		assert.Equal(t, "void", reply.data()["status"])
		assert.Equal(t, "void", f.do(t, f.tokens["owner"], "POST", path, "").data()["status"], "voiding again is harmless")
		var after int64
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", acme.BillingUserId).Select("quota").Scan(&after).Error)
		assert.Equal(t, before, after, "a void is not a refund")
	})
}
