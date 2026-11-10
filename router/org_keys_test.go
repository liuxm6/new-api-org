package router

import (
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyFixture is one organization with a wallet that holds distinctive figures,
// so any leak of them into a key-facing response is recognizable.
type keyFixture struct {
	*orgRoutesFixture
	orgID, wsID int
	walletID    int
}

const (
	walletQuota = 7_654_321
	walletUsed  = 1_234_567
)

func setupKeyFixture(t *testing.T) *keyFixture {
	t.Helper()
	f := setupOrgRoutes(t)
	SetDashboardRouter(f.engine)
	SetRelayRouter(f.engine)
	SetTaskPluginProtocolRouter(f.engine)
	SetVideoRouter(f.engine)
	SetTaskRouter(f.engine)
	f.user(t, "owner", "owner@example.com")
	f.user(t, "dev", "dev@example.com")
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs", `{"name":"Acme","slug":"acme"}`).Status)
	var org model.Organization
	require.NoError(t, f.db.Where("slug = ?", "acme").First(&org).Error)
	var ws model.Workspace
	require.NoError(t, f.db.Where("org_id = ? AND is_default = ?", org.Id, true).First(&ws).Error)
	require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: org.Id, UserId: f.users["dev"].Id, Role: types.OrgRoleMember,
		Status: types.OrgMemberStatusActive}).Error)
	uid := strconv.Itoa(f.users["dev"].Id)
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "PUT", "/api/orgs/acme/workspaces/default/members/"+uid, `{"role":"member"}`).Status)
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", org.BillingUserId).
		Updates(map[string]any{"quota": walletQuota, "used_quota": walletUsed}).Error)
	return &keyFixture{orgRoutesFixture: f, orgID: org.Id, wsID: ws.Id, walletID: org.BillingUserId}
}

type issuedKey struct {
	ID        int
	Plaintext string
}

// issue creates a key through the real route and returns its id and secret.
func (f *keyFixture) issue(t *testing.T, as, body string) issuedKey {
	t.Helper()
	reply := f.do(t, f.tokens[as], "POST", "/api/orgs/acme/workspaces/default/keys", body)
	require.Equal(t, 200, reply.Status, reply.Raw)
	data := reply.data()
	return issuedKey{ID: int(data["key"].(map[string]any)["id"].(float64)), Plaintext: data["plaintext"].(string)}
}

// keyCall sends a request authenticated by an API key, not a session.
func (f *keyFixture) keyCall(t *testing.T, plaintext, method, path string) routeReply {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	request.Header.Set("Authorization", "Bearer "+plaintext)
	request.RemoteAddr = "192.0.2.20:1234"
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	reply := routeReply{Status: recorder.Code, Raw: recorder.Body.String(), Body: map[string]any{}}
	_ = common.Unmarshal(recorder.Body.Bytes(), &reply.Body)
	return reply
}

func number(t *testing.T, reply routeReply, field string) float64 {
	t.Helper()
	value, ok := reply.Body[field].(float64)
	require.True(t, ok, "field %s in %s", field, reply.Raw)
	return value
}

func TestOrgKeyBillingEndpoints(t *testing.T) {
	f := setupKeyFixture(t)
	limited := f.issue(t, "dev", `{"name":"capped","owner":"me","quota_limit":900000}`)
	system := f.issue(t, "owner", `{"name":"svc","owner":"workspace"}`)
	require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", limited.ID).Update("used_quota", 100000).Error)
	previous := common.DisplayTokenStatEnabled
	t.Cleanup(func() { common.DisplayTokenStatEnabled = previous })

	// dollars shown for a quota figure at the default display type
	usd := func(quota float64) float64 { return quota / common.QuotaPerUnit }
	walletFigures := []float64{usd(walletUsed), usd(walletQuota + walletUsed),
		walletUsed, walletQuota + walletUsed, usd(walletUsed) * 100}

	paths := map[string][]string{
		"subscription": {"/dashboard/billing/subscription", "/v1/dashboard/billing/subscription"},
		"usage":        {"/dashboard/billing/usage", "/v1/dashboard/billing/usage"},
	}
	for _, display := range []bool{true, false} {
		common.DisplayTokenStatEnabled = display
		name := "DisplayTokenStatEnabled=" + strconv.FormatBool(display)
		t.Run(name+": a limited key sees only its own quota", func(t *testing.T) {
			for _, path := range paths["subscription"] {
				reply := f.keyCall(t, limited.Plaintext, "GET", path)
				require.Equal(t, 200, reply.Status, reply.Raw)
				// remaining 900000 + used 100000 = the key's granted total
				assert.InDelta(t, usd(1_000_000), number(t, reply, "hard_limit_usd"), 1e-9, path)
				assert.InDelta(t, usd(1_000_000), number(t, reply, "soft_limit_usd"), 1e-9, path)
			}
			for _, path := range paths["usage"] {
				reply := f.keyCall(t, limited.Plaintext, "GET", path)
				require.Equal(t, 200, reply.Status, reply.Raw)
				assert.InDelta(t, usd(100000)*100, number(t, reply, "total_usage"), 1e-9, path)
			}
		})
		t.Run(name+": an unlimited system key is bounded by the organization balance", func(t *testing.T) {
			for _, path := range paths["subscription"] {
				reply := f.keyCall(t, system.Plaintext, "GET", path)
				require.Equal(t, 200, reply.Status, reply.Raw)
				assert.InDelta(t, usd(walletQuota), number(t, reply, "hard_limit_usd"), 1e-9, path)
			}
			for _, path := range paths["usage"] {
				reply := f.keyCall(t, system.Plaintext, "GET", path)
				assert.EqualValues(t, 0, number(t, reply, "total_usage"), path+": the key has spent nothing, whatever the wallet has")
			}
		})
		t.Run(name+": the organization consumption never appears in any response", func(t *testing.T) {
			for _, plaintext := range []string{limited.Plaintext, system.Plaintext} {
				for _, group := range paths {
					for _, path := range group {
						reply := f.keyCall(t, plaintext, "GET", path)
						for _, field := range []string{"hard_limit_usd", "soft_limit_usd", "system_hard_limit_usd", "total_usage"} {
							value, present := reply.Body[field].(float64)
							if !present {
								continue
							}
							for _, wallet := range walletFigures {
								assert.NotEqual(t, wallet, value, "%s %s must not equal an organization consumption figure", path, field)
							}
						}
					}
				}
			}
		})
	}

	t.Run("the smaller of key remaining and budget headroom wins", func(t *testing.T) {
		common.DisplayTokenStatEnabled = false
		windowStart := time.Date(time.Now().UTC().Year(), time.Now().UTC().Month(), 1, 0, 0, 0, 0, time.UTC).Unix()
		require.NoError(t, f.db.Create(&model.Budget{OrgId: f.orgID, Scope: types.BudgetScopeWorkspace, SubjectId: f.wsID,
			Period: types.BudgetPeriodMonthly, LimitQuota: 500000, Enabled: true}).Error)
		require.NoError(t, f.db.Create(&model.OrgBudgetUsage{OrgId: f.orgID, Scope: types.BudgetScopeWorkspace, SubjectId: f.wsID,
			Period: types.BudgetPeriodMonthly, WindowStart: windowStart, SpentQuota: 300000, HeldQuota: 50000}).Error)
		// headroom 150000 < key remaining 900000; used 100000 is added to show the granted total
		reply := f.keyCall(t, limited.Plaintext, "GET", "/v1/dashboard/billing/subscription")
		assert.InDelta(t, usd(150000+100000), number(t, reply, "hard_limit_usd"), 1e-9)
		// the unlimited system key is bounded by the budget too
		reply = f.keyCall(t, system.Plaintext, "GET", "/v1/dashboard/billing/subscription")
		assert.InDelta(t, usd(150000), number(t, reply, "hard_limit_usd"), 1e-9)
		// a disabled budget no longer bounds anything
		require.NoError(t, f.db.Model(&model.Budget{}).Where("org_id = ?", f.orgID).Update("enabled", false).Error)
		reply = f.keyCall(t, system.Plaintext, "GET", "/v1/dashboard/billing/subscription")
		assert.InDelta(t, usd(walletQuota), number(t, reply, "hard_limit_usd"), 1e-9, "only the organization balance bounds it")
	})

	t.Run("a personal key keeps the existing behavior", func(t *testing.T) {
		personal := &model.Token{UserId: f.users["owner"].Id, Key: "personalkey0123456789abcdef", Name: "p", Status: common.TokenStatusEnabled,
			ExpiredTime: -1, RemainQuota: 42_000, UsedQuota: 8_000, AllowUserQuotaQuery: true}
		require.NoError(t, f.db.Create(personal).Error)
		require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["owner"].Id).
			Updates(map[string]any{"quota": 3_000_000, "used_quota": 500_000}).Error)
		common.DisplayTokenStatEnabled = true
		reply := f.keyCall(t, "sk-"+personal.Key, "GET", "/v1/dashboard/billing/subscription")
		assert.InDelta(t, usd(50_000), number(t, reply, "hard_limit_usd"), 1e-9)
		common.DisplayTokenStatEnabled = false
		reply = f.keyCall(t, "sk-"+personal.Key, "GET", "/v1/dashboard/billing/subscription")
		assert.InDelta(t, usd(3_500_000), number(t, reply, "hard_limit_usd"), 1e-9, "the personal wallet view is unchanged")
	})
}

// TestOrgKeyEndpointInventory walks the real route table. Every GET route a key
// can reach outside /api must be in the audited inventory, every inventory entry
// must exist, and each key-authenticated entry must really demand a key. A new
// TokenAuth route that nobody classified fails here.
func TestOrgKeyEndpointInventory(t *testing.T) {
	f := setupKeyFixture(t)
	registered := map[string]bool{}
	for _, route := range f.engine.Routes() {
		if route.Method != "GET" {
			continue
		}
		key := "GET " + route.Path
		if strings.HasPrefix(route.Path, "/api/") && !strings.HasPrefix(route.Path, "/api/usage/") && route.Path != "/api/log/token" {
			continue
		}
		// /scim/v2 authenticates a scim_service credential only; TestOrgSCIMRoutes
		// proves an API key is refused there.
		if strings.HasPrefix(route.Path, "/scim/") {
			continue
		}
		registered[key] = true
	}
	inventory := map[string]bool{}
	for _, key := range middleware.OrgKeyEndpointKeys() {
		inventory[key] = true
	}
	for key := range registered {
		assert.True(t, inventory[key], "route %s is reachable with an API key but is not classified in orgKeyEndpointRules", key)
	}
	for key := range inventory {
		assert.True(t, registered[key], "inventory lists %s but no such route is registered", key)
	}

	t.Run("every key-authenticated entry demands a key", func(t *testing.T) {
		skipped := map[string]string{
			"GET /v1/tasks/:key/artifacts/:artifact_key/content": "authorized by a signed capability, covered by Task 14",
			"GET /v1/realtime":  "WebSocket upgrade",
			"GET /v1/responses": "WebSocket upgrade",
		}
		param := regexp.MustCompile(`:[A-Za-z_]+`)
		for key := range inventory {
			class, _ := middleware.OrgKeyEndpoint(key)
			if class == middleware.OrgKeyPublic || skipped[key] != "" {
				continue
			}
			path := param.ReplaceAllString(strings.TrimPrefix(key, "GET "), "x")
			recorder := httptest.NewRecorder()
			f.engine.ServeHTTP(recorder, httptest.NewRequest("GET", path, nil))
			assert.Equal(t, 401, recorder.Code, "%s must refuse an anonymous caller", key)
		}
	})

	t.Run("the denied class refuses an organization key and still serves a personal one", func(t *testing.T) {
		org := f.issue(t, "dev", `{"name":"k","owner":"me"}`)
		personal := &model.Token{UserId: f.users["owner"].Id, Key: "personalreadonly0123456789", Name: "p",
			Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true}
		require.NoError(t, f.db.Create(personal).Error)
		for key := range inventory {
			if class, _ := middleware.OrgKeyEndpoint(key); class != middleware.OrgKeyDenied {
				continue
			}
			path := strings.TrimPrefix(key, "GET ")
			denied := f.keyCall(t, org.Plaintext, "GET", path)
			assert.Equal(t, 403, denied.Status, key)
			assert.NotContains(t, denied.Raw, walletQuotaText, key)
			assert.Equal(t, 200, f.keyCall(t, "sk-"+personal.Key, "GET", path).Status, key+" for a personal key")
		}
	})

	t.Run("the usage endpoint never reports the wallet even if the key asks to", func(t *testing.T) {
		personalAsOrg := f.issue(t, "dev", `{"name":"asks","owner":"me"}`)
		// a stored flag on an organization key must not matter
		require.NoError(t, f.db.Model(&model.Token{}).Where("id = ?", personalAsOrg.ID).Update("allow_user_quota_query", true).Error)
		reply := f.keyCall(t, personalAsOrg.Plaintext, "GET", "/api/usage/token/")
		assert.Equal(t, 403, reply.Status)
		assert.NotContains(t, reply.Raw, "user_quota")
	})
}

var walletQuotaText = strconv.Itoa(walletQuota)

func TestOrgKeyRouteOwnership(t *testing.T) {
	f := setupKeyFixture(t)
	f.user(t, "other", "other@example.com")
	keys := "/api/orgs/acme/workspaces/default/keys"

	t.Run("the body cannot choose ownership; the secret appears once", func(t *testing.T) {
		for _, body := range []string{
			`{"name":"x","owner":"me","org_id":999}`, `{"name":"x","owner":"me","user_id":1}`,
			`{"name":"x","owner":"me","workspace_id":2}`, `{"name":"x","owner":"me","created_by":1}`,
			`{"name":"x","owner":"me","access_principal_id":"prn_x"}`, `{"name":"x","owner":"me","allow_user_quota_query":true}`,
			`{"name":"x","owner":"me","key":"sk-chosen"}`,
		} {
			assert.Equal(t, 400, f.do(t, f.tokens["dev"], "POST", keys, body).Status, body)
		}
		issued := f.issue(t, "dev", `{"name":"mine","owner":"me"}`)
		row := loadToken(t, f, issued.ID)
		assert.Equal(t, f.walletID, row.UserId)
		assert.Equal(t, f.users["dev"].Id, row.CreatedBy)
		assert.False(t, row.AllowUserQuotaQuery)
		assert.Equal(t, "sk-"+row.Key, issued.Plaintext)

		list := f.do(t, f.tokens["dev"], "GET", keys, "")
		assert.NotContains(t, list.Raw, row.Key, "listings are masked")
		assert.Equal(t, "no-store", func() string {
			request := httptest.NewRequest("GET", keys, nil)
			request.Header.Set("Authorization", "Bearer "+f.tokens["dev"])
			recorder := httptest.NewRecorder()
			f.engine.ServeHTTP(recorder, request)
			return recorder.Header().Get("Cache-Control")
		}())
	})

	t.Run("the generic token API cannot see, reveal, change or delete an organization key", func(t *testing.T) {
		issued := f.issue(t, "dev", `{"name":"private","owner":"me"}`)
		row := loadToken(t, f, issued.ID)
		id := strconv.Itoa(issued.ID)
		// A person's own session, and the session of the wallet's owner, are both blind to it.
		for _, who := range []string{"dev", "owner"} {
			bearer := f.tokens[who]
			list := f.do(t, bearer, "GET", "/api/token/", "")
			assert.NotContains(t, list.Raw, row.Key, who)
			assert.NotContains(t, list.Raw, `"private"`, who)
			search := f.do(t, bearer, "GET", "/api/token/search?keyword=private", "")
			assert.NotContains(t, search.Raw, `"private"`, who)
			for _, call := range []struct{ method, path, body string }{
				{"GET", "/api/token/" + id, ""},
				{"POST", "/api/token/" + id + "/key", ""},
				{"POST", "/api/token/batch/keys", `{"ids":[` + id + `]}`},
				{"PUT", "/api/token/", `{"id":` + id + `,"name":"hijack","status":1,"org_id":0,"user_id":` + strconv.Itoa(f.users[who].Id) + `}`},
				{"DELETE", "/api/token/" + id, ""},
				{"POST", "/api/token/batch", `{"ids":[` + id + `]}`},
			} {
				reply := f.do(t, bearer, call.method, call.path, call.body)
				assert.NotContains(t, reply.Raw, row.Key, "%s %s %s", who, call.method, call.path)
			}
		}
		after := loadToken(t, f, issued.ID)
		assert.Equal(t, "private", after.Name)
		assert.Equal(t, f.walletID, after.UserId)
		assert.Equal(t, f.orgID, after.OrgId)
		assert.Equal(t, f.users["dev"].Id, after.CreatedBy)
		assert.EqualValues(t, 1, func() int64 {
			var n int64
			f.db.Model(&model.Token{}).Where("id = ?", issued.ID).Count(&n)
			return n
		}(), "the key is still there")
	})

	t.Run("management through the workspace routes follows ownership", func(t *testing.T) {
		mine := f.issue(t, "dev", `{"name":"rename-me","owner":"me"}`)
		id := strconv.Itoa(mine.ID)
		assert.Equal(t, 404, f.do(t, f.tokens["other"], "PATCH", keys+"/"+id, `{"name":"x"}`).Status, "a stranger sees nothing")
		assert.Equal(t, 400, f.do(t, f.tokens["dev"], "PATCH", keys+"/"+id, `{"name":"x","org_id":3}`).Status)
		assert.Equal(t, 400, f.do(t, f.tokens["dev"], "PATCH", keys+"/"+id, `{"remain_quota":999999999}`).Status, "quota is not editable here")
		assert.Equal(t, 200, f.do(t, f.tokens["dev"], "PATCH", keys+"/"+id, `{"name":"renamed"}`).Status)
		rotated := f.do(t, f.tokens["dev"], "POST", keys+"/"+id+"/rotate", "")
		require.Equal(t, 200, rotated.Status, rotated.Raw)
		assert.NotContains(t, rotated.Raw, mine.Plaintext)
		assert.Contains(t, rotated.Raw, `"plaintext":"sk-`)
		assert.Equal(t, 409, f.do(t, f.tokens["dev"], "POST", keys+"/"+id+"/rotate", "").Status, "the old key is no longer rotatable")
		assert.Equal(t, 401, f.keyCall(t, mine.Plaintext, "GET", "/v1/dashboard/billing/subscription").Status, "the rotated-out key stops working")
		assert.Equal(t, 200, f.do(t, f.tokens["dev"], "DELETE", keys+"/"+id, "").Status)
	})

	t.Run("an organization key cannot be used as a session or reach the control plane", func(t *testing.T) {
		issued := f.issue(t, "dev", `{"name":"cp","owner":"me"}`)
		for _, path := range []string{"/api/orgs", "/api/orgs/acme", keys, "/api/token/", "/api/user/self"} {
			reply := f.do(t, issued.Plaintext, "GET", path, "")
			assert.Equal(t, 401, reply.Status, path)
		}
	})
}

func loadToken(t *testing.T, f *keyFixture, id int) model.Token {
	t.Helper()
	var token model.Token
	require.NoError(t, f.db.Unscoped().First(&token, id).Error)
	return token
}
