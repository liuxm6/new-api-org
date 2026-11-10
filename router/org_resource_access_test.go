package router

import (
	"encoding/base64"
	"encoding/csv"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/config"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// resourceFixture is two organizations and the people and keys that make the
// object-level rules observable: a workspace with a member (dev), a peer, an
// auditor and an organization-wide billing member; a second workspace; a system
// key; and a second organization with its own key. Every key owns one task and
// one Midjourney row, and each task names an upstream URL that must never leak.
type resourceFixture struct {
	*keyFixture
	labsID   int
	keys     map[string]issuedKey
	upstream *httptest.Server
}

const upstreamLeak = "upstream-leak.invalid"

func (f *resourceFixture) issueIn(t *testing.T, as, org, ws, body string) issuedKey {
	t.Helper()
	reply := f.do(t, f.tokens[as], "POST", "/api/orgs/"+org+"/workspaces/"+ws+"/keys", body)
	require.Equal(t, 200, reply.Status, reply.Raw)
	data := reply.data()
	return issuedKey{ID: int(data["key"].(map[string]any)["id"].(float64)), Plaintext: data["plaintext"].(string)}
}

func (f *resourceFixture) addOrgMember(t *testing.T, name, role string) {
	t.Helper()
	f.user(t, name, name+"@example.com")
	require.NoError(t, f.db.Create(&model.OrganizationMember{OrgId: f.orgID, UserId: f.users[name].Id, Role: role,
		Status: types.OrgMemberStatusActive}).Error)
}

func (f *resourceFixture) grant(t *testing.T, ws, name, role string) {
	t.Helper()
	path := "/api/orgs/acme/workspaces/" + ws + "/members/" + strconv.Itoa(f.users[name].Id)
	require.Equal(t, 200, f.do(t, f.tokens["owner"], "PUT", path, `{"role":"`+role+`"}`).Status)
}

// task stores a task the way the submit path does: attributed from the key's
// trusted subject. Its upstream URL is a recognizable leak canary.
func (f *resourceFixture) task(t *testing.T, key issuedKey, id string) {
	t.Helper()
	var token model.Token
	require.NoError(t, f.db.First(&token, key.ID).Error)
	subject, ok := model.OrgSubjectFromToken(&token)
	require.True(t, ok)
	task := &model.Task{TaskID: id, Platform: "document", UserId: token.UserId, ChannelId: 1, Action: constant.TaskActionTextToVideo,
		Status: model.TaskStatusSuccess, Progress: "100%", SubmitTime: 10, FinishTime: 20,
		PrivateData: model.TaskPrivateData{ResultURL: f.upstream.URL + "/" + id + ".mp4?host=" + upstreamLeak}}
	task.ApplyOrgSubject(subject)
	require.NoError(t, f.db.Create(task).Error)
	mj := &model.Midjourney{MjId: "mj_" + id, UserId: token.UserId, Action: "IMAGINE", Status: "SUCCESS", Progress: "100%",
		ChannelId: 1, ImageUrl: f.upstream.URL + "/" + id + ".png?host=" + upstreamLeak, VideoUrl: "https://" + upstreamLeak + "/v.mp4"}
	mj.ApplyOrgSubject(subject)
	require.NoError(t, f.db.Create(mj).Error)
}

func setupResourceFixture(t *testing.T) *resourceFixture {
	t.Helper()
	k := setupKeyFixture(t)
	require.NoError(t, k.db.AutoMigrate(&model.Channel{}, &model.Log{}, &model.QuotaData{}))

	previousSecret, previousAddress := common.CryptoSecret, system_setting.ServerAddress
	previousMemoryCache := common.MemoryCacheEnabled
	previousFetch := *system_setting.GetFetchSetting()
	common.CryptoSecret = "org-resource-access-secret"
	system_setting.ServerAddress = "https://gateway.example"
	common.MemoryCacheEnabled = false
	system_setting.GetFetchSetting().EnableSSRFProtection = true
	system_setting.GetFetchSetting().AllowPrivateIp = true
	system_setting.GetFetchSetting().AllowedPorts = []string{"1-65535"}
	service.InitHttpClient()
	t.Cleanup(func() {
		common.CryptoSecret, system_setting.ServerAddress = previousSecret, previousAddress
		common.MemoryCacheEnabled = previousMemoryCache
		*system_setting.GetFetchSetting() = previousFetch
		service.InitHttpClient()
	})

	f := &resourceFixture{keyFixture: k, keys: map[string]issuedKey{}}
	f.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("MEDIA-BYTES"))
	}))
	t.Cleanup(f.upstream.Close)
	baseURL := f.upstream.URL
	require.NoError(t, k.db.Create(&model.Channel{Id: 1, Name: "media", Key: "upstream-secret", BaseURL: &baseURL,
		Status: common.ChannelStatusEnabled}).Error)

	f.addOrgMember(t, "peer", types.OrgRoleMember)
	f.addOrgMember(t, "audit", types.OrgRoleMember)
	f.addOrgMember(t, "bill", types.OrgRoleBilling)
	f.addOrgMember(t, "admin", types.OrgRoleAdmin)
	f.grant(t, "default", "peer", "member")
	f.grant(t, "default", "audit", "auditor")
	f.user(t, "stranger", "stranger@example.com")
	f.user(t, "globex-owner", "globex@example.com")
	f.user(t, "root", "root@example.com")
	require.NoError(t, f.db.Model(&model.User{}).Where("id = ?", f.users["root"].Id).Update("role", common.RoleRootUser).Error)

	require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/workspaces", `{"name":"Labs","slug":"labs"}`).Status)
	var labs model.Workspace
	require.NoError(t, k.db.Where("org_id = ? AND slug = ?", k.orgID, "labs").First(&labs).Error)
	f.labsID = labs.Id
	f.grant(t, "labs", "dev", "member")
	require.Equal(t, 200, f.do(t, f.tokens["globex-owner"], "POST", "/api/orgs", `{"name":"Globex","slug":"globex"}`).Status)

	f.keys["dev"] = f.issueIn(t, "dev", "acme", "default", `{"name":"dev","owner":"me"}`)
	f.keys["peer"] = f.issueIn(t, "peer", "acme", "default", `{"name":"peer","owner":"me"}`)
	f.keys["system"] = f.issueIn(t, "owner", "acme", "default", `{"name":"svc","owner":"workspace"}`)
	f.keys["labs"] = f.issueIn(t, "dev", "acme", "labs", `{"name":"labs","owner":"me"}`)
	f.keys["globex"] = f.issueIn(t, "globex-owner", "globex", "default", `{"name":"gx","owner":"me"}`)
	for owner, id := range map[string]string{"dev": "task_dev", "peer": "task_peer", "system": "task_system", "labs": "task_labs", "globex": "task_globex"} {
		f.task(t, f.keys[owner], id)
	}
	return f
}

// keyDo sends a request authenticated by an API key, with an optional body.
func (f *resourceFixture) keyDo(t *testing.T, plaintext, method, path, body string) routeReply {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+plaintext)
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = "192.0.2.21:1234"
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	reply := routeReply{Status: recorder.Code, Raw: recorder.Body.String(), Body: map[string]any{}}
	_ = common.Unmarshal(recorder.Body.Bytes(), &reply.Body)
	return reply
}

// readRoute is one way a key can read a task, with what its answer looks like
// when the task is hidden from the caller and when it is theirs.
type readRoute struct {
	name    string
	method  string
	path    func(task string) string
	body    func(task string) string
	hidden  func(reply routeReply) bool
	visible func(reply routeReply, task string) bool
}

func orgReadRoutes() []readRoute {
	notFound := func(reply routeReply) bool { return reply.Status == 404 }
	contains := func(marker string) func(routeReply) bool {
		return func(reply routeReply) bool { return strings.Contains(reply.Raw, marker) }
	}
	mine := func(reply routeReply, task string) bool {
		return reply.Status == 200 && strings.Contains(reply.Raw, task)
	}
	return []readRoute{
		{"GET /v1/tasks/:key", "GET", func(id string) string { return "/v1/tasks/" + id }, nil, notFound, mine},
		{"GET /v1/tasks/:key/artifacts", "GET", func(id string) string { return "/v1/tasks/" + id + "/artifacts" }, nil, notFound, mine},
		{"GET /v1/video/generations/:task_id", "GET", func(id string) string { return "/v1/video/generations/" + id }, nil,
			contains("task_not_exist"), mine},
		{"GET /v1/videos/:task_id", "GET", func(id string) string { return "/v1/videos/" + id }, nil,
			contains("task_not_exist"), func(reply routeReply, _ string) bool { return !strings.Contains(reply.Raw, "task_not_exist") }},
		{"GET /v1/videos/:task_id/content", "GET", func(id string) string { return "/v1/videos/" + id + "/content" }, nil, notFound,
			func(reply routeReply, _ string) bool { return reply.Status == 200 && reply.Raw == "MEDIA-BYTES" }},
		{"GET /v1/tasks/:key/artifacts/:artifact_key/content", "GET",
			func(id string) string { return "/v1/tasks/" + id + "/artifacts/video/content" }, nil, notFound,
			func(reply routeReply, _ string) bool { return reply.Status == 200 && reply.Raw == "MEDIA-BYTES" }},
		{"GET /v1/responses/:response_id", "GET", func(id string) string { return "/v1/responses/resp_" + strings.TrimPrefix(id, "task_") }, nil,
			notFound, nil},
		{"GET /mj/task/:id/fetch", "GET", func(id string) string { return "/mj/task/mj_" + id + "/fetch" }, nil,
			contains("task_no_found"), func(reply routeReply, task string) bool {
				return reply.Status == 200 && strings.Contains(reply.Raw, "mj_"+task)
			}},
		{"GET /mj/task/:id/image-seed", "GET", func(id string) string { return "/mj/task/mj_" + id + "/image-seed" }, nil,
			contains("task_no_found"), func(reply routeReply, _ string) bool { return !strings.Contains(reply.Raw, "task_no_found") }},
		{"POST /mj/task/list-by-condition", "POST", func(string) string { return "/mj/task/list-by-condition" },
			func(id string) string { return `{"ids":["mj_` + id + `"]}` },
			func(reply routeReply) bool { return reply.Status == 200 && strings.TrimSpace(reply.Raw) == "[]" },
			func(reply routeReply, task string) bool {
				return reply.Status == 200 && strings.Contains(reply.Raw, "mj_"+task)
			}},
	}
}

func TestOrgTaskIsolation(t *testing.T) {
	f := setupResourceFixture(t)
	owners := map[string]string{"dev": "task_dev", "peer": "task_peer", "system": "task_system", "labs": "task_labs", "globex": "task_globex"}

	t.Run("a key reads exactly its own task on every route", func(t *testing.T) {
		for _, route := range orgReadRoutes() {
			for caller, key := range f.keys {
				for owner, task := range owners {
					reply := f.keyDo(t, key.Plaintext, route.method, route.path(task), func() string {
						if route.body != nil {
							return route.body(task)
						}
						return ""
					}())
					label := route.name + " as " + caller + " reading " + owner + "'s task"
					if caller == owner {
						if route.visible != nil {
							assert.True(t, route.visible(reply, task), label+": "+reply.Raw)
						}
						assert.NotContains(t, reply.Raw, upstreamLeak, label+" must not name the upstream")
						continue
					}
					assert.True(t, route.hidden(reply), label+": "+reply.Raw)
					assert.NotContains(t, reply.Raw, task, label+" must not even echo the id back as a hit")
				}
			}
		}
	})

	t.Run("the same member in another workspace is a different reader", func(t *testing.T) {
		assert.Equal(t, 404, f.keyDo(t, f.keys["labs"].Plaintext, "GET", "/v1/tasks/task_dev", "").Status)
		assert.Equal(t, 404, f.keyDo(t, f.keys["dev"].Plaintext, "GET", "/v1/tasks/task_labs", "").Status)
	})

	t.Run("a task cannot be continued through an origin the key cannot read", func(t *testing.T) {
		reply := f.keyDo(t, f.keys["peer"].Plaintext, "POST", "/v1/videos/task_dev/remix", `{"model":"m","prompt":"p"}`)
		assert.NotEqual(t, 200, reply.Status)
		assert.NotContains(t, reply.Raw, "task_dev\"")
	})

	t.Run("rotation hands a system key's history to its successor and to nobody else", func(t *testing.T) {
		rotated := f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/workspaces/default/keys/"+strconv.Itoa(f.keys["system"].ID)+"/rotate", "")
		require.Equal(t, 200, rotated.Status, rotated.Raw)
		successor := rotated.data()["plaintext"].(string)
		assert.Equal(t, 200, f.keyDo(t, successor, "GET", "/v1/tasks/task_system", "").Status, "the rotated key reads the history")
		assert.Equal(t, 401, f.keyDo(t, f.keys["system"].Plaintext, "GET", "/v1/tasks/task_system", "").Status, "the old key is gone")
		fresh := f.issueIn(t, "owner", "acme", "default", `{"name":"another","owner":"workspace"}`)
		assert.Equal(t, 404, f.keyDo(t, fresh.Plaintext, "GET", "/v1/tasks/task_system", "").Status, "a new system key is a new principal")
		f.keys["system"] = issuedKey{ID: f.keys["system"].ID, Plaintext: successor}
	})

	t.Run("the console follows the reader's standing", func(t *testing.T) {
		list := func(who, ws string) (int, []string) {
			reply := f.do(t, f.tokens[who], "GET", "/api/orgs/acme/workspaces/"+ws+"/tasks", "")
			var ids []string
			if data := reply.data(); data != nil {
				items, _ := data["items"].([]any)
				for _, item := range items {
					ids = append(ids, item.(map[string]any)["task_id"].(string))
				}
			}
			return reply.Status, ids
		}
		for who, want := range map[string][]string{
			"owner": {"task_dev", "task_peer", "task_system"}, "admin": {"task_dev", "task_peer", "task_system"},
			"audit": {"task_dev", "task_peer", "task_system"}, "dev": {"task_dev"}, "peer": {"task_peer"},
		} {
			status, ids := list(who, "default")
			assert.Equal(t, 200, status, who)
			assert.ElementsMatch(t, want, ids, who)
		}
		for _, who := range []string{"bill", "stranger", "globex-owner"} {
			status, ids := list(who, "default")
			assert.Equal(t, 404, status, who+": no standing in this workspace means no workspace")
			assert.Empty(t, ids, who)
		}
		status, ids := list("dev", "labs")
		assert.Equal(t, 200, status)
		assert.Equal(t, []string{"task_labs"}, ids)
		status, _ = list("peer", "labs")
		assert.Equal(t, 404, status, "the peer has no role in the second workspace")

		one := f.do(t, f.tokens["dev"], "GET", "/api/orgs/acme/workspaces/default/tasks/task_peer", "")
		assert.Equal(t, 404, one.Status, "a member cannot open a colleague's task by id")
		for who, task := range map[string]string{"dev": "task_dev", "audit": "task_peer", "owner": "task_system"} {
			reply := f.do(t, f.tokens[who], "GET", "/api/orgs/acme/workspaces/default/tasks/"+task, "")
			require.Equal(t, 200, reply.Status, who+": "+reply.Raw)
			assert.EqualValues(t, 0, reply.data()["user_id"], "the shared wallet id is not shown")
			assert.NotContains(t, reply.Raw, upstreamLeak)
			assert.Nil(t, reply.data()["data"], "the vendor snapshot is not shown")
		}
		assert.Equal(t, 404, f.do(t, f.tokens["bill"], "GET", "/api/orgs/acme/workspaces/default/tasks/task_dev/artifacts", "").Status,
			"the billing role has no artifact access")
		mj := f.do(t, f.tokens["dev"], "GET", "/api/orgs/acme/workspaces/default/midjourney", "")
		require.Equal(t, 200, mj.Status, mj.Raw)
		assert.Contains(t, mj.Raw, "mj_task_dev")
		assert.NotContains(t, mj.Raw, "mj_task_peer")
		assert.NotContains(t, mj.Raw, upstreamLeak)
	})

	t.Run("personal dashboards cannot reach organization tasks", func(t *testing.T) {
		for _, who := range []string{"owner", "dev", "root"} {
			for _, path := range []string{"/api/task/self", "/api/mj/self", "/api/task/task_dev/artifacts"} {
				reply := f.do(t, f.tokens[who], "GET", path, "")
				assert.NotContains(t, reply.Raw, "task_dev", who+" "+path)
				assert.NotContains(t, reply.Raw, "mj_task_dev", who+" "+path)
			}
		}
		for _, path := range []string{"/api/task", "/api/mj/"} {
			reply := f.do(t, f.tokens["root"], "GET", path, "")
			assert.Equal(t, 200, reply.Status, path)
			assert.NotContains(t, reply.Raw, "task_", "the platform tables list personal tasks only: "+path)
		}
	})
}

// anonymousGet calls a gateway URL exactly as a browser would: no credentials,
// only what the URL itself carries.
func (f *resourceFixture) anonymousGet(t *testing.T, rawURL string) routeReply {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	request := httptest.NewRequest("GET", parsed.RequestURI(), nil)
	request.RemoteAddr = "192.0.2.50:1234"
	recorder := httptest.NewRecorder()
	f.engine.ServeHTTP(recorder, request)
	return routeReply{Status: recorder.Code, Raw: recorder.Body.String(), Body: map[string]any{}}
}

// artifactURL reads a task's artifact listing and returns the gateway content URL.
func (f *resourceFixture) artifactURL(t *testing.T, reply routeReply) string {
	t.Helper()
	require.Equal(t, 200, reply.Status, reply.Raw)
	body := reply.Body
	if data, ok := body["data"].(map[string]any); ok {
		body = data
	}
	contentURL, _ := body["legacy_content_url"].(string)
	require.NotEmpty(t, contentURL, reply.Raw)
	return contentURL
}

func (f *resourceFixture) devArtifactURL(t *testing.T, task string) string {
	t.Helper()
	return f.artifactURL(t, f.keyDo(t, f.keys["dev"].Plaintext, "GET", "/v1/tasks/"+task+"/artifacts", ""))
}

func TestOrgArtifactTicket(t *testing.T) {
	f := setupResourceFixture(t)
	personalOwner := f.users["owner"]
	require.NoError(t, f.db.Create(&model.Token{UserId: personalOwner.Id, Key: "personalartifactkey0123456789", Name: "p",
		Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true}).Error)
	require.NoError(t, f.db.Create(&model.Task{TaskID: "task_personal", Platform: "document", UserId: personalOwner.Id, ChannelId: 1,
		Action: constant.TaskActionTextToVideo, Status: model.TaskStatusSuccess, Progress: "100%",
		PrivateData: model.TaskPrivateData{ResultURL: f.upstream.URL + "/p.mp4"}}).Error)
	devToken := func() model.Token {
		var token model.Token
		require.NoError(t, f.db.First(&token, f.keys["dev"].ID).Error)
		return token
	}
	setStatus := func(modelValue any, id int, column string, value any) {
		require.NoError(t, f.db.Model(modelValue).Where("id = ?", id).Update(column, value).Error)
	}

	t.Run("an organization task gets a v2 ticket on a gateway URL, and a personal task keeps its permanent capability", func(t *testing.T) {
		orgURL := f.devArtifactURL(t, "task_dev")
		assert.True(t, strings.HasPrefix(orgURL, "https://gateway.example/v1/tasks/task_dev/artifacts/video/content?access=o2."), orgURL)
		assert.NotContains(t, orgURL, upstreamLeak)
		assert.NotContains(t, orgURL, f.upstream.URL)

		personal := f.artifactURL(t, f.keyDo(t, "sk-personalartifactkey0123456789", "GET", "/v1/tasks/task_personal/artifacts", ""))
		parsed, err := url.Parse(personal)
		require.NoError(t, err)
		assert.Len(t, parsed.Query().Get("access"), 43, "the personal capability is unchanged")
		assert.Equal(t, 200, f.anonymousGet(t, personal).Status)
	})

	t.Run("the ticket is the only credential the download needs, and it names no upstream", func(t *testing.T) {
		reply := f.anonymousGet(t, f.devArtifactURL(t, "task_dev"))
		assert.Equal(t, 200, reply.Status)
		assert.Equal(t, "MEDIA-BYTES", reply.Raw)
	})

	t.Run("a ticket is bound to its task and artifact and is not a personal capability", func(t *testing.T) {
		orgURL := f.devArtifactURL(t, "task_dev")
		parsed, _ := url.Parse(orgURL)
		ticket := parsed.Query().Get("access")
		other := "https://gateway.example/v1/tasks/task_peer/artifacts/video/content?access=" + url.QueryEscape(ticket)
		assert.Equal(t, 404, f.anonymousGet(t, other).Status, "moved to a colleague's task")
		assert.Equal(t, 404, f.anonymousGet(t, strings.Replace(orgURL, "/video/", "/audio/", 1)).Status, "moved to another artifact")
		assert.Equal(t, 404, f.anonymousGet(t, orgURL[:len(orgURL)-3]+"AAA").Status, "tampered")

		// A permanent capability minted for an organization task is refused.
		v1, err := service.IssueTaskArtifactAccess("task_dev", "video")
		require.NoError(t, err)
		assert.Equal(t, 404, f.anonymousGet(t, "https://gateway.example/v1/tasks/task_dev/artifacts/video/content?access="+v1).Status)
		assert.NotContains(t, f.anonymousGet(t, other).Raw, "MEDIA-BYTES")
	})

	t.Run("an expired ticket is refused, and reading the task again returns one that works", func(t *testing.T) {
		token := devToken()
		subject, _ := model.OrgSubjectFromToken(&token)
		var org model.Organization
		require.NoError(t, f.db.First(&org, f.orgID).Error)
		claims, ok := service.OrgArtifactClaimsForSubject(subject, org.PolicyVersion)
		require.True(t, ok)
		stale, err := service.IssueOrgArtifactTicket(claims, "task_dev", "video", time.Now().Add(-2*time.Hour))
		require.NoError(t, err)
		staleURL := "https://gateway.example/v1/tasks/task_dev/artifacts/video/content?access=" + url.QueryEscape(stale)
		assert.Equal(t, 404, f.anonymousGet(t, staleURL).Status)
		assert.Equal(t, 200, f.anonymousGet(t, f.devArtifactURL(t, "task_dev")).Status, "a fresh read returns a fresh URL")
	})

	t.Run("a longer platform lifetime is honored", func(t *testing.T) {
		cfg := config.GlobalConfig.Get("org_task_artifact")
		config.UpdateConfigFromMap(cfg, map[string]string{"ticket_ttl_seconds": "7200"})
		t.Cleanup(func() { config.UpdateConfigFromMap(cfg, map[string]string{"ticket_ttl_seconds": "3600"}) })
		parsed, _ := url.Parse(f.devArtifactURL(t, "task_dev"))
		_, rest, _ := strings.Cut(parsed.Query().Get("access"), ".")
		payload, _, _ := strings.Cut(rest, ".")
		decoded, err := base64.RawURLEncoding.DecodeString(payload)
		require.NoError(t, err)
		var claims service.OrgArtifactTicketClaims
		require.NoError(t, common.Unmarshal(decoded, &claims))
		assert.InDelta(t, time.Now().Add(2*time.Hour).Unix(), claims.ExpiresAt, 5)
	})

	t.Run("a console reader gets a ticket for their own standing, and loses it with the standing", func(t *testing.T) {
		consoleURL := func(who, task string) routeReply {
			return f.do(t, f.tokens[who], "GET", "/api/orgs/acme/workspaces/default/tasks/"+task+"/artifacts", "")
		}
		devURL := f.artifactURL(t, consoleURL("dev", "task_dev"))
		assert.Contains(t, devURL, "access=o2.")
		assert.NotContains(t, devURL, upstreamLeak)
		assert.Equal(t, "MEDIA-BYTES", f.anonymousGet(t, devURL).Raw)
		assert.Equal(t, 404, consoleURL("dev", "task_peer").Status, "the member's console cannot mint a ticket for a colleague's task")
		auditURL := f.artifactURL(t, consoleURL("audit", "task_peer"))
		assert.Equal(t, 200, f.anonymousGet(t, auditURL).Status)

		// A ticket is the holder's standing at the time it was issued, so moving
		// the standing makes it fail; the console then hands out a new one.
		uid := strconv.Itoa(f.users["audit"].Id)
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "PUT", "/api/orgs/acme/workspaces/default/members/"+uid, `{"role":"member"}`).Status)
		assert.Equal(t, 404, f.anonymousGet(t, auditURL).Status, "demoted from auditor")
		assert.Equal(t, 404, consoleURL("audit", "task_peer").Status)
		f.grant(t, "default", "audit", "auditor")
		assert.Equal(t, 200, f.anonymousGet(t, f.artifactURL(t, consoleURL("audit", "task_peer"))).Status)

		removed := f.artifactURL(t, consoleURL("audit", "task_dev"))
		setStatus(&model.User{}, f.users["audit"].Id, "status", common.UserStatusDisabled)
		assert.Equal(t, 404, f.anonymousGet(t, removed).Status, "a disabled person's tickets stop")
		setStatus(&model.User{}, f.users["audit"].Id, "status", common.UserStatusEnabled)
	})

	t.Run("a Midjourney image of an organization task needs a ticket and is served through the gateway", func(t *testing.T) {
		fetch := f.keyDo(t, f.keys["dev"].Plaintext, "GET", "/mj/task/mj_task_dev/fetch", "")
		require.Equal(t, 200, fetch.Status, fetch.Raw)
		imageURL, _ := fetch.Body["imageUrl"].(string)
		require.NotEmpty(t, imageURL, fetch.Raw)
		assert.True(t, strings.HasPrefix(imageURL, "https://gateway.example/mj/image/mj_task_dev?access=o2."), imageURL)
		assert.NotContains(t, fetch.Raw, upstreamLeak)
		assert.Equal(t, "", fetch.Body["videoUrl"], "video URLs are withheld rather than exposed outside the gateway")
		assert.Equal(t, "MEDIA-BYTES", f.anonymousGet(t, imageURL).Raw)

		for name, target := range map[string]string{
			"no ticket":         "https://gateway.example/mj/image/mj_task_dev",
			"another task":      strings.Replace(imageURL, "mj_task_dev", "mj_task_peer", 1),
			"a personal ticket": "https://gateway.example/mj/image/mj_task_dev?access=" + strings.Repeat("A", 43),
			"tampered":          imageURL[:len(imageURL)-3] + "AAA",
		} {
			reply := f.anonymousGet(t, target)
			assert.NotEqual(t, 200, reply.Status, name)
			assert.NotContains(t, reply.Raw, "MEDIA-BYTES", name)
		}
		require.NoError(t, f.db.Create(&model.Midjourney{MjId: "mj_personal", UserId: personalOwner.Id, Status: "SUCCESS",
			ImageUrl: f.upstream.URL + "/p.png", ChannelId: 1}).Error)
		assert.Equal(t, "MEDIA-BYTES", f.anonymousGet(t, "https://gateway.example/mj/image/mj_personal").Raw, "personal images are unchanged")
		setStatus(&model.Token{}, f.keys["dev"].ID, "status", common.TokenStatusDisabled)
		assert.NotEqual(t, 200, f.anonymousGet(t, imageURL).Status, "a disabled key's image ticket stops")
		setStatus(&model.Token{}, f.keys["dev"].ID, "status", common.TokenStatusEnabled)
	})

	t.Run("suspension, a disabled or deleted key and a changed policy refuse a ticket that is signed and unexpired", func(t *testing.T) {
		ticketURL := f.devArtifactURL(t, "task_dev")
		require.Equal(t, 200, f.anonymousGet(t, ticketURL).Status)
		for name, step := range map[string]struct{ break_, fix func() }{
			"organization suspended": {func() { setStatus(&model.Organization{}, f.orgID, "status", types.OrgStatusSuspended) },
				func() { setStatus(&model.Organization{}, f.orgID, "status", types.OrgStatusActive) }},
			"workspace suspended": {func() { setStatus(&model.Workspace{}, f.wsID, "status", types.WorkspaceStatusSuspended) },
				func() { setStatus(&model.Workspace{}, f.wsID, "status", types.WorkspaceStatusActive) }},
			"key disabled": {func() { setStatus(&model.Token{}, f.keys["dev"].ID, "status", common.TokenStatusDisabled) },
				func() { setStatus(&model.Token{}, f.keys["dev"].ID, "status", common.TokenStatusEnabled) }},
			"owner of the key disabled": {func() { setStatus(&model.User{}, f.users["dev"].Id, "status", common.UserStatusDisabled) },
				func() { setStatus(&model.User{}, f.users["dev"].Id, "status", common.UserStatusEnabled) }},
		} {
			step.break_()
			assert.Equal(t, 404, f.anonymousGet(t, ticketURL).Status, name)
			step.fix()
			assert.Equal(t, 200, f.anonymousGet(t, ticketURL).Status, name+": restored")
		}

		// Any policy change moves the organization's version past the ticket's.
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/workspaces/labs/suspend", "").Status)
		assert.Equal(t, 404, f.anonymousGet(t, ticketURL).Status, "policy_version moved on")
		require.Equal(t, 200, f.do(t, f.tokens["owner"], "POST", "/api/orgs/acme/workspaces/labs/resume", "").Status)
		fresh := f.devArtifactURL(t, "task_dev")
		assert.NotEqual(t, ticketURL, fresh)
		assert.Equal(t, 200, f.anonymousGet(t, fresh).Status, "reading the task again gives a URL for the new policy")

		deleted := f.devArtifactURL(t, "task_dev")
		require.NoError(t, f.db.Delete(&model.Token{}, f.keys["dev"].ID).Error)
		assert.Equal(t, 404, f.anonymousGet(t, deleted).Status, "a deleted key's tickets stop at once")
	})
}

// usageRows seeds one log and one display aggregate per (workspace, actor) so a
// total identifies exactly which rows a reader was allowed to see.
func (f *resourceFixture) usageRows(t *testing.T) {
	t.Helper()
	now := common.GetTimestamp()
	hour := now - now%3600
	var globex model.Organization
	require.NoError(t, f.db.Where("slug = ?", "globex").First(&globex).Error)
	type row struct {
		org, ws, actor, quota int
		name                  string
	}
	for _, r := range []row{
		{f.orgID, f.wsID, f.users["dev"].Id, 1, "dev-default"},
		{f.orgID, f.wsID, f.users["peer"].Id, 10, "peer-default"},
		{f.orgID, f.wsID, 0, 100, "system-default"},
		{f.orgID, f.labsID, f.users["dev"].Id, 1000, "dev-labs"},
		{globex.Id, 1, f.users["globex-owner"].Id, 10000, "globex"},
	} {
		require.NoError(t, f.db.Create(&model.Log{OrgId: r.org, WorkspaceId: r.ws, ActorUserId: r.actor, UserId: f.walletID,
			Type: model.LogTypeConsume, Quota: r.quota, ModelName: r.name, CreatedAt: now - 5, TokenId: f.keys["dev"].ID}).Error)
		require.NoError(t, f.db.Create(&model.QuotaData{OrgID: r.org, WorkspaceID: r.ws, ActorUserID: r.actor, ModelName: r.name,
			CreatedAt: hour, Count: 1, Quota: r.quota}).Error)
	}
	require.NoError(t, f.db.Create(&model.Log{UserId: f.users["dev"].Id, Type: model.LogTypeConsume, Quota: 100000, ModelName: "personal",
		CreatedAt: now - 5}).Error)
}

func quotaSum(reply routeReply) int {
	data := reply.data()
	if data == nil {
		return -1
	}
	total, _ := data["total_quota"].(float64)
	return int(total)
}

func pageItems(reply routeReply) []map[string]any {
	var items []map[string]any
	if data := reply.data(); data != nil {
		raw, _ := data["items"].([]any)
		for _, item := range raw {
			items = append(items, item.(map[string]any))
		}
	}
	return items
}

func TestOrgUsageAndAuditScope(t *testing.T) {
	f := setupResourceFixture(t)
	f.usageRows(t)
	org, ws := "/api/orgs/acme", "/api/orgs/acme/workspaces/default"

	t.Run("organization statistics: owners, admins and billing see the organization, a member only themselves", func(t *testing.T) {
		for who, want := range map[string]int{"owner": 1111, "admin": 1111, "bill": 1111, "dev": 1001, "peer": 10, "audit": 0} {
			reply := f.do(t, f.tokens[who], "GET", org+"/activity", "")
			require.Equal(t, 200, reply.Status, who+": "+reply.Raw)
			assert.Equal(t, want, quotaSum(reply), who)
			assert.Equal(t, true, reply.data()["display_only"], "quota_data says it is only a display aggregate")
		}
		for _, who := range []string{"stranger", "globex-owner"} {
			reply := f.do(t, f.tokens[who], "GET", org+"/activity", "")
			assert.Equal(t, 404, reply.Status, who)
			assert.NotContains(t, reply.Raw, "total_quota")
		}
	})

	t.Run("workspace statistics: owners, admins and auditors see the workspace, a member only themselves, billing nothing", func(t *testing.T) {
		for who, want := range map[string]int{"owner": 111, "admin": 111, "audit": 111, "dev": 1, "peer": 10} {
			reply := f.do(t, f.tokens[who], "GET", ws+"/usage", "")
			require.Equal(t, 200, reply.Status, who+": "+reply.Raw)
			assert.Equal(t, want, quotaSum(reply), who)
		}
		for _, who := range []string{"bill", "stranger", "globex-owner"} {
			assert.Equal(t, 404, f.do(t, f.tokens[who], "GET", ws+"/usage", "").Status, who)
		}
		labs := f.do(t, f.tokens["dev"], "GET", org+"/workspaces/labs/usage", "")
		assert.Equal(t, 1000, quotaSum(labs))
		assert.Equal(t, 404, f.do(t, f.tokens["peer"], "GET", org+"/workspaces/labs/usage", "").Status)
	})

	t.Run("the log list, its total and its export cover the same rows", func(t *testing.T) {
		for who, want := range map[string]int{"owner": 111, "audit": 111, "dev": 1, "peer": 10} {
			list := f.do(t, f.tokens[who], "GET", ws+"/logs?p=1&page_size=50", "")
			require.Equal(t, 200, list.Status, who+": "+list.Raw)
			var quota int
			for _, item := range pageItems(list) {
				quota += int(item["quota"].(float64))
				assert.NotContains(t, item["model_name"], "personal", who)
				assert.NotContains(t, item["model_name"], "globex", who)
				assert.Empty(t, item["channel_name"], who)
			}
			assert.Equal(t, want, quota, who)

			export := f.do(t, f.tokens[who], "GET", ws+"/logs/export", "")
			require.Equal(t, 200, export.Status, who)
			lines := strings.Split(strings.TrimSpace(export.Raw), "\n")
			exported := 0
			for _, line := range lines[:len(lines)-1] {
				var log model.Log
				require.NoError(t, common.Unmarshal([]byte(line), &log), line)
				exported += log.Quota
			}
			assert.Equal(t, want, exported, who+" export")
			assert.Contains(t, lines[len(lines)-1], `"success":true`)
			assert.EqualValues(t, len(lines)-1, int(list.data()["total"].(float64)), who+": total matches the export")
		}
		page := f.do(t, f.tokens["owner"], "GET", ws+"/logs?p=1&page_size=1", "")
		assert.Len(t, pageItems(page), 1)
		assert.EqualValues(t, 3, page.data()["total"], "paging does not change the total")
		for _, who := range []string{"bill", "stranger"} {
			assert.Equal(t, 404, f.do(t, f.tokens[who], "GET", ws+"/logs", "").Status, who)
			assert.Equal(t, 404, f.do(t, f.tokens[who], "GET", ws+"/logs/export", "").Status, who)
		}
	})

	t.Run("history survives the deletion of the key that produced it", func(t *testing.T) {
		before := quotaSum(f.do(t, f.tokens["dev"], "GET", org+"/activity", ""))
		require.NoError(t, f.db.Delete(&model.Token{}, f.keys["dev"].ID).Error)
		assert.Equal(t, before, quotaSum(f.do(t, f.tokens["dev"], "GET", org+"/activity", "")))
		assert.Len(t, pageItems(f.do(t, f.tokens["dev"], "GET", ws+"/logs", "")), 1)
	})

	t.Run("audit: organization readers see the organization trail, a member only their own actions", func(t *testing.T) {
		require.NoError(t, f.db.Create(&model.OrgAuditLog{OrgId: f.orgID, WorkspaceId: f.wsID, ActorUserId: f.users["dev"].Id, ActorKind: "user",
			Action: "=HYPERLINK(\"http://evil\")", TargetType: "key", TargetId: "-1+1", CredentialRef: "credhash",
			Detail: `{"name":"k","token":"sk-LEAKLEAKLEAK1234","note":"Bearer abcdef"}`, Ip: "198.51.100.1", CreatedAt: common.GetTimestamp()}).Error)
		require.NoError(t, f.db.Create(&model.OrgAuditLog{OrgId: f.orgID + 99, ActorUserId: 1, Action: "foreign.org", CreatedAt: common.GetTimestamp()}).Error)

		all := f.do(t, f.tokens["owner"], "GET", org+"/audit-logs?page_size=100", "")
		require.Equal(t, 200, all.Status, all.Raw)
		assert.NotContains(t, all.Raw, "foreign.org")
		assert.NotContains(t, all.Raw, "LEAKLEAK")
		assert.NotContains(t, all.Raw, "credhash")
		assert.NotContains(t, all.Raw, "Bearer abcdef")
		bill := f.do(t, f.tokens["bill"], "GET", org+"/audit-logs?page_size=100", "")
		assert.Equal(t, all.data()["total"], bill.data()["total"], "billing reads the organization trail")
		mine := f.do(t, f.tokens["dev"], "GET", org+"/audit-logs?page_size=100", "")
		require.Equal(t, 200, mine.Status)
		for _, item := range pageItems(mine) {
			assert.EqualValues(t, f.users["dev"].Id, item["actor_user_id"], "a member sees only their own actions")
		}
		assert.Less(t, mine.data()["total"], all.data()["total"])
		assert.Equal(t, 404, f.do(t, f.tokens["stranger"], "GET", org+"/audit-logs", "").Status)
		inWs := f.do(t, f.tokens["audit"], "GET", ws+"/audit-logs?page_size=100", "")
		require.Equal(t, 200, inWs.Status, inWs.Raw)
		for _, item := range pageItems(inWs) {
			assert.EqualValues(t, f.wsID, item["workspace_id"], "a workspace auditor reads workspace rows only")
		}
		assert.Equal(t, 404, f.do(t, f.tokens["bill"], "GET", ws+"/audit-logs", "").Status)
	})

	t.Run("the audit CSV export carries no secret and no live formula", func(t *testing.T) {
		export := f.do(t, f.tokens["owner"], "GET", org+"/audit-logs/export", "")
		require.Equal(t, 200, export.Status)
		records, err := csv.NewReader(strings.NewReader(export.Raw)).ReadAll()
		require.NoError(t, err)
		assert.Equal(t, []string{"id", "created_at", "org_id", "workspace_id", "actor_user_id", "actor_kind", "action", "target_type",
			"target_id", "detail", "ip"}, records[0])
		for _, banned := range []string{"credhash", "LEAKLEAK", "Bearer abcdef", "foreign.org", "credential_ref"} {
			assert.NotContains(t, export.Raw, banned)
		}
		var sawFormula bool
		for _, record := range records[1:] {
			for _, cell := range record {
				assert.False(t, cell != "" && strings.ContainsAny(cell[:1], "=+-@"), "cell %q would be read as a formula", cell)
			}
			sawFormula = sawFormula || strings.HasPrefix(record[6], "'=")
		}
		assert.True(t, sawFormula, "the formula-shaped action is present, neutralized")
		own := f.do(t, f.tokens["dev"], "GET", org+"/audit-logs/export", "")
		ownRecords, err := csv.NewReader(strings.NewReader(own.Raw)).ReadAll()
		require.NoError(t, err)
		for _, record := range ownRecords[1:] {
			assert.Equal(t, strconv.Itoa(f.users["dev"].Id), record[4])
		}
		assert.Equal(t, 404, f.do(t, f.tokens["stranger"], "GET", org+"/audit-logs/export", "").Status)
	})

	t.Run("platform staff read an organization only through the audited entry", func(t *testing.T) {
		platform := "/api/admin/orgs/acme"
		for _, path := range []string{"/activity", "/logs", "/audit-logs", "/tasks", "/midjourney"} {
			for _, who := range []string{"owner", "dev", "stranger"} {
				assert.Equal(t, 403, f.do(t, f.tokens[who], "GET", platform+path, "").Status, who+" is not platform staff: "+path)
			}
			assert.Equal(t, 401, f.do(t, "", "GET", platform+path, "").Status, "anonymous "+path)
		}
		orgSession := f.session(t, f.users["root"], types.AuthScopeOrg, f.orgID)
		assert.NotEqual(t, 200, f.do(t, orgSession, "GET", platform+"/activity", "").Status, "an org-restricted session never reaches the platform entry")

		var before int64
		f.db.Model(&model.OrgAuditLog{}).Where("org_id = ? AND action = ?", f.orgID, "platform.access").Count(&before)
		assert.Zero(t, before)
		activity := f.do(t, f.tokens["root"], "GET", platform+"/activity", "")
		require.Equal(t, 200, activity.Status, activity.Raw)
		assert.Equal(t, 1111, quotaSum(activity), "the platform entry spans the whole organization")
		narrowed := f.do(t, f.tokens["root"], "GET", platform+"/activity?workspace_id="+strconv.Itoa(f.wsID)+"&actor_user_id="+strconv.Itoa(f.users["peer"].Id), "")
		assert.Equal(t, 10, quotaSum(narrowed))
		tasks := f.do(t, f.tokens["root"], "GET", platform+"/tasks?page_size=50", "")
		require.Equal(t, 200, tasks.Status, tasks.Raw)
		assert.Len(t, pageItems(tasks), 4, "all four of the organization's tasks, none of the other organization's")
		assert.NotContains(t, tasks.Raw, "task_globex")
		assert.Equal(t, 404, f.do(t, f.tokens["root"], "GET", "/api/admin/orgs/nonexistent/activity", "").Status)
		assert.Equal(t, 400, f.do(t, f.tokens["root"], "GET", platform+"/activity?workspace_id=-1", "").Status)

		// Every call is on the organization's own trail, where its owner can see it.
		trail := f.do(t, f.tokens["owner"], "GET", "/api/orgs/acme/audit-logs?action=platform.access&page_size=50", "")
		require.Equal(t, 200, trail.Status, trail.Raw)
		items := pageItems(trail)
		require.GreaterOrEqual(t, len(items), 3)
		for _, item := range items {
			assert.Equal(t, "platform", item["actor_kind"])
			assert.EqualValues(t, f.users["root"].Id, item["actor_user_id"])
		}

		// If the access cannot be recorded, nothing is returned.
		require.NoError(t, f.db.Callback().Create().Before("gorm:create").Register("fail_audit", func(tx *gorm.DB) {
			if tx.Statement.Table == "org_audit_logs" {
				_ = tx.AddError(errors.New("audit store down"))
			}
		}))
		t.Cleanup(func() { _ = f.db.Callback().Create().Remove("fail_audit") })
		blocked := f.do(t, f.tokens["root"], "GET", platform+"/logs", "")
		assert.Equal(t, 500, blocked.Status)
		assert.NotContains(t, blocked.Raw, "dev-default")
		assert.NotContains(t, blocked.Raw, "audit store down")
	})
}

// taskLikeRoute is what the inventory test treats as a route that concerns
// tasks, media or organization usage. It is deliberately broad: a route it
// catches that nobody classified fails the test.
var taskLikeRoute = regexp.MustCompile(`(^|/)(tasks?|videos?|mj|midjourney|responses|artifacts)(/|$)|/images/(generations|edits|variations)|video/generations|^/api/admin/orgs/|^/api/orgs/:org/(activity|audit-logs)|/workspaces/:ws/(usage|logs|audit-logs)`)

// normalizedTaskRoute maps a route onto the probe that covers it: HEAD behaves
// as GET, and the :mode prefix of the Midjourney routes is the same handler.
func normalizedTaskRoute(key string) string {
	key = strings.Replace(key, "HEAD ", "GET ", 1)
	return strings.Replace(key, "/:mode", "", 1)
}

func TestOrgTaskEntryInventory(t *testing.T) {
	f := setupResourceFixture(t)
	registered := map[string]bool{}
	for _, route := range f.engine.Routes() {
		if taskLikeRoute.MatchString(route.Path) {
			registered[route.Method+" "+route.Path] = true
		}
	}
	inventory := map[string]bool{}
	for _, key := range middleware.OrgTaskEntryKeys() {
		inventory[key] = true
	}

	t.Run("every task, media and usage route is classified, and every classified route exists", func(t *testing.T) {
		for key := range registered {
			assert.True(t, inventory[key], "route %s concerns tasks or organization usage but is not classified in orgTaskEntryRules", key)
		}
		for key := range inventory {
			assert.True(t, registered[key], "orgTaskEntryRules lists %s but no such route is registered", key)
		}
	})

	t.Run("every key read has an isolation probe in TestOrgTaskIsolation", func(t *testing.T) {
		probes := map[string]bool{}
		for _, route := range orgReadRoutes() {
			probes[route.name] = true
		}
		for key := range inventory {
			if class, _ := middleware.OrgTaskEntry(key); class == middleware.OrgTaskKeyRead {
				assert.True(t, probes[normalizedTaskRoute(key)], "key-read route %s has no probe in orgReadRoutes", key)
			}
		}
		for name := range probes {
			assert.True(t, inventory[name], "probe %s is not an inventoried route", name)
		}
	})

	t.Run("the mode-prefixed Midjourney reads hide a foreign task like the plain ones", func(t *testing.T) {
		for _, route := range orgReadRoutes() {
			if !strings.Contains(route.name, "/mj/") {
				continue
			}
			path := "/mj-fast" + strings.TrimPrefix(route.path("task_dev"), "")
			body := ""
			if route.body != nil {
				body = route.body("task_dev")
			}
			foreign := f.keyDo(t, f.keys["peer"].Plaintext, route.method, path, body)
			assert.True(t, route.hidden(foreign), route.name+" via mode prefix: "+foreign.Raw)
		}
	})

	t.Run("each class demands the credential and standing it names", func(t *testing.T) {
		param := regexp.MustCompile(`:[A-Za-z_]+`)
		fill := func(key string) (method, path string) {
			method, path, _ = strings.Cut(key, " ")
			path = strings.NewReplacer(":org", "acme", ":ws", "default", ":task_id", "task_dev", ":mode", "mj-fast").Replace(path)
			return method, param.ReplaceAllString(path, "x")
		}
		for key := range inventory {
			class, _ := middleware.OrgTaskEntry(key)
			method, path := fill(key)
			switch class {
			case middleware.OrgTaskKeyRead, middleware.OrgTaskSubmit:
				if strings.HasSuffix(key, "GET /v1/responses") {
					continue
				}
				assert.Equal(t, 401, f.do(t, "", method, path, "").Status, key+" needs a key")
			case middleware.OrgTaskConsole, middleware.OrgUsageConsole:
				assert.Equal(t, 401, f.do(t, "", method, path, "").Status, key+" needs a session")
				assert.Equal(t, 404, f.do(t, f.tokens["stranger"], method, path, "").Status, key+" is invisible to a stranger")
				assert.Equal(t, 404, f.do(t, f.tokens["globex-owner"], method, path, "").Status, key+" is invisible to another organization's owner")
				assert.True(t, middleware.OrgSessionRouteAllowed(method, strings.NewReplacer(":org", ":org").Replace(strings.SplitN(key, " ", 2)[1])),
					key+" must be reachable by an organization-restricted session")
			case middleware.OrgTaskPlatformAudited, middleware.OrgTaskPlatformOps:
				assert.Equal(t, 403, f.do(t, f.tokens["owner"], method, path, "").Status, key+" is platform-only")
			case middleware.OrgTaskPersonal, middleware.OrgTaskPlatformTable:
				scoped := f.session(t, f.users["owner"], types.AuthScopeOrg, f.orgID)
				assert.NotEqual(t, 200, f.do(t, scoped, method, path, "").Status, key+" is closed to an organization-restricted session")
				assert.False(t, middleware.OrgSessionRouteAllowed(method, strings.SplitN(key, " ", 2)[1]), key)
			}
		}
	})
}

// legacyTaskLookups are the model functions that authorize by billing user id
// (or by nothing). Organization reads go through TaskScope; what remains here
// is deliberate and listed.
var legacyTaskLookups = []string{"GetByTaskId", "GetByOnlyTaskId", "GetUniqueByOnlyTaskId", "GetByTaskIdsForPlatforms",
	"GetTaskForProtocolObservation", "GetByMJId", "GetByMJIds", "GetByOnlyMJId", "GetMjByuId", "TaskGetAllUserTask",
	"TaskCountAllUserTask", "GetAllUserTask", "CountAllUserTask", "TaskGetAllTasks", "TaskCountAllTasks", "GetAllTasks", "CountAllTasks"}

// TestOrgLegacyTaskLookupGuard fails when code outside model starts calling a
// legacy lookup, or stops calling one the list says it does. Each remaining use
// is safe on its own: the model functions exclude organization rows
// (org_id = 0), and the callers below are personal or platform-table paths.
func TestOrgLegacyTaskLookupGuard(t *testing.T) {
	allowed := map[string][]string{
		"../controller/plugin_protocol.go": {"GetByTaskId", "GetTaskForProtocolObservation"}, // defaults; organization requests rebind them (forOrgRequest)
		"../controller/task.go":            {"GetByOnlyTaskId", "GetUniqueByOnlyTaskId", "TaskCountAllTasks", "TaskCountAllUserTask", "TaskGetAllTasks", "TaskGetAllUserTask"},
		"../controller/midjourney.go":      {"CountAllTasks", "CountAllUserTask", "GetAllTasks", "GetAllUserTask"},
		"../relay/mjproxy_handler.go":      {"GetByOnlyMJId"}, // image route (org tasks need a ticket) and the unregistered notify hook
	}
	found := map[string][]string{}
	fileSet := token.NewFileSet()
	for _, dir := range []string{"../controller", "../middleware", "../relay", "../service", "../router", "../pkg"} {
		require.NoError(t, filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			parsed, parseErr := parser.ParseFile(fileSet, path, nil, 0)
			require.NoError(t, parseErr)
			ast.Inspect(parsed, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := selector.X.(*ast.Ident)
				if ok && pkg.Name == "model" && slices.Contains(legacyTaskLookups, selector.Sel.Name) {
					found[path] = append(found[path], selector.Sel.Name)
				}
				return true
			})
			return nil
		}))
	}
	for path, names := range found {
		slices.Sort(names)
		want, listed := allowed[path]
		assert.True(t, listed, "%s calls the legacy task lookups %v; read tasks through model.TaskScope instead", path, names)
		if listed {
			slices.Sort(want)
			assert.Equal(t, want, slices.Compact(names), "%s: the legacy lookups it uses changed", path)
		}
	}
	for path := range allowed {
		assert.Contains(t, found, path, "%s no longer calls a legacy lookup; remove it from the list", path)
	}
}
