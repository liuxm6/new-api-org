package service

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/model"
	orgservice "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func addGuardrail(t *testing.T, db *gorm.DB, row model.Guardrail) {
	t.Helper()
	if row.Status == 0 {
		row.Status = 1
	}
	require.NoError(t, db.Create(&row).Error)
}

func TestOrgGuardrailComposition(t *testing.T) {
	db := setupChannelSelectAutoGroupsTest(t)
	require.NoError(t, db.AutoMigrate(&model.Guardrail{}))
	subject := types.OrgSubject{OrgID: 1, WorkspaceID: 10, ActorUserID: 100, TokenID: 1000}

	resolve := func(t *testing.T, version int64) *orgservice.ResolvedOrgPolicy {
		t.Helper()
		policy, err := orgservice.ResolveGuardrails(subject, version)
		require.NoError(t, err)
		return policy
	}
	reset := func(t *testing.T) {
		require.NoError(t, db.Exec("DELETE FROM guardrails").Error)
	}

	t.Run("no guardrail means no restriction", func(t *testing.T) {
		reset(t)
		policy := resolve(t, 100)
		assert.True(t, policy.AllowsModel("anything-at-all"))
		_, restricted := policy.ProviderFilter()
		assert.False(t, restricted)
	})

	t.Run("allow lists intersect across layers", func(t *testing.T) {
		reset(t)
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: `{"allowed_models":["gpt-*","claude-*"]}`})
		addGuardrail(t, db, model.Guardrail{OrgId: 1, WorkspaceId: 10, TargetType: types.GuardrailTargetWorkspaceDefault, Config: `{"allowed_models":["gpt-*"]}`})
		policy := resolve(t, 101)
		assert.True(t, policy.AllowsModel("gpt-4o"))
		assert.False(t, policy.AllowsModel("claude-3"), "allowed by the org but not by the workspace")
		assert.False(t, policy.AllowsModel("llama-3"))
	})

	t.Run("deny lists union and win over allow", func(t *testing.T) {
		reset(t)
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: `{"allowed_models":["gpt-*"]}`})
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetMember, TargetId: 100, Config: `{"denied_models":["gpt-4o"]}`})
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetKey, TargetId: 1000, Config: `{"denied_models":["gpt-3*"]}`})
		policy := resolve(t, 102)
		assert.False(t, policy.AllowsModel("gpt-4o"))
		assert.False(t, policy.AllowsModel("gpt-3.5-turbo"))
		assert.True(t, policy.AllowsModel("gpt-4.1"))
	})

	t.Run("an explicit empty allow list denies everything, an absent one does not", func(t *testing.T) {
		reset(t)
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: `{"allowed_models":[]}`})
		assert.False(t, resolve(t, 103).AllowsModel("gpt-4o"))
		reset(t)
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: `{"denied_models":["x"]}`})
		assert.True(t, resolve(t, 104).AllowsModel("gpt-4o"))
	})

	t.Run("wildcards cross slashes and respect literals", func(t *testing.T) {
		reset(t)
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: `{"allowed_models":["openai/*","exact-model","*-mini"]}`})
		policy := resolve(t, 105)
		assert.True(t, policy.AllowsModel("openai/gpt-4o"))
		assert.True(t, policy.AllowsModel("exact-model"))
		assert.False(t, policy.AllowsModel("exact-model-2"))
		assert.True(t, policy.AllowsModel("gpt-4o-mini"))
		assert.False(t, policy.AllowsModel("anthropic/claude"))
		assert.False(t, policy.AllowsModel("Exact-Model"), "matching is case-sensitive")
	})

	t.Run("only guardrails that apply to this subject count", func(t *testing.T) {
		reset(t)
		deny := `{"denied_models":["gpt-4o"]}`
		addGuardrail(t, db, model.Guardrail{OrgId: 2, TargetType: types.GuardrailTargetOrgDefault, Config: deny})                             // other org
		addGuardrail(t, db, model.Guardrail{OrgId: 1, WorkspaceId: 11, TargetType: types.GuardrailTargetWorkspaceDefault, Config: deny})      // other workspace
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetMember, TargetId: 101, Config: deny})                  // other member
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetKey, TargetId: 1001, Config: deny})                    // other key
		addGuardrail(t, db, model.Guardrail{OrgId: 1, WorkspaceId: 11, TargetType: types.GuardrailTargetMember, TargetId: 100, Config: deny}) // member rule scoped to another workspace
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: deny, Status: 2})                  // disabled
		assert.True(t, resolve(t, 106).AllowsModel("gpt-4o"))
		addGuardrail(t, db, model.Guardrail{OrgId: 1, WorkspaceId: 10, TargetType: types.GuardrailTargetMember, TargetId: 100, Config: deny}) // member rule scoped to this workspace
		assert.False(t, resolve(t, 107).AllowsModel("gpt-4o"))
	})

	t.Run("a system key has no member layer", func(t *testing.T) {
		reset(t)
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetMember, TargetId: 0, Config: `{"denied_models":["gpt-4o"]}`})
		system := types.OrgSubject{OrgID: 1, WorkspaceID: 10, ActorUserID: 0, TokenID: 2000}
		policy, err := orgservice.ResolveGuardrails(system, 108)
		require.NoError(t, err)
		assert.True(t, policy.AllowsModel("gpt-4o"))
	})

	t.Run("policy_version invalidates the cached policy", func(t *testing.T) {
		reset(t)
		assert.True(t, resolve(t, 200).AllowsModel("gpt-4o"))
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: `{"denied_models":["gpt-4o"]}`})
		assert.True(t, resolve(t, 200).AllowsModel("gpt-4o"), "same version reuses the cached policy")
		assert.False(t, resolve(t, 201).AllowsModel("gpt-4o"), "a bumped version re-reads the database")
	})

	t.Run("an unreadable stored rule fails closed", func(t *testing.T) {
		reset(t)
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: `{"allowed_models": "gpt-4o"`})
		_, err := orgservice.ResolveGuardrails(subject, 300)
		require.Error(t, err)
		reset(t)
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: `{"budget_refs":["b1"]}`})
		_, err = orgservice.ResolveGuardrails(subject, 301)
		require.ErrorIs(t, err, orgservice.ErrGuardrailInvalid)
	})

	t.Run("provider rules compile into a channel filter", func(t *testing.T) {
		reset(t)
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: `{"allowed_providers":["OpenAI","Anthropic"]}`})
		addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetMember, TargetId: 100, Config: `{"allowed_providers":["openai"],"denied_providers":["Azure"]}`})
		filter, restricted := resolve(t, 400).ProviderFilter()
		require.True(t, restricted)
		assert.Equal(t, dto.FilterOrgProvider, filter.Kind)
		assert.ElementsMatch(t, [][]string{{"openai", "anthropic"}, {"openai"}}, filter.OrgProviderAllowSets)
		assert.Equal(t, []string{"azure"}, filter.OrgProviderDeny)
	})
}

func TestOrgGuardrailNoBudget(t *testing.T) {
	cases := []struct {
		name   string
		config string
		ok     bool
	}{
		{"valid", `{"allowed_models":["a"],"denied_providers":["b"]}`, true},
		{"empty config", ``, true},
		{"empty object", `{}`, true},
		{"budget_refs removed in v4", `{"budget_refs":["b1"]}`, false},
		{"any budget-like field", `{"budget_limit":100}`, false},
		{"unknown field", `{"allowed_modles":["a"]}`, false},
		{"wrong type", `{"allowed_models":"a"}`, false},
		{"not an object", `["a"]`, false},
		{"empty entry", `{"allowed_models":[""]}`, false},
		{"blank entry", `{"denied_models":["   "]}`, false},
		{"oversize entry", `{"allowed_models":["` + strings.Repeat("a", 129) + `"]}`, false},
		{"too many entries", `{"allowed_models":[` + strings.TrimSuffix(strings.Repeat(`"m",`, 201), ",") + `]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := orgservice.ParseGuardrailConfig(tc.config)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.True(t, errors.Is(err, orgservice.ErrGuardrailInvalid))
		})
	}
}

func tagChannel(t *testing.T, db *gorm.DB, id int, tag string) {
	t.Helper()
	if tag == "" {
		return
	}
	require.NoError(t, db.Model(&model.Channel{}).Where("id = ?", id).Update("tag", tag).Error)
}

var guardrailTestVersion int64 = 1000

// providerFilterContext builds a request context whose constraints carry the
// provider rules resolved from the given guardrail config.
func providerFilterContext(t *testing.T, db *gorm.DB, config string) *gin.Context {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&model.Guardrail{}))
	require.NoError(t, db.Exec("DELETE FROM guardrails").Error)
	addGuardrail(t, db, model.Guardrail{OrgId: 1, TargetType: types.GuardrailTargetOrgDefault, Config: config})
	// Every call is a new policy version, as a real guardrail write would be.
	guardrailTestVersion++
	policy, err := orgservice.ResolveGuardrails(types.OrgSubject{OrgID: 1, WorkspaceID: 1, TokenID: 1}, guardrailTestVersion)
	require.NoError(t, err)
	gin.SetMode(gin.TestMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	common.SetContextKey(ctx, constant.ContextKeyUserGroup, "default")
	if filter, ok := policy.ProviderFilter(); ok {
		GetChannelConstraints(ctx).AddFilter(filter)
	}
	return ctx
}

func TestOrgProviderRetryConstraint(t *testing.T) {
	db := setupChannelSelectAutoGroupsTest(t)
	const modelName = "provider-guard-model"
	createChannelSelectAutoGroupsChannel(t, db, 3101, "default", modelName) // provider A
	createChannelSelectAutoGroupsChannel(t, db, 3102, "default", modelName) // provider B, supports the same model
	createChannelSelectAutoGroupsChannel(t, db, 3103, "default", modelName) // no provider tag
	tagChannel(t, db, 3101, "providerA")
	tagChannel(t, db, 3102, "providerB")
	model.InitChannelCache()

	selectOnce := func(ctx *gin.Context, retry int) (*model.Channel, *ChannelSelectError) {
		channel, _, err := SelectChannelForRequest(ctx, modelName, &RetryParam{
			Ctx: ctx, ModelName: modelName, TokenGroup: "default",
			RequestPath: "/v1/chat/completions", Retry: &retry,
		})
		return channel, err
	}

	t.Run("a denied provider never receives a request, across first attempts and retries", func(t *testing.T) {
		ctx := providerFilterContext(t, db, `{"denied_providers":["providerB"]}`)
		hits := map[int]int{}
		for attempt := 0; attempt < 300; attempt++ {
			channel, err := selectOnce(ctx, attempt%4)
			require.Nil(t, err)
			hits[channel.Id]++
		}
		assert.Zero(t, hits[3102], "the denied provider supports the model but must receive 0 requests")
		assert.Positive(t, hits[3101])
		assert.Positive(t, hits[3103], "an unmapped channel is allowed while only a deny list exists")
	})

	t.Run("with an allow list only the allowed provider serves, even when A is retried", func(t *testing.T) {
		ctx := providerFilterContext(t, db, `{"allowed_providers":["providera"]}`)
		for attempt := 0; attempt < 100; attempt++ {
			channel, err := selectOnce(ctx, attempt%3)
			require.Nil(t, err)
			assert.Equal(t, 3101, channel.Id, "B and the unmapped channel can never be chosen")
		}
	})

	t.Run("an allow list with no provable provider fails instead of widening", func(t *testing.T) {
		ctx := providerFilterContext(t, db, `{"allowed_providers":["providerZ"]}`)
		channel, err := selectOnce(ctx, 0)
		assert.Nil(t, channel)
		require.NotNil(t, err)
	})

	t.Run("a pin does not exempt a denied provider", func(t *testing.T) {
		ctx := providerFilterContext(t, db, `{"denied_providers":["providerB"]}`)
		GetChannelConstraints(ctx).AddPin(dto.ChannelPin{ChannelId: 3102, Source: dto.PinSourceToken, Rank: dto.PinRankToken, RetryMode: dto.PinRetrySingleAttempt})
		channel, err := selectOnce(ctx, 0)
		assert.Nil(t, channel)
		require.NotNil(t, err)
		assert.Equal(t, dto.FilterOrgProvider, err.FilterKind)
	})

	t.Run("without guardrails every channel is eligible", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		common.SetContextKey(ctx, constant.ContextKeyUserGroup, "default")
		seen := map[int]bool{}
		for attempt := 0; attempt < 300; attempt++ {
			channel, err := selectOnce(ctx, 0)
			require.Nil(t, err)
			seen[channel.Id] = true
		}
		assert.True(t, seen[3101] && seen[3102] && seen[3103])
	})
}
