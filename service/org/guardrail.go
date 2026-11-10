package org

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/QuantumNous/new-api/types"
)

// ErrGuardrailInvalid is returned for a guardrail config that is malformed or
// carries fields this version does not define (including the removed
// budget_refs: budgets are configured only through the budget API).
var ErrGuardrailInvalid = errors.New("invalid guardrail config")

const (
	maxGuardrailEntries     = 200
	maxGuardrailEntryLength = 128
)

// GuardrailConfig is the stored JSON of one guardrail. A nil list means "not
// restricted"; a present empty allow list means "nothing is allowed".
type GuardrailConfig struct {
	AllowedModels    []string `json:"allowed_models,omitempty"`
	DeniedModels     []string `json:"denied_models,omitempty"`
	AllowedProviders []string `json:"allowed_providers,omitempty"`

	// DeniedProviders is the provider counterpart of DeniedModels.
	DeniedProviders []string `json:"denied_providers,omitempty"`

	allowedModelsSet, allowedProvidersSet bool
}

var guardrailConfigFields = map[string]bool{
	"allowed_models": true, "denied_models": true,
	"allowed_providers": true, "denied_providers": true,
}

// ParseGuardrailConfig strictly decodes a guardrail config. Unknown fields
// (budget_refs among them), oversize lists and empty entries are rejected so a
// misspelled rule can never silently widen access.
func ParseGuardrailConfig(raw string) (*GuardrailConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return &GuardrailConfig{}, nil
	}
	var keys map[string]common.RawMessage
	if err := common.Unmarshal([]byte(raw), &keys); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGuardrailInvalid, err)
	}
	for key := range keys {
		if !guardrailConfigFields[key] {
			return nil, fmt.Errorf("%w: unknown field %q", ErrGuardrailInvalid, key)
		}
	}
	config := &GuardrailConfig{}
	if err := common.Unmarshal([]byte(raw), config); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGuardrailInvalid, err)
	}
	// encoding/json leaves a present empty array as a non-nil empty slice and a
	// missing key as nil, which is the distinction the semantics rely on.
	_, config.allowedModelsSet = keys["allowed_models"]
	_, config.allowedProvidersSet = keys["allowed_providers"]
	if config.allowedModelsSet && config.AllowedModels == nil {
		config.AllowedModels = []string{}
	}
	if config.allowedProvidersSet && config.AllowedProviders == nil {
		config.AllowedProviders = []string{}
	}
	for name, list := range map[string][]string{
		"allowed_models": config.AllowedModels, "denied_models": config.DeniedModels,
		"allowed_providers": config.AllowedProviders, "denied_providers": config.DeniedProviders,
	} {
		if len(list) > maxGuardrailEntries {
			return nil, fmt.Errorf("%w: %s has too many entries", ErrGuardrailInvalid, name)
		}
		for i, entry := range list {
			entry = strings.TrimSpace(entry)
			if entry == "" || len(entry) > maxGuardrailEntryLength {
				return nil, fmt.Errorf("%w: %s entry %d is empty or too long", ErrGuardrailInvalid, name, i)
			}
			list[i] = entry
		}
	}
	for i, provider := range config.AllowedProviders {
		config.AllowedProviders[i] = strings.ToLower(provider)
	}
	for i, provider := range config.DeniedProviders {
		config.DeniedProviders[i] = strings.ToLower(provider)
	}
	return config, nil
}

// ResolvedOrgPolicy is the effective rule set of one request after composing
// every applicable guardrail layer: allow lists intersect, deny lists union and
// deny wins.
type ResolvedOrgPolicy struct {
	PolicyVersion int64
	modelAllow    [][]string
	modelDeny     []string
	providerAllow [][]string
	providerDeny  []string
}

func (p *ResolvedOrgPolicy) add(config *GuardrailConfig) {
	if config.allowedModelsSet {
		p.modelAllow = append(p.modelAllow, config.AllowedModels)
	}
	if config.allowedProvidersSet {
		p.providerAllow = append(p.providerAllow, config.AllowedProviders)
	}
	p.modelDeny = append(p.modelDeny, config.DeniedModels...)
	p.providerDeny = append(p.providerDeny, config.DeniedProviders...)
}

// matchGuardrailPattern reports whether name matches pattern, where "*" matches
// any run of characters including "/" (model ids such as vendor/model contain
// slashes). Matching is case-sensitive, like model lookup.
func matchGuardrailPattern(pattern, name string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		index := strings.Index(name, part)
		if index < 0 {
			return false
		}
		name = name[index+len(part):]
	}
	return strings.HasSuffix(name, parts[len(parts)-1]) && len(name) >= len(parts[len(parts)-1])
}

func matchesAnyGuardrailPattern(patterns []string, names []string) bool {
	for _, pattern := range patterns {
		for _, name := range names {
			if matchGuardrailPattern(pattern, name) {
				return true
			}
		}
	}
	return false
}

// modelForms lists the names a request model can be known by: the id the client
// sent and its routing-normalized base. Deny rules match any form so an alias
// or a parameterized variant cannot slip past; allow rules also accept either
// form, mirroring the platform's per-key model limit.
func modelForms(requested string) []string {
	forms := []string{requested}
	if base := ratio_setting.RoutingMatchModelName(requested); base != "" && base != requested {
		forms = append(forms, base)
	}
	return forms
}

// AllowsModel reports whether the requested model passes every layer.
func (p *ResolvedOrgPolicy) AllowsModel(requested string) bool {
	if p == nil {
		return true
	}
	forms := modelForms(requested)
	if matchesAnyGuardrailPattern(p.modelDeny, forms) {
		return false
	}
	for _, allowed := range p.modelAllow {
		if !matchesAnyGuardrailPattern(allowed, forms) {
			return false
		}
	}
	return true
}

// ProviderFilter returns the channel filter carrying the provider rules, or
// ok = false when no layer restricts providers.
func (p *ResolvedOrgPolicy) ProviderFilter() (dto.ChannelFilter, bool) {
	if p == nil || (len(p.providerAllow) == 0 && len(p.providerDeny) == 0) {
		return dto.ChannelFilter{}, false
	}
	return dto.ChannelFilter{
		Kind:                 dto.FilterOrgProvider,
		OrgProviderAllowSets: slices.Clone(p.providerAllow),
		OrgProviderDeny:      slices.Clone(p.providerDeny),
	}, true
}

// guardrailLayer is one stored guardrail applying to a request.
type guardrailLayer struct {
	targetType  string
	workspaceID int
	targetID    int
}

type policyCacheKey struct {
	orgID, workspaceID, actorUserID, tokenID int
	version                                  int64
}

var (
	policyCacheMu sync.RWMutex
	policyCache   = map[policyCacheKey]*ResolvedOrgPolicy{}
)

const policyCacheLimit = 4096

// ResolveGuardrails composes the org default, workspace default, member and key
// guardrails that apply to the subject. policyVersion comes from the primary
// database on every request; any guardrail write bumps it, so a cached policy is
// only reused while it is still current.
func ResolveGuardrails(subject types.OrgSubject, policyVersion int64) (*ResolvedOrgPolicy, error) {
	if subject.OrgID <= 0 {
		return nil, errors.New("organization subject is required")
	}
	cacheKey := policyCacheKey{subject.OrgID, subject.WorkspaceID, subject.ActorUserID, subject.TokenID, policyVersion}
	policyCacheMu.RLock()
	cached := policyCache[cacheKey]
	policyCacheMu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	var rows []model.Guardrail
	query := model.DB.Where("org_id = ? AND status = ?", subject.OrgID, 1).
		Where("(target_type = ? AND workspace_id = 0) OR (target_type = ? AND workspace_id = ?) OR (target_type = ? AND target_id = ?) OR (target_type = ? AND target_id = ?)",
			types.GuardrailTargetOrgDefault,
			types.GuardrailTargetWorkspaceDefault, subject.WorkspaceID,
			types.GuardrailTargetMember, subject.ActorUserID,
			types.GuardrailTargetKey, subject.TokenID)
	if err := query.Order("id ASC").Find(&rows).Error; err != nil {
		return nil, err
	}
	policy := &ResolvedOrgPolicy{PolicyVersion: policyVersion}
	for _, row := range rows {
		// A member guardrail is org-wide (workspace 0) or scoped to this
		// workspace; one scoped to another workspace does not apply here.
		if row.TargetType == types.GuardrailTargetMember && row.WorkspaceId != 0 && row.WorkspaceId != subject.WorkspaceID {
			continue
		}
		if row.TargetType == types.GuardrailTargetMember && subject.ActorUserID == 0 {
			continue
		}
		config, err := ParseGuardrailConfig(row.Config)
		if err != nil {
			// A stored rule that cannot be read must not silently widen access.
			return nil, fmt.Errorf("guardrail %d: %w", row.Id, err)
		}
		policy.add(config)
	}

	policyCacheMu.Lock()
	if len(policyCache) >= policyCacheLimit {
		clear(policyCache)
	}
	policyCache[cacheKey] = policy
	policyCacheMu.Unlock()
	return policy, nil
}
