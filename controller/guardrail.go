package controller

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// guardrailView is the console shape of a guardrail.
type guardrailView struct {
	Id          int               `json:"id"`
	Name        string            `json:"name"`
	TargetType  string            `json:"target_type"`
	TargetId    int               `json:"target_id"`
	WorkspaceId int               `json:"workspace_id"`
	Config      common.RawMessage `json:"config"`
	Enabled     bool              `json:"enabled"`
	CreatedAt   int64             `json:"created_at"`
	UpdatedAt   int64             `json:"updated_at"`
}

func newGuardrailView(row model.Guardrail) guardrailView {
	config := common.RawMessage(row.Config)
	if common.GetJsonType(config) != "object" {
		config = common.RawMessage("{}")
	}
	return guardrailView{Id: row.Id, Name: row.Name, TargetType: row.TargetType, TargetId: row.TargetId,
		WorkspaceId: row.WorkspaceId, Config: config, Enabled: row.Status == 1,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}

func guardrailViews(rows []model.Guardrail) []guardrailView {
	views := make([]guardrailView, 0, len(rows))
	for _, row := range rows {
		views = append(views, newGuardrailView(row))
	}
	return views
}

// guardrailScope resolves the scope of the route: a workspace when :ws is part
// of the path, otherwise the organization. Both were already proved by OrgAuth
// and WorkspaceAuth.
func guardrailScope(c *gin.Context) (orgsvc.GuardrailScope, bool) {
	if wsAccess, ok := middleware.WorkspaceAccessFromContext(c); ok {
		return orgsvc.GuardrailScope{OrgID: wsAccess.Org.Id, WorkspaceID: wsAccess.Workspace.Id}, true
	}
	access, ok := requestedOrg(c)
	if !ok {
		return orgsvc.GuardrailScope{}, false
	}
	return orgsvc.GuardrailScope{OrgID: access.Org.Id}, true
}

// decodeGuardrailInput reads the fixed body: name, target_type, target_id,
// config (a JSON object) and enabled. Anything else is rejected.
func decodeGuardrailInput(c *gin.Context) (orgsvc.GuardrailInput, bool) {
	fields, ok := decodeOrgFields(c, "name", "target_type", "target_id", "config", "enabled")
	if !ok {
		return orgsvc.GuardrailInput{}, false
	}
	input := orgsvc.GuardrailInput{}
	enabled := true
	for name, dst := range map[string]any{"name": &input.Name, "target_type": &input.TargetType,
		"target_id": &input.TargetID, "enabled": &enabled} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return input, false
		}
	}
	raw, present := fields["config"]
	if !present || common.GetJsonType(raw) != "object" {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return input, false
	}
	input.Config = string(raw)
	input.Disabled = !enabled
	return input, true
}

// ListGuardrails returns the rules stored in the scope; a workspace listing
// also carries the organization-level rules inherited by it.
func ListGuardrails(c *gin.Context) {
	scope, ok := guardrailScope(c)
	if !ok {
		return
	}
	own, inherited, err := orgsvc.ListGuardrails(orgContext(c), c.GetInt("id"), scope)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"items": guardrailViews(own), "inherited": guardrailViews(inherited)})
}

// CreateGuardrail adds a rule to the scope.
func CreateGuardrail(c *gin.Context) {
	scope, ok := guardrailScope(c)
	if !ok {
		return
	}
	input, ok := decodeGuardrailInput(c)
	if !ok {
		return
	}
	created, err := orgsvc.CreateGuardrail(orgContext(c), c.GetInt("id"), scope, input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, newGuardrailView(*created))
}

// UpdateGuardrail changes name, config and enabled state of a rule. The target
// is fixed once created.
func UpdateGuardrail(c *gin.Context) {
	scope, ok := guardrailScope(c)
	if !ok {
		return
	}
	id, ok := pathID(c, "gid")
	if !ok {
		return
	}
	input, ok := decodeGuardrailInput(c)
	if !ok {
		return
	}
	updated, err := orgsvc.UpdateGuardrail(orgContext(c), c.GetInt("id"), scope, id, input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, newGuardrailView(*updated))
}

// DeleteGuardrail removes a rule from the scope.
func DeleteGuardrail(c *gin.Context) {
	scope, ok := guardrailScope(c)
	if !ok {
		return
	}
	id, ok := pathID(c, "gid")
	if !ok {
		return
	}
	if err := orgsvc.DeleteGuardrail(orgContext(c), c.GetInt("id"), scope, id); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}
