package controller

import (
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// platformOrg resolves :org for platform staff, including suspended and
// soft-deleted organizations: staff must be able to reach exactly those.
func platformOrg(c *gin.Context) (*model.Organization, bool) {
	org, err := model.GetOrganizationByRef(model.DB.Unscoped().WithContext(c.Request.Context()), c.Param("org"))
	if err != nil {
		if model.IsOrgNotFound(err) {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrNotFound))
		} else {
			respondOrgError(c, err)
		}
		return nil, false
	}
	return org, true
}

// reasonFrom reads the mandatory reason of a platform write.
func reasonFrom(c *gin.Context, fields map[string]common.RawMessage) (string, bool) {
	var reason string
	if present, err := orgField(fields, "reason", &reason); err != nil || !present || strings.TrimSpace(reason) == "" {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return "", false
	}
	return strings.TrimSpace(reason), true
}

// PlatformListOrganizations: GET /api/admin/orgs?keyword=
func PlatformListOrganizations(c *gin.Context) {
	pageInfo := common.GetPageQuery(c)
	rows, total, err := model.SearchOrganizations(c.Request.Context(), strings.TrimSpace(c.Query("keyword")),
		pageInfo.GetStartIdx(), pageInfo.GetPageSize())
	if err != nil {
		respondOrgError(c, err)
		return
	}
	pageInfo.SetTotal(int(total))
	pageInfo.SetItems(rows)
	common.ApiSuccess(c, pageInfo)
}

// PlatformUpdateOrganization: PATCH /api/admin/orgs/:org with a mandatory
// reason. Status changes go through the lifecycle (suspend and resume leave keys
// as they are); billing group and seat limit change the platform's own fields.
func PlatformUpdateOrganization(c *gin.Context) {
	org, ok := platformOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "status", "billing_group", "seat_limit", "reason")
	if !ok {
		return
	}
	reason, ok := reasonFrom(c, fields)
	if !ok {
		return
	}
	operator := c.GetInt("id")
	var status int
	if present, err := orgField(fields, "status", &status); err != nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	} else if present {
		if err := orgsvc.SetOrganizationStatus(orgContext(c), org.Id, status, operator, reason); err != nil {
			respondOrgError(c, err)
			return
		}
	}
	var settings model.PlatformOrgSettings
	var group string
	var seats int
	if present, err := orgField(fields, "billing_group", &group); err != nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	} else if present {
		settings.BillingGroup = &group
	}
	if present, err := orgField(fields, "seat_limit", &seats); err != nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	} else if present {
		settings.SeatLimit = &seats
	}
	if settings.BillingGroup != nil || settings.SeatLimit != nil {
		if err := model.UpdateOrgPlatformSettings(c.Request.Context(), org.Id, operator, settings, reason); err != nil {
			respondOrgError(c, err)
			return
		}
	}
	common.ApiSuccess(c, gin.H{})
}

// PlatformAdjustOrganization: POST /api/admin/orgs/:org/adjust moves the wallet
// by a signed amount with a mandatory reason and an Idempotency-Key. The same
// key and amount is a replay; the same key with another amount is a conflict.
func PlatformAdjustOrganization(c *gin.Context) {
	org, ok := platformOrg(c)
	if !ok {
		return
	}
	key := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	fields, ok := decodeOrgFields(c, "delta_quota", "reason")
	if !ok {
		return
	}
	reason, ok := reasonFrom(c, fields)
	if !ok {
		return
	}
	var delta int64
	if present, err := orgField(fields, "delta_quota", &delta); err != nil || !present || delta == 0 ||
		delta > common.MaxWalletQuota || delta < -common.MaxWalletQuota {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	balance, err := model.AdjustOrganizationWallet(org.Id, c.GetInt("id"), delta, reason, key)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"available_quota": balance})
}

// PlatformListBillingOperations: GET /api/admin/orgs/:org/billing-operations?state=
func PlatformListBillingOperations(c *gin.Context) {
	org, ok := platformOrg(c)
	if !ok {
		return
	}
	pageInfo := common.GetPageQuery(c)
	rows, total, err := model.ListOrgBillingOperations(c.Request.Context(), org.Id, c.Query("state"),
		pageInfo.GetStartIdx(), pageInfo.GetPageSize())
	if err != nil {
		respondOrgError(c, err)
		return
	}
	type view struct {
		OperationId   string `json:"operation_id"`
		State         string `json:"state"`
		SourceKind    string `json:"source_kind"`
		ModelName     string `json:"model_name"`
		Bound         int64  `json:"bound"`
		CapturedQuota int64  `json:"captured_quota"`
		Revision      int64  `json:"revision"`
		SettledBy     string `json:"settled_by"`
		CreatedAt     int64  `json:"created_at"`
	}
	items := make([]view, 0, len(rows))
	for _, row := range rows {
		items = append(items, view{row.OperationId, row.State, row.SourceKind, row.ModelName, row.Bound, row.CapturedQuota,
			row.Revision, row.SettledBy, row.CreatedAt})
	}
	pageInfo.SetTotal(int(total))
	pageInfo.SetItems(items)
	common.ApiSuccess(c, pageInfo)
}

// PlatformResolveBillingOperation: POST .../billing-operations/:operation/resolve.
// It needs the revision the staff member saw, the action, the evidence and a
// reason; nothing here edits a balance except through the settlement rules.
func PlatformResolveBillingOperation(c *gin.Context) {
	org, ok := platformOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "expected_revision", "action", "target_quota", "evidence_ref", "reason")
	if !ok {
		return
	}
	reason, ok := reasonFrom(c, fields)
	if !ok {
		return
	}
	in := model.OrgOperationResolution{OperationID: c.Param("operation"), Reason: reason, OperatorID: c.GetInt("id")}
	for name, dst := range map[string]any{"expected_revision": &in.ExpectedRevision, "action": &in.Action,
		"target_quota": &in.TargetQuota, "evidence_ref": &in.EvidenceRef} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
	}
	result, err := model.ResolveOrgOperation(c.Request.Context(), org.Id, in)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"state": result.State, "captured": result.Captured, "revision": result.Revision, "replayed": result.Replayed})
}
