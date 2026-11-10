package controller

import (
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/model_setting"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// maxTransferQuota keeps one transfer inside the single-request domain.
const maxTransferQuota = 1 << 31

type orgLedgerRow struct {
	Id           int    `json:"id"`
	Type         string `json:"type"`
	AmountQuota  int64  `json:"amount_quota"`
	BalanceAfter int64  `json:"balance_after"`
	RefType      string `json:"ref_type"`
	RefId        string `json:"ref_id"`
	CreatedAt    int64  `json:"created_at"`
}

// GetOrganizationBilling is the finance page: the wallet split into what can be
// spent and what in-flight requests hold (never a negative balance), the
// money-in ledger, and the two states that limit new work.
func GetOrganizationBilling(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	pageInfo := common.GetPageQuery(c)
	capQuota := int64(model_setting.OrgWriteoffDailyLimitUSD() * common.QuotaPerUnit)
	view, err := model.GetOrgBillingView(c.Request.Context(), access.Org.Id, pageInfo.GetStartIdx(), pageInfo.GetPageSize(), capQuota)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	rows := make([]orgLedgerRow, 0, len(view.Ledger))
	for _, row := range view.Ledger {
		rows = append(rows, orgLedgerRow{Id: row.Id, Type: row.Type, AmountQuota: row.AmountQuota, BalanceAfter: row.BalanceAfter,
			RefType: row.RefType, RefId: row.RefId, CreatedAt: row.CreatedAt})
	}
	limited := view.WriteoffLimitedModels
	if limited == nil {
		limited = []string{}
	}
	common.ApiSuccess(c, gin.H{
		"wallet": gin.H{"available_quota": view.Balance.Available, "held_quota": view.Balance.InFlight,
			"lease_held_quota": view.Balance.LeaseHeld, "direct_held_quota": view.Balance.DirectHeld},
		"ledger":                       gin.H{"items": rows, "total": view.LedgerTotal},
		"recovery_required_count":      view.RecoveryRequiredCount,
		"recovery_required_held_quota": view.RecoveryRequiredHeld,
		"writeoff_limited_models":      limited,
		"writeoff_limited_until":       view.WriteoffLimitedUntil,
	})
}

// TopUpOrganization redeems a code into the organization wallet. The caller is
// an owner or billing member (checked by the route); the operator is recorded.
func TopUpOrganization(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "key")
	if !ok {
		return
	}
	var key string
	if present, err := orgField(fields, "key", &key); err != nil || !present || strings.TrimSpace(key) == "" {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	quota, err := model.RedeemToOrganization(strings.TrimSpace(key), access.Org.BillingUserId, c.GetInt("id"))
	if err != nil {
		// The model reports every failure of a code the same way; so does the API.
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	common.ApiSuccess(c, gin.H{"quota": quota})
}

// TransferCreditsToOrganization moves the caller's own balance into the
// organization. It needs a global session (the route is declared that way), an
// Idempotency-Key, and a single-use proof bound to this organization, amount
// and key, so an organization session can never spend personal money.
func TransferCreditsToOrganization(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	key := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if key == "" || len(key) > 100 {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	fields, ok := decodeOrgFields(c, "amount_quota")
	if !ok {
		return
	}
	var amount int64
	if present, err := orgField(fields, "amount_quota", &amount); err != nil || !present || amount <= 0 || amount >= maxTransferQuota {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	if !requireSensitive(c, types.SensitiveCreditTransfer, access.Org.Id, transferResource(access.Org.Id, int(amount), key)) {
		return
	}
	balance, err := model.TransferToOrganization(access.Org.Id, c.GetInt("id"), int(amount), key)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"available_quota": balance})
}

type orgInvoiceView struct {
	Id              int               `json:"id"`
	Number          string            `json:"number"`
	Type            string            `json:"type"`
	PeriodStart     int64             `json:"period_start"`
	PeriodEnd       int64             `json:"period_end"`
	Currency        string            `json:"currency"`
	AmountCents     int64             `json:"amount_cents"`
	Quota           int64             `json:"quota"`
	Status          string            `json:"status"`
	ProfileSnapshot common.RawMessage `json:"profile_snapshot"`
	LineSnapshot    common.RawMessage `json:"line_snapshot"`
	CreatedAt       int64             `json:"created_at"`
}

func newOrgInvoiceView(row model.OrgInvoice, detail bool) orgInvoiceView {
	view := orgInvoiceView{Id: row.Id, Number: row.Number, Type: row.Type, PeriodStart: row.PeriodStart, PeriodEnd: row.PeriodEnd,
		Currency: row.Currency, AmountCents: row.AmountCents, Quota: row.Quota, Status: row.Status, CreatedAt: row.CreatedAt}
	if detail {
		view.ProfileSnapshot, view.LineSnapshot = common.RawMessage("{}"), common.RawMessage("[]")
		if common.GetJsonType(common.RawMessage(row.ProfileSnapshot)) == "object" {
			view.ProfileSnapshot = common.RawMessage(row.ProfileSnapshot)
		}
		if common.GetJsonType(common.RawMessage(row.LineSnapshot)) == "array" {
			view.LineSnapshot = common.RawMessage(row.LineSnapshot)
		}
	}
	return view
}

// ListOrganizationInvoices lists receipts and statements.
func ListOrganizationInvoices(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	pageInfo := common.GetPageQuery(c)
	rows, total, err := model.ListOrgInvoices(c.Request.Context(), access.Org.Id, c.Query("type"), pageInfo.GetStartIdx(), pageInfo.GetPageSize())
	if err != nil {
		respondOrgError(c, err)
		return
	}
	items := make([]orgInvoiceView, 0, len(rows))
	for _, row := range rows {
		items = append(items, newOrgInvoiceView(row, false))
	}
	pageInfo.SetTotal(int(total))
	pageInfo.SetItems(items)
	common.ApiSuccess(c, pageInfo)
}

// GetOrganizationInvoice returns one invoice with its frozen header and lines.
// The amounts are the server's; the page prints them as they are.
func GetOrganizationInvoice(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	id, ok := pathID(c, "iid")
	if !ok {
		return
	}
	row, err := model.GetOrgInvoice(c.Request.Context(), access.Org.Id, id)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, newOrgInvoiceView(*row, true))
}

// VoidOrganizationInvoice voids an invoice. Owners only; it refunds nothing.
func VoidOrganizationInvoice(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	id, ok := pathID(c, "iid")
	if !ok {
		return
	}
	row, err := model.VoidOrgInvoice(c.Request.Context(), access.Org.Id, id, c.GetInt("id"))
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, newOrgInvoiceView(*row, true))
}

// GetOrganizationBillingProfile reads the invoice header.
func GetOrganizationBillingProfile(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	profile, err := model.GetOrgBillingProfile(c.Request.Context(), access.Org.Id)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"legal_name": profile.LegalName, "tax_id": profile.TaxId, "address": profile.Address,
		"billing_email": profile.BillingEmail})
}

// SaveOrganizationBillingProfile replaces the invoice header.
func SaveOrganizationBillingProfile(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "legal_name", "tax_id", "address", "billing_email")
	if !ok {
		return
	}
	profile := model.OrgBillingProfile{OrgId: access.Org.Id}
	for name, dst := range map[string]*string{"legal_name": &profile.LegalName, "tax_id": &profile.TaxId,
		"address": &profile.Address, "billing_email": &profile.BillingEmail} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
	}
	if err := model.SaveOrgBillingProfile(c.Request.Context(), profile, c.GetInt("id")); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}
