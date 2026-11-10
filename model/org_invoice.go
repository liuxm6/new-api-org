package model

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"github.com/shopspring/decimal"
	"gorm.io/gorm"
)

// nextOrgInvoiceNumberTx hands out INV-<org>-<sequence> under the organization
// row lock, so two workers can never issue the same number. The sequence is
// advanced in the same transaction as the invoice: a failure leaves no gap.
func nextOrgInvoiceNumberTx(tx *gorm.DB, orgID int) (string, error) {
	org, err := orgFindOne[Organization](lockForUpdate(tx.Unscoped().Select("id", "invoice_sequence").Where("id = ?", orgID)))
	if err != nil {
		return "", err
	}
	if org == nil {
		return "", orgNotFoundError()
	}
	next := org.InvoiceSequence + 1
	if err := tx.Unscoped().Model(&Organization{}).Where("id = ?", orgID).Update("invoice_sequence", next).Error; err != nil {
		return "", err
	}
	return fmt.Sprintf("INV-%d-%d", orgID, next), nil
}

// orgProfileSnapshotTx freezes the billing header at issue time. Without a
// profile the organization's own name stands in.
func orgProfileSnapshotTx(tx *gorm.DB, orgID int) (string, error) {
	profile, err := orgFindOne[OrgBillingProfile](tx.Where("org_id = ?", orgID))
	if err != nil {
		return "", err
	}
	snapshot := map[string]string{}
	if profile != nil {
		snapshot = map[string]string{"legal_name": profile.LegalName, "tax_id": profile.TaxId,
			"address": profile.Address, "billing_email": profile.BillingEmail}
	}
	if snapshot["legal_name"] == "" {
		org, err := orgFindOne[Organization](tx.Unscoped().Select("name").Where("id = ?", orgID))
		if err != nil {
			return "", err
		}
		if org != nil {
			snapshot["legal_name"] = org.Name
		}
	}
	data, err := common.Marshal(snapshot)
	return string(data), err
}

// quotaToUSD converts quota to USD with decimal arithmetic. Statements sum the
// decimals of every line first and round to cents once, with usdToCents.
func quotaToUSD(quota int64) decimal.Decimal {
	return decimal.NewFromInt(quota).Div(decimal.NewFromFloat(common.QuotaPerUnit))
}

func usdToCents(usd decimal.Decimal) int64 {
	return usd.Mul(decimal.NewFromInt(100)).Round(0).IntPart() // half away from zero (RoundBank would be banker's rounding)
}

// IssueOrgReceipt issues the receipt of one credit, found by its ledger
// idempotency key. It is safe to run twice: the business key is unique, so a
// repeat returns the invoice that already exists. An order is receipted in the
// currency and amount it was paid in; a code, a transfer and every other credit
// in USD at the quota conversion. A platform adjustment is a correction, not a
// payment, and gets no receipt.
func IssueOrgReceipt(ctx context.Context, orgID int, ledgerKey string) (*OrgInvoice, error) {
	var issued *OrgInvoice
	err := retryOrgTx(ctx, func(tx *gorm.DB) error {
		businessKey := "receipt:" + ledgerKey
		if existing, err := orgFindOne[OrgInvoice](tx.Where("org_id = ? AND business_key = ?", orgID, businessKey)); err != nil {
			return err
		} else if existing != nil {
			issued = existing
			return nil
		}
		ledger, err := orgFindOne[OrgBillingLedger](tx.Where("org_id = ? AND idempotency_key = ?", orgID, ledgerKey))
		if err != nil {
			return err
		}
		if ledger == nil || ledger.Type == types.OrgLedgerAdjust {
			return orgNotFoundError()
		}
		currency, cents, quota := "USD", usdToCents(quotaToUSD(ledger.AmountQuota)), ledger.AmountQuota
		var topUpID int
		if ledger.RefType == "topup" {
			topUpID, _ = strconv.Atoi(ledger.RefId)
			if order, err := orgFindOne[TopUp](tx.Where("id = ?", topUpID)); err != nil {
				return err
			} else if order != nil {
				cents = usdToCents(decimal.NewFromFloat(order.Money))
			}
		}
		profile, err := orgProfileSnapshotTx(tx, orgID)
		if err != nil {
			return err
		}
		number, err := nextOrgInvoiceNumberTx(tx, orgID)
		if err != nil {
			return err
		}
		line, _ := common.Marshal([]map[string]any{{"description": ledger.Type, "ref_type": ledger.RefType, "ref_id": ledger.RefId,
			"quota": quota, "amount_cents": cents, "currency": currency}})
		now := common.GetTimestamp()
		invoice := OrgInvoice{OrgId: orgID, Number: number, Type: types.OrgInvoiceReceipt, PeriodStart: ledger.CreatedAt, PeriodEnd: ledger.CreatedAt,
			Currency: currency, AmountCents: cents, Quota: quota, Status: types.OrgInvoiceStatusIssued, ProfileSnapshot: profile,
			LineSnapshot: string(line), TopupId: topUpID, ReceiptRef: ledgerKey, BusinessKey: businessKey, CreatedAt: now, UpdatedAt: now}
		if err := tx.Create(&invoice).Error; err != nil {
			return err
		}
		issued = &invoice
		return nil
	})
	return issued, err
}

// ErrOrgPeriodOpen means the month has not ended yet by the database clock.
var ErrOrgPeriodOpen = fmt.Errorf("the statement period has not ended")

// rollupPrice splits a rollup key back into its parts. A key that was hashed
// because it was too long keeps only the hash as its label and the current
// conversion.
func rollupPrice(key string) (label string, quotaPerUnit decimal.Decimal) {
	quotaPerUnit = decimal.NewFromFloat(common.QuotaPerUnit)
	parts := splitRollupKey(key)
	if len(parts) != 4 {
		return key, quotaPerUnit
	}
	if parsed, err := decimal.NewFromString(parts[3]); err == nil && parsed.IsPositive() {
		quotaPerUnit = parsed
	}
	return parts[0] + " " + parts[1], quotaPerUnit
}

func splitRollupKey(key string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			parts = append(parts, key[start:i])
			start = i + 1
		}
	}
	return append(parts, key[start:])
}

// IssueOrgStatement closes one UTC month of consumption into a statement
// (design 4.6). The wallet row is locked first and the database clock read
// after, so by the time the month is seen to be over, every fold that could
// still land in it has committed: the rollups read here are final. The amount
// is the sum of every line's exact decimal, rounded to cents once. A month with
// no rollup rows produces no statement; a second run returns the same one.
func IssueOrgStatement(ctx context.Context, orgID int, period string) (*OrgInvoice, error) {
	start, err := time.Parse("2006-01", period)
	if err != nil {
		return nil, orgInvalidError()
	}
	end := start.AddDate(0, 1, 0).Unix()
	org, err := orgFindOne[Organization](DB.WithContext(ctx).Unscoped().Select("id", "billing_user_id").Where("id = ?", orgID))
	if err != nil {
		return nil, err
	}
	if org == nil {
		return nil, orgNotFoundError()
	}
	var issued *OrgInvoice
	err = retryOrgTx(ctx, func(tx *gorm.DB) error {
		if _, err := orgFindOne[User](lockForUpdate(tx.Unscoped().Select("id").Where("id = ?", org.BillingUserId))); err != nil {
			return err
		}
		now, err := orgDBNow(tx)
		if err != nil {
			return err
		}
		if now < end {
			return ErrOrgPeriodOpen
		}
		businessKey := "statement:" + period
		if existing, err := orgFindOne[OrgInvoice](tx.Where("org_id = ? AND business_key = ?", orgID, businessKey)); err != nil {
			return err
		} else if existing != nil {
			issued = existing
			return nil
		}
		var rollups []OrgSpendRollup
		if err := tx.Where("org_id = ? AND period = ?", orgID, period).
			Order("rollup_key ASC, workspace_id ASC, effective_period ASC").Find(&rollups).Error; err != nil {
			return err
		}
		if len(rollups) == 0 {
			return nil // no consumption and no adjustment: no statement
		}
		return writeOrgStatementTx(tx, orgID, period, start.Unix(), end, rollups, &issued)
	})
	return issued, err
}

func writeOrgStatementTx(tx *gorm.DB, orgID int, period string, start, end int64, rollups []OrgSpendRollup, out **OrgInvoice) error {
	var total decimal.Decimal
	var quota int64
	lines := make([]map[string]any, 0, len(rollups))
	for _, row := range rollups {
		label, perUnit := rollupPrice(row.RollupKey)
		usd := decimal.NewFromInt(row.SpendQuota).Div(perUnit)
		total = total.Add(usd)
		quota += row.SpendQuota
		line := map[string]any{"description": label, "workspace_id": row.WorkspaceId, "effective_period": row.EffectivePeriod,
			"quota": row.SpendQuota, "events": row.EventCount, "amount_usd": usd.String()}
		if row.EffectivePeriod != period {
			line["late_adjustment"] = true // consumption of an earlier month, folded late
		}
		lines = append(lines, line)
	}
	lineJSON, err := common.Marshal(lines)
	if err != nil {
		return err
	}
	profile, err := orgProfileSnapshotTx(tx, orgID)
	if err != nil {
		return err
	}
	number, err := nextOrgInvoiceNumberTx(tx, orgID)
	if err != nil {
		return err
	}
	now := common.GetTimestamp()
	invoice := OrgInvoice{OrgId: orgID, Number: number, Type: types.OrgInvoiceStatement, PeriodStart: start, PeriodEnd: end,
		Currency: "USD", AmountCents: usdToCents(total), Quota: quota, Status: types.OrgInvoiceStatusIssued, ProfileSnapshot: profile,
		LineSnapshot: string(lineJSON), BusinessKey: "statement:" + period, CreatedAt: now, UpdatedAt: now}
	if err := tx.Create(&invoice).Error; err != nil {
		return err
	}
	*out = &invoice
	return nil
}

// VoidOrgInvoice marks an invoice void. Voiding never refunds and never
// reopens the period, and it cannot be undone: the status only moves one way.
func VoidOrgInvoice(ctx context.Context, orgID, invoiceID, operatorID int) (*OrgInvoice, error) {
	var result *OrgInvoice
	err := retryOrgTx(ctx, func(tx *gorm.DB) error {
		invoice, err := orgFindOne[OrgInvoice](lockForUpdate(tx.Where("id = ? AND org_id = ?", invoiceID, orgID)))
		if err != nil {
			return err
		}
		if invoice == nil {
			return orgNotFoundError()
		}
		result = invoice
		if invoice.Status == types.OrgInvoiceStatusVoid {
			return nil // already void: a repeat changes nothing
		}
		invoice.Status, invoice.UpdatedAt = types.OrgInvoiceStatusVoid, common.GetTimestamp()
		if err := tx.Model(&OrgInvoice{}).Where("id = ?", invoice.Id).
			Updates(map[string]any{"status": invoice.Status, "updated_at": invoice.UpdatedAt}).Error; err != nil {
			return err
		}
		return RecordOrgAuditTx(tx, OrgAuditEntry{OrgId: orgID, ActorUserId: operatorID, Action: "invoice.void",
			TargetType: "invoice", TargetId: invoice.Number})
	})
	return result, err
}

// OrgStatementExists reports whether the statement of a month was issued.
func OrgStatementExists(ctx context.Context, orgID int, period string) (bool, error) {
	var count int64
	err := DB.WithContext(ctx).Model(&OrgInvoice{}).Where("org_id = ? AND business_key = ?", orgID, "statement:"+period).Count(&count).Error
	return count > 0, err
}

// ListOrgInvoices pages the invoices of an organization, newest first.
func ListOrgInvoices(ctx context.Context, orgID int, invoiceType string, offset, limit int) ([]OrgInvoice, int64, error) {
	query := DB.WithContext(ctx).Model(&OrgInvoice{}).Where("org_id = ?", orgID)
	if invoiceType == types.OrgInvoiceReceipt || invoiceType == types.OrgInvoiceStatement {
		query = query.Where("type = ?", invoiceType)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []OrgInvoice
	err := query.Order("id DESC").Offset(offset).Limit(limit).Find(&rows).Error
	return rows, total, err
}

// GetOrgInvoice reads one invoice of an organization; another organization's
// invoice is reported as missing.
func GetOrgInvoice(ctx context.Context, orgID, invoiceID int) (*OrgInvoice, error) {
	invoice, err := orgFindOne[OrgInvoice](DB.WithContext(ctx).Where("id = ? AND org_id = ?", invoiceID, orgID))
	if err == nil && invoice == nil {
		err = orgNotFoundError()
	}
	return invoice, err
}

// GetOrgBillingProfile reads the invoice header; an organization that never set
// one has an empty header.
func GetOrgBillingProfile(ctx context.Context, orgID int) (OrgBillingProfile, error) {
	profile, err := orgFindOne[OrgBillingProfile](DB.WithContext(ctx).Where("org_id = ?", orgID))
	if profile == nil {
		return OrgBillingProfile{OrgId: orgID}, err
	}
	return *profile, err
}

// SaveOrgBillingProfile replaces the invoice header. Invoices already issued keep
// the header they were issued with.
func SaveOrgBillingProfile(ctx context.Context, profile OrgBillingProfile, operatorID int) error {
	if profile.OrgId <= 0 || len(profile.LegalName) > 255 || len(profile.TaxId) > 64 || len(profile.Address) > 2000 || len(profile.BillingEmail) > 255 {
		return orgInvalidError()
	}
	return retryOrgTx(ctx, func(tx *gorm.DB) error {
		now := common.GetTimestamp()
		existing, err := orgFindOne[OrgBillingProfile](lockForUpdate(tx.Where("org_id = ?", profile.OrgId)))
		if err != nil {
			return err
		}
		if existing == nil {
			profile.CreatedAt, profile.UpdatedAt = now, now
			if err := tx.Create(&profile).Error; err != nil {
				return err
			}
		} else if err := tx.Model(&OrgBillingProfile{}).Where("id = ?", existing.Id).
			Updates(map[string]any{"legal_name": profile.LegalName, "tax_id": profile.TaxId, "address": profile.Address,
				"billing_email": profile.BillingEmail, "updated_at": now}).Error; err != nil {
			return err
		}
		return RecordOrgAuditTx(tx, OrgAuditEntry{OrgId: profile.OrgId, ActorUserId: operatorID, Action: "billing.profile_update",
			TargetType: "billing_profile", TargetId: strconv.Itoa(profile.OrgId)})
	})
}
