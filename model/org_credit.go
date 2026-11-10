package model

import (
	"context"
	"strconv"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// orgCreditSource says where credited money came from. The idempotency key is
// built from it, so a callback or a manual completion that repeats can never
// credit twice: topup:<order id>, redemption:<code id>, transfer:<key>.
type orgCreditSource struct {
	ledgerType string
	refType    string
	refID      string
	key        string
	operatorID int
	ip         string
}

func topUpSource(topUp *TopUp, ip string) *orgCreditSource {
	id := strconv.Itoa(topUp.Id)
	return &orgCreditSource{ledgerType: types.OrgLedgerTopUp, refType: "topup", refID: id, key: "topup:" + id, ip: ip}
}

// creditWalletTx adds quota to a wallet inside the caller's transaction. A
// personal wallet takes the existing path untouched. An organization wallet
// also gets, in the same transaction, its ledger row, a billing.topup audit row
// and the receipt and notification jobs, so a credit is never half recorded
// (design 4.5). It is the one place organization money comes in.
func creditWalletTx(tx *gorm.DB, userID, quota int, updates map[string]any, source *orgCreditSource) error {
	billing, err := isBillingAccountByID(tx, userID)
	if err != nil {
		return err
	}
	if !billing {
		return creditTopUpQuota(tx, userID, quota, updates)
	}
	if source == nil || source.key == "" {
		return orgInvalidError() // organization money must always say where it came from
	}
	// Account fields (the Creem payer email) never go onto a wallet.
	org, err := orgFindOne[Organization](tx.Unscoped().Select("id", "billing_user_id").Where("billing_user_id = ?", userID))
	if err != nil {
		return err
	}
	if org == nil {
		return orgNotFoundError()
	}
	prior, err := orgFindOne[OrgBillingLedger](tx.Where("org_id = ? AND idempotency_key = ?", org.Id, source.key))
	if err != nil {
		return err
	}
	if prior != nil {
		if prior.AmountQuota != int64(quota) {
			return orgConflictError() // same source, different amount
		}
		return nil // already credited
	}
	if err := creditTopUpQuota(tx, userID, quota, nil); err != nil {
		return err
	}
	return recordOrgCreditRowsTx(tx, org.Id, userID, int64(quota), source)
}

// recordOrgCreditRowsTx writes what a credit leaves behind: the ledger row with
// the balance after it, the audit row, and two durable jobs, one to issue the
// receipt and one to tell the owners. The jobs are rows, not goroutines, so a
// crash after the commit still delivers them.
func recordOrgCreditRowsTx(tx *gorm.DB, orgID, walletID int, quota int64, source *orgCreditSource) error {
	balance, err := OrgWalletAvailable(tx, walletID)
	if err != nil {
		return err
	}
	now := common.GetTimestamp()
	ledger := OrgBillingLedger{OrgId: orgID, Type: source.ledgerType, AmountQuota: quota, BalanceAfter: balance,
		RefType: source.refType, RefId: source.refID, IdempotencyKey: source.key, OperatorUserId: source.operatorID, CreatedAt: now}
	if err := tx.Create(&ledger).Error; err != nil {
		return err
	}
	if err := RecordOrgAuditTx(tx, OrgAuditEntry{OrgId: orgID, ActorUserId: source.operatorID, Action: "billing.topup",
		TargetType: source.refType, TargetId: source.refID, Ip: source.ip,
		Detail: map[string]any{"amount_quota": quota, "type": source.ledgerType, "key": source.key}}); err != nil {
		return err
	}
	for _, kind := range []string{types.OrgJobKindReceipt, types.OrgJobKindNotify} {
		job := OrgBillingJob{OrgId: orgID, Kind: kind, BusinessKey: source.key, Status: types.OrgJobStatusPending,
			NextRunAt: now, CreatedAt: now, UpdatedAt: now}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&job).Error; err != nil {
			return err
		}
	}
	return nil
}

//__NEXT__

// TransferToOrganization moves money from a person to an organization wallet.
// Both wallets are locked in id order, the total is conserved, and the pair
// of ledger rows share one transfer id. The caller must already have proven
// the person is an owner or billing member of the organization and holds a
// global session; this function proves nothing about identity.
func TransferToOrganization(orgID, fromUserID, quota int, idempotencyKey string) (balance int64, err error) {
	if quota <= 0 || idempotencyKey == "" || len(idempotencyKey) > 100 {
		return 0, orgInvalidError()
	}
	err = DB.Transaction(func(tx *gorm.DB) error {
		org, err := orgFindOne[Organization](tx.Select("id", "billing_user_id", "status").Where("id = ?", orgID))
		if err != nil {
			return err
		}
		if org == nil {
			return orgNotFoundError()
		}
		key := "transfer:" + idempotencyKey
		if prior, err := orgFindOne[OrgBillingLedger](tx.Where("org_id = ? AND idempotency_key = ?", orgID, key)); err != nil {
			return err
		} else if prior != nil {
			if prior.AmountQuota != int64(quota) || prior.OperatorUserId != fromUserID {
				return orgConflictError()
			}
			balance = prior.BalanceAfter
			return nil
		}
		ids := []int{fromUserID, org.BillingUserId}
		if ids[0] > ids[1] {
			ids[0], ids[1] = ids[1], ids[0]
		}
		for _, id := range ids {
			if _, err := orgFindOne[User](lockForUpdate(tx.Unscoped().Select("id").Where("id = ?", id))); err != nil {
				return err
			}
		}
		if ok, err := DecreaseOrgWalletTx(tx, fromUserID, int64(quota)); err != nil {
			return err
		} else if !ok {
			return types.NewOrgAccessError(types.OrgErrQuotaExhausted)
		}
		if err := creditTopUpQuota(tx, org.BillingUserId, quota, nil); err != nil {
			return err
		}
		source := &orgCreditSource{ledgerType: types.OrgLedgerTransferIn, refType: "transfer", refID: idempotencyKey,
			key: key, operatorID: fromUserID}
		if err := recordOrgCreditRowsTx(tx, orgID, org.BillingUserId, int64(quota), source); err != nil {
			return err
		}
		balance, err = OrgWalletAvailable(tx, org.BillingUserId)
		return err
	})
	if err == nil {
		syncCreditUserQuotaCache(fromUserID, -quota, "personal transfer out")
	}
	return balance, err
}

// AdjustOrganizationWallet is the platform's manual correction. A reason is
// mandatory. A debit can only take what no lease or hold has claimed, so it
// never reaches into money an in-flight request is using; a debit larger than
// that is refused with org_quota_in_use and can be retried after the holds free.
func AdjustOrganizationWallet(orgID, operatorID int, delta int64, reason, idempotencyKey string) (balance int64, err error) {
	if delta == 0 || reason == "" || len(reason) > 500 || idempotencyKey == "" || len(idempotencyKey) > 100 || operatorID <= 0 {
		return 0, orgInvalidError()
	}
	err = DB.Transaction(func(tx *gorm.DB) error {
		org, err := orgFindOne[Organization](tx.Unscoped().Select("id", "billing_user_id").Where("id = ?", orgID))
		if err != nil {
			return err
		}
		if org == nil {
			return orgNotFoundError()
		}
		key := "adjust:" + idempotencyKey
		if prior, err := orgFindOne[OrgBillingLedger](tx.Where("org_id = ? AND idempotency_key = ?", orgID, key)); err != nil {
			return err
		} else if prior != nil {
			if prior.AmountQuota != delta {
				return orgConflictError()
			}
			balance = prior.BalanceAfter
			return nil
		}
		if _, err := orgFindOne[User](lockForUpdate(tx.Unscoped().Select("id").Where("id = ?", org.BillingUserId))); err != nil {
			return err
		}
		if delta > 0 {
			err = creditTopUpQuota(tx, org.BillingUserId, int(delta), nil)
		} else if ok, derr := DecreaseOrgWalletTx(tx, org.BillingUserId, -delta); derr != nil {
			err = derr
		} else if !ok {
			err = types.NewOrgAccessError(types.OrgErrQuotaInUse)
		}
		if err != nil {
			return err
		}
		balance, err = OrgWalletAvailable(tx, org.BillingUserId)
		if err != nil {
			return err
		}
		now := common.GetTimestamp()
		if err := tx.Create(&OrgBillingLedger{OrgId: orgID, Type: types.OrgLedgerAdjust, AmountQuota: delta, BalanceAfter: balance,
			RefType: "adjust", RefId: idempotencyKey, IdempotencyKey: key, OperatorUserId: operatorID, CreatedAt: now}).Error; err != nil {
			return err
		}
		return RecordOrgAuditTx(tx, OrgAuditEntry{OrgId: orgID, ActorUserId: operatorID, ActorKind: "platform",
			Action: "platform.adjust", TargetType: "wallet", TargetId: strconv.Itoa(org.BillingUserId),
			Detail: map[string]any{"delta_quota": delta, "reason": reason}})
	})
	return balance, err
}

// OrgBillingView is the finance page of an organization: what can be spent,
// what in-flight requests hold, the money-in ledger, operations waiting for a
// platform decision, and the models whose daily write-off cap is reached.
type OrgBillingView struct {
	Balance               OrgBalance
	Ledger                []OrgBillingLedger
	LedgerTotal           int64
	RecoveryRequiredCount int64
	RecoveryRequiredHeld  int64
	WriteoffLimitedModels []string
	WriteoffLimitedUntil  int64
}

// GetOrgBillingView reads the finance page. The ledger is newest first.
func GetOrgBillingView(ctx context.Context, orgID, offset, limit int, writeoffCapQuota int64) (OrgBillingView, error) {
	var view OrgBillingView
	var err error
	if view.Balance, err = OrgBalanceView(ctx, orgID); err != nil {
		return view, err
	}
	db := DB.WithContext(ctx)
	if err := db.Model(&OrgBillingLedger{}).Where("org_id = ?", orgID).Count(&view.LedgerTotal).Error; err != nil {
		return view, err
	}
	if err := db.Where("org_id = ?", orgID).Order("id DESC").Offset(offset).Limit(limit).Find(&view.Ledger).Error; err != nil {
		return view, err
	}
	var parked []OrgBillingOperation
	if err := db.Select("id", "holds").Where("org_id = ? AND state = ?", orgID, types.OrgOpStateRecoveryRequired).
		Find(&parked).Error; err != nil {
		return view, err
	}
	view.RecoveryRequiredCount = int64(len(parked))
	for _, op := range parked {
		holds, err := decodeOrgHolds(op.Holds)
		if err != nil {
			return view, err
		}
		for _, hold := range holds {
			if hold.TargetType == types.OrgHoldTargetWallet {
				view.RecoveryRequiredHeld += hold.Amount - hold.Released - hold.Captured
			}
		}
	}
	today := time.Now().UTC()
	var rows []OrgWriteoffDaily
	if err := db.Where("org_id = ? AND day = ? AND writeoff_quota >= ?", orgID, today.Format("2006-01-02"), writeoffCapQuota).
		Find(&rows).Error; err != nil {
		return view, err
	}
	for _, row := range rows {
		view.WriteoffLimitedModels = append(view.WriteoffLimitedModels, row.ModelName)
	}
	if len(rows) > 0 {
		view.WriteoffLimitedUntil = time.Date(today.Year(), today.Month(), today.Day()+1, 0, 0, 0, 0, time.UTC).Unix()
	}
	return view, nil
}
