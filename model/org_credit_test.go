package model

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func (e *billingEnv) migrateCredit(t *testing.T) {
	t.Helper()
	require.NoError(t, e.db.AutoMigrate(&TopUp{}, &Redemption{}, &Log{}))
}

func (e *billingEnv) pendingTopUp(t *testing.T, userID int, trade string, amount int64) TopUp {
	t.Helper()
	topUp := TopUp{UserId: userID, Amount: amount, Money: float64(amount), TradeNo: trade, PaymentMethod: "alipay",
		PaymentProvider: PaymentProviderEpay, Status: common.TopUpStatusPending, CreateTime: common.GetTimestamp()}
	require.NoError(t, e.db.Create(&topUp).Error)
	return topUp
}

func (e *billingEnv) ledger(t *testing.T) []OrgBillingLedger {
	t.Helper()
	var rows []OrgBillingLedger
	require.NoError(t, e.db.Order("id ASC").Find(&rows).Error)
	return rows
}

func TestOrgCreditCompletion(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		e.migrateCredit(t)
		credit := int64(float64(common.QuotaPerUnit) * 3)
		clean := func() {
			for _, m := range []any{&OrgBillingLedger{}, &OrgAuditLog{}, &OrgBillingJob{}, &TopUp{}, &Redemption{}} {
				require.NoError(t, e.db.Unscoped().Where("1 = 1").Delete(m).Error)
			}
			e.reset(t, 1000)
		}

		t.Run("a paid order credits the wallet and leaves ledger, audit and jobs together", func(t *testing.T) {
			clean()
			e.pendingTopUp(t, e.f.wallet.Id, "trade-1", 3)
			done, err := RechargeEpay("trade-1", "", "10.0.0.1")
			require.NoError(t, err)
			assert.False(t, done)
			assert.EqualValues(t, 1000+credit, e.walletQuota(t))

			rows := e.ledger(t)
			require.Len(t, rows, 1)
			assert.Equal(t, types.OrgLedgerTopUp, rows[0].Type)
			assert.Equal(t, credit, rows[0].AmountQuota)
			assert.EqualValues(t, 1000+credit, rows[0].BalanceAfter, "balance_after is the available balance at that instant")
			assert.Equal(t, "topup:"+rows[0].RefId, rows[0].IdempotencyKey)
			assert.Equal(t, "topup", rows[0].RefType)
			var audits int64
			require.NoError(t, e.db.Model(&OrgAuditLog{}).Where("action = ? AND org_id = ?", "billing.topup", e.f.org.Id).Count(&audits).Error)
			assert.EqualValues(t, 1, audits)
			var jobs []OrgBillingJob
			require.NoError(t, e.db.Order("kind").Find(&jobs).Error)
			require.Len(t, jobs, 2)
			assert.Equal(t, types.OrgJobKindNotify, jobs[0].Kind)
			assert.Equal(t, types.OrgJobKindReceipt, jobs[1].Kind)
			assert.Equal(t, rows[0].IdempotencyKey, jobs[1].BusinessKey)
		})

		t.Run("a repeated callback credits and records once", func(t *testing.T) {
			clean()
			e.pendingTopUp(t, e.f.wallet.Id, "trade-2", 3)
			_, err := RechargeEpay("trade-2", "", "")
			require.NoError(t, err)
			done, err := RechargeEpay("trade-2", "", "")
			require.NoError(t, err)
			assert.True(t, done)
			assert.EqualValues(t, 1000+credit, e.walletQuota(t))
			assert.Len(t, e.ledger(t), 1)
		})

		t.Run("a redemption code credits the wallet and names the operator", func(t *testing.T) {
			clean()
			code := Redemption{Key: "ORG-CODE-1", Name: "c", Quota: 700, Status: common.RedemptionCodeStatusEnabled,
				CreatedTime: common.GetTimestamp(), UserId: e.f.member.Id}
			require.NoError(t, e.db.Create(&code).Error)
			quota, err := RedeemToOrganization("ORG-CODE-1", e.f.wallet.Id, e.f.member.Id)
			require.NoError(t, err)
			assert.Equal(t, 700, quota)
			assert.EqualValues(t, 1700, e.walletQuota(t))
			rows := e.ledger(t)
			require.Len(t, rows, 1)
			assert.Equal(t, "redemption:"+strconv.Itoa(code.Id), rows[0].IdempotencyKey)
			assert.Equal(t, e.f.member.Id, rows[0].OperatorUserId)

			_, err = RedeemToOrganization("ORG-CODE-1", e.f.wallet.Id, e.f.member.Id)
			require.Error(t, err, "a code works once")
			assert.EqualValues(t, 1700, e.walletQuota(t))
			assert.Len(t, e.ledger(t), 1)
			var personalLogs int64
			require.NoError(t, e.db.Model(&Log{}).Where("user_id = ?", e.f.wallet.Id).Count(&personalLogs).Error)
			assert.Zero(t, personalLogs, "the wallet keeps a ledger, not a personal log")
		})

		t.Run("Creem never writes the payer email onto a wallet", func(t *testing.T) {
			clean()
			topUp := TopUp{UserId: e.f.wallet.Id, Amount: 5, Money: 5, TradeNo: "creem-1", PaymentMethod: PaymentMethodCreem,
				PaymentProvider: PaymentProviderCreem, Status: common.TopUpStatusPending, CreateTime: common.GetTimestamp()}
			require.NoError(t, e.db.Create(&topUp).Error)
			require.NoError(t, RechargeCreem("creem-1", "payer@example.com", "Payer", ""))
			var wallet User
			require.NoError(t, e.db.First(&wallet, e.f.wallet.Id).Error)
			assert.Empty(t, wallet.Email, "a wallet has no email, so nothing can reach it through recovery")
			assert.Len(t, e.ledger(t), 1)
		})

		t.Run("a source cannot be reused with another amount", func(t *testing.T) {
			clean()
			source := &orgCreditSource{ledgerType: types.OrgLedgerTopUp, refType: "topup", refID: "77", key: "topup:77"}
			credit := func(quota int) error {
				return e.db.Transaction(func(tx *gorm.DB) error { return creditWalletTx(tx, e.f.wallet.Id, quota, nil, source) })
			}
			require.NoError(t, credit(100))
			require.NoError(t, credit(100), "the same amount is a replay")
			assert.EqualValues(t, 1100, e.walletQuota(t))
			requireConflict(t, credit(250))
			assert.EqualValues(t, 1100, e.walletQuota(t))
			assert.Len(t, e.ledger(t), 1)
		})

		t.Run("organization money must say where it came from", func(t *testing.T) {
			clean()
			err := e.db.Transaction(func(tx *gorm.DB) error { return creditWalletTx(tx, e.f.wallet.Id, 100, nil, nil) })
			require.Error(t, err)
			assert.EqualValues(t, 1000, e.walletQuota(t))
		})

		t.Run("a failure after the credit rolls everything back", func(t *testing.T) {
			clean()
			source := &orgCreditSource{ledgerType: types.OrgLedgerTopUp, refType: "topup", refID: "88", key: "topup:88"}
			err := e.db.Transaction(func(tx *gorm.DB) error {
				if err := creditWalletTx(tx, e.f.wallet.Id, 100, nil, source); err != nil {
					return err
				}
				return gorm.ErrInvalidTransaction
			})
			require.Error(t, err)
			assert.EqualValues(t, 1000, e.walletQuota(t))
			assert.Empty(t, e.ledger(t))
			var jobs int64
			require.NoError(t, e.db.Model(&OrgBillingJob{}).Count(&jobs).Error)
			assert.Zero(t, jobs)
		})

		t.Run("a transfer conserves the total and a repeated key moves nothing", func(t *testing.T) {
			clean()
			require.NoError(t, e.db.Model(&User{}).Where("id = ?", e.f.member.Id).Update("quota", 500).Error)
			balance, err := TransferToOrganization(e.f.org.Id, e.f.member.Id, 200, "tr-1")
			require.NoError(t, err)
			assert.EqualValues(t, 1200, balance)
			assert.EqualValues(t, 1200, e.walletQuota(t))
			var member User
			require.NoError(t, e.db.First(&member, e.f.member.Id).Error)
			assert.EqualValues(t, 300, member.Quota)
			assert.EqualValues(t, 1500, int64(member.Quota)+e.walletQuota(t), "1000 + 500 before, the same after: the total never changes")

			again, err := TransferToOrganization(e.f.org.Id, e.f.member.Id, 200, "tr-1")
			require.NoError(t, err)
			assert.EqualValues(t, 1200, again)
			assert.EqualValues(t, 1200, e.walletQuota(t))
			_, err = TransferToOrganization(e.f.org.Id, e.f.member.Id, 201, "tr-1")
			requireConflict(t, err)
			rows := e.ledger(t)
			require.Len(t, rows, 1)
			assert.Equal(t, types.OrgLedgerTransferIn, rows[0].Type)
			assert.Equal(t, e.f.member.Id, rows[0].OperatorUserId)
		})

		t.Run("a transfer cannot overdraw the person", func(t *testing.T) {
			clean()
			require.NoError(t, e.db.Model(&User{}).Where("id = ?", e.f.member.Id).Update("quota", 50).Error)
			_, err := TransferToOrganization(e.f.org.Id, e.f.member.Id, 51, "tr-2")
			requireOrgRefusal(t, err, types.OrgErrQuotaExhausted)
			var member User
			require.NoError(t, e.db.First(&member, e.f.member.Id).Error)
			assert.EqualValues(t, 50, member.Quota)
			assert.EqualValues(t, 1000, e.walletQuota(t))
			assert.Empty(t, e.ledger(t))
			_, err = TransferToOrganization(e.f.org.Id, e.f.member.Id, 0, "tr-3")
			require.Error(t, err)
			_, err = TransferToOrganization(e.f.org.Id, e.f.member.Id, 5, "")
			require.Error(t, err)
		})

		t.Run("a platform adjustment needs a reason and cannot take leased money", func(t *testing.T) {
			clean()
			_, err := AdjustOrganizationWallet(e.f.org.Id, e.f.member.Id, 100, "", "adj-1")
			require.Error(t, err, "a reason is mandatory")
			balance, err := AdjustOrganizationWallet(e.f.org.Id, e.f.member.Id, 250, "goodwill credit", "adj-2")
			require.NoError(t, err)
			assert.EqualValues(t, 1250, balance)
			again, err := AdjustOrganizationWallet(e.f.org.Id, e.f.member.Id, 250, "goodwill credit", "adj-2")
			require.NoError(t, err)
			assert.EqualValues(t, 1250, again)
			assert.EqualValues(t, 1250, e.walletQuota(t))
			_, err = AdjustOrganizationWallet(e.f.org.Id, e.f.member.Id, 300, "different", "adj-2")
			requireConflict(t, err)

			_, err = e.reserve(t, e.f.memberKey, "adj-hold", 1000)
			require.NoError(t, err) // 1000 held, 250 left
			_, err = AdjustOrganizationWallet(e.f.org.Id, e.f.member.Id, -400, "correction", "adj-3")
			requireOrgRefusal(t, err, types.OrgErrQuotaInUse)
			balance, err = AdjustOrganizationWallet(e.f.org.Id, e.f.member.Id, -250, "correction", "adj-4")
			require.NoError(t, err)
			assert.EqualValues(t, 0, balance)
			assert.GreaterOrEqual(t, e.walletQuota(t), int64(0))
		})

		t.Run("many people transferring at once never deadlock and conserve the total", func(t *testing.T) {
			clean()
			const people, each = 12, 25
			ids := make([]int, 0, people)
			for i := range people {
				user := User{Username: "payer-" + strconv.Itoa(i) + "-" + strconv.FormatInt(common.GetTimestamp(), 36),
					Password: "x", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Quota: 1000,
					AffCode: "pa" + strconv.Itoa(i) + strconv.FormatInt(common.GetTimestamp(), 36)}
				require.NoError(t, e.db.Create(&user).Error)
				ids = append(ids, user.Id)
			}
			var wg sync.WaitGroup
			var failures atomic.Int64
			for round := range 4 {
				for _, id := range ids {
					wg.Go(func() {
						if _, err := TransferToOrganization(e.f.org.Id, id, each, "stress-"+strconv.Itoa(id)+"-"+strconv.Itoa(round)); err != nil {
							failures.Add(1)
						}
					})
				}
			}
			wg.Wait()
			assert.Zero(t, failures.Load(), "no transfer may fail on a lock cycle")
			assert.EqualValues(t, 1000+people*4*each, e.walletQuota(t))
			var remaining int64
			require.NoError(t, e.db.Model(&User{}).Where("id IN ?", ids).Select("SUM(quota)").Scan(&remaining).Error)
			assert.EqualValues(t, people*(1000-4*each), remaining)
			assert.Len(t, e.ledger(t), people*4)
		})

		t.Run("a personal wallet takes the old path and leaves no organization rows", func(t *testing.T) {
			clean()
			require.NoError(t, e.db.Model(&User{}).Where("id = ?", e.f.member.Id).Update("quota", 0).Error)
			e.pendingTopUp(t, e.f.member.Id, "trade-p", 2)
			_, err := RechargeEpay("trade-p", "", "")
			require.NoError(t, err)
			var member User
			require.NoError(t, e.db.First(&member, e.f.member.Id).Error)
			assert.EqualValues(t, int64(float64(common.QuotaPerUnit)*2), member.Quota)
			assert.Empty(t, e.ledger(t))
		})
	})
}
