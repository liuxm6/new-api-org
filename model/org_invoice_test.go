package model

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestOrgInvoiceRounding(t *testing.T) {
	cases := map[string]struct {
		usd  string
		want int64
	}{
		"exact cents":                        {"1.23", 123},
		"half rounds away from zero (0.005)": {"0.005", 1},
		"half rounds away from zero (1.115)": {"1.115", 112},
		"below half":                         {"0.004", 0},
		"negative half goes away from zero":  {"-0.005", -1},
		"large":                              {"123456.785", 12345679},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			value, err := decimal.NewFromString(tc.usd)
			require.NoError(t, err)
			assert.Equal(t, tc.want, usdToCents(value))
		})
	}
	t.Run("lines are summed exactly and rounded once", func(t *testing.T) {
		// Three lines of 0.004 round to 0 each (0 in total) but sum to 0.012 -> 1.
		sum := decimal.Zero
		for range 3 {
			sum = sum.Add(decimal.RequireFromString("0.004"))
		}
		assert.EqualValues(t, 1, usdToCents(sum))
	})
}

func (e *billingEnv) migrateInvoices(t *testing.T) {
	t.Helper()
	e.migrateCredit(t)
	require.NoError(t, e.db.AutoMigrate(&OrgInvoice{}, &OrgBillingProfile{}))
}

func (e *billingEnv) wipeInvoices(t *testing.T) {
	t.Helper()
	for _, m := range []any{&OrgInvoice{}, &OrgBillingProfile{}, &OrgBillingLedger{}, &OrgBillingJob{}, &OrgAuditLog{}, &OrgSpendRollup{}, &TopUp{}, &Redemption{}} {
		require.NoError(t, e.db.Unscoped().Where("1 = 1").Delete(m).Error)
	}
	require.NoError(t, e.db.Model(&Organization{}).Where("id = ?", e.f.org.Id).Update("invoice_sequence", 0).Error)
	e.reset(t, 1000)
}

func TestOrgReceipts(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		e.migrateInvoices(t)
		ctx := context.Background()

		t.Run("an order is receipted in the amount it was paid, once, with a numbered header", func(t *testing.T) {
			e.wipeInvoices(t)
			require.NoError(t, e.db.Create(&OrgBillingProfile{OrgId: e.f.org.Id, LegalName: "Acme Ltd", TaxId: "TX-1",
				BillingEmail: "ap@acme.test"}).Error)
			order := TopUp{UserId: e.f.wallet.Id, Amount: 3, Money: 21.505, TradeNo: "rcpt-1", PaymentMethod: "alipay",
				PaymentProvider: PaymentProviderEpay, Status: common.TopUpStatusPending, CreateTime: common.GetTimestamp()}
			require.NoError(t, e.db.Create(&order).Error)
			_, err := RechargeEpay("rcpt-1", "", "")
			require.NoError(t, err)

			key := "topup:" + strconv.Itoa(order.Id)
			first, err := IssueOrgReceipt(ctx, e.f.org.Id, key)
			require.NoError(t, err)
			require.NotNil(t, first)
			assert.Equal(t, fmt.Sprintf("INV-%d-1", e.f.org.Id), first.Number)
			assert.Equal(t, types.OrgInvoiceReceipt, first.Type)
			assert.EqualValues(t, 2151, first.AmountCents, "21.505 rounds half away from zero to 21.51")
			assert.Contains(t, first.ProfileSnapshot, "Acme Ltd")
			assert.Equal(t, order.Id, first.TopupId)

			// The header is frozen: changing it later does not change the receipt.
			require.NoError(t, e.db.Model(&OrgBillingProfile{}).Where("org_id = ?", e.f.org.Id).Update("legal_name", "Renamed").Error)
			again, err := IssueOrgReceipt(ctx, e.f.org.Id, key)
			require.NoError(t, err)
			assert.Equal(t, first.Id, again.Id, "a repeat returns the invoice that exists")
			assert.Contains(t, again.ProfileSnapshot, "Acme Ltd")
			var count int64
			require.NoError(t, e.db.Model(&OrgInvoice{}).Count(&count).Error)
			assert.EqualValues(t, 1, count)
		})

		t.Run("a redemption is receipted in USD and an adjustment gets no receipt", func(t *testing.T) {
			e.wipeInvoices(t)
			code := Redemption{Key: "RCPT-CODE", Name: "c", Quota: int(common.QuotaPerUnit) * 2, Status: common.RedemptionCodeStatusEnabled,
				CreatedTime: common.GetTimestamp(), UserId: e.f.member.Id}
			require.NoError(t, e.db.Create(&code).Error)
			_, err := RedeemToOrganization("RCPT-CODE", e.f.wallet.Id, e.f.member.Id)
			require.NoError(t, err)
			receipt, err := IssueOrgReceipt(ctx, e.f.org.Id, "redemption:"+strconv.Itoa(code.Id))
			require.NoError(t, err)
			assert.EqualValues(t, 200, receipt.AmountCents)
			assert.Equal(t, "USD", receipt.Currency)

			_, err = AdjustOrganizationWallet(e.f.org.Id, e.f.member.Id, 100, "goodwill", "rcpt-adj")
			require.NoError(t, err)
			_, err = IssueOrgReceipt(ctx, e.f.org.Id, "adjust:rcpt-adj")
			requireOrgRefusal(t, err, types.OrgErrNotFound)
			_, err = IssueOrgReceipt(ctx, e.f.org.Id, "topup:999999")
			requireOrgRefusal(t, err, types.OrgErrNotFound)
		})

		t.Run("numbers never repeat when workers race", func(t *testing.T) {
			e.wipeInvoices(t)
			const credits = 10
			for i := range credits {
				source := &orgCreditSource{ledgerType: types.OrgLedgerTopUp, refType: "redemption", refID: strconv.Itoa(i + 1),
					key: "redemption:" + strconv.Itoa(i+1)}
				require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error { return creditWalletTx(tx, e.f.wallet.Id, 100, nil, source) }))
			}
			var wg sync.WaitGroup
			var failed atomic.Int64
			for i := range credits {
				for range 2 { // two workers per credit
					wg.Go(func() {
						if _, err := IssueOrgReceipt(ctx, e.f.org.Id, "redemption:"+strconv.Itoa(i+1)); err != nil {
							failed.Add(1)
						}
					})
				}
			}
			wg.Wait()
			assert.Zero(t, failed.Load())
			var numbers []string
			require.NoError(t, e.db.Model(&OrgInvoice{}).Order("id").Pluck("number", &numbers).Error)
			assert.Len(t, numbers, credits, "one invoice per credit however many workers ran")
			seen := map[string]bool{}
			for _, number := range numbers {
				assert.False(t, seen[number], "duplicate number %s", number)
				seen[number] = true
			}
		})
	})
}

func (e *billingEnv) rollup(t *testing.T, period, key string, workspace int, effective string, spend int64) {
	t.Helper()
	require.NoError(t, e.db.Create(&OrgSpendRollup{OrgId: e.f.org.Id, Period: period, RollupKey: key, WorkspaceId: workspace,
		EffectivePeriod: effective, SpendQuota: spend, EventCount: 1}).Error)
}

func TestOrgStatements(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		e.migrateInvoices(t)
		ctx := context.Background()
		past := time.Now().UTC().AddDate(0, -2, 0).Format("2006-01")
		perUnit := strconv.FormatFloat(common.QuotaPerUnit, 'g', -1, 64)
		gpt := "gpt-x|expr:abc|USD|" + perUnit

		t.Run("an open month cannot be closed", func(t *testing.T) {
			e.wipeInvoices(t)
			current := time.Now().UTC().Format("2006-01")
			e.rollup(t, current, gpt, 1, current, 500)
			_, err := IssueOrgStatement(ctx, e.f.org.Id, current)
			require.ErrorIs(t, err, ErrOrgPeriodOpen)
			_, err = IssueOrgStatement(ctx, e.f.org.Id, "not-a-month")
			require.Error(t, err)
		})

		t.Run("lines are summed exactly, rounded once, and late adjustments are marked", func(t *testing.T) {
			e.wipeInvoices(t)
			earlier := time.Now().UTC().AddDate(0, -3, 0).Format("2006-01")
			unit := int64(common.QuotaPerUnit)
			// Three lines of $0.004 each: 0 cents apiece, 1 cent in total.
			for i := range 3 {
				e.rollup(t, past, "m"+strconv.Itoa(i)+"|expr:v|USD|"+perUnit, i+1, past, unit*4/1000)
			}
			e.rollup(t, past, gpt, 9, earlier, unit) // consumption of an earlier month folded late: $1
			statement, err := IssueOrgStatement(ctx, e.f.org.Id, past)
			require.NoError(t, err)
			require.NotNil(t, statement)
			assert.Equal(t, types.OrgInvoiceStatement, statement.Type)
			assert.EqualValues(t, 101, statement.AmountCents, "$1.012 -> 101 cents, rounded once")
			assert.Equal(t, "statement:"+past, statement.BusinessKey)
			assert.Contains(t, statement.LineSnapshot, `"late_adjustment":true`)
			assert.Contains(t, statement.LineSnapshot, `"effective_period":"`+earlier+`"`)
			var lines []map[string]any
			require.NoError(t, common.Unmarshal([]byte(statement.LineSnapshot), &lines))
			assert.Len(t, lines, 4)
		})

		t.Run("a second run returns the same statement and a month without rollups has none", func(t *testing.T) {
			e.wipeInvoices(t)
			none, err := IssueOrgStatement(ctx, e.f.org.Id, past)
			require.NoError(t, err)
			assert.Nil(t, none, "no consumption, no statement")
			e.rollup(t, past, gpt, 1, past, 12345)
			first, err := IssueOrgStatement(ctx, e.f.org.Id, past)
			require.NoError(t, err)
			again, err := IssueOrgStatement(ctx, e.f.org.Id, past)
			require.NoError(t, err)
			assert.Equal(t, first.Id, again.Id)
			exists, err := OrgStatementExists(ctx, e.f.org.Id, past)
			require.NoError(t, err)
			assert.True(t, exists)
			var count int64
			require.NoError(t, e.db.Model(&OrgInvoice{}).Count(&count).Error)
			assert.EqualValues(t, 1, count)
		})

		t.Run("racing workers issue one statement", func(t *testing.T) {
			e.wipeInvoices(t)
			e.rollup(t, past, gpt, 1, past, 777)
			var wg sync.WaitGroup
			var failed atomic.Int64
			for range 6 {
				wg.Go(func() {
					if _, err := IssueOrgStatement(ctx, e.f.org.Id, past); err != nil {
						failed.Add(1)
					}
				})
			}
			wg.Wait()
			assert.Zero(t, failed.Load())
			var count int64
			require.NoError(t, e.db.Model(&OrgInvoice{}).Count(&count).Error)
			assert.EqualValues(t, 1, count)
		})

		t.Run("voiding is one-way, audited, and changes no money", func(t *testing.T) {
			e.wipeInvoices(t)
			e.rollup(t, past, gpt, 1, past, 500)
			statement, err := IssueOrgStatement(ctx, e.f.org.Id, past)
			require.NoError(t, err)
			wallet := e.walletQuota(t)
			voided, err := VoidOrgInvoice(ctx, e.f.org.Id, statement.Id, e.f.member.Id)
			require.NoError(t, err)
			assert.Equal(t, types.OrgInvoiceStatusVoid, voided.Status)
			assert.Equal(t, wallet, e.walletQuota(t), "void does not refund")
			again, err := VoidOrgInvoice(ctx, e.f.org.Id, statement.Id, e.f.member.Id)
			require.NoError(t, err)
			assert.Equal(t, types.OrgInvoiceStatusVoid, again.Status)
			var audits int64
			require.NoError(t, e.db.Model(&OrgAuditLog{}).Where("action = ?", "invoice.void").Count(&audits).Error)
			assert.EqualValues(t, 1, audits, "a repeat is not audited twice")
			_, err = VoidOrgInvoice(ctx, e.f.org.Id+100, statement.Id, e.f.member.Id)
			requireOrgRefusal(t, err, types.OrgErrNotFound)
			// A void statement is not reissued: the business key is taken.
			reissued, err := IssueOrgStatement(ctx, e.f.org.Id, past)
			require.NoError(t, err)
			assert.Equal(t, statement.Id, reissued.Id)
			assert.Equal(t, types.OrgInvoiceStatusVoid, reissued.Status)
		})
	})
}

func TestOrgBillingJobs(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		e.migrateInvoices(t)
		ctx := context.Background()
		kinds := []string{types.OrgJobKindReceipt}

		t.Run("enqueueing the same work twice is one job", func(t *testing.T) {
			e.wipeInvoices(t)
			require.NoError(t, EnqueueOrgJob(ctx, e.f.org.Id, types.OrgJobKindReceipt, "topup:1", ""))
			require.NoError(t, EnqueueOrgJob(ctx, e.f.org.Id, types.OrgJobKindReceipt, "topup:1", ""))
			var count int64
			require.NoError(t, e.db.Model(&OrgBillingJob{}).Count(&count).Error)
			assert.EqualValues(t, 1, count)
		})

		t.Run("racing workers never share a job", func(t *testing.T) {
			e.wipeInvoices(t)
			for i := range 20 {
				require.NoError(t, EnqueueOrgJob(ctx, e.f.org.Id, types.OrgJobKindReceipt, "k"+strconv.Itoa(i), ""))
			}
			var claimed atomic.Int64
			seen := sync.Map{}
			var duplicate atomic.Int64
			var wg sync.WaitGroup
			for range 6 {
				wg.Go(func() {
					jobs, err := ClaimOrgJobs(ctx, kinds, 20)
					assert.NoError(t, err)
					for _, job := range jobs {
						claimed.Add(1)
						if _, loaded := seen.LoadOrStore(job.Id, true); loaded {
							duplicate.Add(1)
						}
					}
				})
			}
			wg.Wait()
			assert.EqualValues(t, 20, claimed.Load(), "every job is claimed exactly once")
			assert.Zero(t, duplicate.Load())
		})

		t.Run("a crashed worker's job is taken over after its lease, a live one's is not", func(t *testing.T) {
			e.wipeInvoices(t)
			require.NoError(t, EnqueueOrgJob(ctx, e.f.org.Id, types.OrgJobKindReceipt, "lease-1", ""))
			first, err := ClaimOrgJobs(ctx, kinds, 5)
			require.NoError(t, err)
			require.Len(t, first, 1)
			again, err := ClaimOrgJobs(ctx, kinds, 5)
			require.NoError(t, err)
			assert.Empty(t, again, "a running job under a live lease is not available")
			require.NoError(t, e.db.Model(&OrgBillingJob{}).Where("id = ?", first[0].Id).Update("lease_until", time.Now().Unix()-5).Error)
			taken, err := ClaimOrgJobs(ctx, kinds, 5)
			require.NoError(t, err)
			require.Len(t, taken, 1)
			assert.Equal(t, 2, taken[0].Attempts)
		})

		t.Run("failure backs off, then parks; success finishes", func(t *testing.T) {
			e.wipeInvoices(t)
			require.NoError(t, EnqueueOrgJob(ctx, e.f.org.Id, types.OrgJobKindReceipt, "fail-1", ""))
			jobs, _ := ClaimOrgJobs(ctx, kinds, 5)
			require.Len(t, jobs, 1)
			require.NoError(t, FailOrgJob(ctx, jobs[0], fmt.Errorf("smtp down")))
			var row OrgBillingJob
			require.NoError(t, e.db.First(&row, jobs[0].Id).Error)
			assert.Equal(t, types.OrgJobStatusPending, row.Status)
			assert.Greater(t, row.NextRunAt, time.Now().Unix())
			assert.Contains(t, row.LastError, "smtp down")
			none, _ := ClaimOrgJobs(ctx, kinds, 5)
			assert.Empty(t, none, "not due yet")

			exhausted := jobs[0]
			exhausted.Attempts = orgJobMaxAttempts
			require.NoError(t, FailOrgJob(ctx, exhausted, fmt.Errorf("still down")))
			require.NoError(t, e.db.First(&row, jobs[0].Id).Error)
			assert.Equal(t, types.OrgJobStatusFailed, row.Status)

			require.NoError(t, FinishOrgJob(ctx, jobs[0].Id))
			require.NoError(t, e.db.First(&row, jobs[0].Id).Error)
			assert.Equal(t, types.OrgJobStatusDone, row.Status)
		})
	})
}
