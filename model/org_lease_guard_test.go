package model

import (
	"errors"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// The pre-check in pickOrgLease is only advisory. These tests call the
// conditional update directly, the way a request that lost a race would, and
// prove the update alone refuses a lease that is full, expired, outside its
// window or revoked.
func TestOrgLeaseConditionalUpdateIsTheAuthority(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		e.reset(t, 1000)
		now := time.Now().Unix()
		newLease := func(mutate func(*OrgQuotaLease)) OrgQuotaLease {
			lease := OrgQuotaLease{OrgId: e.f.org.Id, TargetType: types.OrgLeaseTargetWallet, TargetId: e.f.wallet.Id,
				InstanceId: "inst-a", Amount: 10, Status: types.OrgLeaseStatusActive, ExpiresAt: now + 600, CreatedAt: now}
			mutate(&lease)
			require.NoError(t, e.db.Create(&lease).Error)
			return lease
		}
		extend := func(lease OrgQuotaLease, amount int64) error {
			return e.db.Transaction(func(tx *gorm.DB) error {
				dbNow, err := orgDBNow(tx)
				require.NoError(t, err)
				return extendOrgLease(tx, leaseUse{id: lease.Id, key: "wallet", amount: amount}, dbNow)
			})
		}
		refused := func(err error) {
			var rejected *orgLeaseRejected
			require.True(t, errors.As(err, &rejected), "expected the lease to be refused, got %v", err)
		}

		t.Run("capacity", func(t *testing.T) {
			lease := newLease(func(l *OrgQuotaLease) { l.Allocated, l.Consumed = 4, 3 })
			require.NoError(t, extend(lease, 3), "3 of the remaining 3 fits")
			refused(extend(lease, 1))
			row := e.lease(t, lease.Id)
			assert.EqualValues(t, 7, row.Allocated)
			assert.LessOrEqual(t, row.Allocated+row.Consumed, row.Amount)
		})
		t.Run("expiry", func(t *testing.T) {
			lease := newLease(func(l *OrgQuotaLease) { l.ExpiresAt = now - 5 })
			refused(extend(lease, 1))
			assert.EqualValues(t, 0, e.lease(t, lease.Id).Allocated)
		})
		t.Run("window", func(t *testing.T) {
			lease := newLease(func(l *OrgQuotaLease) { l.WindowEnd = now - 1 })
			refused(extend(lease, 1))
			open := newLease(func(l *OrgQuotaLease) { l.WindowEnd = now + 600 })
			require.NoError(t, extend(open, 1))
		})
		t.Run("revoked and closed", func(t *testing.T) {
			for _, status := range []string{types.OrgLeaseStatusRevoked, types.OrgLeaseStatusClosed} {
				lease := newLease(func(l *OrgQuotaLease) { l.Status = status })
				refused(extend(lease, 1))
				assert.EqualValues(t, 0, e.lease(t, lease.Id).Allocated, status)
			}
		})
		t.Run("a missing lease", func(t *testing.T) {
			refused(extend(OrgQuotaLease{Id: 999999}, 1))
		})
	})
}

// Closing returns money, so it must only ever happen once and only for a
// revoked lease with nothing in flight.
func TestOrgLeaseCloseGuard(t *testing.T) {
	forEachBillingDialect(t, func(t *testing.T, e *billingEnv) {
		close := func(id int) bool {
			closed := false
			require.NoError(t, e.db.Transaction(func(tx *gorm.DB) error {
				var err error
				closed, err = closeOrgLeaseTx(tx, id)
				return err
			}))
			return closed
		}
		leaseWith := func(status string, allocated, consumed int64) OrgQuotaLease {
			lease := OrgQuotaLease{OrgId: e.f.org.Id, TargetType: types.OrgLeaseTargetWallet, TargetId: e.f.wallet.Id,
				InstanceId: "inst-a", Amount: 20, Allocated: allocated, Consumed: consumed, Status: status,
				ExpiresAt: time.Now().Unix() + 600, CreatedAt: time.Now().Unix()}
			require.NoError(t, e.db.Create(&lease).Error)
			return lease
		}

		e.reset(t, 100)
		active := leaseWith(types.OrgLeaseStatusActive, 0, 0)
		assert.False(t, close(active.Id), "an active lease is never closed")
		inFlight := leaseWith(types.OrgLeaseStatusRevoked, 5, 0)
		assert.False(t, close(inFlight.Id), "a lease with allocation is never closed")
		assert.EqualValues(t, 100, e.walletQuota(t), "refused closes return nothing")

		done := leaseWith(types.OrgLeaseStatusRevoked, 0, 8)
		assert.True(t, close(done.Id))
		assert.EqualValues(t, 112, e.walletQuota(t), "amount - consumed = 12 comes back")
		assert.False(t, close(done.Id), "closing twice cannot refund twice")
		assert.EqualValues(t, 112, e.walletQuota(t))
		assert.False(t, close(999999), "a missing lease is not an error")
	})
}
