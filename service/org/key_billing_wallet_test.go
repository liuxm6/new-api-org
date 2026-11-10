package org

import (
	"context"
	"testing"

	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestOrgKeyBillingIsBoundedByTheWallet(t *testing.T) {
	eachDialect(t, func(t *testing.T, db *gorm.DB) {
		ctx := context.Background()
		f := newBillingWorkerFixture(t, db, 5_000)
		setWallet := func(quota int) {
			require.NoError(t, db.Model(&model.User{}).Where("id = ?", f.wallet).Update("quota", quota).Error)
		}

		t.Run("an unlimited key sees the organization balance", func(t *testing.T) {
			view, err := KeyBillingFor(ctx, f.subject)
			require.NoError(t, err)
			assert.EqualValues(t, 5_000, view.Remaining)
		})
		t.Run("an empty or negative wallet shows zero", func(t *testing.T) {
			setWallet(0)
			view, err := KeyBillingFor(ctx, f.subject)
			require.NoError(t, err)
			assert.EqualValues(t, 0, view.Remaining)
			setWallet(-50)
			view, err = KeyBillingFor(ctx, f.subject)
			require.NoError(t, err)
			assert.EqualValues(t, 0, view.Remaining)
		})
		t.Run("a smaller key remainder wins over a larger balance", func(t *testing.T) {
			setWallet(5_000)
			require.NoError(t, db.Model(&model.Token{}).Where("id = ?", f.subject.TokenID).
				Updates(map[string]any{"unlimited_quota": false, "remain_quota": 300}).Error)
			view, err := KeyBillingFor(ctx, f.subject)
			require.NoError(t, err)
			assert.EqualValues(t, 300, view.Remaining)
			setWallet(120)
			view, err = KeyBillingFor(ctx, f.subject)
			require.NoError(t, err)
			assert.EqualValues(t, 120, view.Remaining, "the balance is the smallest")
		})
	})
}
