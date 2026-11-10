package model

import (
	"errors"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// ErrBillingAccount is returned when an interactive human flow (login, password
// recovery, check-in, affiliate transfer, subscription grant) targets an
// organization wallet. Wallets are hidden users rows that no person signs in as.
var ErrBillingAccount = errors.New("organization billing account cannot use this operation")

// IsBillingAccount reports whether the row is an organization wallet.
func (user *User) IsBillingAccount() bool {
	return user != nil && user.Kind == types.UserKindBilling
}

// isBillingAccountByID reads kind for one user. A missing row is not a billing
// account; callers that need existence check it themselves.
func isBillingAccountByID(tx *gorm.DB, userID int) (bool, error) {
	var kind int
	err := tx.Model(&User{}).Unscoped().Where("id = ?", userID).Select("kind").Limit(1).Scan(&kind).Error
	if err != nil {
		return false, err
	}
	return kind == types.UserKindBilling, nil
}

// CreateBillingAccountTx creates the hidden wallet of an organization inside the
// caller's transaction. It deliberately bypasses User.Insert and finishInsert:
// the wallet starts at zero quota, receives no sign-up or invitation bonus, has
// no email, and carries a random credential nobody knows, so no login path can
// reach it. The caller owns commit, rollback and any notification.
func CreateBillingAccountTx(tx *gorm.DB, group string) (*User, error) {
	if tx == nil {
		return nil, errors.New("transaction is required")
	}
	if group == "" {
		group = "default"
	}
	password, err := common.HashAccountPassword(common.GetRandomString(32))
	if err != nil {
		return nil, err
	}
	user := &User{
		Username: "org_" + common.GetRandomString(12),
		Password: password,
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
		Group:    group,
		AffCode:  common.GetRandomString(12),
		Quota:    0,
		Kind:     types.UserKindBilling,
	}
	user.DisplayName = user.Username
	if err := tx.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

// billingKindCache remembers whether a user id is an organization wallet. The
// kind never changes after creation, so a wallet stays cached; an ordinary user
// is rechecked after a short while only to bound the cache.
var billingKindCache sync.Map // user id -> billingKindEntry

type billingKindEntry struct {
	billing   bool
	checkedAt int64
}

const billingKindRecheckSeconds = 30

func resetBillingKindCache() {
	billingKindCache.Clear()
}

// rejectBillingAccountWrite is the second line of defence behind the service
// layer: the non-transactional wallet writers refuse an organization wallet, so
// no stray call can move organization money outside the lease and hold rules
// (design 4.2.4). It runs before anything is queued for the batch flusher.
func rejectBillingAccountWrite(userID int) error {
	if DB == nil {
		return nil // no database means no wallet to protect (early start-up, unit tests)
	}
	now := time.Now().Unix()
	if cached, ok := billingKindCache.Load(userID); ok {
		entry := cached.(billingKindEntry)
		if entry.billing {
			return ErrBillingAccount
		}
		if now-entry.checkedAt < billingKindRecheckSeconds {
			return nil
		}
	}
	billing, err := isBillingAccountByID(DB, userID)
	if err != nil {
		return err
	}
	billingKindCache.Store(userID, billingKindEntry{billing: billing, checkedAt: now})
	if billing {
		return ErrBillingAccount
	}
	return nil
}

// sealedOrgUsageWrite reports, and logs, an attempt to count usage on an
// organization wallet outside the fold worker. An organization's used_quota and
// request_count come only from FoldOrgSpend, so a stray legacy call is dropped
// rather than counted twice.
func sealedOrgUsageWrite(userID int) bool {
	// Only a confirmed wallet is dropped. A failed lookup lets the update through:
	// this is a counter, not the money path, and losing an ordinary user's usage
	// to a transient database error would be the worse outcome.
	if err := rejectBillingAccountWrite(userID); errors.Is(err, ErrBillingAccount) {
		common.SysError(common.LogText("dropped a legacy usage update for organization wallet %d", userID))
		return true
	}
	return false
}
