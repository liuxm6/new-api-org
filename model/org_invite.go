package model

import (
	"gorm.io/gorm"
)

// GetInviteByTokenHash finds an invitation by the SHA-256 of its token. The
// plaintext token is never stored or compared.
func GetInviteByTokenHash(db *gorm.DB, hash string) (*Invite, error) {
	var invites []Invite
	if err := db.Where("token_hash = ?", hash).Limit(1).Find(&invites).Error; err != nil {
		return nil, err
	}
	if len(invites) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &invites[0], nil
}

// LockInviteByTokenHashTx re-reads an invitation under a row lock.
func LockInviteByTokenHashTx(tx *gorm.DB, hash string) (*Invite, error) {
	var invites []Invite
	if err := lockForUpdate(tx).Where("token_hash = ?", hash).Limit(1).Find(&invites).Error; err != nil {
		return nil, err
	}
	if len(invites) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &invites[0], nil
}
