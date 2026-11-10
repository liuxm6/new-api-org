package model

import (
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// CountOrgSeats returns the seats an organization uses: every active or
// suspended member, plus every pending, unexpired invitation whose address does
// not already belong to such a member (a workspace invitation to someone who
// is already in takes no seat). An invitation to excludeEmail is ignored, so
// the person being admitted is not counted twice.
//
// With lock = true the rows are read with FOR UPDATE. That makes the count see
// the latest committed rows even on MySQL REPEATABLE READ, which the seat check
// needs when it runs inside a transaction that may already hold a snapshot.
// The sets are bounded by the seat limit, so locking them is cheap.
func CountOrgSeats(db *gorm.DB, orgID int, excludeEmail string, lock bool) (int, error) {
	memberQuery := db.Model(&OrganizationMember{}).
		Where("org_id = ? AND status IN ?", orgID, []int{types.OrgMemberStatusActive, types.OrgMemberStatusSuspended})
	inviteQuery := db.Model(&Invite{}).
		Where("org_id = ? AND status = ? AND expires_at > ?", orgID, types.InviteStatusPending, common.GetTimestamp())
	if lock {
		memberQuery, inviteQuery = lockForUpdate(memberQuery), lockForUpdate(inviteQuery)
	}
	var userIDs []int
	if err := memberQuery.Pluck("user_id", &userIDs).Error; err != nil {
		return 0, err
	}
	var inviteEmails []string
	if err := inviteQuery.Pluck("email", &inviteEmails).Error; err != nil {
		return 0, err
	}
	memberEmails := map[string]bool{}
	if len(userIDs) > 0 && len(inviteEmails) > 0 {
		var emails []string
		if err := db.Model(&User{}).Where("id IN ?", userIDs).Pluck("email", &emails).Error; err != nil {
			return 0, err
		}
		for _, email := range emails {
			memberEmails[NormalizeEmail(email)] = true
		}
	}
	excludeEmail = NormalizeEmail(excludeEmail)
	seats := len(userIDs)
	for _, email := range inviteEmails {
		email = strings.ToLower(email)
		if email != excludeEmail && !memberEmails[email] {
			seats++
		}
	}
	return seats, nil
}

// OrgMemberByEmail finds an active or suspended member of the organization by
// email address, case-insensitively. A missing member is gorm.ErrRecordNotFound.
func OrgMemberByEmail(db *gorm.DB, orgID int, email string) (*OrganizationMember, error) {
	var userIDs []int
	if err := db.Model(&User{}).Where("email = ?", NormalizeEmail(email)).Pluck("id", &userIDs).Error; err != nil {
		return nil, err
	}
	if len(userIDs) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	var members []OrganizationMember
	if err := db.Where("org_id = ? AND user_id IN ? AND status IN ?", orgID, userIDs,
		[]int{types.OrgMemberStatusActive, types.OrgMemberStatusSuspended}).Limit(1).Find(&members).Error; err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &members[0], nil
}
