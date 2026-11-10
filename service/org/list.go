package org

import (
	"context"

	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
)

// OrganizationSummary is one row of "my organizations".
type OrganizationSummary struct {
	Id           int    `json:"id"`
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	Status       int    `json:"status"`
	Role         string `json:"role"`
	MemberStatus int    `json:"member_status"`
	SeatLimit    int    `json:"seat_limit"`
	SeatsUsed    int    `json:"seats_used"`
}

// ListOrganizations returns the organizations a person belongs to, including
// suspended memberships (so they can see why they are locked out) but not
// removed ones.
func ListOrganizations(ctx context.Context, userID int) ([]OrganizationSummary, error) {
	db := model.DB.WithContext(ctx)
	var members []model.OrganizationMember
	if err := db.Where("user_id = ? AND status <> ?", userID, types.OrgMemberStatusRemoved).
		Order("org_id").Find(&members).Error; err != nil {
		return nil, err
	}
	result := make([]OrganizationSummary, 0, len(members))
	for _, member := range members {
		var org model.Organization
		found := db.Where("id = ?", member.OrgId).Limit(1).Find(&org)
		if found.Error != nil {
			return nil, found.Error
		}
		if found.RowsAffected == 0 {
			continue
		}
		used, err := SeatsInUse(db, org.Id)
		if err != nil {
			return nil, err
		}
		result = append(result, OrganizationSummary{Id: org.Id, Slug: org.Slug, Name: org.Name, Status: org.Status,
			Role: member.Role, MemberStatus: member.Status, SeatLimit: org.SeatLimit, SeatsUsed: used})
	}
	return result, nil
}
