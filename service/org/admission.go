package org

import (
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// AdmitInput describes one person joining one organization. Every way in
// (invitation, SSO just-in-time provisioning, SCIM, manual) goes through
// AdmitMemberTx, so seat counting, owner protection and the rules for
// returning members exist once.
type AdmitInput struct {
	OrgID   int
	UserID  int
	OrgRole string
	// Source is one of the types.OrgMemberSource* values.
	Source    string
	InvitedBy int
}

// AdmitResult reports the resulting membership. Joined is true when the person
// took a seat (a new member or a reactivated one) and false when they were
// already an active member and nothing changed.
type AdmitResult struct {
	Org    *model.Organization
	Member model.OrganizationMember
	Joined bool
}

// SeatsInUse reports the seats an organization currently uses, for display.
// Admission does its own locking count.
func SeatsInUse(db *gorm.DB, orgID int) (int, error) {
	return model.CountOrgSeats(db, orgID, "", false)
}

// AdmitMemberTx adds a person to an organization inside the caller's
// transaction. It locks the organization row first, so concurrent admissions
// are counted one at a time and the seat limit cannot be exceeded by a race.
// Rules:
//
//   - the organization must be active and the person an enabled human account;
//   - the owner role can never be granted this way;
//   - an active member is left as is and takes no seat (a workspace invitation
//     to an existing member relies on this);
//   - a suspended member is never revived by joining;
//   - a member removed by SCIM is restored only by SCIM, and a domain match is
//     never authority to restore anyone;
//   - everyone else takes a seat, and the seat count includes pending
//     invitations, so invitations cannot be oversold.
//
// Reactivation never restores keys disabled when the person left.
func AdmitMemberTx(tx *gorm.DB, in AdmitInput) (*AdmitResult, error) {
	if !validOrgRole(in.OrgRole) {
		return nil, refuse(types.OrgErrInvalidInput)
	}
	if in.OrgRole == types.OrgRoleOwner {
		return nil, refuse(types.OrgErrOwnerRole)
	}
	org, err := model.LockOrganizationTx(tx, in.OrgID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, refuse(types.OrgErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	if org.Status != types.OrgStatusActive {
		return nil, refuse(types.OrgErrSuspended)
	}
	var user model.User
	if err := tx.Select("id", "email", "status", "kind").Where("id = ?", in.UserID).Take(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, refuse(types.OrgErrForbidden)
		}
		return nil, err
	}
	if user.Status != common.UserStatusEnabled || user.IsBillingAccount() {
		return nil, refuse(types.OrgErrForbidden)
	}

	existing, err := model.LockOrganizationMemberTx(tx, in.OrgID, in.UserID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	found := err == nil
	if found {
		switch {
		case existing.Status == types.OrgMemberStatusActive:
			return &AdmitResult{Org: org, Member: *existing}, nil
		case existing.Status == types.OrgMemberStatusSuspended:
			return nil, refuse(types.OrgErrMemberSuspended)
		case in.Source == types.OrgMemberSourceDomain, in.Source == types.OrgMemberSourceSSO,
			existing.Source == types.OrgMemberSourceSCIM && in.Source != types.OrgMemberSourceSCIM:
			return nil, refuse(types.OrgErrMemberSuspended)
		}
	}

	seats, err := model.CountOrgSeats(tx, in.OrgID, user.Email, true)
	if err != nil {
		return nil, err
	}
	if seats >= org.SeatLimit {
		return nil, refuse(types.OrgErrSeatLimitReached)
	}

	now := common.GetTimestamp()
	member := model.OrganizationMember{OrgId: in.OrgID, UserId: in.UserID, Role: in.OrgRole,
		Status: types.OrgMemberStatusActive, Source: in.Source, InvitedBy: in.InvitedBy, JoinedAt: now,
		CreatedAt: now, UpdatedAt: now}
	if found {
		member.Id, member.CreatedAt = existing.Id, existing.CreatedAt
		err = tx.Model(&model.OrganizationMember{}).Where("id = ?", existing.Id).Updates(map[string]any{
			"role": in.OrgRole, "status": types.OrgMemberStatusActive, "source": in.Source,
			"invited_by": in.InvitedBy, "joined_at": now, "updated_at": now}).Error
	} else {
		err = tx.Create(&member).Error
	}
	if err != nil {
		return nil, err
	}
	if err := model.BumpOrgPolicyVersionTx(tx, in.OrgID); err != nil {
		return nil, err
	}
	err = model.RecordOrgAuditTx(tx, model.OrgAuditEntry{OrgId: in.OrgID, ActorUserId: in.InvitedBy, Action: "member.join",
		TargetType: "member", TargetId: itoa(in.UserID), Detail: map[string]any{"role": in.OrgRole, "source": in.Source, "reactivated": found}})
	if err != nil {
		return nil, err
	}
	return &AdmitResult{Org: org, Member: member, Joined: true}, nil
}
