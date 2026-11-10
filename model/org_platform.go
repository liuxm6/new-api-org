package model

import (
	"context"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// OrgAdminRow is one organization in the platform list.
type OrgAdminRow struct {
	Id            int    `json:"id"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	Status        int    `json:"status"`
	SeatLimit     int    `json:"seat_limit"`
	BillingGroup  string `json:"billing_group"`
	BillingUserId int    `json:"billing_user_id"`
	Quota         int64  `json:"quota"`
	CreatedAt     int64  `json:"created_at"`
}

// SearchOrganizations pages organizations for platform staff, by slug or name.
func SearchOrganizations(ctx context.Context, keyword string, offset, limit int) ([]OrgAdminRow, int64, error) {
	query := DB.WithContext(ctx).Table("organizations o").Where("o.deleted_at IS NULL")
	if keyword != "" {
		like := "%" + keyword + "%"
		query = query.Where("o.slug LIKE ? OR o.name LIKE ?", like, like)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []OrgAdminRow
	err := query.Select("o.id, o.slug, o.name, o.status, o.seat_limit, o.billing_group, o.billing_user_id, o.created_at, u.quota").
		Joins("LEFT JOIN users u ON u.id = o.billing_user_id").Order("o.id DESC").Offset(offset).Limit(limit).Scan(&rows).Error
	return rows, total, err
}

// PlatformOrgSettings is what staff may change besides the status: both need a
// reason, and neither is a tenant setting.
type PlatformOrgSettings struct {
	BillingGroup *string
	SeatLimit    *int
}

// UpdateOrgPlatformSettings changes the billing group or the seat limit. The
// seat limit cannot drop below the seats already taken.
func UpdateOrgPlatformSettings(ctx context.Context, orgID, operatorID int, settings PlatformOrgSettings, reason string) error {
	if reason == "" || len(reason) > 500 || (settings.BillingGroup == nil && settings.SeatLimit == nil) {
		return orgInvalidError()
	}
	return retryOrgTx(ctx, func(tx *gorm.DB) error {
		org, err := orgFindOne[Organization](lockForUpdate(tx.Where("id = ?", orgID)))
		if err != nil {
			return err
		}
		if org == nil {
			return orgNotFoundError()
		}
		updates := map[string]any{"updated_at": common.GetTimestamp()}
		detail := map[string]any{"reason": reason}
		if settings.BillingGroup != nil {
			group := *settings.BillingGroup
			if group == "" || len(group) > 64 {
				return orgInvalidError()
			}
			updates["billing_group"], detail["billing_group"] = group, group
			// The wallet's group is the organization's billing group, never a person's.
			if err := tx.Unscoped().Model(&User{}).Where("id = ?", org.BillingUserId).Update(commonGroupCol, group).Error; err != nil {
				return err
			}
		}
		if settings.SeatLimit != nil {
			limit := *settings.SeatLimit
			var taken int64
			if err := tx.Model(&OrganizationMember{}).Where("org_id = ? AND status <> ?", orgID, types.OrgMemberStatusRemoved).
				Count(&taken).Error; err != nil {
				return err
			}
			if limit < 1 || limit > 100000 || int64(limit) < taken {
				return orgInvalidError()
			}
			updates["seat_limit"], detail["seat_limit"] = limit, limit
		}
		if err := tx.Model(&Organization{}).Where("id = ?", orgID).Updates(updates).Error; err != nil {
			return err
		}
		if err := BumpOrgPolicyVersionTx(tx, orgID); err != nil {
			return err
		}
		return RecordOrgAuditTx(tx, OrgAuditEntry{OrgId: orgID, ActorUserId: operatorID, ActorKind: "platform",
			Action: "platform.settings", TargetType: "organization", TargetId: org.Slug, Detail: detail})
	})
}

// ListOrgBillingOperations pages operations of an organization in one state.
func ListOrgBillingOperations(ctx context.Context, orgID int, state string, offset, limit int) ([]OrgBillingOperation, int64, error) {
	query := DB.WithContext(ctx).Model(&OrgBillingOperation{}).Where("org_id = ?", orgID)
	if state != "" {
		query = query.Where("state = ?", state)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []OrgBillingOperation
	err := query.Order("id DESC").Offset(offset).Limit(limit).Find(&rows).Error
	return rows, total, err
}

// OrgSettledByPlatform marks an operation that staff resolved from evidence.
const OrgSettledByPlatform = "platform"

// OrgOperationResolution is staff's decision on a parked operation.
type OrgOperationResolution struct {
	OperationID      string
	ExpectedRevision int64
	Action           string // "cancel" or "settle"
	TargetQuota      int64
	EvidenceRef      string
	Reason           string
	OperatorID       int
}

// ResolveOrgOperation settles or cancels an operation that is waiting for a
// platform decision (design 4.2.6). It goes through the same hold and event
// rules as any settlement: nothing edits a balance directly. The expected
// revision fences a stale decision, and repeating a decision that was already
// applied returns it unchanged. A settle is capped at the bound like any other.
func ResolveOrgOperation(ctx context.Context, orgID int, in OrgOperationResolution) (types.OrgBillingResult, error) {
	if in.OperationID == "" || in.Reason == "" || len(in.Reason) > 500 || len(in.EvidenceRef) > 191 || in.OperatorID <= 0 ||
		(in.Action != "cancel" && in.Action != "settle") || in.TargetQuota < 0 || in.ExpectedRevision < 0 {
		return types.OrgBillingResult{}, orgInvalidError()
	}
	var result types.OrgBillingResult
	err := retryOrgTx(ctx, func(tx *gorm.DB) error {
		op, err := orgFindOne[OrgBillingOperation](lockForUpdate(tx.Where("operation_id = ? AND org_id = ?", in.OperationID, orgID)))
		if err != nil {
			return err
		}
		if op == nil {
			return orgNotFoundError()
		}
		holds, err := decodeOrgHolds(op.Holds)
		if err != nil {
			return err
		}
		charge := min(in.TargetQuota, op.Bound)
		if op.State != types.OrgOpStateRecoveryRequired {
			applied := op.SettledBy == OrgSettledByPlatform &&
				((in.Action == "cancel" && op.State == types.OrgOpStateCanceled) ||
					(in.Action == "settle" && op.State == types.OrgOpStateClosed && op.CapturedQuota == charge))
			if !applied {
				return orgConflictError()
			}
			result = orgResult(op, holds, true, 0)
			return nil
		}
		if in.ExpectedRevision != op.Revision {
			return orgConflictError()
		}
		now, err := orgDBNow(tx)
		if err != nil {
			return err
		}
		update := map[string]any{"settled_by": OrgSettledByPlatform, "lease_owner": "", "lease_until": 0, "updated_at": now}
		applied := int64(0)
		if in.Action == "cancel" {
			if err := settleOrgHoldsTx(tx, holds, 0); err != nil {
				return err
			}
			op.State = types.OrgOpStateCanceled
		} else {
			if err := settleOrgHoldsTx(tx, holds, charge); err != nil {
				return err
			}
			if _, err := recordOrgSpendTx(tx, op, orgSpendInput{kind: types.OrgSpendEventCapture, revision: op.Revision + 1,
				delta: charge, writeoff: 0, holds: holds}, now); err != nil {
				return err
			}
			op.State, op.Revision, op.CapturedQuota, applied = types.OrgOpStateClosed, op.Revision+1, charge, charge
			update["revision"], update["captured_quota"] = op.Revision, charge
		}
		encoded, err := encodeOrgHolds(holds)
		if err != nil {
			return err
		}
		update["state"], update["holds"] = op.State, encoded
		if err := tx.Model(&OrgBillingOperation{}).Where("id = ?", op.Id).Updates(update).Error; err != nil {
			return err
		}
		op.Holds, op.SettledBy = encoded, OrgSettledByPlatform
		if err := RecordOrgAuditTx(tx, OrgAuditEntry{OrgId: orgID, ActorUserId: in.OperatorID, ActorKind: "platform",
			Action: "platform.resolve_operation", TargetType: "operation", TargetId: op.OperationId,
			Detail: map[string]any{"action": in.Action, "charge": charge, "evidence_ref": in.EvidenceRef, "reason": in.Reason}}); err != nil {
			return err
		}
		result = orgResult(op, holds, false, applied)
		return nil
	})
	return result, err
}
