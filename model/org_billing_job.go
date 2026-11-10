package model

import (
	"context"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// OrgJobLeaseSeconds is how long a worker owns a job before another may take
	// it over, so a crashed worker delays a job but never loses it.
	OrgJobLeaseSeconds = 120
	orgJobMaxAttempts  = 8
)

// EnqueueOrgJob adds a durable job. The (org, kind, business key) triple is
// unique, so enqueueing the same work twice is a no-op.
func EnqueueOrgJob(ctx context.Context, orgID int, kind, businessKey, payload string) error {
	now := common.GetTimestamp()
	job := OrgBillingJob{OrgId: orgID, Kind: kind, BusinessKey: businessKey, Payload: payload,
		Status: types.OrgJobStatusPending, NextRunAt: now, CreatedAt: now, UpdatedAt: now}
	return DB.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&job).Error
}

// ClaimOrgJobs takes up to limit due jobs of the given kinds. A job is due when
// it is pending and its time has come, or it is running under a lease that has
// run out. Each claim is a conditional update that records the new lease, so
// two workers can never hold the same job.
func ClaimOrgJobs(ctx context.Context, kinds []string, limit int) ([]OrgBillingJob, error) {
	db := DB.WithContext(ctx)
	now, err := orgDBNow(db)
	if err != nil {
		return nil, err
	}
	var candidates []OrgBillingJob
	err = db.Where("kind IN ? AND ((status = ? AND next_run_at <= ?) OR (status = ? AND lease_until < ?))",
		kinds, types.OrgJobStatusPending, now, types.OrgJobStatusRunning, now).Order("id ASC").Limit(limit).Find(&candidates).Error
	if err != nil {
		return nil, err
	}
	var claimed []OrgBillingJob
	for _, job := range candidates {
		result := db.Model(&OrgBillingJob{}).
			Where("id = ? AND ((status = ? AND next_run_at <= ?) OR (status = ? AND lease_until < ?))",
				job.Id, types.OrgJobStatusPending, now, types.OrgJobStatusRunning, now).
			Updates(map[string]any{"status": types.OrgJobStatusRunning, "lease_until": now + OrgJobLeaseSeconds,
				"attempts": gorm.Expr("attempts + 1"), "updated_at": now})
		if result.Error != nil {
			return claimed, result.Error
		}
		if result.RowsAffected == 1 {
			job.Attempts++
			claimed = append(claimed, job)
		}
	}
	return claimed, nil
}

// FinishOrgJob marks a claimed job done.
func FinishOrgJob(ctx context.Context, id int) error {
	return DB.WithContext(ctx).Model(&OrgBillingJob{}).Where("id = ?", id).
		Updates(map[string]any{"status": types.OrgJobStatusDone, "lease_until": 0, "last_error": "",
			"updated_at": common.GetTimestamp()}).Error
}

// FailOrgJob puts a job back for a later retry with exponential backoff, or
// parks it as failed once it has used its attempts. The money that triggered it
// is already committed: a failed job never undoes a credit.
func FailOrgJob(ctx context.Context, job OrgBillingJob, cause error) error {
	status, next := types.OrgJobStatusPending, time.Now().Unix()+int64(30<<min(job.Attempts, 10))
	if job.Attempts >= orgJobMaxAttempts {
		status = types.OrgJobStatusFailed
	}
	message := cause.Error()
	if len(message) > 500 {
		message = message[:500]
	}
	return DB.WithContext(ctx).Model(&OrgBillingJob{}).Where("id = ?", job.Id).
		Updates(map[string]any{"status": status, "next_run_at": next, "lease_until": 0, "last_error": message,
			"updated_at": common.GetTimestamp()}).Error
}
