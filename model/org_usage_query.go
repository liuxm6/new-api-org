package model

import (
	"context"
	"regexp"
	"strings"

	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
)

// OrgUsageScope is the one boundary shared by the organization usage list, its
// statistics and its export. Rows carry the organization, workspace and actor
// that were stamped when they were written, so deleting a key later changes
// nothing about who a row belongs to. OrgID is required; a zero WorkspaceID or
// ActorUserID means "not narrowed", so a caller that must be narrowed to one
// person passes the person.
type OrgUsageScope struct {
	OrgID       int
	WorkspaceID int
	ActorUserID int
}

func (s OrgUsageScope) apply(tx *gorm.DB, table string) *gorm.DB {
	if s.OrgID <= 0 {
		return tx.Where("1 = 0")
	}
	prefix := ""
	if table != "" {
		prefix = table + "."
	}
	tx = tx.Where(prefix+"org_id = ?", s.OrgID)
	if s.WorkspaceID > 0 {
		tx = tx.Where(prefix+"workspace_id = ?", s.WorkspaceID)
	}
	if s.ActorUserID > 0 {
		tx = tx.Where(prefix+"actor_user_id = ?", s.ActorUserID)
	}
	return tx
}

// GetOrgLogs pages the usage logs inside a scope. Logs are operational records,
// not the billing source; the organization's financial figures come from the
// spend facts. The rows are shaped like the personal log list a member sees.
func GetOrgLogs(scope OrgUsageScope, filter LogFilter, startIdx, num int) (logs []*Log, total int64, err error) {
	tx, err := filter.apply(scope.apply(LOG_DB, "logs"))
	if err != nil {
		return nil, 0, err
	}
	if err = tx.Model(&Log{}).Limit(logSearchCountLimit).Count(&total).Error; err != nil {
		common.SysError(common.LogText("failed to count organization logs: %s", err.Error()))
		return nil, 0, common.NewMessage("Failed to query logs")
	}
	order := "logs.id desc"
	if common.UsingLogDatabase(common.DatabaseTypeClickHouse) {
		order = clickHouseLogOrder("logs.")
	}
	if err = tx.Order(order).Limit(num).Offset(startIdx).Find(&logs).Error; err != nil {
		common.SysError(common.LogText("failed to search organization logs: %s", err.Error()))
		return nil, 0, common.NewMessage("Failed to query logs")
	}
	formatUserLogs(logs, startIdx)
	return logs, total, nil
}

// StreamOrgLogs calls fn with each log inside the scope, newest first, shaped
// like GetOrgLogs. Rows are read one at a time.
func StreamOrgLogs(ctx context.Context, scope OrgUsageScope, filter LogFilter, fn func(*Log) error) error {
	tx, err := filter.apply(scope.apply(LOG_DB.WithContext(ctx), "logs"))
	if err != nil {
		return err
	}
	count := 0
	return streamLogs(tx, "logs.id desc", func(log *Log) error {
		count++
		log.Id = count
		log.ChannelName = ""
		log.Other = formatLogOtherJSON(log.Other, logOtherVisibilityUser)
		return fn(log)
	})
}

// OrgUsageRow is one display bucket of the quota_data aggregation.
type OrgUsageRow struct {
	WorkspaceID int    `json:"workspace_id"`
	ActorUserID int    `json:"actor_user_id"`
	ModelName   string `json:"model_name"`
	CreatedAt   int64  `json:"created_at"`
	Count       int    `json:"count"`
	Quota       int    `json:"quota"`
	TokenUsed   int    `json:"token_used"`
}

// GetOrgUsage aggregates quota_data inside a scope, per workspace, actor, model
// and hour. quota_data is a display aggregation: it can be switched off or
// cleaned, so it never stands in for the organization's financial record.
func GetOrgUsage(scope OrgUsageScope, startTime, endTime int64) ([]OrgUsageRow, error) {
	rows := make([]OrgUsageRow, 0)
	tx := scope.apply(DB.Table("quota_data"), "")
	err := tx.Select("workspace_id, actor_user_id, model_name, created_at, sum(count) as count, sum(quota) as quota, sum(token_used) as token_used").
		Where("created_at >= ? AND created_at <= ?", startTime, endTime).
		Group("workspace_id, actor_user_id, model_name, created_at").
		Order("created_at asc").Find(&rows).Error
	return rows, err
}

// OrgAuditFilter narrows an audit query.
type OrgAuditFilter struct {
	Action         string
	StartTimestamp int64
	EndTimestamp   int64
}

func (f OrgAuditFilter) apply(tx *gorm.DB) *gorm.DB {
	if f.Action != "" {
		tx = tx.Where("action = ?", f.Action)
	}
	if f.StartTimestamp != 0 {
		tx = tx.Where("created_at >= ?", f.StartTimestamp)
	}
	if f.EndTimestamp != 0 {
		tx = tx.Where("created_at <= ?", f.EndTimestamp)
	}
	return tx
}

// ListOrgAuditLogs pages the audit trail inside a scope, newest first. The
// credential reference is dropped and the detail redacted, so no output of this
// package can carry a usable secret.
func ListOrgAuditLogs(scope OrgUsageScope, filter OrgAuditFilter, startIdx, num int) ([]OrgAuditLog, int64, error) {
	tx := filter.apply(scope.apply(DB.Model(&OrgAuditLog{}), ""))
	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []OrgAuditLog
	if err := tx.Order("id desc").Limit(num).Offset(startIdx).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	for i := range rows {
		rows[i] = rows[i].Redacted()
	}
	return rows, total, nil
}

// StreamOrgAuditLogs calls fn with each audit row inside the scope, newest
// first, redacted like ListOrgAuditLogs. Rows are read in id-ordered batches.
func StreamOrgAuditLogs(ctx context.Context, scope OrgUsageScope, filter OrgAuditFilter, fn func(OrgAuditLog) error) error {
	batch := orgAuditStreamBatch
	var before int
	for {
		tx := filter.apply(scope.apply(DB.WithContext(ctx).Model(&OrgAuditLog{}), ""))
		if before > 0 {
			tx = tx.Where("id < ?", before)
		}
		var rows []OrgAuditLog
		if err := tx.Order("id desc").Limit(batch).Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			if err := fn(row.Redacted()); err != nil {
				return err
			}
			before = row.Id
		}
		if len(rows) < batch {
			return nil
		}
	}
}

// orgAuditStreamBatch is how many audit rows an export reads per query.
var orgAuditStreamBatch = 500

var (
	// auditSecretKey matches detail keys that name a credential.
	auditSecretKey = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|authorization|credential|cookie|signature|otp|code)`)
	// auditSecretValue matches values shaped like a gateway key or bearer token.
	auditSecretValue = regexp.MustCompile(`(?i)(\bsk-[A-Za-z0-9_-]{8,}|\bBearer\s+\S+)`)
)

const auditRedacted = "[redacted]"

// Redacted returns the row as it may leave the system: no credential reference,
// and a detail with credential-like keys and values masked. The recorder never
// writes secrets; this is the second line of defense for rows written by older
// or future code.
func (l OrgAuditLog) Redacted() OrgAuditLog {
	l.CredentialRef = ""
	l.Detail = redactAuditDetail(l.Detail)
	return l
}

func redactAuditDetail(detail string) string {
	if detail == "" {
		return ""
	}
	var value any
	if err := common.UnmarshalJsonStr(detail, &value); err != nil {
		return auditRedacted
	}
	encoded, err := common.Marshal(redactAuditValue(value))
	if err != nil {
		return auditRedacted
	}
	return string(encoded)
}

func redactAuditValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			if auditSecretKey.MatchString(key) {
				out[key] = auditRedacted
				continue
			}
			out[key] = redactAuditValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = redactAuditValue(item)
		}
		return out
	case string:
		if auditSecretValue.MatchString(typed) {
			return auditRedacted
		}
		return typed
	}
	return value
}

// CSVSafe neutralizes a cell that a spreadsheet would read as a formula. Audit
// text includes member-chosen names, so an export must not turn one into a
// command.
func CSVSafe(cell string) string {
	if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
		return "'" + cell
	}
	return cell
}
