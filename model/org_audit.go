package model

import (
	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
)

// OrgAuditEntry describes one audit event. Detail is marshaled to JSON by the
// recorder and must never hold passwords, verification codes, plaintext keys,
// invite tokens or any other usable credential.
type OrgAuditEntry struct {
	OrgId         int
	WorkspaceId   int
	ActorUserId   int
	ActorKind     string
	CredentialRef string
	Action        string
	TargetType    string
	TargetId      string
	Detail        map[string]any
	Ip            string
}

// RecordOrgAuditTx writes an audit row in the caller's transaction, so a change
// and its audit trail commit or roll back together.
func RecordOrgAuditTx(tx *gorm.DB, entry OrgAuditEntry) error {
	detail := ""
	if len(entry.Detail) > 0 {
		data, err := common.Marshal(entry.Detail)
		if err != nil {
			return err
		}
		detail = string(data)
	}
	if entry.ActorKind == "" {
		entry.ActorKind = "user"
	}
	return tx.Create(&OrgAuditLog{
		OrgId: entry.OrgId, WorkspaceId: entry.WorkspaceId, ActorUserId: entry.ActorUserId,
		ActorKind: entry.ActorKind, CredentialRef: entry.CredentialRef, Action: entry.Action,
		TargetType: entry.TargetType, TargetId: entry.TargetId, Detail: detail, Ip: entry.Ip,
		CreatedAt: common.GetTimestamp(),
	}).Error
}
