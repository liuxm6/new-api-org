package org

import (
	"context"

	"github.com/QuantumNous/new-api/model"

	"gorm.io/gorm"
)

type clientIPKey struct{}

// WithClientIP attaches the caller's address to ctx so audit rows written
// deep in a transaction record where the request came from. Controllers call
// it once per request.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// recordAudit writes an audit row in tx and stamps the client address.
func recordAudit(ctx context.Context, tx *gorm.DB, entry model.OrgAuditEntry) error {
	if ip, ok := ctx.Value(clientIPKey{}).(string); ok && entry.Ip == "" {
		entry.Ip = ip
	}
	if ref, ok := managementCredentialFrom(ctx); ok {
		// Always name the credential. A SCIM write keeps its own actor kind; an
		// action a person's management credential performs is "management_key".
		entry.CredentialRef = ref
		if entry.ActorKind == "" || entry.ActorKind == "user" {
			entry.ActorKind = "management_key"
		}
	}
	return model.RecordOrgAuditTx(tx, entry)
}
