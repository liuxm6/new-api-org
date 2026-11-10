package org

import (
	"context"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

const (
	keyNameMaxRunes = 50

	// KeyOwnerMe makes a member key owned by the caller; KeyOwnerWorkspace makes
	// a system key owned by the workspace.
	KeyOwnerMe        = "me"
	KeyOwnerWorkspace = "workspace"
)

// WorkspaceKeyLimit caps the live keys of one workspace. It replaces the
// personal per-user limit, which would count the whole organization's keys
// against the wallet. A package variable so a platform setting can drive it.
var WorkspaceKeyLimit = 1000

// KeyView is what the API shows of an organization key. The plaintext is never
// part of it and the access principal id is not exposed. Masked is the only
// form of the secret that listings and exports carry.
type KeyView struct {
	Id             int    `json:"id"`
	Name           string `json:"name"`
	Masked         string `json:"key"`
	OwnerType      string `json:"owner_type"`
	CreatedBy      int    `json:"created_by"`
	Status         int    `json:"status"`
	UnlimitedQuota bool   `json:"unlimited_quota"`
	RemainQuota    int    `json:"remain_quota"`
	UsedQuota      int    `json:"used_quota"`
	ExpiredTime    int64  `json:"expired_time"`
	ModelLimits    string `json:"model_limits"`
	ModelLimitsOn  bool   `json:"model_limits_enabled"`
	AllowIps       string `json:"allow_ips"`
	CreatedTime    int64  `json:"created_time"`
	AccessedTime   int64  `json:"accessed_time"`
}

// NewKeyView renders a token row for the API.
func NewKeyView(token *model.Token) KeyView {
	allow := ""
	if token.AllowIps != nil {
		allow = *token.AllowIps
	}
	return KeyView{Id: token.Id, Name: token.Name, Masked: token.GetMaskedKey(), OwnerType: token.OwnerType,
		CreatedBy: token.CreatedBy, Status: token.Status, UnlimitedQuota: token.UnlimitedQuota, RemainQuota: token.RemainQuota,
		UsedQuota: token.UsedQuota, ExpiredTime: token.ExpiredTime, ModelLimits: token.ModelLimits,
		ModelLimitsOn: token.ModelLimitsEnabled, AllowIps: allow, CreatedTime: token.CreatedTime, AccessedTime: token.AccessedTime}
}

// KeyIssued is the response of creating or rotating a key: the only time the
// usable secret leaves the server. Plaintext includes the "sk-" prefix clients
// send.
type KeyIssued struct {
	Key       KeyView `json:"key"`
	Plaintext string  `json:"plaintext"`
}

// CreateKeyInput is everything a client chooses. Ownership, billing account,
// organization, workspace, creator and principal are written by the server.
type CreateKeyInput struct {
	Name  string
	Owner string
	// QuotaLimit > 0 makes the key limited to that one-time total; 0 leaves it
	// unlimited, which is the default because periodic budgets control spend.
	QuotaLimit  int
	ExpiredTime int64
	ModelLimits []string
	AllowIps    string
}

func validateKeyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > keyNameMaxRunes {
		return "", refuse(types.OrgErrInvalidInput)
	}
	return name, nil
}

// CreateWorkspaceKey issues a member key (Owner "me": workspace admins and
// members) or a system key (Owner "workspace": workspace admins only). The
// workspace, the organization and the actor's standing are all proved inside
// the transaction. A member key carries the actor as creator and consuming
// actor; a system key has no actor (created_by 0, the creator is on the audit
// row) and a new access principal.
func CreateWorkspaceKey(ctx context.Context, actorID, orgID, workspaceID int, in CreateKeyInput) (*KeyIssued, error) {
	if in.Owner != KeyOwnerMe && in.Owner != KeyOwnerWorkspace {
		return nil, refuse(types.OrgErrInvalidInput)
	}
	var issued *KeyIssued
	err := model.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		roles := []string{types.WorkspaceRoleAdmin, types.WorkspaceRoleMember}
		if in.Owner == KeyOwnerWorkspace {
			roles = []string{types.WorkspaceRoleAdmin}
		}
		if _, _, err := RequireWorkspaceRoleTx(tx, orgID, workspaceID, actorID, false, roles...); err != nil {
			return err
		}
		name, err := validateKeyName(in.Name)
		if err != nil {
			return err
		}
		if in.QuotaLimit < 0 || in.QuotaLimit > math.MaxInt32 || in.ExpiredTime < -1 {
			return refuse(types.OrgErrInvalidInput)
		}
		live, err := model.CountWorkspaceKeysTx(tx, orgID, workspaceID)
		if err != nil {
			return err
		}
		if int(live) >= WorkspaceKeyLimit {
			return refuse(types.OrgErrKeyLimit)
		}
		var orgs []model.Organization
		if err := tx.Select("id", "billing_user_id").Where("id = ?", orgID).Limit(1).Find(&orgs).Error; err != nil || len(orgs) == 0 {
			return refuse(types.OrgErrNotFound)
		}
		secret, err := common.GenerateKey()
		if err != nil {
			return err
		}
		principal, err := common.GenerateRandomCharsKey(32)
		if err != nil {
			return err
		}
		now := common.GetTimestamp()
		allow := strings.TrimSpace(in.AllowIps)
		token := model.Token{UserId: orgs[0].BillingUserId, Key: secret, Name: name, Status: common.TokenStatusEnabled,
			CreatedTime: now, AccessedTime: now, ExpiredTime: in.ExpiredTime, OrgId: orgID, WorkspaceId: workspaceID,
			UnlimitedQuota: in.QuotaLimit == 0, RemainQuota: in.QuotaLimit, AllowUserQuotaQuery: false,
			OwnerType: types.TokenOwnerWorkspace, AccessPrincipalId: "prn_" + principal}
		if in.ExpiredTime == 0 {
			token.ExpiredTime = -1
		}
		if in.Owner == KeyOwnerMe {
			token.OwnerType, token.CreatedBy = types.TokenOwnerMember, actorID
		}
		if len(in.ModelLimits) > 0 {
			token.ModelLimitsEnabled, token.ModelLimits = true, strings.Join(in.ModelLimits, ",")
		}
		if allow != "" {
			token.AllowIps = &allow
		}
		if err := tx.Create(&token).Error; err != nil {
			return err
		}
		issued = &KeyIssued{Key: NewKeyView(&token), Plaintext: "sk-" + secret}
		return recordAudit(ctx, tx, model.OrgAuditEntry{OrgId: orgID, WorkspaceId: workspaceID, ActorUserId: actorID,
			Action: "key.create", TargetType: "key", TargetId: itoa(token.Id),
			Detail: map[string]any{"owner": in.Owner, "name": name}})
	})
	if err != nil {
		return nil, err
	}
	return issued, nil
}

// ListWorkspaceKeys returns the masked keys the role may see: all of them for
// workspace admins and auditors, only their own for members. role comes from
// WorkspaceAuth.
func ListWorkspaceKeys(ctx context.Context, orgID, workspaceID, actorID int, role string) ([]KeyView, error) {
	query := model.DB.WithContext(ctx).Where("org_id = ? AND workspace_id = ?", orgID, workspaceID).Order("id DESC").Limit(1000)
	if role != types.WorkspaceRoleAdmin && role != types.WorkspaceRoleAuditor {
		query = query.Where("owner_type = ? AND created_by = ?", types.TokenOwnerMember, actorID)
	}
	var tokens []model.Token
	if err := query.Find(&tokens).Error; err != nil {
		return nil, err
	}
	views := make([]KeyView, 0, len(tokens))
	for i := range tokens {
		views = append(views, NewKeyView(&tokens[i]))
	}
	return views, nil
}
