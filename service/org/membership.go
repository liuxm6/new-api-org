package org

import (
	"context"
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"

	"gorm.io/gorm"
)

// OrgAccess is the proven standing of one human in one organization.
type OrgAccess struct {
	Org    *model.Organization
	Member model.OrganizationMember
}

// WorkspaceAccess adds the effective workspace role. Implicit is true when the
// role comes from being an organization owner or admin rather than a grant.
type WorkspaceAccess struct {
	OrgAccess
	Workspace *model.Workspace
	Role      string
	Implicit  bool
}

func refuse(code string) error { return types.NewOrgAccessError(code) }

// unavailable logs a database failure and returns the fail-closed refusal.
func unavailable(err error) error {
	common.SysError(common.LogText("organization access check failed: %v", err))
	return refuse(types.OrgErrStateUnavailable)
}

func roleAllowed(role string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == role {
			return true
		}
	}
	return false
}

// ResolveOrgAccess proves that userID may act in the organization named by ref
// with one of the allowed roles (any role when allowed is empty).
//
// restrictOrgID > 0 pins the call to the single organization an org-scoped
// session is bound to; every other organization answers as not found. Order
// matters for what a caller can learn: a stranger gets 404 whether or not the
// organization is suspended, a member gets the state-specific 403 first, and
// only then the role check.
func ResolveOrgAccess(ctx context.Context, userID int, ref string, restrictOrgID int, allowed ...string) (*OrgAccess, error) {
	db := model.DB.WithContext(ctx)
	org, err := model.GetOrganizationByRef(db, ref)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, refuse(types.OrgErrNotFound)
	}
	if err != nil {
		return nil, unavailable(err)
	}
	if restrictOrgID > 0 && org.Id != restrictOrgID {
		return nil, refuse(types.OrgErrNotFound)
	}
	member, err := cachedOrgMember(db, org, userID)
	if err != nil {
		return nil, err
	}
	if member.Status == types.OrgMemberStatusRemoved {
		return nil, refuse(types.OrgErrNotFound)
	}
	if org.Status != types.OrgStatusActive {
		return nil, refuse(types.OrgErrSuspended)
	}
	if member.Status != types.OrgMemberStatusActive {
		return nil, refuse(types.OrgErrMemberSuspended)
	}
	if !roleAllowed(member.Role, allowed) {
		return nil, refuse(types.OrgErrForbidden)
	}
	return &OrgAccess{Org: org, Member: member}, nil
}

// cachedOrgMember reads the membership through the version-keyed cache. A
// non-member is cached too (as not found) because becoming a member bumps the
// version.
func cachedOrgMember(db *gorm.DB, org *model.Organization, userID int) (model.OrganizationMember, error) {
	key := orgMemberCacheKey(org.Id, userID, org.PolicyVersion)
	if entry, ok := memberAccessCache.get(key); ok {
		if !entry.found {
			return model.OrganizationMember{}, refuse(types.OrgErrNotFound)
		}
		return model.OrganizationMember{OrgId: org.Id, UserId: userID, Role: entry.role, Status: entry.status}, nil
	}
	member, err := model.GetOrganizationMember(db, org.Id, userID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		memberAccessCache.put(key, accessCacheEntry{})
		return model.OrganizationMember{}, refuse(types.OrgErrNotFound)
	}
	if err != nil {
		return model.OrganizationMember{}, unavailable(err)
	}
	memberAccessCache.put(key, accessCacheEntry{role: member.Role, status: member.Status, found: true})
	return *member, nil
}

// ResolveWorkspaceAccess extends ResolveOrgAccess to a workspace of that
// organization. Organization owners and admins are implicit workspace admins;
// everyone else needs an active projected workspace role. The billing role
// grants no workspace access. A workspace of another organization is a 404.
func ResolveWorkspaceAccess(ctx context.Context, userID int, orgRef, wsRef string, restrictOrgID int, allowed ...string) (*WorkspaceAccess, error) {
	access, err := ResolveOrgAccess(ctx, userID, orgRef, restrictOrgID)
	if err != nil {
		return nil, err
	}
	db := model.DB.WithContext(ctx)
	workspace, err := model.GetWorkspaceByRef(db, access.Org.Id, wsRef)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, refuse(types.OrgErrWorkspaceNotFound)
	}
	if err != nil {
		return nil, unavailable(err)
	}
	result := &WorkspaceAccess{OrgAccess: *access, Workspace: workspace}
	if model.OrgRoleAtLeast(access.Member.Role, types.OrgRoleAdmin) {
		result.Role, result.Implicit = types.WorkspaceRoleAdmin, true
	} else {
		member, err := cachedWorkspaceMember(db, access.Org, workspace.Id, userID)
		if err != nil {
			return nil, err
		}
		result.Role = member.Role
	}
	if workspace.Status != types.WorkspaceStatusActive {
		return nil, refuse(types.OrgErrWorkspaceSuspended)
	}
	if !roleAllowed(result.Role, allowed) {
		return nil, refuse(types.OrgErrWorkspaceForbidden)
	}
	return result, nil
}

func cachedWorkspaceMember(db *gorm.DB, org *model.Organization, workspaceID, userID int) (model.WorkspaceMember, error) {
	key := wsMemberCacheKey(org.Id, workspaceID, userID, org.PolicyVersion)
	if entry, ok := memberAccessCache.get(key); ok {
		if !entry.found {
			return model.WorkspaceMember{}, refuse(types.OrgErrWorkspaceNotFound)
		}
		return model.WorkspaceMember{WorkspaceId: workspaceID, OrgId: org.Id, UserId: userID, Role: entry.role, Status: entry.status}, nil
	}
	member, err := model.GetWorkspaceMember(db, workspaceID, userID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return model.WorkspaceMember{}, unavailable(err)
	}
	if err != nil || member.Status != 1 {
		memberAccessCache.put(key, accessCacheEntry{})
		return model.WorkspaceMember{}, refuse(types.OrgErrWorkspaceNotFound)
	}
	memberAccessCache.put(key, accessCacheEntry{role: member.Role, status: member.Status, found: true})
	return *member, nil
}

// RequireOrgRoleTx is the in-transaction authorization every organization
// write starts with. It locks the organization and the actor's membership and
// re-reads both, so a role that was revoked after the request was admitted
// (or a stale cache entry) cannot authorize the write. Locks are taken in the
// fixed order organization, then member.
func RequireOrgRoleTx(tx *gorm.DB, orgID, actorID int, allowed ...string) (*model.Organization, *model.OrganizationMember, error) {
	org, err := model.LockOrganizationTx(tx, orgID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, refuse(types.OrgErrNotFound)
	}
	if err != nil {
		return nil, nil, err
	}
	member, err := model.LockOrganizationMemberTx(tx, orgID, actorID)
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && member.Status == types.OrgMemberStatusRemoved) {
		return nil, nil, refuse(types.OrgErrNotFound)
	}
	if err != nil {
		return nil, nil, err
	}
	if org.Status != types.OrgStatusActive {
		return nil, nil, refuse(types.OrgErrSuspended)
	}
	if member.Status != types.OrgMemberStatusActive {
		return nil, nil, refuse(types.OrgErrMemberSuspended)
	}
	// A management credential acts with at most administrator standing, even
	// when its creator is the owner: owner-only actions stay with people.
	if _, capped := managementCredentialFrom(tx.Statement.Context); capped && member.Role == types.OrgRoleOwner {
		clone := *member
		clone.Role = types.OrgRoleAdmin
		member = &clone
	}
	if !roleAllowed(member.Role, allowed) {
		return nil, nil, refuse(types.OrgErrForbidden)
	}
	return org, member, nil
}
