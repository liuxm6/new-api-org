package controller

import (
	"github.com/QuantumNous/new-api/common"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// UpdateOrganizationMember changes a member's role and/or status. :mid is the
// member's user id. Owner and admin only; the service re-proves the role in
// its transaction and applies the owner rules (an admin cannot touch owners,
// the last owner stays).
func UpdateOrganizationMember(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	userID, ok := pathID(c, "mid")
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "role", "status")
	if !ok {
		return
	}
	var role string
	var status int
	hasRole, roleErr := orgField(fields, "role", &role)
	hasStatus, statusErr := orgField(fields, "status", &status)
	if roleErr != nil || statusErr != nil || (!hasRole && !hasStatus) {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	actor := c.GetInt("id")
	if hasRole {
		if err := orgsvc.ChangeMemberRole(orgContext(c), actor, access.Org.Id, userID, role); err != nil {
			respondOrgError(c, err)
			return
		}
	}
	if hasStatus {
		if err := orgsvc.SetMemberStatus(orgContext(c), actor, access.Org.Id, userID, status); err != nil {
			respondOrgError(c, err)
			return
		}
	}
	common.ApiSuccess(c, gin.H{})
}

// RemoveOrganizationMember removes a member (:mid is the user id). Any member
// may remove themselves; removing others needs owner or admin.
func RemoveOrganizationMember(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	userID, ok := pathID(c, "mid")
	if !ok {
		return
	}
	if err := orgsvc.RemoveMember(orgContext(c), c.GetInt("id"), access.Org.Id, userID); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}

// DeleteOrganization soft-deletes the organization. Owner only; the slug must
// be typed back in "confirm_slug".
func DeleteOrganization(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "confirm_slug")
	if !ok {
		return
	}
	var confirm string
	if _, err := orgField(fields, "confirm_slug", &confirm); err != nil {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	if confirm != access.Org.Slug {
		respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
		return
	}
	if !requireSensitive(c, types.SensitiveOrgDelete, access.Org.Id, orgDeleteResource(access.Org.Slug)) {
		return
	}
	if err := orgsvc.DeleteOrganization(orgContext(c), c.GetInt("id"), access.Org.Id, confirm); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}
