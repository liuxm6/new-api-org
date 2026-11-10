package controller

import (
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

// CreateOrganizationInvite issues or re-issues an invitation. The service
// returns the plaintext token once; this handler mails it and, when no mail
// goes out, returns the link to the inviting admin. The token is never stored,
// logged or audited.
func CreateOrganizationInvite(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	fields, ok := decodeOrgFields(c, "email", "org_role", "workspace_id", "workspace_role")
	if !ok {
		return
	}
	var input orgsvc.CreateInviteInput
	for name, dst := range map[string]any{"email": &input.Email, "org_role": &input.OrgRole,
		"workspace_id": &input.WorkspaceID, "workspace_role": &input.WorkspaceRole} {
		if _, err := orgField(fields, name, dst); err != nil {
			respondOrgError(c, types.NewOrgAccessError(types.OrgErrInvalidInput))
			return
		}
	}
	actorID := c.GetInt("id")
	issued, err := orgsvc.CreateInvite(orgContext(c), actorID, access.Org.Id, input)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	inviterName := ""
	var inviter model.User
	if err := model.DB.Select("id", "username", "display_name").Where("id = ?", actorID).Limit(1).Find(&inviter).Error; err == nil {
		inviterName = inviter.DisplayName
		if inviterName == "" {
			inviterName = inviter.Username
		}
	}
	sent, _ := service.SendOrgInviteEmail(i18n.StatedLang(c), issued.Invite.Email, inviterName, access.Org.Name, issued.Token)
	response := gin.H{"id": issued.Invite.Id, "email": issued.Invite.Email, "expires_at": issued.Invite.ExpiresAt,
		"rotated": issued.Rotated, "email_sent": sent}
	if !sent {
		response["invite_url"] = service.OrgInviteURL(issued.Token)
	}
	c.Header("Cache-Control", "no-store")
	common.ApiSuccess(c, response)
}

// ListOrganizationInvites lists invitations without any token material.
func ListOrganizationInvites(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	list, err := orgsvc.ListInvites(orgContext(c), access.Org.Id)
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, list)
}

// RevokeOrganizationInvite withdraws a pending invitation.
func RevokeOrganizationInvite(c *gin.Context) {
	access, ok := requestedOrg(c)
	if !ok {
		return
	}
	inviteID, ok := pathID(c, "iid")
	if !ok {
		return
	}
	if err := orgsvc.RevokeInvite(orgContext(c), c.GetInt("id"), access.Org.Id, inviteID); err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{})
}

// AcceptInvite redeems an invitation token for the signed-in account. The token
// is in the path by design (/api/invites/:token/accept); the access logger
// redacts it. Responses are not cacheable.
func AcceptInvite(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Referrer-Policy", "no-referrer")
	result, err := orgsvc.AcceptInvite(orgContext(c), c.GetInt("id"), c.Param("token"))
	if err != nil {
		respondOrgError(c, err)
		return
	}
	common.ApiSuccess(c, gin.H{"organization": newOrgView(&result.Org, ""), "joined": result.Joined})
}
