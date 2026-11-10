package service

import (
	"html"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	orgsvc "github.com/QuantumNous/new-api/service/org"
	"github.com/QuantumNous/new-api/setting/system_setting"
)

// OrgInviteURL builds the link a recipient opens. It uses the configured server
// address, never the request's Host header (host header injection), and puts
// the token in the URL fragment so it is not sent to the server in the page
// request, is absent from access logs and is not leaked by a Referer header.
func OrgInviteURL(token string) string {
	return strings.TrimRight(system_setting.ServerAddress, "/") + "/#/invite/" + url.PathEscape(token)
}

// SendOrgInviteEmail mails an invitation in the recipient's language. Mail
// delivery belongs to this layer because service/org must not depend on it.
// It reports whether the message was handed to the mail provider; when no
// provider is configured, or sending fails, the caller returns the invite URL
// to the inviting admin instead. Organization and inviter names are
// user-controlled and are HTML-escaped before they enter the message.
func SendOrgInviteEmail(lang, to, inviterName, orgName, token string) (sent bool, err error) {
	link := OrgInviteURL(token)
	args := map[string]any{
		"SystemName": html.EscapeString(common.SystemName),
		"Inviter":    html.EscapeString(inviterName),
		"Org":        html.EscapeString(orgName),
		"Link":       link,
		"Days":       int(orgsvc.InviteTTL.Hours() / 24),
	}
	// The subject is a header, not HTML: names go in raw but without line breaks
	// or other control characters that could inject headers.
	subjectArgs := map[string]any{"SystemName": common.SystemName,
		"Inviter": stripControl(inviterName), "Org": stripControl(orgName)}
	subject := i18n.Translate(lang, i18n.MsgEmailInviteSubject, subjectArgs)
	body := i18n.Translate(lang, i18n.MsgEmailInviteIntro, args) + "<br>" +
		i18n.Translate(lang, i18n.MsgEmailInviteLink, args) + "<br>" +
		i18n.Translate(lang, i18n.MsgEmailInviteExpiry, args)
	if err := common.SendEmail(subject, to, body); err != nil {
		common.SysLog(common.LogText("organization invite email was not sent: %s", err.Error()))
		return false, err
	}
	return true, nil
}

func stripControl(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
}
