package system_setting

import "github.com/QuantumNous/new-api/setting/config"

// OrgOIDCEgressRule is one platform-owned exception that lets organization
// OIDC traffic reach a private or otherwise restricted destination. Only the
// platform root can edit it (it is an ordinary option key); organizations never
// supply or widen rules. Loopback, link-local and cloud metadata addresses stay
// denied whatever a rule says.
type OrgOIDCEgressRule struct {
	// Host is one exact lower-case domain name or IP literal. No scheme, port or wildcard.
	Host string `json:"host"`
	// Ports lists the allowed destination ports. Empty means 443 only.
	Ports []int `json:"ports"`
	// CIDRs lists the restricted (private or special-use) networks Host may
	// resolve into. Empty means Host must resolve to public addresses only.
	CIDRs []string `json:"cidrs"`
}

// OrgOIDCEgressSetting is the platform policy of the organization OIDC
// outbound client.
type OrgOIDCEgressSetting struct {
	Rules []OrgOIDCEgressRule `json:"rules"`
	// MaxRedirects is the number of redirect hops followed (0 to 3). The
	// default 0 rejects every redirect.
	MaxRedirects int `json:"max_redirects"`
}

var defaultOrgOIDCEgressSetting = OrgOIDCEgressSetting{
	Rules:        []OrgOIDCEgressRule{},
	MaxRedirects: 0,
}

func init() {
	config.GlobalConfig.Register("org_oidc_egress", &defaultOrgOIDCEgressSetting)
}

func GetOrgOIDCEgressSetting() *OrgOIDCEgressSetting {
	return &defaultOrgOIDCEgressSetting
}
