package system_setting

import (
	"time"

	"github.com/QuantumNous/new-api/setting/config"
)

const (
	// DefaultOrgTaskArtifactTicketTTLSeconds is one hour: long enough for an
	// asynchronous video download to start after the task is read, short enough
	// that a leaked URL stops working on its own. Reading the task again returns
	// a fresh URL.
	DefaultOrgTaskArtifactTicketTTLSeconds = 3600
	MinOrgTaskArtifactTicketTTLSeconds     = 60
	MaxOrgTaskArtifactTicketTTLSeconds     = 24 * 60 * 60
)

// OrgTaskArtifactSetting configures the signed artifact tickets issued for
// organization tasks. Personal-task tickets are permanent capabilities and are
// not affected by it.
type OrgTaskArtifactSetting struct {
	TicketTTLSeconds int `json:"ticket_ttl_seconds"`
}

var orgTaskArtifactSetting = OrgTaskArtifactSetting{TicketTTLSeconds: DefaultOrgTaskArtifactTicketTTLSeconds}

func init() {
	config.GlobalConfig.Register("org_task_artifact", &orgTaskArtifactSetting)
}

// OrgTaskArtifactTicketTTL is the platform-configured ticket lifetime, clamped
// to its bounds so a bad option value can neither disable expiry nor issue a
// ticket that is useless on arrival.
func OrgTaskArtifactTicketTTL() time.Duration {
	seconds := orgTaskArtifactSetting.TicketTTLSeconds
	if seconds <= 0 {
		seconds = DefaultOrgTaskArtifactTicketTTLSeconds
	}
	seconds = min(max(seconds, MinOrgTaskArtifactTicketTTLSeconds), MaxOrgTaskArtifactTicketTTLSeconds)
	return time.Duration(seconds) * time.Second
}
