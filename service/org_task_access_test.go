package service

import (
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/config"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setTicketSecret(t *testing.T) {
	t.Helper()
	previous := common.CryptoSecret
	common.CryptoSecret = "org-artifact-ticket-test-secret"
	t.Cleanup(func() { common.CryptoSecret = previous })
}

func memberClaims() OrgArtifactTicketClaims {
	return OrgArtifactTicketClaims{OrgID: 7, WorkspaceID: 3, Kind: OrgArtifactSubjectMemberKey, UserID: 42, TokenID: 9, PolicyVersion: 5}
}

func TestOrgArtifactTicketCodec(t *testing.T) {
	setTicketSecret(t)
	now := time.Unix(1_800_000_000, 0)
	issue := func(claims OrgArtifactTicketClaims, task, artifact string) string {
		ticket, err := IssueOrgArtifactTicket(claims, task, artifact, now)
		require.NoError(t, err)
		return ticket
	}

	t.Run("a ticket carries its claims and a one hour default expiry", func(t *testing.T) {
		ticket := issue(memberClaims(), "task_a", "video")
		assert.True(t, IsOrgArtifactTicket(ticket))
		assert.False(t, IsOrgArtifactTicket("short-personal-capability"))
		claims, err := VerifyOrgArtifactTicket(ticket, "task_a", "video", now)
		require.NoError(t, err)
		assert.Equal(t, memberClaims().OrgID, claims.OrgID)
		assert.Equal(t, memberClaims().UserID, claims.UserID)
		assert.EqualValues(t, 5, claims.PolicyVersion)
		assert.Equal(t, now.Add(time.Hour).Unix(), claims.ExpiresAt)
		assert.NotContains(t, ticket, "task_a", "the task id is bound by the signature, not carried in the ticket")
	})

	t.Run("the platform can change the lifetime, within bounds", func(t *testing.T) {
		require.Equal(t, time.Hour, system_setting.OrgTaskArtifactTicketTTL())
		cfg := config.GlobalConfig.Get("org_task_artifact")
		require.NotNil(t, cfg, "the setting is registered, so option org_task_artifact.ticket_ttl_seconds updates it")
		t.Cleanup(func() { config.UpdateConfigFromMap(cfg, map[string]string{"ticket_ttl_seconds": "3600"}) })
		for configured, want := range map[string]time.Duration{
			"7200": 2 * time.Hour, "5": time.Minute, "0": time.Hour, "-3": time.Hour, "864000": 24 * time.Hour,
		} {
			config.UpdateConfigFromMap(cfg, map[string]string{"ticket_ttl_seconds": configured})
			assert.Equal(t, want, system_setting.OrgTaskArtifactTicketTTL(), "configured %s", configured)
		}
	})

	t.Run("expiry is decided from the signature alone, after the signature", func(t *testing.T) {
		ticket := issue(memberClaims(), "task_a", "video")
		_, err := VerifyOrgArtifactTicket(ticket, "task_a", "video", now.Add(time.Hour-time.Second))
		require.NoError(t, err)
		_, err = VerifyOrgArtifactTicket(ticket, "task_a", "video", now.Add(time.Hour))
		assert.ErrorIs(t, err, ErrOrgArtifactTicketExpired)

		// A forged ticket is invalid whatever the clock says: expiry must not be
		// probeable without a valid signature.
		payload := strings.Split(ticket, ".")[1]
		forged := "o2." + payload + ".AAAA"
		_, err = VerifyOrgArtifactTicket(forged, "task_a", "video", now.Add(48*time.Hour))
		assert.ErrorIs(t, err, ErrOrgArtifactTicketInvalid)
	})

	t.Run("a ticket cannot be moved to another task, artifact or secret", func(t *testing.T) {
		ticket := issue(memberClaims(), "task_a", "video")
		for name, args := range map[string][2]string{"task": {"task_b", "video"}, "artifact": {"task_a", "audio"}} {
			_, err := VerifyOrgArtifactTicket(ticket, args[0], args[1], now)
			assert.ErrorIs(t, err, ErrOrgArtifactTicketInvalid, name)
		}
		common.CryptoSecret = "another-secret"
		_, err := VerifyOrgArtifactTicket(ticket, "task_a", "video", now)
		assert.ErrorIs(t, err, ErrOrgArtifactTicketInvalid)
	})

	t.Run("claims cannot be edited, widened or replayed as another version", func(t *testing.T) {
		ticket := issue(memberClaims(), "task_a", "video")
		parts := strings.Split(ticket, ".")
		other := memberClaims()
		other.OrgID = 8
		widened := issue(other, "task_a", "video")
		spliced := "o2." + strings.Split(widened, ".")[1] + "." + parts[2]
		_, err := VerifyOrgArtifactTicket(spliced, "task_a", "video", now)
		assert.ErrorIs(t, err, ErrOrgArtifactTicketInvalid)
		for _, bad := range []string{"", "o2", "o2.", "o2.x", "o2.x.y.z", "o1." + parts[1] + "." + parts[2], parts[1] + "." + parts[2],
			strings.Repeat("a", 4096), "o2." + parts[1] + "." + parts[2] + "=="} {
			_, err := VerifyOrgArtifactTicket(bad, "task_a", "video", now)
			assert.ErrorIs(t, err, ErrOrgArtifactTicketInvalid, bad)
		}
		// A personal capability is not a v2 ticket and the reverse.
		personal, err := IssueTaskArtifactAccess("task_a", "video")
		require.NoError(t, err)
		_, err = VerifyOrgArtifactTicket(personal, "task_a", "video", now)
		assert.ErrorIs(t, err, ErrOrgArtifactTicketInvalid)
		assert.False(t, VerifyTaskArtifactAccess(ticket, "task_a", "video"))
	})

	t.Run("only well formed claims can be issued", func(t *testing.T) {
		for name, claims := range map[string]OrgArtifactTicketClaims{
			"no org":              {WorkspaceID: 1, Kind: OrgArtifactSubjectHuman, UserID: 1},
			"no workspace":        {OrgID: 1, Kind: OrgArtifactSubjectHuman, UserID: 1},
			"member without key":  {OrgID: 1, WorkspaceID: 1, Kind: OrgArtifactSubjectMemberKey, UserID: 1},
			"system without hash": {OrgID: 1, WorkspaceID: 1, Kind: OrgArtifactSubjectSystemKey, TokenID: 1},
			"human with a key":    {OrgID: 1, WorkspaceID: 1, Kind: OrgArtifactSubjectHuman, UserID: 1, TokenID: 2},
			"unknown kind":        {OrgID: 1, WorkspaceID: 1, Kind: "x", UserID: 1},
		} {
			_, err := IssueOrgArtifactTicket(claims, "task_a", "video", now)
			assert.ErrorIs(t, err, ErrOrgArtifactTicketInvalid, name)
		}
		_, err := IssueOrgArtifactTicket(memberClaims(), "", "video", now)
		assert.Error(t, err)
		_, err = IssueOrgArtifactTicket(memberClaims(), strings.Repeat("t", 192), "video", now)
		assert.Error(t, err)
	})

	t.Run("a ticket for the longest task id and key still fits the query limit", func(t *testing.T) {
		claims := OrgArtifactTicketClaims{OrgID: 2_000_000_000, WorkspaceID: 2_000_000_000, Kind: OrgArtifactSubjectSystemKey,
			TokenID: 2_000_000_000, PrincipalHash: OrgArtifactPrincipalDigest("prn-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), PolicyVersion: 1 << 40}
		ticket := issue(claims, strings.Repeat("t", 191), strings.Repeat("k", 128))
		assert.LessOrEqual(t, len(ticket), maxOrgArtifactTicketLength)
		_, err := VerifyOrgArtifactTicket(ticket, strings.Repeat("t", 191), strings.Repeat("k", 128), now)
		assert.NoError(t, err)
	})

	t.Run("a system ticket stores a digest of the principal, not the principal", func(t *testing.T) {
		digest := OrgArtifactPrincipalDigest("prn-secret-principal")
		assert.NotEmpty(t, digest)
		assert.NotContains(t, digest, "prn-secret")
		assert.NotEqual(t, digest, OrgArtifactPrincipalDigest("prn-other"))
		assert.Empty(t, OrgArtifactPrincipalDigest(""))
	})
}
