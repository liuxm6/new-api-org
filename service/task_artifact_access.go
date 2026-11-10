package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/system_setting"
)

const (
	TaskArtifactAccessQueryParameter = "access"
	taskArtifactAccessVersion        = "v1"
	taskArtifactAccessLength         = 43
	maxTaskArtifactTaskIDLength      = 191
	maxTaskArtifactKeyLength         = 128
)

var ErrTaskArtifactAccessInvalid = errors.New("task artifact access is invalid")

func taskArtifactAccessMessage(taskID, artifactKey string) []byte {
	return []byte(taskArtifactAccessVersion + "\x00" + taskID + "\x00" + artifactKey)
}

// IssueTaskArtifactAccess creates a stable capability bound to exactly one
// public task ID and artifact key. It contains no user or upstream data.
func IssueTaskArtifactAccess(taskID, artifactKey string) (string, error) {
	taskID = strings.TrimSpace(taskID)
	artifactKey = strings.TrimSpace(artifactKey)
	if taskID == "" || len(taskID) > maxTaskArtifactTaskIDLength ||
		artifactKey == "" || len(artifactKey) > maxTaskArtifactKeyLength ||
		common.CryptoSecret == "" {
		return "", ErrTaskArtifactAccessInvalid
	}

	mac := hmac.New(sha256.New, []byte(common.CryptoSecret))
	_, _ = mac.Write(taskArtifactAccessMessage(taskID, artifactKey))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyTaskArtifactAccess verifies the route binding without reading task,
// user, or token state. Signature comparison is constant-time.
func VerifyTaskArtifactAccess(access, taskID, artifactKey string) bool {
	taskID = strings.TrimSpace(taskID)
	artifactKey = strings.TrimSpace(artifactKey)
	if len(access) != taskArtifactAccessLength ||
		taskID == "" || len(taskID) > maxTaskArtifactTaskIDLength ||
		artifactKey == "" || len(artifactKey) > maxTaskArtifactKeyLength ||
		common.CryptoSecret == "" {
		return false
	}

	actualSignature, err := base64.RawURLEncoding.Strict().DecodeString(access)
	if err != nil || len(actualSignature) != sha256.Size {
		return false
	}

	mac := hmac.New(sha256.New, []byte(common.CryptoSecret))
	_, _ = mac.Write(taskArtifactAccessMessage(taskID, artifactKey))
	return hmac.Equal(actualSignature, mac.Sum(nil))
}

// ValidateTaskArtifactBaseURL validates configuration syntax only. It
// deliberately performs no DNS lookup or reachability probe.
func ValidateTaskArtifactBaseURL(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("task artifact base URL is empty")
	}
	if raw != trimmed {
		return errors.New("task artifact base URL must not contain surrounding whitespace")
	}
	raw = trimmed
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return errors.New("task artifact base URL is invalid")
	}
	if !strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https") {
		return errors.New("task artifact base URL must use http or https")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" {
		return errors.New("task artifact base URL must contain a host and no userinfo")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("task artifact base URL must not contain a query or fragment")
	}
	return nil
}

// BuildTaskArtifactContentURL returns an absolute, long-lived capability URL.
// TaskPublicAddress wins when configured; ServerAddress is the only fallback.
// Request Host headers are intentionally not involved. It is for personal tasks
// only; organization tasks get a v2 ticket from BuildOrgTaskArtifactContentURL.
func BuildTaskArtifactContentURL(taskID, artifactKey string) (string, error) {
	return buildArtifactContentURL(taskID, artifactKey, func() (string, error) {
		return IssueTaskArtifactAccess(taskID, artifactKey)
	})
}

// buildArtifactContentURL validates the identifiers and the configured public
// address, then asks issue for the access value to attach.
func buildArtifactContentURL(taskID, artifactKey string, issue func() (string, error)) (string, error) {
	taskID = strings.TrimSpace(taskID)
	artifactKey = strings.TrimSpace(artifactKey)
	if taskID == "" || len(taskID) > maxTaskArtifactTaskIDLength ||
		artifactKey == "" || len(artifactKey) > maxTaskArtifactKeyLength {
		return "", ErrTaskArtifactAccessInvalid
	}

	baseAddress := strings.TrimSpace(system_setting.TaskPublicAddress)
	if baseAddress == "" {
		baseAddress = strings.TrimSpace(system_setting.ServerAddress)
	}
	if err := ValidateTaskArtifactBaseURL(baseAddress); err != nil {
		return "", err
	}
	baseURL, err := url.Parse(baseAddress)
	if err != nil {
		return "", err
	}

	access, err := issue()
	if err != nil {
		return "", err
	}

	basePath := strings.TrimRight(baseURL.Path, "/")
	escapedBasePath := strings.TrimRight(baseURL.EscapedPath(), "/")
	suffixPath := fmt.Sprintf("/v1/tasks/%s/artifacts/%s/content", taskID, artifactKey)
	escapedSuffixPath := fmt.Sprintf(
		"/v1/tasks/%s/artifacts/%s/content",
		url.PathEscape(taskID),
		url.PathEscape(artifactKey),
	)
	baseURL.Path = basePath + suffixPath
	baseURL.RawPath = escapedBasePath + escapedSuffixPath
	query := baseURL.Query()
	query.Set(TaskArtifactAccessQueryParameter, access)
	baseURL.RawQuery = query.Encode()
	return baseURL.String(), nil
}

// Organization artifact tickets (v2). Unlike the permanent personal capability
// above, a v2 ticket carries its own claims and an expiry, so it can be refused
// from its signature alone, before any database read. The signature covers the
// claims, the task id and the artifact key, so a ticket cannot be moved to
// another task or artifact. What the claims allow is decided again against the
// database at download time (see AuthorizeOrgArtifactTicket).

const (
	orgArtifactTicketPrefix     = "o2"
	orgArtifactTicketDomain     = "org-artifact-ticket-v2"
	maxOrgArtifactTicketLength  = 480
	orgArtifactPrincipalDigestN = 16
)

// OrgArtifactSubjectKind says what kind of reader the ticket was issued to.
type OrgArtifactSubjectKind string

const (
	// OrgArtifactSubjectMemberKey: a member API key. Rechecked against that key
	// row and its actor.
	OrgArtifactSubjectMemberKey OrgArtifactSubjectKind = "m"
	// OrgArtifactSubjectSystemKey: a workspace (system) API key. Rechecked against
	// that key row and its access principal.
	OrgArtifactSubjectSystemKey OrgArtifactSubjectKind = "s"
	// OrgArtifactSubjectHuman: a console user. Rechecked against the user's
	// current organization and workspace role.
	OrgArtifactSubjectHuman OrgArtifactSubjectKind = "h"
)

var (
	// ErrOrgArtifactTicketInvalid covers a malformed ticket and a bad signature.
	ErrOrgArtifactTicketInvalid = errors.New("organization artifact ticket is invalid")
	// ErrOrgArtifactTicketExpired is a correctly signed ticket past its expiry.
	ErrOrgArtifactTicketExpired = errors.New("organization artifact ticket has expired")
)

// OrgArtifactTicketClaims is the signed content of a v2 ticket. It holds ids and
// a digest of the access principal, never a credential.
type OrgArtifactTicketClaims struct {
	OrgID         int                    `json:"o"`
	WorkspaceID   int                    `json:"w"`
	Kind          OrgArtifactSubjectKind `json:"k"`
	UserID        int                    `json:"u,omitempty"`
	TokenID       int                    `json:"t,omitempty"`
	PrincipalHash string                 `json:"p,omitempty"`
	PolicyVersion int64                  `json:"v"`
	ExpiresAt     int64                  `json:"e"`
}

// OrgArtifactPrincipalDigest is the short, one-way form of an access principal
// stored in a ticket.
func OrgArtifactPrincipalDigest(principal string) string {
	if principal == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(orgArtifactTicketDomain + "\x00principal\x00" + principal))
	return base64.RawURLEncoding.EncodeToString(sum[:orgArtifactPrincipalDigestN])
}

// wellFormed checks that the claims name a complete reader. The expiry is not
// part of it: the issuer stamps it, and the verifier checks it separately.
func (c OrgArtifactTicketClaims) wellFormed() bool {
	if c.OrgID <= 0 || c.WorkspaceID <= 0 || c.PolicyVersion < 0 {
		return false
	}
	switch c.Kind {
	case OrgArtifactSubjectMemberKey:
		return c.UserID > 0 && c.TokenID > 0 && c.PrincipalHash == ""
	case OrgArtifactSubjectSystemKey:
		return c.UserID == 0 && c.TokenID > 0 && c.PrincipalHash != ""
	case OrgArtifactSubjectHuman:
		return c.UserID > 0 && c.TokenID == 0 && c.PrincipalHash == ""
	}
	return false
}

func orgArtifactTicketMAC(payload, taskID, artifactKey string) []byte {
	mac := hmac.New(sha256.New, []byte(common.CryptoSecret))
	_, _ = mac.Write([]byte(orgArtifactTicketDomain + "\x00" + payload + "\x00" + taskID + "\x00" + artifactKey))
	return mac.Sum(nil)
}

// IssueOrgArtifactTicket signs claims for one task and artifact. ExpiresAt is
// set here from the platform TTL; the caller supplies the rest.
func IssueOrgArtifactTicket(claims OrgArtifactTicketClaims, taskID, artifactKey string, now time.Time) (string, error) {
	taskID = strings.TrimSpace(taskID)
	artifactKey = strings.TrimSpace(artifactKey)
	if taskID == "" || len(taskID) > maxTaskArtifactTaskIDLength ||
		artifactKey == "" || len(artifactKey) > maxTaskArtifactKeyLength ||
		common.CryptoSecret == "" {
		return "", ErrOrgArtifactTicketInvalid
	}
	claims.ExpiresAt = now.Add(system_setting.OrgTaskArtifactTicketTTL()).Unix()
	if !claims.wellFormed() {
		return "", ErrOrgArtifactTicketInvalid
	}
	encoded, err := common.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(encoded)
	signature := base64.RawURLEncoding.EncodeToString(orgArtifactTicketMAC(payload, taskID, artifactKey))
	ticket := orgArtifactTicketPrefix + "." + payload + "." + signature
	if len(ticket) > maxOrgArtifactTicketLength {
		return "", ErrOrgArtifactTicketInvalid
	}
	return ticket, nil
}

// IsOrgArtifactTicket reports whether an access value is in the v2 shape, so
// callers can route it without trying it as a personal capability.
func IsOrgArtifactTicket(access string) bool {
	return strings.HasPrefix(access, orgArtifactTicketPrefix+".")
}

// VerifyOrgArtifactTicket checks the signature, the binding to this task and
// artifact, and the expiry, without reading any state. The signature is
// verified before the claims are decoded, and before the expiry is looked at, so
// neither can be probed with a forged ticket.
func VerifyOrgArtifactTicket(access, taskID, artifactKey string, now time.Time) (OrgArtifactTicketClaims, error) {
	var claims OrgArtifactTicketClaims
	taskID = strings.TrimSpace(taskID)
	artifactKey = strings.TrimSpace(artifactKey)
	if len(access) == 0 || len(access) > maxOrgArtifactTicketLength ||
		taskID == "" || len(taskID) > maxTaskArtifactTaskIDLength ||
		artifactKey == "" || len(artifactKey) > maxTaskArtifactKeyLength ||
		common.CryptoSecret == "" {
		return claims, ErrOrgArtifactTicketInvalid
	}
	prefix, rest, ok := strings.Cut(access, ".")
	payload, signature, ok2 := strings.Cut(rest, ".")
	if !ok || !ok2 || prefix != orgArtifactTicketPrefix || payload == "" || strings.Contains(signature, ".") {
		return claims, ErrOrgArtifactTicketInvalid
	}
	actual, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || !hmac.Equal(actual, orgArtifactTicketMAC(payload, taskID, artifactKey)) {
		return claims, ErrOrgArtifactTicketInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil || common.Unmarshal(decoded, &claims) != nil || !claims.wellFormed() || claims.ExpiresAt <= 0 {
		return OrgArtifactTicketClaims{}, ErrOrgArtifactTicketInvalid
	}
	if !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return claims, ErrOrgArtifactTicketExpired
	}
	return claims, nil
}

// BuildOrgTaskArtifactContentURL returns the gateway URL for one artifact of an
// organization task, carrying a v2 ticket. The URL goes through the gateway's
// authenticated content route; it never points at the upstream.
func BuildOrgTaskArtifactContentURL(claims OrgArtifactTicketClaims, taskID, artifactKey string) (string, error) {
	return buildArtifactContentURL(taskID, artifactKey, func() (string, error) {
		return IssueOrgArtifactTicket(claims, taskID, artifactKey, time.Now())
	})
}

// OrgMidjourneyImageArtifactKey is the artifact key a Midjourney image ticket is
// bound to. The task id in the ticket is the Midjourney task id.
const OrgMidjourneyImageArtifactKey = "image"

// BuildOrgMidjourneyImageURL returns the gateway image URL for an organization
// Midjourney task, carrying a v2 ticket. Like every organization artifact URL it
// goes through the gateway and never names the upstream.
func BuildOrgMidjourneyImageURL(claims OrgArtifactTicketClaims, mjID string) (string, error) {
	mjID = strings.TrimSpace(mjID)
	base := strings.TrimSpace(system_setting.ServerAddress)
	if mjID == "" || len(mjID) > maxTaskArtifactTaskIDLength {
		return "", ErrOrgArtifactTicketInvalid
	}
	if err := ValidateTaskArtifactBaseURL(base); err != nil {
		return "", err
	}
	access, err := IssueOrgArtifactTicket(claims, mjID, OrgMidjourneyImageArtifactKey, time.Now())
	if err != nil {
		return "", err
	}
	query := url.Values{TaskArtifactAccessQueryParameter: {access}}
	return strings.TrimRight(base, "/") + "/mj/image/" + url.PathEscape(mjID) + "?" + query.Encode(), nil
}
