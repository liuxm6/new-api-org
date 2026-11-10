package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// AuthFlowPurposeOrgOIDC is the auth_flows purpose of an organization OIDC ceremony.
const AuthFlowPurposeOrgOIDC = "org_oidc"

const (
	// OrgOIDCFlowTTL bounds how long a ceremony may stay pending (ASVS 5.0.0 10.4.3).
	OrgOIDCFlowTTL = 10 * time.Minute
	// OrgOIDCFreshMaxAge is the largest auth_time age accepted for a sensitive operation.
	OrgOIDCFreshMaxAge = 5 * time.Minute
	// OrgOIDCClockSkew is the tolerated clock difference for iat, nbf and auth_time.
	OrgOIDCClockSkew = 2 * time.Minute

	orgOIDCBodyLimit      = 1 << 20
	orgOIDCContextLimit   = 256
	orgOIDCSubjectLimit   = 255
	orgOIDCDiscoveryTTL   = 10 * time.Minute
	orgOIDCJWKSCooldown   = 30 * time.Second
	orgOIDCDefaultScopes  = "openid profile email"
	orgOIDCFreshMaxAgeSec = "0"
)

var (
	ErrOrgOIDCConfig           = errors.New("org oidc provider is not a valid OpenID Connect configuration")
	ErrOrgOIDCFlowInvalid      = errors.New("org oidc flow is invalid")
	ErrOrgOIDCFlowExpired      = errors.New("org oidc flow has expired")
	ErrOrgOIDCFlowReplayed     = errors.New("org oidc flow was already used")
	ErrOrgOIDCFlowMismatch     = errors.New("org oidc flow does not match this organization, provider or redirect")
	ErrOrgOIDCBindingMismatch  = errors.New("org oidc flow is not bound to this browser")
	ErrOrgOIDCProviderError    = errors.New("org oidc provider returned an error")
	ErrOrgOIDCDiscovery        = errors.New("org oidc discovery failed")
	ErrOrgOIDCIssuerMismatch   = errors.New("org oidc issuer does not match the configured issuer")
	ErrOrgOIDCTokenExchange    = errors.New("org oidc token exchange failed")
	ErrOrgOIDCNoIDToken        = errors.New("org oidc token response has no id_token")
	ErrOrgOIDCIDTokenInvalid   = errors.New("org oidc id_token is invalid")
	ErrOrgOIDCIDTokenExpired   = errors.New("org oidc id_token is expired")
	ErrOrgOIDCNonceMismatch    = errors.New("org oidc id_token nonce does not match this flow")
	ErrOrgOIDCAudienceInvalid  = errors.New("org oidc id_token audience or azp is invalid")
	ErrOrgOIDCSubjectInvalid   = errors.New("org oidc id_token subject is invalid")
	ErrOrgOIDCUserInfoMismatch = errors.New("org oidc userinfo subject does not match the id_token")
	ErrOrgOIDCFreshUnsupported = errors.New("org oidc provider did not return auth_time")
	ErrOrgOIDCFreshStale       = errors.New("org oidc authentication is not recent enough")
	ErrOrgOIDCIdentityMismatch = errors.New("org oidc subject is not the expected identity")
	ErrOrgOIDCEgressDenied     = errors.New("org oidc outbound request was denied by the egress policy")
	ErrOrgOIDCUnavailable      = errors.New("org oidc provider is unavailable")
)

// OrgOIDCError carries a stable public Kind and a private Cause. The cause may
// hold text from the IdP (error bodies, library messages); it is for the
// operator's log only, never for the browser or an audit event.
type OrgOIDCError struct {
	Kind  error
	Cause error
}

func (e *OrgOIDCError) Error() string { return e.Kind.Error() }

// Unwrap lets errors.Is match both the Kind and the Cause (for example the
// transport's egress denial).
func (e *OrgOIDCError) Unwrap() []error {
	if e.Cause == nil {
		return []error{e.Kind}
	}
	return []error{e.Kind, e.Cause}
}

func orgOIDCErr(kind error, cause error) error { return &OrgOIDCError{Kind: kind, Cause: cause} }

var orgOIDCAuditCodes = []struct {
	err  error
	code string
}{
	{ErrOrgOIDCEgressDenied, "egress_denied"},
	{ErrOrgOIDCConfig, "config_invalid"},
	{ErrOrgOIDCFlowReplayed, "flow_replayed"},
	{ErrOrgOIDCFlowExpired, "flow_expired"},
	{ErrOrgOIDCFlowMismatch, "flow_mismatch"},
	{ErrOrgOIDCBindingMismatch, "binding_mismatch"},
	{ErrOrgOIDCFlowInvalid, "flow_invalid"},
	{ErrOrgOIDCProviderError, "provider_error"},
	{ErrOrgOIDCIssuerMismatch, "issuer_mismatch"},
	{ErrOrgOIDCDiscovery, "discovery_failed"},
	{ErrOrgOIDCTokenExchange, "token_exchange_failed"},
	{ErrOrgOIDCNoIDToken, "id_token_missing"},
	{ErrOrgOIDCIDTokenExpired, "id_token_expired"},
	{ErrOrgOIDCNonceMismatch, "nonce_mismatch"},
	{ErrOrgOIDCAudienceInvalid, "audience_invalid"},
	{ErrOrgOIDCSubjectInvalid, "subject_invalid"},
	{ErrOrgOIDCIDTokenInvalid, "id_token_invalid"},
	{ErrOrgOIDCUserInfoMismatch, "userinfo_sub_mismatch"},
	{ErrOrgOIDCFreshUnsupported, "fresh_unsupported"},
	{ErrOrgOIDCFreshStale, "fresh_stale"},
	{ErrOrgOIDCIdentityMismatch, "identity_mismatch"},
	{ErrOrgOIDCUnavailable, "provider_unavailable"},
}

// OrgOIDCAuditCode maps a failure to a fixed, secret-free reason code for
// audit events. It never echoes err text, which can contain IdP-controlled
// content.
func OrgOIDCAuditCode(err error) string {
	for _, entry := range orgOIDCAuditCodes {
		if errors.Is(err, entry.err) {
			return entry.code
		}
	}
	return "unknown"
}

// OrgOIDCConfig is the validated configuration of one organization IdP. The
// redirect URI is built by the server; the browser never supplies it.
type OrgOIDCConfig struct {
	OrgID        int
	ProviderID   int
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
	// AuthStyle follows CustomOAuthProvider.AuthStyle (0 auto, 1 params, 2 header).
	AuthStyle int
}

// NewOrgOIDCConfig derives the configuration from a stored provider row.
// Endpoint fields on the row are ignored: the issuer discovery document is the
// only source of endpoints, which pins them to the configured issuer.
func NewOrgOIDCConfig(provider *model.CustomOAuthProvider, redirectURI string) (*OrgOIDCConfig, error) {
	if provider == nil || provider.OrgId <= 0 {
		return nil, orgOIDCErr(ErrOrgOIDCConfig, errors.New("provider is not bound to an organization"))
	}
	scopes := strings.Fields(provider.Scopes)
	if len(scopes) == 0 {
		scopes = strings.Fields(orgOIDCDefaultScopes)
	}
	cfg := &OrgOIDCConfig{
		OrgID:        provider.OrgId,
		ProviderID:   provider.Id,
		Issuer:       strings.TrimSpace(provider.Issuer),
		ClientID:     strings.TrimSpace(provider.ClientId),
		ClientSecret: provider.ClientSecret,
		Scopes:       scopes,
		RedirectURI:  strings.TrimSpace(redirectURI),
		AuthStyle:    provider.AuthStyle,
	}
	if wellKnown := strings.TrimSpace(provider.WellKnown); wellKnown != "" &&
		wellKnown != strings.TrimSuffix(cfg.Issuer, "/")+"/.well-known/openid-configuration" {
		return nil, orgOIDCErr(ErrOrgOIDCConfig, errors.New("well_known must be the issuer discovery URL"))
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *OrgOIDCConfig) validate() error {
	switch {
	case cfg.OrgID <= 0 || cfg.ProviderID <= 0:
		return orgOIDCErr(ErrOrgOIDCConfig, errors.New("organization and provider ids are required"))
	case cfg.ClientID == "" || cfg.ClientSecret == "":
		return orgOIDCErr(ErrOrgOIDCConfig, errors.New("a confidential client is required"))
	case !slices.Contains(cfg.Scopes, oidc.ScopeOpenID):
		return orgOIDCErr(ErrOrgOIDCConfig, errors.New("the openid scope is required: plain OAuth2 is not accepted"))
	case cfg.AuthStyle < 0 || cfg.AuthStyle > 2:
		return orgOIDCErr(ErrOrgOIDCConfig, errors.New("unknown client authentication style"))
	}
	if err := validateOrgOIDCURL(cfg.Issuer, true); err != nil {
		return orgOIDCErr(ErrOrgOIDCConfig, fmt.Errorf("issuer: %w", err))
	}
	if err := validateOrgOIDCURL(cfg.RedirectURI, false); err != nil {
		return orgOIDCErr(ErrOrgOIDCConfig, fmt.Errorf("redirect uri: %w", err))
	}
	return nil
}

// validateOrgOIDCURL accepts only absolute https URLs without credentials or a
// fragment. Issuers additionally carry no query (OIDC Core 1.0 section 2).
func validateOrgOIDCURL(raw string, issuer bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.Opaque != "" || strings.Contains(raw, "#") {
		return errors.New("must be an absolute https URL without credentials or fragment")
	}
	if issuer && parsed.RawQuery != "" {
		return errors.New("an issuer has no query")
	}
	return nil
}

// OrgOIDCProvider is the OpenID Connect relying party of one organization IdP.
// It is deliberately separate from GenericOAuthProvider: identity is the
// verified ID Token (iss+sub), never a UserInfo field mapping, and a provider
// without an ID Token is rejected. The HTTP client is injected and must be the
// restricted outbound client; this package cannot import service.
type OrgOIDCProvider struct {
	cfg    *OrgOIDCConfig
	client *http.Client
	now    func() time.Time
	// jwksCooldown is the minimum gap between JWKS fetches; it bounds how often
	// tokens with unknown key ids can make us call the IdP.
	jwksCooldown time.Duration

	mu        sync.Mutex
	discovery *orgOIDCDiscovery
}

type OrgOIDCOption func(*OrgOIDCProvider)

// WithOrgOIDCClock replaces the clock. Production code does not set it.
func WithOrgOIDCClock(now func() time.Time) OrgOIDCOption {
	return func(p *OrgOIDCProvider) { p.now = now }
}

// WithOrgOIDCJWKSCooldown overrides the minimum gap between JWKS fetches.
func WithOrgOIDCJWKSCooldown(d time.Duration) OrgOIDCOption {
	return func(p *OrgOIDCProvider) { p.jwksCooldown = d }
}

// NewOrgOIDCProvider builds a provider over client, which must be the
// restricted outbound client. A client without a transport is rejected so a
// caller cannot fall back to http.DefaultTransport by omission.
func NewOrgOIDCProvider(cfg *OrgOIDCConfig, client *http.Client, opts ...OrgOIDCOption) (*OrgOIDCProvider, error) {
	if cfg == nil {
		return nil, orgOIDCErr(ErrOrgOIDCConfig, errors.New("missing configuration"))
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if client == nil || client.Transport == nil {
		return nil, orgOIDCErr(ErrOrgOIDCConfig, errors.New("a restricted outbound client is required"))
	}
	provider := &OrgOIDCProvider{cfg: cfg, client: client, now: time.Now, jwksCooldown: orgOIDCJWKSCooldown}
	for _, opt := range opts {
		opt(provider)
	}
	return provider, nil
}

type orgOIDCDiscovery struct {
	fetchedAt     time.Time
	authEndpoint  string
	tokenEndpoint string
	userInfoURL   string
	jwksURL       string
	algs          []string
	basicAuth     bool
	issParam      bool
	verifier      *oidc.IDTokenVerifier
}

var orgOIDCSigningAlgs = []string{
	oidc.RS256, oidc.RS384, oidc.RS512, oidc.PS256, oidc.PS384, oidc.PS512,
	oidc.ES256, oidc.ES384, oidc.ES512, oidc.EdDSA,
}

// jwksGate throttles requests to the JWKS URL. go-oidc refetches the key set
// whenever a token carries an unknown kid; the gate caps that to one fetch per
// cooldown so forged kids cannot turn us into a request amplifier.
type jwksGate struct {
	next     http.RoundTripper
	jwksURL  string
	cooldown time.Duration
	now      func() time.Time
	mu       sync.Mutex
	last     time.Time
}

func (g *jwksGate) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() == g.jwksURL {
		g.mu.Lock()
		if !g.last.IsZero() && g.now().Sub(g.last) < g.cooldown {
			g.mu.Unlock()
			return nil, errors.New("jwks refresh is cooling down")
		}
		g.last = g.now()
		g.mu.Unlock()
	}
	return g.next.RoundTrip(req)
}

type orgOIDCKeyErrKey struct{}

// orgOIDCKeySet records why a key fetch failed. go-oidc flattens that error to
// text, which would hide an egress denial behind a generic invalid-token result.
type orgOIDCKeySet struct{ inner oidc.KeySet }

func (k orgOIDCKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	payload, err := k.inner.VerifySignature(ctx, jwt)
	if err != nil {
		if holder, ok := ctx.Value(orgOIDCKeyErrKey{}).(*error); ok {
			*holder = err
		}
	}
	return payload, err
}

// discover returns the cached discovery result, refetching it after the TTL.
// The document must carry exactly the configured issuer (ASVS 5.0.0 10.5.3).
func (p *OrgOIDCProvider) discover(ctx context.Context) (*orgOIDCDiscovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if d := p.discovery; d != nil && p.now().Sub(d.fetchedAt) < orgOIDCDiscoveryTTL {
		return d, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, p.client), p.cfg.Issuer)
	if err != nil {
		var mismatch *oidc.IssuerMismatchError
		if errors.As(err, &mismatch) {
			return nil, orgOIDCErr(ErrOrgOIDCIssuerMismatch, err)
		}
		return nil, orgOIDCErr(ErrOrgOIDCDiscovery, err)
	}
	var meta struct {
		JWKSURI       string   `json:"jwks_uri"`
		UserInfo      string   `json:"userinfo_endpoint"`
		ResponseTypes []string `json:"response_types_supported"`
		Algs          []string `json:"id_token_signing_alg_values_supported"`
		PKCE          []string `json:"code_challenge_methods_supported"`
		AuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
		IssParam      bool     `json:"authorization_response_iss_parameter_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCDiscovery, err)
	}
	endpoint := provider.Endpoint()
	d := &orgOIDCDiscovery{
		fetchedAt: p.now(), authEndpoint: endpoint.AuthURL, tokenEndpoint: endpoint.TokenURL,
		userInfoURL: meta.UserInfo, jwksURL: meta.JWKSURI, issParam: meta.IssParam,
	}
	for _, raw := range []string{d.authEndpoint, d.tokenEndpoint, d.jwksURL} {
		if err := validateOrgOIDCURL(raw, false); err != nil {
			return nil, orgOIDCErr(ErrOrgOIDCDiscovery, fmt.Errorf("endpoint: %w", err))
		}
	}
	if d.userInfoURL != "" {
		if err := validateOrgOIDCURL(d.userInfoURL, false); err != nil {
			return nil, orgOIDCErr(ErrOrgOIDCDiscovery, fmt.Errorf("userinfo endpoint: %w", err))
		}
	}
	if len(meta.ResponseTypes) > 0 && !slices.Contains(meta.ResponseTypes, "code") {
		return nil, orgOIDCErr(ErrOrgOIDCDiscovery, errors.New("authorization code flow is not supported"))
	}
	if !slices.Contains(meta.PKCE, "S256") {
		return nil, orgOIDCErr(ErrOrgOIDCDiscovery, errors.New("PKCE S256 is not advertised"))
	}
	if d.algs = orgOIDCAlgs(meta.Algs); len(d.algs) == 0 {
		return nil, orgOIDCErr(ErrOrgOIDCDiscovery, errors.New("no supported id_token signing algorithm"))
	}
	if d.basicAuth, err = p.chooseAuthStyle(meta.AuthMethods); err != nil {
		return nil, err
	}
	if prev := p.discovery; prev != nil && prev.jwksURL == d.jwksURL && slices.Equal(prev.algs, d.algs) {
		d.verifier = prev.verifier
	} else {
		gated := *p.client
		gated.Transport = &jwksGate{next: p.client.Transport, jwksURL: d.jwksURL, cooldown: p.jwksCooldown, now: p.now}
		keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), &gated), d.jwksURL)
		// Issuer, audience and expiry are checked in verifyIDToken so each
		// failure is distinguishable (and go-oidc's Google issuer alias cannot
		// apply); signature and algorithm stay with go-oidc.
		d.verifier = oidc.NewVerifier(p.cfg.Issuer, orgOIDCKeySet{inner: keys}, &oidc.Config{
			SupportedSigningAlgs: d.algs, SkipClientIDCheck: true, SkipExpiryCheck: true, SkipIssuerCheck: true,
		})
	}
	p.discovery = d
	return d, nil
}

// orgOIDCAlgs intersects the advertised algorithms with the allowlist. An
// omitted list means RS256, the OIDC default. HMAC and "none" are never allowed.
func orgOIDCAlgs(advertised []string) []string {
	if len(advertised) == 0 {
		return []string{oidc.RS256}
	}
	var algs []string
	for _, alg := range orgOIDCSigningAlgs {
		if slices.Contains(advertised, alg) {
			algs = append(algs, alg)
		}
	}
	return algs
}

func (p *OrgOIDCProvider) chooseAuthStyle(methods []string) (bool, error) {
	switch p.cfg.AuthStyle {
	case 1:
		return false, nil
	case 2:
		return true, nil
	}
	if len(methods) == 0 || slices.Contains(methods, "client_secret_basic") {
		return true, nil
	}
	if slices.Contains(methods, "client_secret_post") {
		return false, nil
	}
	return false, orgOIDCErr(ErrOrgOIDCDiscovery, errors.New("no supported client authentication method"))
}

// OrgOIDCBeginRequest starts a ceremony. Fresh asks the IdP to authenticate the
// user again for a sensitive operation; it requires the dashboard session the
// proof will be bound to, and may pin the subject that must come back.
type OrgOIDCBeginRequest struct {
	Fresh bool
	// UserID and SessionID bind a fresh ceremony to the requesting session.
	UserID    int
	SessionID string
	// ExpectedSubject pins the subject a fresh ceremony must return (the issuer
	// is always the provider's).
	ExpectedSubject string
	// Context is an opaque server-side binding (action, resource) echoed back
	// in the identity. It never reaches the IdP.
	Context string
}

// OrgOIDCBegin is the result of starting a ceremony.
type OrgOIDCBegin struct {
	AuthorizationURL string
	// BrowserBinding must be set as an HttpOnly, Secure, SameSite cookie scoped
	// to the callback path and sent back unchanged in OrgOIDCCallback.
	BrowserBinding string
	ExpiresAt      time.Time
}

type orgOIDCFlowPayload struct {
	OrgID           int    `json:"org_id"`
	ProviderID      int    `json:"provider_id"`
	Issuer          string `json:"issuer"`
	ClientID        string `json:"client_id"`
	RedirectURI     string `json:"redirect_uri"`
	Nonce           string `json:"nonce"`
	CodeVerifier    string `json:"code_verifier"`
	BindingHash     string `json:"binding_hash"`
	Fresh           bool   `json:"fresh"`
	ExpectedSubject string `json:"expected_subject,omitempty"`
	Context         string `json:"context,omitempty"`
	StartedAt       int64  `json:"started_at"`
}

func (p *OrgOIDCProvider) flowProvider() string {
	return fmt.Sprintf("org:%d:%d", p.cfg.OrgID, p.cfg.ProviderID)
}

func orgOIDCRandom() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func orgOIDCBindingHash(binding string) string {
	sum := sha256.Sum256([]byte(binding))
	return hex.EncodeToString(sum[:])
}

// Begin creates the single-use flow (state) carrying nonce and PKCE verifier,
// and returns the authorization URL. State, nonce and verifier are bound to
// this organization, provider, client and redirect URI, and to the browser by
// the binding cookie (ASVS 5.0.0 10.1.2, 10.2.1, 10.4.6, 10.5.1).
func (p *OrgOIDCProvider) Begin(ctx context.Context, req OrgOIDCBeginRequest) (*OrgOIDCBegin, error) {
	if len(req.Context) > orgOIDCContextLimit || len(req.ExpectedSubject) > orgOIDCSubjectLimit ||
		(req.Fresh && (req.UserID <= 0 || req.SessionID == "")) ||
		(!req.Fresh && (req.UserID != 0 || req.SessionID != "" || req.ExpectedSubject != "")) {
		return nil, orgOIDCErr(ErrOrgOIDCFlowInvalid, nil)
	}
	discovery, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	nonce, err := orgOIDCRandom()
	if err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCUnavailable, err)
	}
	binding, err := orgOIDCRandom()
	if err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCUnavailable, err)
	}
	payload := orgOIDCFlowPayload{
		OrgID: p.cfg.OrgID, ProviderID: p.cfg.ProviderID, Issuer: p.cfg.Issuer, ClientID: p.cfg.ClientID,
		RedirectURI: p.cfg.RedirectURI, Nonce: nonce, CodeVerifier: oauth2.GenerateVerifier(),
		BindingHash: orgOIDCBindingHash(binding), Fresh: req.Fresh, ExpectedSubject: req.ExpectedSubject,
		Context: req.Context, StartedAt: p.now().Unix(),
	}
	encoded, err := common.Marshal(payload)
	if err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCUnavailable, err)
	}
	intent := model.AuthFlowIntentLogin
	if req.Fresh {
		intent = model.AuthFlowIntentVerify
	}
	expiresAt := p.now().Add(OrgOIDCFlowTTL)
	state, _, err := model.CreateAuthFlow(model.AuthFlowCreate{
		Purpose: AuthFlowPurposeOrgOIDC, Provider: p.flowProvider(), Intent: intent,
		UserId: req.UserID, SessionId: req.SessionID, Payload: string(encoded), ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCUnavailable, err)
	}
	authURL, err := url.Parse(discovery.authEndpoint)
	if err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCDiscovery, err)
	}
	query := authURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", p.cfg.ClientID)
	query.Set("redirect_uri", p.cfg.RedirectURI)
	query.Set("scope", strings.Join(p.cfg.Scopes, " "))
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", oauth2.S256ChallengeFromVerifier(payload.CodeVerifier))
	query.Set("code_challenge_method", "S256")
	if req.Fresh {
		query.Set("prompt", "login")
		query.Set("max_age", orgOIDCFreshMaxAgeSec)
	}
	authURL.RawQuery = query.Encode()
	return &OrgOIDCBegin{AuthorizationURL: authURL.String(), BrowserBinding: binding, ExpiresAt: expiresAt}, nil
}

// OrgOIDCCallback is what the redirect back from the IdP delivers, plus the
// server-side facts the controller already established.
type OrgOIDCCallback struct {
	State string
	Code  string
	// Issuer is the RFC 9207 "iss" response parameter, when the IdP sends it.
	Issuer string
	// Error is the "error" response parameter. Only an allowlisted code is
	// kept; error_description is never read.
	Error string
	// BrowserBinding is the cookie value returned by Begin.
	BrowserBinding string
	// UserID and SessionID identify the dashboard session of a fresh ceremony.
	UserID    int
	SessionID string
}

// OrgOIDCIdentity is the verified result. Identity is Issuer+Subject only;
// Email and names are claims for display and are never used to match accounts.
type OrgOIDCIdentity struct {
	OrgID         int
	ProviderID    int
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Username      string
	AuthTime      *time.Time
	ACR           string
	AMR           []string
	Fresh         bool
	Context       string
	// UserInfoSkipped reports that UserInfo was unavailable; the identity is
	// still proven by the ID Token.
	UserInfoSkipped bool
}

var orgOIDCProviderErrors = []string{
	"access_denied", "invalid_request", "unauthorized_client", "unsupported_response_type", "invalid_scope",
	"server_error", "temporarily_unavailable", "interaction_required", "login_required",
	"account_selection_required", "consent_required",
}

func (p *OrgOIDCProvider) consumeFlow(cb OrgOIDCCallback) (*orgOIDCFlowPayload, error) {
	if cb.State == "" {
		return nil, orgOIDCErr(ErrOrgOIDCFlowInvalid, nil)
	}
	pending, err := model.GetAuthFlow(cb.State, model.AuthFlowMatch{Purpose: AuthFlowPurposeOrgOIDC})
	if err != nil {
		return nil, mapOrgOIDCFlowError(err)
	}
	if pending.Provider != p.flowProvider() {
		return nil, orgOIDCErr(ErrOrgOIDCFlowMismatch, nil)
	}
	match := model.AuthFlowMatch{Purpose: AuthFlowPurposeOrgOIDC, Provider: pending.Provider, Intent: pending.Intent}
	switch pending.Intent {
	case model.AuthFlowIntentVerify:
		// A fresh ceremony completes only in the session that started it. A
		// different session fails here without spending the flow.
		if cb.UserID != pending.UserId || cb.SessionID != pending.SessionId || cb.SessionID == "" {
			return nil, orgOIDCErr(ErrOrgOIDCBindingMismatch, nil)
		}
		match.UserId, match.SessionId = pending.UserId, pending.SessionId
	case model.AuthFlowIntentLogin:
		if cb.UserID != 0 || cb.SessionID != "" {
			return nil, orgOIDCErr(ErrOrgOIDCFlowMismatch, nil)
		}
	default:
		return nil, orgOIDCErr(ErrOrgOIDCFlowInvalid, nil)
	}
	flow, err := model.ConsumeAuthFlow(cb.State, match)
	if err != nil {
		return nil, mapOrgOIDCFlowError(err)
	}
	var payload orgOIDCFlowPayload
	if err := common.UnmarshalJsonStr(flow.Payload, &payload); err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCFlowInvalid, err)
	}
	if payload.Fresh != (flow.Intent == model.AuthFlowIntentVerify) {
		return nil, orgOIDCErr(ErrOrgOIDCFlowInvalid, nil)
	}
	return &payload, nil
}

func mapOrgOIDCFlowError(err error) error {
	switch {
	case errors.Is(err, model.ErrAuthFlowConsumed):
		return orgOIDCErr(ErrOrgOIDCFlowReplayed, nil)
	case errors.Is(err, model.ErrAuthFlowExpired):
		return orgOIDCErr(ErrOrgOIDCFlowExpired, nil)
	case errors.Is(err, model.ErrAuthFlowInvalid):
		return orgOIDCErr(ErrOrgOIDCFlowInvalid, nil)
	}
	return orgOIDCErr(ErrOrgOIDCUnavailable, err)
}

// Complete finishes the ceremony. The flow is spent before any outbound call,
// so a state value works once whatever happens next.
func (p *OrgOIDCProvider) Complete(ctx context.Context, cb OrgOIDCCallback) (*OrgOIDCIdentity, error) {
	payload, err := p.consumeFlow(cb)
	if err != nil {
		return nil, err
	}
	if payload.OrgID != p.cfg.OrgID || payload.ProviderID != p.cfg.ProviderID || payload.Issuer != p.cfg.Issuer ||
		payload.ClientID != p.cfg.ClientID || payload.RedirectURI != p.cfg.RedirectURI {
		return nil, orgOIDCErr(ErrOrgOIDCFlowMismatch, nil)
	}
	if payload.BindingHash == "" || cb.BrowserBinding == "" ||
		subtle.ConstantTimeCompare([]byte(payload.BindingHash), []byte(orgOIDCBindingHash(cb.BrowserBinding))) != 1 {
		return nil, orgOIDCErr(ErrOrgOIDCBindingMismatch, nil)
	}
	if cb.Error != "" {
		code := "unknown"
		if slices.Contains(orgOIDCProviderErrors, cb.Error) {
			code = cb.Error
		}
		return nil, orgOIDCErr(ErrOrgOIDCProviderError, errors.New(code))
	}
	if cb.Code == "" {
		return nil, orgOIDCErr(ErrOrgOIDCFlowInvalid, nil)
	}
	discovery, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	if (cb.Issuer != "" && cb.Issuer != p.cfg.Issuer) || (discovery.issParam && cb.Issuer == "") {
		return nil, orgOIDCErr(ErrOrgOIDCIssuerMismatch, nil)
	}
	token, err := p.exchangeCode(ctx, discovery, cb.Code, payload.CodeVerifier)
	if err != nil {
		return nil, err
	}
	identity, err := p.verifyIDToken(ctx, discovery, token, payload)
	if err != nil {
		return nil, err
	}
	if err := p.mergeUserInfo(ctx, discovery, token, identity); err != nil {
		return nil, err
	}
	return identity, nil
}

type orgOIDCTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
}

func (p *OrgOIDCProvider) exchangeCode(ctx context.Context, d *orgOIDCDiscovery, code, verifier string) (*orgOIDCTokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURI},
		"code_verifier": {verifier},
	}
	if !d.basicAuth {
		form.Set("client_id", p.cfg.ClientID)
		form.Set("client_secret", p.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCTokenExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if d.basicAuth {
		// RFC 6749 section 2.3.1: credentials are form-urlencoded before Basic encoding.
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}
	body, status, err := p.doJSON(req)
	if err != nil {
		return nil, orgOIDCErr(orgOIDCTransportKind(err, ErrOrgOIDCTokenExchange), err)
	}
	if status != http.StatusOK {
		return nil, orgOIDCErr(ErrOrgOIDCTokenExchange, fmt.Errorf("token endpoint status %d", status))
	}
	var token orgOIDCTokenResponse
	if err := common.Unmarshal(body, &token); err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCTokenExchange, err)
	}
	if token.IDToken == "" {
		return nil, orgOIDCErr(ErrOrgOIDCNoIDToken, nil)
	}
	return &token, nil
}

// orgOIDCTransportKind keeps an egress denial visible as its own kind.
func orgOIDCTransportKind(err error, fallback error) error {
	if errors.Is(err, ErrOrgOIDCEgressDenied) {
		return ErrOrgOIDCEgressDenied
	}
	return fallback
}

func (p *OrgOIDCProvider) doJSON(req *http.Request) ([]byte, int, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, orgOIDCBodyLimit+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > orgOIDCBodyLimit {
		return nil, resp.StatusCode, errors.New("response body is too large")
	}
	return body, resp.StatusCode, nil
}

type orgOIDCIDTokenClaims struct {
	AuthorizedParty   string   `json:"azp"`
	NotBefore         *float64 `json:"nbf"`
	AuthTime          *float64 `json:"auth_time"`
	ACR               string   `json:"acr"`
	AMR               []string `json:"amr"`
	Email             string   `json:"email"`
	EmailVerified     any      `json:"email_verified"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
}

func orgOIDCUnix(seconds float64) time.Time {
	whole := int64(seconds)
	return time.Unix(whole, int64((seconds-float64(whole))*1e9))
}

func orgOIDCBool(v any) bool {
	switch value := v.(type) {
	case bool:
		return value
	case string:
		return value == "true"
	}
	return false
}

// verifyIDToken checks the ID Token against this ceremony: signature (go-oidc,
// allowlisted algorithms, JWKS with one throttled refetch on an unknown kid),
// exact issuer, audience and azp, exp/nbf/iat, nonce and at_hash, then the
// fresh-authentication rule. The identity it returns is the token's iss+sub.
func (p *OrgOIDCProvider) verifyIDToken(ctx context.Context, d *orgOIDCDiscovery, token *orgOIDCTokenResponse, flow *orgOIDCFlowPayload) (*OrgOIDCIdentity, error) {
	var keyErr error
	verifyCtx := context.WithValue(oidc.ClientContext(ctx, p.client), orgOIDCKeyErrKey{}, &keyErr)
	verified, err := d.verifier.Verify(verifyCtx, token.IDToken)
	if err != nil {
		if keyErr != nil {
			err = errors.Join(err, keyErr)
		}
		return nil, orgOIDCErr(orgOIDCTransportKind(err, ErrOrgOIDCIDTokenInvalid), err)
	}
	now := p.now()
	if verified.Issuer != p.cfg.Issuer {
		return nil, orgOIDCErr(ErrOrgOIDCIssuerMismatch, nil)
	}
	if !slices.Contains(verified.Audience, p.cfg.ClientID) {
		return nil, orgOIDCErr(ErrOrgOIDCAudienceInvalid, nil)
	}
	var claims orgOIDCIDTokenClaims
	if err := verified.Claims(&claims); err != nil {
		return nil, orgOIDCErr(ErrOrgOIDCIDTokenInvalid, err)
	}
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != p.cfg.ClientID ||
		len(verified.Audience) > 1 && claims.AuthorizedParty == "" {
		return nil, orgOIDCErr(ErrOrgOIDCAudienceInvalid, nil)
	}
	switch {
	case verified.Expiry.IsZero() || verified.IssuedAt.IsZero():
		return nil, orgOIDCErr(ErrOrgOIDCIDTokenInvalid, errors.New("exp and iat are required"))
	case !verified.Expiry.After(now):
		return nil, orgOIDCErr(ErrOrgOIDCIDTokenExpired, nil)
	case verified.IssuedAt.After(now.Add(OrgOIDCClockSkew)) || !verified.IssuedAt.Before(verified.Expiry):
		return nil, orgOIDCErr(ErrOrgOIDCIDTokenInvalid, errors.New("iat is not plausible"))
	case claims.NotBefore != nil && orgOIDCUnix(*claims.NotBefore).After(now.Add(OrgOIDCClockSkew)):
		return nil, orgOIDCErr(ErrOrgOIDCIDTokenInvalid, errors.New("token is not yet valid"))
	}
	if verified.Nonce == "" || flow.Nonce == "" ||
		subtle.ConstantTimeCompare([]byte(verified.Nonce), []byte(flow.Nonce)) != 1 {
		return nil, orgOIDCErr(ErrOrgOIDCNonceMismatch, nil)
	}
	if verified.Subject == "" || len(verified.Subject) > orgOIDCSubjectLimit {
		return nil, orgOIDCErr(ErrOrgOIDCSubjectInvalid, nil)
	}
	if token.AccessToken != "" && verified.AccessTokenHash != "" {
		if err := verified.VerifyAccessToken(token.AccessToken); err != nil {
			return nil, orgOIDCErr(ErrOrgOIDCIDTokenInvalid, err)
		}
	}
	if flow.ExpectedSubject != "" && flow.ExpectedSubject != verified.Subject {
		return nil, orgOIDCErr(ErrOrgOIDCIdentityMismatch, nil)
	}
	identity := &OrgOIDCIdentity{
		OrgID: p.cfg.OrgID, ProviderID: p.cfg.ProviderID, Issuer: verified.Issuer, Subject: verified.Subject,
		Email: claims.Email, EmailVerified: claims.Email != "" && orgOIDCBool(claims.EmailVerified),
		Name: claims.Name, Username: claims.PreferredUsername, ACR: claims.ACR, AMR: claims.AMR,
		Fresh: flow.Fresh, Context: flow.Context,
	}
	if claims.AuthTime != nil {
		authTime := orgOIDCUnix(*claims.AuthTime)
		identity.AuthTime = &authTime
	}
	if flow.Fresh {
		// The ID Token must show a recent interactive authentication by this
		// user. An IdP that omits auth_time cannot prove that (ASVS 5.0.0 6.8.4).
		switch {
		case identity.AuthTime == nil:
			return nil, orgOIDCErr(ErrOrgOIDCFreshUnsupported, nil)
		case identity.AuthTime.After(now.Add(OrgOIDCClockSkew)):
			return nil, orgOIDCErr(ErrOrgOIDCIDTokenInvalid, errors.New("auth_time is in the future"))
		case now.Sub(*identity.AuthTime) > OrgOIDCFreshMaxAge:
			return nil, orgOIDCErr(ErrOrgOIDCFreshStale, nil)
		}
	}
	return identity, nil
}

// mergeUserInfo asks UserInfo only for display claims. Its sub must equal the
// ID Token sub (OIDC Core 5.3.2); a missing or failing endpoint is skipped, a
// mismatch is fatal, and nothing from it can change the identity.
func (p *OrgOIDCProvider) mergeUserInfo(ctx context.Context, d *orgOIDCDiscovery, token *orgOIDCTokenResponse, identity *OrgOIDCIdentity) error {
	if d.userInfoURL == "" || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "bearer") {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.userInfoURL, nil)
	if err != nil {
		return orgOIDCErr(ErrOrgOIDCUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	body, status, err := p.doJSON(req)
	if err != nil {
		if errors.Is(err, ErrOrgOIDCEgressDenied) {
			return orgOIDCErr(ErrOrgOIDCEgressDenied, err)
		}
		identity.UserInfoSkipped = true
		return nil
	}
	if status != http.StatusOK {
		identity.UserInfoSkipped = true
		return nil
	}
	var info struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     any    `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := common.Unmarshal(body, &info); err != nil {
		identity.UserInfoSkipped = true
		return nil
	}
	if info.Subject != identity.Subject {
		return orgOIDCErr(ErrOrgOIDCUserInfoMismatch, nil)
	}
	if identity.Email == "" && info.Email != "" {
		identity.Email, identity.EmailVerified = info.Email, orgOIDCBool(info.EmailVerified)
	}
	if identity.Name == "" {
		identity.Name = info.Name
	}
	if identity.Username == "" {
		identity.Username = info.PreferredUsername
	}
	return nil
}
