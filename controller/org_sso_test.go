package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/oauth"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fake IdP listens on 127.0.0.1 over TLS, but is addressed as
// example.com:<port>. The outbound client resolves that name through a fake
// resolver to a public address, so the destination policy is exercised on the
// public address and only the final TCP dial is redirected to the listener.
// Loopback is never allowed: the production client denies the same listener.

const (
	orgSSOHost        = "example.com"
	orgSSOPublicIP    = "93.184.216.34"
	orgSSOClientID    = "org-client"
	orgSSOSecret      = "org-secret-value"
	orgSSOAccessToken = "access-token-1"
)

var (
	orgSSOKeysOnce sync.Once
	orgSSOKeyA     *rsa.PrivateKey
	orgSSOKeyB     *rsa.PrivateKey
)

func orgSSOKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	orgSSOKeysOnce.Do(func() {
		var err error
		if orgSSOKeyA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if orgSSOKeyB, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return orgSSOKeyA, orgSSOKeyB
}

type orgIDPGrant struct {
	clientID, redirectURI, challenge, nonce, state string
	used                                           bool
}

// orgIDPSigner is how the next ID Token is signed; tests override it to forge.
type orgIDPSigner struct {
	method jwt.SigningMethod
	key    any
	kid    string
}

type orgIDP struct {
	t      *testing.T
	server *httptest.Server
	issuer string
	port   int

	mu        sync.Mutex
	keys      map[string]*rsa.PrivateKey // kid -> key served by the JWKS
	hits      map[string]int
	grants    map[string]*orgIDPGrant
	authTime  func(now time.Time) *time.Time
	claims    func(claims jwt.MapClaims)
	signer    func(s *orgIDPSigner)
	discovery func(doc map[string]any)
	userinfo  func(w http.ResponseWriter)
	omitID    bool
	tokenCode int
	codeSeq   int
	minted    []string
	rewrite   func(token string) string
	authStyle string // how the last token request authenticated: basic or post
}

// with runs fn while the IdP handlers are locked out, so a test can change the
// IdP between requests without racing its server goroutines.
func (idp *orgIDP) with(fn func()) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	fn()
}

func newOrgIDP(t *testing.T) *orgIDP {
	t.Helper()
	keyA, _ := orgSSOKeys(t)
	idp := &orgIDP{
		t: t, keys: map[string]*rsa.PrivateKey{"key-a": keyA}, hits: map[string]int{}, grants: map[string]*orgIDPGrant{},
		authTime: func(now time.Time) *time.Time { v := now.Add(-time.Minute); return &v },
	}
	idp.server = httptest.NewTLSServer(http.HandlerFunc(idp.serve))
	t.Cleanup(idp.server.Close)
	idp.port = orgSSOPort(t, idp.server)
	idp.issuer = "https://" + net.JoinHostPort(orgSSOHost, strconv.Itoa(idp.port))
	return idp
}

func orgSSOPort(t *testing.T, server *httptest.Server) int {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(parsed.Port())
	require.NoError(t, err)
	return port
}

func (idp *orgIDP) hitCount(path string) int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.hits[path]
}

func orgIDPJWK(kid string, key *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func orgIDPWrite(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := common.Marshal(v)
	_, _ = w.Write(body)
}

func (idp *orgIDP) serve(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	idp.hits[r.URL.Path]++
	idp.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		doc := map[string]any{
			"issuer": idp.issuer, "authorization_endpoint": idp.issuer + "/authorize", "token_endpoint": idp.issuer + "/token",
			"userinfo_endpoint": idp.issuer + "/userinfo", "jwks_uri": idp.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
			"subject_types_supported":               []string{"public"},
		}
		idp.mu.Lock()
		if idp.discovery != nil {
			idp.discovery(doc)
		}
		idp.mu.Unlock()
		orgIDPWrite(w, http.StatusOK, doc)
	case "/jwks":
		idp.mu.Lock()
		keys := make([]any, 0, len(idp.keys))
		for kid, key := range idp.keys {
			keys = append(keys, orgIDPJWK(kid, key))
		}
		idp.mu.Unlock()
		orgIDPWrite(w, http.StatusOK, map[string]any{"keys": keys})
	case "/token":
		idp.token(w, r)
	case "/userinfo":
		idp.mu.Lock()
		handler := idp.userinfo
		idp.mu.Unlock()
		if handler != nil {
			handler(w)
			return
		}
		orgIDPWrite(w, http.StatusOK, map[string]any{"sub": "user-1", "email": "userinfo@example.com", "name": "From UserInfo"})
	default:
		http.NotFound(w, r)
	}
}

// authorize plays the browser and IdP up to the redirect: it validates the
// authorization request the relying party built and returns the code.
func (idp *orgIDP) authorize(authURL string, cfg orgSSOClientConfig) (code, state string, query url.Values) {
	idp.t.Helper()
	parsed, err := url.Parse(authURL)
	require.NoError(idp.t, err)
	query = parsed.Query()
	require.Equal(idp.t, idp.issuer+"/authorize", parsed.Scheme+"://"+parsed.Host+parsed.Path)
	require.Equal(idp.t, "code", query.Get("response_type"))
	require.Equal(idp.t, cfg.clientID, query.Get("client_id"))
	require.Equal(idp.t, "S256", query.Get("code_challenge_method"))
	require.NotEmpty(idp.t, query.Get("code_challenge"))
	require.NotEmpty(idp.t, query.Get("nonce"))
	require.Contains(idp.t, strings.Fields(query.Get("scope")), "openid")
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.codeSeq++
	code = fmt.Sprintf("code-%d", idp.codeSeq)
	idp.grants[code] = &orgIDPGrant{
		clientID: query.Get("client_id"), redirectURI: query.Get("redirect_uri"),
		challenge: query.Get("code_challenge"), nonce: query.Get("nonce"), state: query.Get("state"),
	}
	return code, query.Get("state"), query
}

func (idp *orgIDP) token(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if idp.tokenCode != 0 {
		orgIDPWrite(w, idp.tokenCode, map[string]any{"error": "server_error", "error_description": "secret=" + orgSSOSecret})
		return
	}
	require.NoError(idp.t, r.ParseForm())
	clientID, secret, ok := r.BasicAuth()
	idp.authStyle = "basic"
	if !ok {
		clientID, secret, idp.authStyle = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret"), "post"
	}
	if clientID != orgSSOClientID || secret != orgSSOSecret {
		orgIDPWrite(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}
	grant := idp.grants[r.PostForm.Get("code")]
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case r.PostForm.Get("grant_type") != "authorization_code", grant == nil, grant.used:
		orgIDPWrite(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	case grant.redirectURI != r.PostForm.Get("redirect_uri"),
		base64.RawURLEncoding.EncodeToString(sum[:]) != grant.challenge:
		orgIDPWrite(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	grant.used = true
	response := map[string]any{"access_token": orgSSOAccessToken, "token_type": "Bearer", "expires_in": 300}
	if !idp.omitID {
		response["id_token"] = idp.mintLocked(grant)
	}
	orgIDPWrite(w, http.StatusOK, response)
}

// mintLocked builds and signs the ID Token for grant; claims and signer hooks
// let a test forge any deviation.
func (idp *orgIDP) mintLocked(grant *orgIDPGrant) string {
	now := time.Now()
	atHash := sha256.Sum256([]byte(orgSSOAccessToken))
	claims := jwt.MapClaims{
		"iss": idp.issuer, "sub": "user-1", "aud": orgSSOClientID, "exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(), "nonce": grant.nonce, "email": "user@corp.example", "email_verified": true,
		"name": "Corp User", "at_hash": base64.RawURLEncoding.EncodeToString(atHash[:16]),
	}
	if at := idp.authTime(now); at != nil {
		claims["auth_time"] = at.Unix()
	}
	if idp.claims != nil {
		idp.claims(claims)
	}
	signer := &orgIDPSigner{method: jwt.SigningMethodRS256, key: idp.keys["key-a"], kid: "key-a"}
	if idp.signer != nil {
		idp.signer(signer)
	}
	token := jwt.NewWithClaims(signer.method, claims)
	token.Header["kid"] = signer.kid
	signed, err := token.SignedString(signer.key)
	require.NoError(idp.t, err)
	idp.minted = append(idp.minted, signed)
	if idp.rewrite != nil {
		return idp.rewrite(signed)
	}
	return signed
}

type orgSSOClientConfig struct{ clientID string }

// orgSSOResolver is the fake DNS: host -> addresses. Lookups are counted so a
// test can prove the policy resolves once and dials the checked address.
type orgSSOResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	lookups map[string]int
}

func newOrgSSOResolver(answers map[string][]string) *orgSSOResolver {
	return &orgSSOResolver{answers: answers, lookups: map[string]int{}}
}

func (r *orgSSOResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups[host]++
	values, ok := r.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	addrs := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		addrs = append(addrs, netip.MustParseAddr(value))
	}
	return addrs, nil
}

func (r *orgSSOResolver) lookupCount(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups[host]
}

// orgSSODial routes the checked public address to a local listener chosen by
// destination port. It records what the policy handed it.
type orgSSODial struct {
	mu        sync.Mutex
	listeners map[string]string // port -> real listener address
	dialed    []string
}

func (d *orgSSODial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.dialed = append(d.dialed, address)
	target, ok := d.listeners[port]
	d.mu.Unlock()
	if !ok {
		return nil, errors.New("connection refused")
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func (d *orgSSODial) dialedAddresses() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.dialed...)
}

const orgSSORedirectURI = "https://console.example.org/api/org/sso/callback"

type orgSSO struct {
	t        *testing.T
	idp      *orgIDP
	resolver *orgSSOResolver
	dial     *orgSSODial
	client   *http.Client
	row      *model.CustomOAuthProvider
}

// setupOrgSSO builds the database, fake IdP, restricted client and the
// platform rule that opens the IdP's port. The egress setting is restored
// afterwards.
func setupOrgSSO(t *testing.T) *orgSSO {
	t.Helper()
	setupAuthFlowControllerTest(t)
	previous := *system_setting.GetOrgOIDCEgressSetting()
	t.Cleanup(func() { *system_setting.GetOrgOIDCEgressSetting() = previous })

	idp := newOrgIDP(t)
	*system_setting.GetOrgOIDCEgressSetting() = system_setting.OrgOIDCEgressSetting{
		Rules: []system_setting.OrgOIDCEgressRule{{Host: orgSSOHost, Ports: []int{idp.port}}},
	}
	resolver := newOrgSSOResolver(map[string][]string{orgSSOHost: {orgSSOPublicIP}})
	dial := &orgSSODial{listeners: map[string]string{strconv.Itoa(idp.port): idp.server.Listener.Addr().String()}}
	roots := x509.NewCertPool()
	roots.AddCert(idp.server.Certificate())
	return &orgSSO{
		t: t, idp: idp, resolver: resolver, dial: dial,
		client: service.NewOrgOIDCHTTPClientForTest(service.OrgOIDCClientOptions{Resolver: resolver, DialAddr: dial.dial, RootCAs: roots}),
		row: &model.CustomOAuthProvider{
			Id: 7, OrgId: 3, Issuer: idp.issuer, ClientId: orgSSOClientID, ClientSecret: orgSSOSecret,
			Scopes: "openid profile email",
		},
	}
}

func (f *orgSSO) config() *oauth.OrgOIDCConfig {
	f.t.Helper()
	cfg, err := oauth.NewOrgOIDCConfig(f.row, orgSSORedirectURI)
	require.NoError(f.t, err)
	return cfg
}

// provider builds a relying party. The JWKS cooldown is off unless a test sets it.
func (f *orgSSO) provider(opts ...oauth.OrgOIDCOption) *oauth.OrgOIDCProvider {
	f.t.Helper()
	opts = append([]oauth.OrgOIDCOption{oauth.WithOrgOIDCJWKSCooldown(0)}, opts...)
	p, err := oauth.NewOrgOIDCProvider(f.config(), f.client, opts...)
	require.NoError(f.t, err)
	return p
}

// orgSSOCeremony is one Begin plus the IdP's authorization step.
type orgSSOCeremony struct {
	begin *oauth.OrgOIDCBegin
	code  string
	state string
	query url.Values
}

func (f *orgSSO) start(p *oauth.OrgOIDCProvider, req oauth.OrgOIDCBeginRequest) orgSSOCeremony {
	f.t.Helper()
	begin, err := p.Begin(context.Background(), req)
	require.NoError(f.t, err)
	code, state, query := f.idp.authorize(begin.AuthorizationURL, orgSSOClientConfig{clientID: orgSSOClientID})
	return orgSSOCeremony{begin: begin, code: code, state: state, query: query}
}

func (c orgSSOCeremony) callback() oauth.OrgOIDCCallback {
	return oauth.OrgOIDCCallback{State: c.state, Code: c.code, BrowserBinding: c.begin.BrowserBinding}
}

// login runs a whole non-fresh ceremony; edit may change the callback.
func (f *orgSSO) login(p *oauth.OrgOIDCProvider, edit func(*oauth.OrgOIDCCallback)) (*oauth.OrgOIDCIdentity, error) {
	f.t.Helper()
	cb := f.start(p, oauth.OrgOIDCBeginRequest{}).callback()
	if edit != nil {
		edit(&cb)
	}
	return p.Complete(context.Background(), cb)
}

var orgSSOFreshSession = oauth.OrgOIDCBeginRequest{Fresh: true, UserID: 11, SessionID: "session-11", ExpectedSubject: "user-1", Context: "action=sso.update;org=3"}

func orgSSOFreshCallback(c orgSSOCeremony) oauth.OrgOIDCCallback {
	cb := c.callback()
	cb.UserID, cb.SessionID = 11, "session-11"
	return cb
}

// requireOrgSSOKind asserts the failure category and that its text carries no secret.
func requireOrgSSOKind(t *testing.T, err error, kind error) {
	t.Helper()
	require.Error(t, err)
	assert.ErrorIs(t, err, kind)
	assert.NotContains(t, err.Error(), orgSSOSecret)
	assert.NotContains(t, oauth.OrgOIDCAuditCode(err), orgSSOSecret)
}

// orgSSOGet sends GET url through client and returns the body or the error.
func orgSSOGet(client *http.Client, target string, header http.Header) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	for name, values := range header {
		req.Header[name] = values
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func orgSSOPortOf(t *testing.T, server *httptest.Server) string {
	t.Helper()
	return strconv.Itoa(orgSSOPort(t, server))
}

func mustAtoi(t *testing.T, values ...string) []int {
	t.Helper()
	out := make([]int, 0, len(values))
	for _, value := range values {
		n, err := strconv.Atoi(value)
		require.NoError(t, err)
		out = append(out, n)
	}
	return out
}

// orgSSORebinder answers each lookup with the next entry, like a DNS server
// that changes its answer after the first query.
type orgSSORebinder struct {
	answers [][]string
	calls   int
}

func (r *orgSSORebinder) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	index := min(r.calls, len(r.answers)-1)
	r.calls++
	addrs := make([]netip.Addr, 0)
	for _, value := range r.answers[index] {
		addrs = append(addrs, netip.MustParseAddr(value))
	}
	return addrs, nil
}

func orgSSOSetEgress(t *testing.T, setting system_setting.OrgOIDCEgressSetting) {
	t.Helper()
	previous := *system_setting.GetOrgOIDCEgressSetting()
	t.Cleanup(func() { *system_setting.GetOrgOIDCEgressSetting() = previous })
	*system_setting.GetOrgOIDCEgressSetting() = setting
}

// TestOrgOIDCOutboundBoundary covers the destination policy of the client that
// discovery, token, UserInfo and JWKS share: scheme, port, every DNS answer,
// the pinned dial, redirects, proxies, response size and platform exceptions.
func TestOrgOIDCOutboundBoundary(t *testing.T) {
	t.Run("production client refuses loopback and local names", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("reached")) }))
		defer server.Close()
		_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
		portNumber, _ := strconv.Atoi(port)
		// Even a platform rule naming the loopback host and port cannot open it.
		orgSSOSetEgress(t, system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{
			{Host: "127.0.0.1", Ports: []int{portNumber}, CIDRs: []string{"127.0.0.0/8"}},
			{Host: "localhost", Ports: []int{portNumber}},
		}})
		for _, target := range []string{"https://127.0.0.1:" + port + "/", "https://localhost:" + port + "/", "https://[::1]:" + port + "/"} {
			_, err := orgSSOGet(service.OrgOIDCHTTPClient(), target, nil)
			assert.ErrorIs(t, err, oauth.ErrOrgOIDCEgressDenied, target)
		}
	})

	policy := func(rules ...system_setting.OrgOIDCEgressRule) system_setting.OrgOIDCEgressSetting {
		return system_setting.OrgOIDCEgressSetting{Rules: rules}
	}
	rule := func(host string, ports []int, cidrs ...string) system_setting.OrgOIDCEgressRule {
		return system_setting.OrgOIDCEgressRule{Host: host, Ports: ports, CIDRs: cidrs}
	}
	answers := map[string][]string{
		"public.test": {"93.184.216.34"}, "dual.test": {"93.184.216.34", "2606:2800:220:1::1"},
		"loop.test": {"127.0.0.1"}, "mixed.test": {"93.184.216.34", "127.0.0.1"}, "mixed6.test": {"93.184.216.34", "::1"},
		"meta.test": {"169.254.169.254"}, "alibaba.test": {"100.100.100.200"}, "azure.test": {"168.63.129.16"},
		"private.test": {"10.1.2.3"}, "private2.test": {"10.9.9.9"}, "ula.test": {"fd12:3456::7"},
		"mapped.test": {"::ffff:127.0.0.1"}, "nat64.test": {"64:ff9b::7f00:1"}, "sixtofour.test": {"2002:7f00:1::1"},
		"awsv6.test": {"fd00:ec2::254"}, "linklocal6.test": {"fe80::1"}, "unspecified.test": {"0.0.0.0"},
		// A hosts file or resolver can map these names anywhere; the name itself is refused.
		"localhost": {"93.184.216.34"}, "idp.localhost": {"93.184.216.34"},
	}
	tests := []struct {
		name   string
		target string
		setup  system_setting.OrgOIDCEgressSetting
		dialed string // expected dial target; empty means denied
	}{
		{name: "public host", target: "https://public.test/x", dialed: "93.184.216.34:443"},
		{name: "public host with an AAAA answer", target: "https://dual.test/x", dialed: "93.184.216.34:443"},
		{name: "plain http", target: "http://public.test/x"},
		{name: "credentials in the URL", target: "https://user:pw@public.test/x"},
		{name: "non-default port needs a rule", target: "https://public.test:8443/x"},
		{name: "port opened for that host", target: "https://public.test:8443/x", setup: policy(rule("public.test", []int{8443})), dialed: "93.184.216.34:8443"},
		{name: "rule for another port", target: "https://public.test:9443/x", setup: policy(rule("public.test", []int{8443}))},
		{name: "rule for another host", target: "https://dual.test:8443/x", setup: policy(rule("public.test", []int{8443}))},
		{name: "dns failure", target: "https://missing.test/x"},
		{name: "loopback literal", target: "https://127.0.0.1/x"},
		{name: "ipv6 loopback literal", target: "https://[::1]/x"},
		{name: "ipv4-mapped loopback literal", target: "https://[::ffff:127.0.0.1]/x"},
		{name: "decimal loopback literal", target: "https://2130706433/x"},
		{name: "hex loopback literal", target: "https://0x7f000001/x"},
		{name: "metadata literal", target: "https://169.254.169.254/x"},
		{name: "localhost name", target: "https://localhost/x"},
		{name: "subdomain of localhost", target: "https://idp.localhost/x"},
		{name: "name resolving to loopback", target: "https://loop.test/x"},
		{name: "name resolving to metadata", target: "https://meta.test/x"},
		{name: "alibaba metadata", target: "https://alibaba.test/x"},
		{name: "azure wire server", target: "https://azure.test/x"},
		{name: "aws ipv6 metadata", target: "https://awsv6.test/x"},
		{name: "ipv6 link-local", target: "https://linklocal6.test/x"},
		{name: "unspecified address", target: "https://unspecified.test/x"},
		{name: "mapped loopback answer", target: "https://mapped.test/x"},
		{name: "nat64 embedded loopback", target: "https://nat64.test/x"},
		{name: "6to4 embedded loopback", target: "https://sixtofour.test/x"},
		{name: "public and loopback answers", target: "https://mixed.test/x"},
		{name: "public and ipv6 loopback answers", target: "https://mixed6.test/x"},
		{name: "private answer without a rule", target: "https://private.test/x"},
		{name: "private literal without a rule", target: "https://10.1.2.3/x"},
		{name: "private answer with a matching rule", target: "https://private.test/x", setup: policy(rule("private.test", nil, "10.0.0.0/8")), dialed: "10.1.2.3:443"},
		{name: "private answer outside the rule CIDR", target: "https://private2.test/x", setup: policy(rule("private2.test", nil, "10.1.0.0/16"))},
		{name: "private rule without CIDRs", target: "https://private.test/x", setup: policy(rule("private.test", nil))},
		{name: "private rule for the wrong port", target: "https://private.test:8443/x", setup: policy(rule("private.test", []int{443}, "10.0.0.0/8"))},
		{name: "private literal with a rule", target: "https://10.1.2.3/x", setup: policy(rule("10.1.2.3", nil, "10.1.2.0/24")), dialed: "10.1.2.3:443"},
		{name: "ula answer with a rule", target: "https://ula.test/x", setup: policy(rule("ula.test", nil, "fd12::/16")), dialed: "[fd12:3456::7]:443"},
		{name: "rule cannot open metadata", target: "https://meta.test/x", setup: policy(rule("meta.test", nil, "169.254.0.0/16"))},
		{name: "rule cannot open loopback", target: "https://loop.test/x", setup: policy(rule("loop.test", nil, "127.0.0.0/8", "0.0.0.0/0"))},
		{name: "rule cannot open the whole internet", target: "https://private.test/x", setup: policy(rule("private.test", nil, "0.0.0.0/0"))},
		{name: "rule cannot open alibaba metadata", target: "https://alibaba.test/x", setup: policy(rule("alibaba.test", nil, "100.64.0.0/10"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orgSSOSetEgress(t, tt.setup)
			dial := &orgSSODial{listeners: map[string]string{}}
			var dialed []string
			client := service.NewOrgOIDCHTTPClientForTest(service.OrgOIDCClientOptions{
				Resolver: newOrgSSOResolver(answers),
				DialAddr: func(ctx context.Context, network, address string) (net.Conn, error) {
					dialed = append(dialed, address)
					return dial.dial(ctx, network, address)
				},
			})
			_, err := orgSSOGet(client, tt.target, nil)
			if tt.dialed == "" {
				assert.ErrorIs(t, err, oauth.ErrOrgOIDCEgressDenied)
				assert.Empty(t, dialed, "a denied destination is never dialed")
				return
			}
			// The only failure left is the missing listener: a checked address was dialed.
			assert.NotErrorIs(t, err, oauth.ErrOrgOIDCEgressDenied)
			require.NotEmpty(t, dialed)
			assert.Equal(t, tt.dialed, dialed[0])
			for _, address := range dialed {
				assert.NotContains(t, address, "127.0.0.1", "only checked addresses are dialed")
			}
		})
	}

	t.Run("one lookup, the checked address is the one dialed", func(t *testing.T) {
		orgSSOSetEgress(t, system_setting.OrgOIDCEgressSetting{})
		rebinding := &orgSSORebinder{answers: [][]string{{"93.184.216.34"}, {"127.0.0.1"}}}
		var dialed []string
		client := service.NewOrgOIDCHTTPClientForTest(service.OrgOIDCClientOptions{
			Resolver: rebinding,
			DialAddr: func(_ context.Context, _, address string) (net.Conn, error) {
				dialed = append(dialed, address)
				return nil, errors.New("connection refused")
			},
		})
		_, err := orgSSOGet(client, "https://rebind.test/x", nil)
		require.Error(t, err)
		assert.Equal(t, 1, rebinding.calls, "a second lookup could be answered with a different address")
		assert.Equal(t, []string{"93.184.216.34:443"}, dialed)
	})

	t.Run("redirects", func(t *testing.T) {
		var hitsB sync.Map
		serverB := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count, _ := hitsB.LoadOrStore("n", new(int))
			*count.(*int)++
			_, _ = w.Write([]byte("B auth=" + r.Header.Get("Authorization") + " cookie=" + r.Header.Get("Cookie")))
		}))
		defer serverB.Close()
		var serverA *httptest.Server
		var hitsA int
		var muA sync.Mutex
		serverA = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			muA.Lock()
			hitsA++
			muA.Unlock()
			redirect := func(to string, code int) { http.Redirect(w, r, to, code) }
			switch r.URL.Path {
			case "/to-b":
				redirect("https://"+orgSSOHost+":"+orgSSOPortOf(t, serverB)+"/", http.StatusFound)
			case "/to-self":
				redirect("/same", http.StatusFound)
			case "/same":
				_, _ = w.Write([]byte("A auth=" + r.Header.Get("Authorization")))
			case "/to-metadata":
				redirect("https://169.254.169.254/latest/meta-data/", http.StatusFound)
			case "/to-loopback":
				redirect("https://127.0.0.1:"+orgSSOPortOf(t, serverB)+"/", http.StatusFound)
			case "/to-http":
				redirect("http://"+orgSSOHost+"/", http.StatusFound)
			case "/loop":
				redirect("/loop", http.StatusFound)
			case "/post307":
				redirect("https://"+orgSSOHost+":"+orgSSOPortOf(t, serverB)+"/", http.StatusTemporaryRedirect)
			}
		}))
		defer serverA.Close()
		portA, portB := orgSSOPortOf(t, serverA), orgSSOPortOf(t, serverB)
		roots := x509.NewCertPool()
		roots.AddCert(serverA.Certificate())
		newClient := func(maxRedirects int) *http.Client {
			orgSSOSetEgress(t, system_setting.OrgOIDCEgressSetting{
				Rules:        []system_setting.OrgOIDCEgressRule{{Host: orgSSOHost, Ports: mustAtoi(t, portA, portB)}},
				MaxRedirects: maxRedirects,
			})
			dial := &orgSSODial{listeners: map[string]string{portA: serverA.Listener.Addr().String(), portB: serverB.Listener.Addr().String()}}
			return service.NewOrgOIDCHTTPClientForTest(service.OrgOIDCClientOptions{
				Resolver: newOrgSSOResolver(map[string][]string{orgSSOHost: {orgSSOPublicIP}}), DialAddr: dial.dial, RootCAs: roots,
			})
		}
		urlA := func(path string) string { return "https://" + orgSSOHost + ":" + portA + path }
		bHits := func() int {
			count, ok := hitsB.Load("n")
			if !ok {
				return 0
			}
			return *count.(*int)
		}
		credentials := http.Header{"Authorization": {"Bearer secret-token"}, "Cookie": {"sid=secret"}}

		_, err := orgSSOGet(newClient(0), urlA("/to-b"), credentials)
		assert.ErrorIs(t, err, service.ErrOrgOIDCRedirectDenied, "redirects are refused by default")
		assert.ErrorIs(t, err, oauth.ErrOrgOIDCEgressDenied)
		assert.Zero(t, bHits())

		body, err := orgSSOGet(newClient(1), urlA("/to-b"), credentials)
		require.NoError(t, err)
		assert.Equal(t, "B auth= cookie=", body, "credentials never follow a redirect to another origin")
		assert.Equal(t, 1, bHits())

		body, err = orgSSOGet(newClient(1), urlA("/to-self"), http.Header{"Authorization": {"Bearer kept"}})
		require.NoError(t, err)
		assert.Equal(t, "A auth=Bearer kept", body, "an allowed same-origin hop keeps its own credentials")

		for _, path := range []string{"/to-metadata", "/to-loopback"} {
			before := bHits()
			_, err = orgSSOGet(newClient(2), urlA(path), nil)
			assert.ErrorIs(t, err, oauth.ErrOrgOIDCEgressDenied, "every hop is checked again: %s", path)
			assert.Equal(t, before, bHits())
		}
		_, err = orgSSOGet(newClient(2), urlA("/to-http"), nil)
		assert.ErrorIs(t, err, oauth.ErrOrgOIDCEgressDenied, "an https request is not downgraded")

		muA.Lock()
		hitsA = 0
		muA.Unlock()
		_, err = orgSSOGet(newClient(2), urlA("/loop"), nil)
		assert.ErrorIs(t, err, service.ErrOrgOIDCRedirectDenied, "hops are bounded")
		muA.Lock()
		assert.Equal(t, 3, hitsA)
		muA.Unlock()

		before := bHits()
		req, reqErr := http.NewRequest(http.MethodPost, urlA("/post307"), strings.NewReader("client_secret=s3cret"))
		require.NoError(t, reqErr)
		resp, err := newClient(2).Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		assert.ErrorIs(t, err, service.ErrOrgOIDCRedirectDenied, "a request with a body is never replayed to a redirect target")
		assert.Equal(t, before, bHits())
	})

	t.Run("response size is capped", func(t *testing.T) {
		big := strings.Repeat("a", 2<<20)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/declared" {
				w.Header().Set("Content-Length", strconv.Itoa(len(big)))
			}
			_, _ = io.WriteString(w, big)
		}))
		defer server.Close()
		port := orgSSOPortOf(t, server)
		orgSSOSetEgress(t, system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: orgSSOHost, Ports: mustAtoi(t, port)}}})
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		dial := &orgSSODial{listeners: map[string]string{port: server.Listener.Addr().String()}}
		client := service.NewOrgOIDCHTTPClientForTest(service.OrgOIDCClientOptions{
			Resolver: newOrgSSOResolver(map[string][]string{orgSSOHost: {orgSSOPublicIP}}), DialAddr: dial.dial, RootCAs: roots,
		})
		for _, path := range []string{"/declared", "/streamed"} {
			_, err := orgSSOGet(client, "https://"+orgSSOHost+":"+port+path, nil)
			assert.ErrorIs(t, err, service.ErrOrgOIDCResponseTooLarge, path)
		}
	})

	t.Run("proxy environment is ignored", func(t *testing.T) {
		orgSSOSetEgress(t, system_setting.OrgOIDCEgressSetting{})
		for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"} {
			t.Setenv(name, "http://127.0.0.1:1")
		}
		t.Setenv("NO_PROXY", "")
		var dialed []string
		client := service.NewOrgOIDCHTTPClientForTest(service.OrgOIDCClientOptions{
			Resolver: newOrgSSOResolver(map[string][]string{"idp.test": {orgSSOPublicIP}}),
			DialAddr: func(_ context.Context, _, address string) (net.Conn, error) {
				dialed = append(dialed, address)
				return nil, errors.New("connection refused")
			},
		})
		_, _ = orgSSOGet(client, "https://idp.test/", nil)
		assert.Equal(t, []string{orgSSOPublicIP + ":443"}, dialed, "the request goes straight to the checked address, never to a proxy")
	})

	t.Run("certificates are verified", func(t *testing.T) {
		f := setupOrgSSO(t)
		untrusting := service.NewOrgOIDCHTTPClientForTest(service.OrgOIDCClientOptions{Resolver: f.resolver, DialAddr: f.dial.dial})
		_, err := orgSSOGet(untrusting, f.idp.issuer+"/jwks", nil)
		require.Error(t, err)
		assert.NotErrorIs(t, err, oauth.ErrOrgOIDCEgressDenied)
		var unknown x509.UnknownAuthorityError
		assert.ErrorAs(t, err, &unknown)
	})

	t.Run("tenant input cannot widen the platform policy", func(t *testing.T) {
		f := setupOrgSSO(t)
		for _, issuer := range []string{
			"https://169.254.169.254", "https://127.0.0.1", "https://10.0.0.5", "https://[::1]",
			"https://" + orgSSOHost + ":6443", // a port the platform did not open for this host
			"https://other.test",              // a name the fake DNS cannot resolve
		} {
			f.row.Issuer = issuer
			_, err := f.provider().Begin(context.Background(), oauth.OrgOIDCBeginRequest{})
			assert.ErrorIs(t, err, oauth.ErrOrgOIDCEgressDenied, issuer)
			assert.NotEmpty(t, oauth.OrgOIDCAuditCode(err), issuer)
		}
		for name, edit := range map[string]func(*model.CustomOAuthProvider){
			"http issuer":           func(r *model.CustomOAuthProvider) { r.Issuer = "http://" + orgSSOHost },
			"credentials in issuer": func(r *model.CustomOAuthProvider) { r.Issuer = "https://user:pw@" + orgSSOHost },
			"query in issuer":       func(r *model.CustomOAuthProvider) { r.Issuer = "https://" + orgSSOHost + "/?x=1" },
			"fragment in issuer":    func(r *model.CustomOAuthProvider) { r.Issuer = "https://" + orgSSOHost + "/#x" },
			"no issuer":             func(r *model.CustomOAuthProvider) { r.Issuer = "" },
			"foreign discovery URL": func(r *model.CustomOAuthProvider) { r.WellKnown = "https://10.0.0.5/.well-known/openid-configuration" },
			"platform provider":     func(r *model.CustomOAuthProvider) { r.OrgId = 0 },
			"no client secret":      func(r *model.CustomOAuthProvider) { r.ClientSecret = "" },
			"openid scope missing":  func(r *model.CustomOAuthProvider) { r.Scopes = "profile email" },
			"unknown auth style":    func(r *model.CustomOAuthProvider) { r.AuthStyle = 9 },
		} {
			row := *f.row
			edit(&row)
			_, err := oauth.NewOrgOIDCConfig(&row, orgSSORedirectURI)
			assert.ErrorIs(t, err, oauth.ErrOrgOIDCConfig, name)
		}
		_, err := oauth.NewOrgOIDCConfig(f.row, "http://console.example.org/cb")
		assert.ErrorIs(t, err, oauth.ErrOrgOIDCConfig, "the redirect URI must be https")
		_, err = oauth.NewOrgOIDCProvider(f.config(), &http.Client{}, oauth.WithOrgOIDCJWKSCooldown(0))
		assert.ErrorIs(t, err, oauth.ErrOrgOIDCConfig, "a client without the restricted transport is refused")
		_, err = oauth.NewOrgOIDCProvider(f.config(), nil)
		assert.ErrorIs(t, err, oauth.ErrOrgOIDCConfig)
	})

	t.Run("endpoints from the discovery document are checked too", func(t *testing.T) {
		// token, JWKS and UserInfo are requested by the server, so they go through
		// the same client and policy as the issuer itself.
		for _, field := range []string{"token_endpoint", "jwks_uri", "userinfo_endpoint"} {
			f := setupOrgSSO(t)
			f.idp.with(func() { f.idp.discovery = func(doc map[string]any) { doc[field] = "https://10.0.0.5/endpoint" } })
			_, err := f.login(f.provider(), nil)
			assert.ErrorIs(t, err, oauth.ErrOrgOIDCEgressDenied, field)
			assert.Equal(t, "egress_denied", oauth.OrgOIDCAuditCode(err), field)
		}
		// The authorization endpoint is only a browser redirect target, but it must still be https.
		for _, field := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"} {
			f := setupOrgSSO(t)
			f.idp.with(func() {
				f.idp.discovery = func(doc map[string]any) { doc[field] = "http://" + orgSSOHost + "/endpoint" }
			})
			_, err := f.provider().Begin(context.Background(), oauth.OrgOIDCBeginRequest{})
			assert.ErrorIs(t, err, oauth.ErrOrgOIDCDiscovery, field)
		}
	})

	t.Run("platform exception settings are validated", func(t *testing.T) {
		for name, tt := range map[string]struct {
			setting system_setting.OrgOIDCEgressSetting
			valid   bool
		}{
			"empty":                 {system_setting.OrgOIDCEgressSetting{}, true},
			"private block":         {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "idp.corp.test", Ports: []int{8443}, CIDRs: []string{"10.20.0.0/16"}}}}, true},
			"redirect limit":        {system_setting.OrgOIDCEgressSetting{MaxRedirects: 3}, true},
			"too many redirects":    {system_setting.OrgOIDCEgressSetting{MaxRedirects: 4}, false},
			"negative redirects":    {system_setting.OrgOIDCEgressSetting{MaxRedirects: -1}, false},
			"wildcard host":         {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "*.corp.test"}}}, false},
			"host with a port":      {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "idp.corp.test:8443"}}}, false},
			"host with a scheme":    {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "https://idp.corp.test"}}}, false},
			"empty host":            {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: " "}}}, false},
			"port zero":             {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "a.test", Ports: []int{0}}}}, false},
			"port too large":        {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "a.test", Ports: []int{70000}}}}, false},
			"public CIDR":           {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "a.test", CIDRs: []string{"93.184.216.0/24"}}}}, false},
			"everything":            {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "a.test", CIDRs: []string{"0.0.0.0/0"}}}}, false},
			"CIDR wider than block": {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "a.test", CIDRs: []string{"10.0.0.0/7"}}}}, false},
			"loopback CIDR":         {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "a.test", CIDRs: []string{"127.0.0.0/8"}}}}, false},
			"metadata CIDR":         {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "a.test", CIDRs: []string{"169.254.169.254/32"}}}}, false},
			"malformed CIDR":        {system_setting.OrgOIDCEgressSetting{Rules: []system_setting.OrgOIDCEgressRule{{Host: "a.test", CIDRs: []string{"10.0.0.0"}}}}, false},
		} {
			err := service.ValidateOrgOIDCEgressSetting(tt.setting)
			if tt.valid {
				assert.NoError(t, err, name)
			} else {
				assert.Error(t, err, name)
			}
		}
	})
}

// TestOrgOIDCTokenValidation covers ID Token verification (signature, JWKS
// rotation, iss, aud, azp, exp, iat, nbf, nonce, at_hash, sub), the state and
// PKCE binding of the ceremony, discovery pinning, UserInfo, and replay.
func TestOrgOIDCTokenValidation(t *testing.T) {
	t.Run("a valid ceremony yields the issuer and subject", func(t *testing.T) {
		f := setupOrgSSO(t)
		p := f.provider()
		ceremony := f.start(p, oauth.OrgOIDCBeginRequest{})
		assert.Equal(t, "S256", ceremony.query.Get("code_challenge_method"))
		assert.Equal(t, orgSSORedirectURI, ceremony.query.Get("redirect_uri"))
		assert.Empty(t, ceremony.query.Get("prompt"), "an ordinary login may reuse the IdP session")
		assert.Empty(t, ceremony.query.Get("max_age"))
		assert.NotContains(t, ceremony.begin.AuthorizationURL, "code_verifier")
		assert.NotContains(t, ceremony.begin.AuthorizationURL, orgSSOSecret)
		assert.NotEqual(t, ceremony.state, ceremony.begin.BrowserBinding)
		assert.True(t, ceremony.begin.ExpiresAt.After(time.Now()))
		assert.LessOrEqual(t, time.Until(ceremony.begin.ExpiresAt), oauth.OrgOIDCFlowTTL)

		var flow model.AuthFlow
		require.NoError(t, model.DB.Where("purpose = ?", oauth.AuthFlowPurposeOrgOIDC).First(&flow).Error)
		assert.Equal(t, "org:3:7", flow.Provider, "state is bound to the organization and provider")
		assert.Equal(t, model.AuthFlowIntentLogin, flow.Intent)
		assert.NotEqual(t, ceremony.state, flow.TokenHash, "the state itself is not stored")

		identity, err := p.Complete(context.Background(), ceremony.callback())
		require.NoError(t, err)
		assert.Equal(t, f.idp.issuer, identity.Issuer)
		assert.Equal(t, "user-1", identity.Subject)
		assert.Equal(t, 3, identity.OrgID)
		assert.Equal(t, 7, identity.ProviderID)
		assert.Equal(t, "user@corp.example", identity.Email, "the ID Token claim wins over UserInfo")
		assert.True(t, identity.EmailVerified)
		assert.Equal(t, "Corp User", identity.Name)
		assert.False(t, identity.UserInfoSkipped)
		assert.False(t, identity.Fresh)
		assert.Equal(t, "basic", f.idp.authStyle)
		assert.Equal(t, 1, f.idp.hitCount("/token"))
	})

	t.Run("ID Token claims", func(t *testing.T) {
		now := time.Now()
		tests := []struct {
			name   string
			claims func(c jwt.MapClaims)
			want   error // nil means accepted
		}{
			{name: "baseline"},
			{name: "issuer differs", claims: func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com" }, want: oauth.ErrOrgOIDCIssuerMismatch},
			{name: "issuer with a trailing slash", claims: func(c jwt.MapClaims) { c["iss"] = c["iss"].(string) + "/" }, want: oauth.ErrOrgOIDCIssuerMismatch},
			{name: "issuer missing", claims: func(c jwt.MapClaims) { delete(c, "iss") }, want: oauth.ErrOrgOIDCIssuerMismatch},
			{name: "audience is another client", claims: func(c jwt.MapClaims) { c["aud"] = "someone-else" }, want: oauth.ErrOrgOIDCAudienceInvalid},
			{name: "audience missing", claims: func(c jwt.MapClaims) { delete(c, "aud") }, want: oauth.ErrOrgOIDCAudienceInvalid},
			{name: "audience list without this client", claims: func(c jwt.MapClaims) { c["aud"] = []string{"a", "b"}; c["azp"] = orgSSOClientID }, want: oauth.ErrOrgOIDCAudienceInvalid},
			{name: "audience list needs azp", claims: func(c jwt.MapClaims) { c["aud"] = []string{orgSSOClientID, "api"} }, want: oauth.ErrOrgOIDCAudienceInvalid},
			{name: "audience list with matching azp", claims: func(c jwt.MapClaims) { c["aud"] = []string{orgSSOClientID, "api"}; c["azp"] = orgSSOClientID }},
			{name: "azp is another client", claims: func(c jwt.MapClaims) { c["azp"] = "someone-else" }, want: oauth.ErrOrgOIDCAudienceInvalid},
			{name: "expired", claims: func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Second).Unix() }, want: oauth.ErrOrgOIDCIDTokenExpired},
			{name: "expired long ago", claims: func(c jwt.MapClaims) {
				c["exp"] = now.Add(-24 * time.Hour).Unix()
				c["iat"] = now.Add(-25 * time.Hour).Unix()
			}, want: oauth.ErrOrgOIDCIDTokenExpired},
			{name: "exp missing", claims: func(c jwt.MapClaims) { delete(c, "exp") }, want: oauth.ErrOrgOIDCIDTokenInvalid},
			{name: "iat missing", claims: func(c jwt.MapClaims) { delete(c, "iat") }, want: oauth.ErrOrgOIDCIDTokenInvalid},
			{name: "iat in the future", claims: func(c jwt.MapClaims) {
				c["iat"] = now.Add(10 * time.Minute).Unix()
				c["exp"] = now.Add(20 * time.Minute).Unix()
			}, want: oauth.ErrOrgOIDCIDTokenInvalid},
			{name: "iat within clock skew", claims: func(c jwt.MapClaims) { c["iat"] = now.Add(time.Minute).Unix() }},
			{name: "iat not before exp", claims: func(c jwt.MapClaims) { c["iat"] = c["exp"] }, want: oauth.ErrOrgOIDCIDTokenInvalid},
			{name: "not valid yet", claims: func(c jwt.MapClaims) { c["nbf"] = now.Add(10 * time.Minute).Unix() }, want: oauth.ErrOrgOIDCIDTokenInvalid},
			{name: "nbf within clock skew", claims: func(c jwt.MapClaims) { c["nbf"] = now.Add(time.Minute).Unix() }},
			{name: "nonce differs", claims: func(c jwt.MapClaims) { c["nonce"] = "another-flow" }, want: oauth.ErrOrgOIDCNonceMismatch},
			{name: "nonce missing", claims: func(c jwt.MapClaims) { delete(c, "nonce") }, want: oauth.ErrOrgOIDCNonceMismatch},
			{name: "nonce empty", claims: func(c jwt.MapClaims) { c["nonce"] = "" }, want: oauth.ErrOrgOIDCNonceMismatch},
			{name: "sub missing", claims: func(c jwt.MapClaims) { delete(c, "sub") }, want: oauth.ErrOrgOIDCSubjectInvalid},
			{name: "sub empty", claims: func(c jwt.MapClaims) { c["sub"] = "" }, want: oauth.ErrOrgOIDCSubjectInvalid},
			{name: "sub too long", claims: func(c jwt.MapClaims) { c["sub"] = strings.Repeat("s", 256) }, want: oauth.ErrOrgOIDCSubjectInvalid},
			{name: "at_hash does not match the access token", claims: func(c jwt.MapClaims) { c["at_hash"] = "AAAAAAAAAAAAAAAAAAAAAA" }, want: oauth.ErrOrgOIDCIDTokenInvalid},
			{name: "at_hash absent", claims: func(c jwt.MapClaims) { delete(c, "at_hash") }},
			{name: "email_verified as a string", claims: func(c jwt.MapClaims) { c["email_verified"] = "true" }},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := setupOrgSSO(t)
				f.idp.with(func() { f.idp.claims = tt.claims })
				identity, err := f.login(f.provider(), nil)
				if tt.want == nil {
					require.NoError(t, err)
					assert.Equal(t, "user-1", identity.Subject)
					return
				}
				requireOrgSSOKind(t, err, tt.want)
				assert.Nil(t, identity)
			})
		}
	})

	t.Run("signatures", func(t *testing.T) {
		keyA, keyB := orgSSOKeys(t)
		publicDER, err := x509.MarshalPKIXPublicKey(&keyA.PublicKey)
		require.NoError(t, err)
		tests := []struct {
			name    string
			signer  func(s *orgIDPSigner)
			rewrite func(token string) string
		}{
			{name: "signed by a key the IdP does not publish", signer: func(s *orgIDPSigner) { s.key = keyB }},
			{name: "unknown kid with a foreign key", signer: func(s *orgIDPSigner) { s.key, s.kid = keyB, "key-x" }},
			{name: "alg none", signer: func(s *orgIDPSigner) { s.method, s.key = jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType }},
			{name: "HS256 keyed with the public key", signer: func(s *orgIDPSigner) { s.method, s.key = jwt.SigningMethodHS256, publicDER }},
			{name: "RS384 is not advertised", signer: func(s *orgIDPSigner) { s.method = jwt.SigningMethodRS384 }},
			{name: "payload swapped under the original signature", rewrite: func(token string) string {
				parts := strings.Split(token, ".")
				forged, _ := common.Marshal(map[string]any{"iss": parts[0], "sub": "admin"})
				parts[1] = base64.RawURLEncoding.EncodeToString(forged)
				return strings.Join(parts, ".")
			}},
			{name: "signature truncated", rewrite: func(token string) string { return token[:len(token)-8] }},
			{name: "not a JWT", rewrite: func(string) string { return "not-a-jwt" }},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := setupOrgSSO(t)
				f.idp.with(func() { f.idp.signer, f.idp.rewrite = tt.signer, tt.rewrite })
				identity, err := f.login(f.provider(), nil)
				requireOrgSSOKind(t, err, oauth.ErrOrgOIDCIDTokenInvalid)
				assert.Nil(t, identity)
			})
		}
	})

	t.Run("JWKS rotation and unknown key ids", func(t *testing.T) {
		_, keyB := orgSSOKeys(t)
		rotate := func(f *orgSSO) {
			f.idp.with(func() {
				f.idp.keys["key-b"] = keyB
				f.idp.signer = func(s *orgIDPSigner) { s.key, s.kid = keyB, "key-b" }
			})
		}
		t.Run("a new kid refetches the key set once and verifies", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			_, err := f.login(p, nil)
			require.NoError(t, err)
			assert.Equal(t, 1, f.idp.hitCount("/jwks"))
			_, err = f.login(p, nil)
			require.NoError(t, err)
			assert.Equal(t, 1, f.idp.hitCount("/jwks"), "a known kid is served from the cache")
			rotate(f)
			identity, err := f.login(p, nil)
			require.NoError(t, err)
			assert.Equal(t, "user-1", identity.Subject)
			assert.Equal(t, 2, f.idp.hitCount("/jwks"), "the unknown kid caused exactly one refetch")
		})
		t.Run("a kid that never appears costs one refetch per login", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			_, err := f.login(p, nil)
			require.NoError(t, err)
			f.idp.with(func() { f.idp.signer = func(s *orgIDPSigner) { s.key, s.kid = keyB, "key-ghost" } })
			_, err = f.login(p, nil)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCIDTokenInvalid)
			assert.Equal(t, 2, f.idp.hitCount("/jwks"), "one refetch, not a loop")
		})
		t.Run("the cooldown stops refetch amplification", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider(oauth.WithOrgOIDCJWKSCooldown(time.Hour))
			_, err := f.login(p, nil)
			require.NoError(t, err)
			require.Equal(t, 1, f.idp.hitCount("/jwks"))
			f.idp.with(func() { f.idp.signer = func(s *orgIDPSigner) { s.key, s.kid = keyB, "key-ghost" } })
			for range 5 {
				_, err = f.login(p, nil)
				requireOrgSSOKind(t, err, oauth.ErrOrgOIDCIDTokenInvalid)
			}
			assert.Equal(t, 1, f.idp.hitCount("/jwks"), "forged kids never reach the IdP inside the cooldown")
			rotate(f)
			_, err = f.login(p, nil)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCIDTokenInvalid)
			assert.Equal(t, 1, f.idp.hitCount("/jwks"))
		})
		t.Run("a removed key stops verifying once the set is refreshed", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			_, err := f.login(p, nil)
			require.NoError(t, err)
			rotate(f)
			f.idp.with(func() { delete(f.idp.keys, "key-a") })
			_, err = f.login(p, nil)
			require.NoError(t, err)
			keyA, _ := orgSSOKeys(t)
			f.idp.with(func() { f.idp.signer = func(s *orgIDPSigner) { s.key, s.kid = keyA, "key-a" } }) // the retired key
			_, err = f.login(p, nil)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCIDTokenInvalid)
		})
	})

	t.Run("token endpoint", func(t *testing.T) {
		f := setupOrgSSO(t)
		f.idp.with(func() { f.idp.omitID = true })
		_, err := f.login(f.provider(), nil)
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCNoIDToken)

		f = setupOrgSSO(t)
		f.idp.with(func() { f.idp.tokenCode = http.StatusInternalServerError })
		_, err = f.login(f.provider(), nil)
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCTokenExchange)
		var failure *oauth.OrgOIDCError
		require.ErrorAs(t, err, &failure)
		assert.NotContains(t, failure.Cause.Error(), orgSSOSecret, "an IdP error body is never copied into the error")

		f = setupOrgSSO(t)
		f.row.ClientSecret = "wrong-secret"
		_, err = f.login(f.provider(), nil)
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCTokenExchange)
		assert.NotContains(t, err.Error(), "wrong-secret")

		f = setupOrgSSO(t)
		f.idp.with(func() {
			f.idp.discovery = func(doc map[string]any) {
				doc["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"}
			}
		})
		_, err = f.login(f.provider(), nil)
		require.NoError(t, err)
		assert.Equal(t, "post", f.idp.authStyle, "the advertised client authentication method is used")

		f = setupOrgSSO(t)
		f.idp.with(func() {
			f.idp.discovery = func(doc map[string]any) { doc["token_endpoint_auth_methods_supported"] = []string{"private_key_jwt"} }
		})
		_, err = f.provider().Begin(context.Background(), oauth.OrgOIDCBeginRequest{})
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCDiscovery)
	})

	t.Run("state, PKCE and browser binding", func(t *testing.T) {
		t.Run("a state value works once", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			cb := f.start(p, oauth.OrgOIDCBeginRequest{}).callback()
			_, err := p.Complete(context.Background(), cb)
			require.NoError(t, err)
			tokenHits := f.idp.hitCount("/token")
			_, err = p.Complete(context.Background(), cb)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowReplayed)
			assert.Equal(t, "flow_replayed", oauth.OrgOIDCAuditCode(err))
			assert.Equal(t, tokenHits, f.idp.hitCount("/token"), "a replay never reaches the IdP")
		})
		t.Run("a failed attempt still spends the state", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			f.idp.with(func() { f.idp.claims = func(c jwt.MapClaims) { c["nonce"] = "wrong" } })
			cb := f.start(p, oauth.OrgOIDCBeginRequest{}).callback()
			_, err := p.Complete(context.Background(), cb)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCNonceMismatch)
			_, err = p.Complete(context.Background(), cb)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowReplayed)
		})
		t.Run("unknown, empty and expired state", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			for _, state := range []string{"", "garbage", strings.Repeat("A", 43)} {
				_, err := p.Complete(context.Background(), oauth.OrgOIDCCallback{State: state, Code: "x", BrowserBinding: "x"})
				requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowInvalid)
			}
			cb := f.start(p, oauth.OrgOIDCBeginRequest{}).callback()
			require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("purpose = ?", oauth.AuthFlowPurposeOrgOIDC).
				Update("expires_at", time.Now().Add(-time.Second)).Error)
			_, err := p.Complete(context.Background(), cb)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowExpired)
		})
		t.Run("state does not cross providers or organizations", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			cb := f.start(p, oauth.OrgOIDCBeginRequest{}).callback()
			for name, edit := range map[string]func(*model.CustomOAuthProvider){
				"other provider": func(r *model.CustomOAuthProvider) { r.Id = 8 },
				"other org":      func(r *model.CustomOAuthProvider) { r.OrgId = 4 },
			} {
				row := *f.row
				edit(&row)
				cfg, err := oauth.NewOrgOIDCConfig(&row, orgSSORedirectURI)
				require.NoError(t, err)
				other, err := oauth.NewOrgOIDCProvider(cfg, f.client)
				require.NoError(t, err)
				_, err = other.Complete(context.Background(), cb)
				requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowMismatch)
				assert.Equal(t, "flow_mismatch", oauth.OrgOIDCAuditCode(err), name)
			}
			_, err := p.Complete(context.Background(), cb)
			require.NoError(t, err, "a probe from the wrong provider does not spend the flow")
		})
		t.Run("configuration drift between begin and complete", func(t *testing.T) {
			for name, drift := range map[string]struct {
				clientID    string
				redirectURI string
			}{
				"redirect uri": {orgSSOClientID, "https://console.example.org/other/callback"},
				"client id":    {"other-client", orgSSORedirectURI},
			} {
				f := setupOrgSSO(t)
				cb := f.start(f.provider(), oauth.OrgOIDCBeginRequest{}).callback()
				row := *f.row
				row.ClientId = drift.clientID
				cfg, err := oauth.NewOrgOIDCConfig(&row, drift.redirectURI)
				require.NoError(t, err)
				changed, err := oauth.NewOrgOIDCProvider(cfg, f.client)
				require.NoError(t, err)
				_, err = changed.Complete(context.Background(), cb)
				requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowMismatch)
				assert.Zero(t, f.idp.hitCount("/token"), name)
			}
		})
		t.Run("the flow is bound to the browser", func(t *testing.T) {
			for name, binding := range map[string]string{"missing": "", "another browser": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
				f := setupOrgSSO(t)
				p := f.provider()
				ceremony := f.start(p, oauth.OrgOIDCBeginRequest{})
				cb := ceremony.callback()
				cb.BrowserBinding = binding
				_, err := p.Complete(context.Background(), cb)
				requireOrgSSOKind(t, err, oauth.ErrOrgOIDCBindingMismatch)
				assert.Zero(t, f.idp.hitCount("/token"), name)
				_, err = p.Complete(context.Background(), ceremony.callback())
				requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowReplayed)
			}
		})
		t.Run("PKCE rejects an authorization code from another ceremony", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			victim := f.start(p, oauth.OrgOIDCBeginRequest{})
			attacker := f.start(p, oauth.OrgOIDCBeginRequest{})
			cb := victim.callback()
			cb.Code = attacker.code
			_, err := p.Complete(context.Background(), cb)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCTokenExchange)
			var failure *oauth.OrgOIDCError
			require.ErrorAs(t, err, &failure)
			assert.Contains(t, failure.Cause.Error(), "400", "the IdP refused the code_verifier")
		})
		t.Run("an authorization code works once", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			first := f.start(p, oauth.OrgOIDCBeginRequest{})
			_, err := p.Complete(context.Background(), first.callback())
			require.NoError(t, err)
			second := f.start(p, oauth.OrgOIDCBeginRequest{})
			cb := second.callback()
			cb.Code = first.code
			_, err = p.Complete(context.Background(), cb)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCTokenExchange)
		})
		t.Run("IdP error callbacks", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			for errorCode, cause := range map[string]string{"access_denied": "access_denied", "<script>alert(1)</script>": "unknown"} {
				cb := f.start(p, oauth.OrgOIDCBeginRequest{}).callback()
				cb.Code, cb.Error = "", errorCode
				_, err := p.Complete(context.Background(), cb)
				requireOrgSSOKind(t, err, oauth.ErrOrgOIDCProviderError)
				var failure *oauth.OrgOIDCError
				require.ErrorAs(t, err, &failure)
				assert.Equal(t, cause, failure.Cause.Error(), "only an allowlisted code is kept")
			}
			assert.Zero(t, f.idp.hitCount("/token"))
			cb := f.start(p, oauth.OrgOIDCBeginRequest{}).callback()
			cb.Code = ""
			_, err := p.Complete(context.Background(), cb)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowInvalid)
		})
		t.Run("authorization response issuer", func(t *testing.T) {
			f := setupOrgSSO(t)
			p := f.provider()
			_, err := f.login(p, func(cb *oauth.OrgOIDCCallback) { cb.Issuer = "https://evil.example.com" })
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCIssuerMismatch)
			_, err = f.login(p, func(cb *oauth.OrgOIDCCallback) { cb.Issuer = f.idp.issuer })
			require.NoError(t, err)
			f.idp.with(func() {
				f.idp.discovery = func(doc map[string]any) { doc["authorization_response_iss_parameter_supported"] = true }
			})
			p = f.provider()
			_, err = f.login(p, nil)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCIssuerMismatch)
			_, err = f.login(p, func(cb *oauth.OrgOIDCCallback) { cb.Issuer = f.idp.issuer })
			require.NoError(t, err)
		})
	})

	t.Run("discovery is pinned to the configured issuer", func(t *testing.T) {
		tests := []struct {
			name string
			edit func(doc map[string]any)
			want error
		}{
			{name: "metadata names another issuer", edit: func(d map[string]any) { d["issuer"] = "https://evil.example.com" }, want: oauth.ErrOrgOIDCIssuerMismatch},
			{name: "issuer with a trailing slash", edit: func(d map[string]any) { d["issuer"] = d["issuer"].(string) + "/" }, want: oauth.ErrOrgOIDCIssuerMismatch},
			{name: "S256 not advertised", edit: func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} }, want: oauth.ErrOrgOIDCDiscovery},
			{name: "PKCE support not stated", edit: func(d map[string]any) { delete(d, "code_challenge_methods_supported") }, want: oauth.ErrOrgOIDCDiscovery},
			{name: "authorization code flow not supported", edit: func(d map[string]any) { d["response_types_supported"] = []string{"token", "id_token"} }, want: oauth.ErrOrgOIDCDiscovery},
			{name: "only HMAC signing", edit: func(d map[string]any) { d["id_token_signing_alg_values_supported"] = []string{"HS256", "none"} }, want: oauth.ErrOrgOIDCDiscovery},
			{name: "no jwks_uri", edit: func(d map[string]any) { delete(d, "jwks_uri") }, want: oauth.ErrOrgOIDCDiscovery},
			{name: "no token endpoint", edit: func(d map[string]any) { delete(d, "token_endpoint") }, want: oauth.ErrOrgOIDCDiscovery},
			{name: "RS256 and ES256 advertised", edit: func(d map[string]any) { d["id_token_signing_alg_values_supported"] = []string{"RS256", "ES256"} }},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := setupOrgSSO(t)
				f.idp.with(func() { f.idp.discovery = tt.edit })
				_, err := f.provider().Begin(context.Background(), oauth.OrgOIDCBeginRequest{})
				if tt.want == nil {
					require.NoError(t, err)
					return
				}
				requireOrgSSOKind(t, err, tt.want)
			})
		}
	})

	t.Run("UserInfo is display data only", func(t *testing.T) {
		userinfo := func(f *orgSSO, handler func(w http.ResponseWriter)) { f.idp.with(func() { f.idp.userinfo = handler }) }
		t.Run("a different subject is refused", func(t *testing.T) {
			f := setupOrgSSO(t)
			userinfo(f, func(w http.ResponseWriter) {
				orgIDPWrite(w, http.StatusOK, map[string]any{"sub": "someone-else", "email": "x@y.z"})
			})
			identity, err := f.login(f.provider(), nil)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCUserInfoMismatch)
			assert.Nil(t, identity)
			assert.Equal(t, "userinfo_sub_mismatch", oauth.OrgOIDCAuditCode(err))
		})
		t.Run("a missing subject is refused", func(t *testing.T) {
			f := setupOrgSSO(t)
			userinfo(f, func(w http.ResponseWriter) { orgIDPWrite(w, http.StatusOK, map[string]any{"email": "x@y.z"}) })
			_, err := f.login(f.provider(), nil)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCUserInfoMismatch)
		})
		t.Run("an outage does not block a proven identity", func(t *testing.T) {
			for name, handler := range map[string]func(w http.ResponseWriter){
				"server error": func(w http.ResponseWriter) {
					orgIDPWrite(w, http.StatusInternalServerError, map[string]any{"error": "boom"})
				},
				"not json": func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) },
			} {
				f := setupOrgSSO(t)
				userinfo(f, handler)
				identity, err := f.login(f.provider(), nil)
				require.NoError(t, err, name)
				assert.True(t, identity.UserInfoSkipped, name)
				assert.Equal(t, "user-1", identity.Subject)
			}
		})
		t.Run("it fills claims the ID Token lacks but never overrides them", func(t *testing.T) {
			f := setupOrgSSO(t)
			f.idp.with(func() {
				f.idp.claims = func(c jwt.MapClaims) { delete(c, "email"); delete(c, "email_verified"); delete(c, "name") }
			})
			userinfo(f, func(w http.ResponseWriter) {
				orgIDPWrite(w, http.StatusOK, map[string]any{"sub": "user-1", "email": "info@corp.example", "name": "Info Name", "preferred_username": "info"})
			})
			identity, err := f.login(f.provider(), nil)
			require.NoError(t, err)
			assert.Equal(t, "info@corp.example", identity.Email)
			assert.False(t, identity.EmailVerified, "UserInfo without email_verified does not prove the address")
			assert.Equal(t, "Info Name", identity.Name)
			assert.Equal(t, "info", identity.Username)
			assert.Equal(t, "user-1", identity.Subject)
			assert.Equal(t, f.idp.issuer, identity.Issuer)
		})
		t.Run("an unverified ID Token email stays unverified", func(t *testing.T) {
			f := setupOrgSSO(t)
			f.idp.with(func() { f.idp.claims = func(c jwt.MapClaims) { c["email_verified"] = false } })
			identity, err := f.login(f.provider(), nil)
			require.NoError(t, err)
			assert.Equal(t, "user@corp.example", identity.Email)
			assert.False(t, identity.EmailVerified)
		})
	})

	t.Run("audit codes carry no secrets", func(t *testing.T) {
		for _, tt := range []struct {
			err  error
			code string
		}{
			{oauth.ErrOrgOIDCEgressDenied, "egress_denied"}, {oauth.ErrOrgOIDCNonceMismatch, "nonce_mismatch"},
			{oauth.ErrOrgOIDCFlowReplayed, "flow_replayed"}, {oauth.ErrOrgOIDCFreshStale, "fresh_stale"},
			{oauth.ErrOrgOIDCFreshUnsupported, "fresh_unsupported"}, {oauth.ErrOrgOIDCIDTokenInvalid, "id_token_invalid"},
			{errors.New("token=" + orgSSOSecret), "unknown"}, {nil, "unknown"},
		} {
			assert.Equal(t, tt.code, oauth.OrgOIDCAuditCode(tt.err))
		}
		cause := errors.New("IdP said: client_secret=" + orgSSOSecret)
		wrapped := &oauth.OrgOIDCError{Kind: oauth.ErrOrgOIDCTokenExchange, Cause: cause}
		assert.NotContains(t, wrapped.Error(), orgSSOSecret)
		assert.NotContains(t, oauth.OrgOIDCAuditCode(wrapped), orgSSOSecret)
	})
}

// TestOrgOIDCFreshAuth covers re-authentication for a sensitive operation: the
// IdP is asked to authenticate again, auth_time must be recent, the nonce
// must belong to this ceremony, and the proof stays with the session that
// asked for it.
func TestOrgOIDCFreshAuth(t *testing.T) {
	t.Run("the request forces re-authentication", func(t *testing.T) {
		f := setupOrgSSO(t)
		ceremony := f.start(f.provider(), orgSSOFreshSession)
		assert.Equal(t, "login", ceremony.query.Get("prompt"))
		assert.Equal(t, "0", ceremony.query.Get("max_age"))
		assert.NotEmpty(t, ceremony.query.Get("nonce"))
		assert.NotContains(t, ceremony.begin.AuthorizationURL, "action%3Dsso.update", "the server-side context never reaches the IdP")
		assert.NotContains(t, ceremony.begin.AuthorizationURL, "session-11")

		var flow model.AuthFlow
		require.NoError(t, model.DB.Where("purpose = ?", oauth.AuthFlowPurposeOrgOIDC).First(&flow).Error)
		assert.Equal(t, model.AuthFlowIntentVerify, flow.Intent)
		assert.Equal(t, 11, flow.UserId)
		assert.Equal(t, "session-11", flow.SessionId)

		identity, err := f.provider().Complete(context.Background(), orgSSOFreshCallback(ceremony))
		require.NoError(t, err)
		assert.True(t, identity.Fresh)
		assert.Equal(t, "user-1", identity.Subject)
		assert.Equal(t, "action=sso.update;org=3", identity.Context)
		require.NotNil(t, identity.AuthTime)
		assert.WithinDuration(t, time.Now().Add(-time.Minute), *identity.AuthTime, 5*time.Second)
	})

	t.Run("begin refuses a malformed request", func(t *testing.T) {
		f := setupOrgSSO(t)
		p := f.provider()
		for name, req := range map[string]oauth.OrgOIDCBeginRequest{
			"fresh without a session":      {Fresh: true},
			"fresh without a user":         {Fresh: true, SessionID: "s"},
			"session on an ordinary login": {UserID: 1, SessionID: "s"},
			"subject on an ordinary login": {ExpectedSubject: "user-1"},
			"oversized context":            {Fresh: true, UserID: 1, SessionID: "s", Context: strings.Repeat("c", 257)},
		} {
			_, err := p.Begin(context.Background(), req)
			assert.ErrorIs(t, err, oauth.ErrOrgOIDCFlowInvalid, name)
		}
		assert.Zero(t, f.idp.hitCount("/.well-known/openid-configuration"), "nothing leaves the process for a bad request")
	})

	t.Run("auth_time age", func(t *testing.T) {
		now := time.Now()
		ago := func(d time.Duration) func(time.Time) *time.Time {
			return func(time.Time) *time.Time { v := now.Add(-d); return &v }
		}
		tests := []struct {
			name     string
			authTime func(time.Time) *time.Time
			want     error
		}{
			{name: "just authenticated", authTime: ago(2 * time.Second)},
			{name: "four minutes ago", authTime: ago(4 * time.Minute)},
			{name: "six minutes ago", authTime: ago(6 * time.Minute), want: oauth.ErrOrgOIDCFreshStale},
			{name: "yesterday's SSO session", authTime: ago(24 * time.Hour), want: oauth.ErrOrgOIDCFreshStale},
			{name: "auth_time absent", authTime: func(time.Time) *time.Time { return nil }, want: oauth.ErrOrgOIDCFreshUnsupported},
			{name: "slightly ahead within skew", authTime: ago(-time.Minute)},
			{name: "far in the future", authTime: ago(-time.Hour), want: oauth.ErrOrgOIDCIDTokenInvalid},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := setupOrgSSO(t)
				f.idp.with(func() { f.idp.authTime = tt.authTime })
				p := f.provider()
				identity, err := p.Complete(context.Background(), orgSSOFreshCallback(f.start(p, orgSSOFreshSession)))
				if tt.want == nil {
					require.NoError(t, err)
					assert.True(t, identity.Fresh)
					return
				}
				requireOrgSSOKind(t, err, tt.want)
				assert.Nil(t, identity)
			})
		}
		t.Run("an IdP that ignores the request cannot prove freshness", func(t *testing.T) {
			f := setupOrgSSO(t)
			f.idp.with(func() { f.idp.authTime = func(time.Time) *time.Time { return nil } })
			p := f.provider()
			_, err := p.Complete(context.Background(), orgSSOFreshCallback(f.start(p, orgSSOFreshSession)))
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFreshUnsupported)
			assert.Equal(t, "fresh_unsupported", oauth.OrgOIDCAuditCode(err))
			// An ordinary login does not need auth_time, so the same IdP still works for it.
			_, err = f.login(p, nil)
			require.NoError(t, err)
		})
		t.Run("an ordinary login ignores auth_time", func(t *testing.T) {
			f := setupOrgSSO(t)
			f.idp.with(func() { f.idp.authTime = ago(48 * time.Hour) })
			identity, err := f.login(f.provider(), nil)
			require.NoError(t, err)
			assert.False(t, identity.Fresh)
		})
	})

	t.Run("an earlier ID Token cannot stand in for this ceremony", func(t *testing.T) {
		f := setupOrgSSO(t)
		p := f.provider()
		// The first ceremony produces a valid, recent ID Token for the same user.
		first := f.start(p, orgSSOFreshSession)
		_, err := p.Complete(context.Background(), orgSSOFreshCallback(first))
		require.NoError(t, err)
		var stolen string
		f.idp.with(func() { stolen = f.idp.minted[0] })
		// An attacker makes the IdP side return that token for a new ceremony.
		f.idp.with(func() { f.idp.rewrite = func(string) string { return stolen } })
		second := f.start(p, orgSSOFreshSession)
		_, err = p.Complete(context.Background(), orgSSOFreshCallback(second))
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCNonceMismatch)
		assert.Equal(t, "nonce_mismatch", oauth.OrgOIDCAuditCode(err))
	})

	t.Run("the proof stays with the session that asked", func(t *testing.T) {
		f := setupOrgSSO(t)
		p := f.provider()
		ceremony := f.start(p, orgSSOFreshSession)
		for name, edit := range map[string]func(*oauth.OrgOIDCCallback){
			"another session":        func(cb *oauth.OrgOIDCCallback) { cb.SessionID = "session-99" },
			"another user":           func(cb *oauth.OrgOIDCCallback) { cb.UserID = 12 },
			"no session":             func(cb *oauth.OrgOIDCCallback) { cb.UserID, cb.SessionID = 0, "" },
			"user without a session": func(cb *oauth.OrgOIDCCallback) { cb.SessionID = "" },
		} {
			cb := orgSSOFreshCallback(ceremony)
			edit(&cb)
			_, err := p.Complete(context.Background(), cb)
			requireOrgSSOKind(t, err, oauth.ErrOrgOIDCBindingMismatch)
			assert.Zero(t, f.idp.hitCount("/token"), name)
		}
		_, err := p.Complete(context.Background(), orgSSOFreshCallback(ceremony))
		require.NoError(t, err, "wrong-session probes do not spend the flow")
		_, err = p.Complete(context.Background(), orgSSOFreshCallback(ceremony))
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowReplayed)
	})

	t.Run("a login flow is not a verification and the reverse", func(t *testing.T) {
		f := setupOrgSSO(t)
		p := f.provider()
		login := f.start(p, oauth.OrgOIDCBeginRequest{})
		cb := login.callback()
		cb.UserID, cb.SessionID = 11, "session-11"
		_, err := p.Complete(context.Background(), cb)
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowMismatch)
		_, err = p.Complete(context.Background(), login.callback())
		require.NoError(t, err, "the login flow was not spent by the misuse")

		fresh := f.start(p, orgSSOFreshSession)
		_, err = p.Complete(context.Background(), fresh.callback())
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCBindingMismatch)
	})

	t.Run("the identity must be the one that was asked for", func(t *testing.T) {
		f := setupOrgSSO(t)
		f.idp.with(func() { f.idp.claims = func(c jwt.MapClaims) { c["sub"] = "attacker-sub" } })
		p := f.provider()
		identity, err := p.Complete(context.Background(), orgSSOFreshCallback(f.start(p, orgSSOFreshSession)))
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCIdentityMismatch)
		assert.Nil(t, identity)
		assert.Equal(t, "identity_mismatch", oauth.OrgOIDCAuditCode(err))
	})

	t.Run("an expired verification flow is refused", func(t *testing.T) {
		f := setupOrgSSO(t)
		p := f.provider()
		ceremony := f.start(p, orgSSOFreshSession)
		require.NoError(t, model.DB.Model(&model.AuthFlow{}).Where("purpose = ?", oauth.AuthFlowPurposeOrgOIDC).
			Update("expires_at", time.Now().Add(-time.Second)).Error)
		_, err := p.Complete(context.Background(), orgSSOFreshCallback(ceremony))
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFlowExpired)
	})

	t.Run("the provider clock decides freshness", func(t *testing.T) {
		f := setupOrgSSO(t)
		later := func() time.Time { return time.Now().Add(oauth.OrgOIDCFreshMaxAge + time.Minute) }
		p := f.provider(oauth.WithOrgOIDCClock(later))
		// With a clock running ahead, auth_time one minute ago is now stale.
		ceremony := f.start(p, orgSSOFreshSession)
		f.idp.with(func() { f.idp.claims = func(c jwt.MapClaims) { c["exp"] = time.Now().Add(time.Hour).Unix() } })
		_, err := p.Complete(context.Background(), orgSSOFreshCallback(ceremony))
		requireOrgSSOKind(t, err, oauth.ErrOrgOIDCFreshStale)
	})
}
