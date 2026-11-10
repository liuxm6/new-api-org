package service

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/oauth"
	"github.com/QuantumNous/new-api/setting/system_setting"
)

// The organization OIDC outbound client is the only HTTP client discovery,
// token, UserInfo and JWKS requests of a tenant IdP may use. The issuer URL is
// tenant input, so every request is treated as an SSRF vector (ASVS 5.0.0
// 1.3.6, 12.2.1, 12.3.1, 12.3.2): HTTPS only, every A/AAAA answer is checked,
// the connection is made to a checked address, redirects are refused unless the
// platform enables a bounded number, and no proxy is consulted.

const (
	orgOIDCClientTimeout = 20 * time.Second
	orgOIDCDialTimeout   = 10 * time.Second
	orgOIDCMaxBody       = 1 << 20
	orgOIDCMaxRedirects  = 3
	orgOIDCProviderCache = 256
)

var (
	// ErrOrgOIDCRedirectDenied marks a redirect refused by policy. It is always
	// joined with oauth.ErrOrgOIDCEgressDenied.
	ErrOrgOIDCRedirectDenied = errors.New("org oidc redirect denied")
	// ErrOrgOIDCResponseTooLarge marks a response above the 1 MiB cap.
	ErrOrgOIDCResponseTooLarge = errors.New("org oidc response is too large")
)

func orgOIDCDenied(reason string) error {
	return fmt.Errorf("%w: %s", oauth.ErrOrgOIDCEgressDenied, reason)
}

type orgOIDCAddrClass int

const (
	orgOIDCAddrPublic orgOIDCAddrClass = iota
	// orgOIDCAddrRestricted is private or special-use space a platform rule may open.
	orgOIDCAddrRestricted
	// orgOIDCAddrForbidden is never reachable: loopback, link-local, multicast,
	// unspecified, reserved and cloud metadata endpoints.
	orgOIDCAddrForbidden
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(values))
	for i, value := range values {
		prefixes[i] = netip.MustParsePrefix(value)
	}
	return prefixes
}

var (
	orgOIDCForbiddenNets = mustPrefixes(
		"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
		"100.100.100.200/32", // Alibaba Cloud metadata, inside CGNAT space
		"192.0.0.192/32",     // Oracle Cloud metadata
		"168.63.129.16/32",   // Azure wire server, a public address
		"::/96", "fe80::/10", "ff00::/8", "fd00:ec2::/32", "2001::/32",
	)
	orgOIDCRestrictedNets = mustPrefixes(
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "192.0.0.0/24",
		"192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"fc00::/7", "2001:db8::/32", "64:ff9b:1::/48", "100::/64",
	)
	orgOIDCNAT64 = netip.MustParsePrefix("64:ff9b::/96")
	orgOIDC6to4  = netip.MustParsePrefix("2002::/16")
)

func orgOIDCContains(nets []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range nets {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// classifyOrgOIDCAddr classifies one address. IPv4-mapped IPv6 is unmapped, and
// the IPv4 embedded in NAT64 and 6to4 addresses is classified instead, so a
// loopback or metadata address cannot hide in an IPv6 spelling.
func classifyOrgOIDCAddr(addr netip.Addr) orgOIDCAddrClass {
	if !addr.IsValid() || addr.Zone() != "" {
		return orgOIDCAddrForbidden
	}
	addr = addr.Unmap()
	if addr.Is6() {
		bytes := addr.As16()
		switch {
		case orgOIDCNAT64.Contains(addr):
			return classifyOrgOIDCAddr(netip.AddrFrom4([4]byte(bytes[12:16])))
		case orgOIDC6to4.Contains(addr):
			return classifyOrgOIDCAddr(netip.AddrFrom4([4]byte(bytes[2:6])))
		}
	}
	switch {
	case orgOIDCContains(orgOIDCForbiddenNets, addr), addr.IsLoopback(), addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(), addr.IsMulticast(), addr.IsUnspecified(), addr.IsInterfaceLocalMulticast():
		return orgOIDCAddrForbidden
	case orgOIDCContains(orgOIDCRestrictedNets, addr), addr.IsPrivate():
		return orgOIDCAddrRestricted
	case !addr.IsGlobalUnicast():
		return orgOIDCAddrForbidden
	}
	return orgOIDCAddrPublic
}

type orgOIDCEgressRule struct {
	ports map[int]bool
	cidrs []netip.Prefix
}

// orgOIDCEgressPolicy is the compiled platform setting. Organizations have no
// input into it.
type orgOIDCEgressPolicy struct {
	rules        map[string]orgOIDCEgressRule
	maxRedirects int
}

func normalizeOrgOIDCHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", errors.New("zones are not allowed")
		}
		return addr.Unmap().String(), nil
	}
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/:*@?#[]\\ \t\r\n") || strings.HasPrefix(host, ".") {
		return "", errors.New("host must be one exact domain name or IP literal")
	}
	return host, nil
}

func compileOrgOIDCRule(rule system_setting.OrgOIDCEgressRule) (string, orgOIDCEgressRule, error) {
	host, err := normalizeOrgOIDCHost(rule.Host)
	if err != nil {
		return "", orgOIDCEgressRule{}, err
	}
	compiled := orgOIDCEgressRule{ports: map[int]bool{}}
	for _, port := range rule.Ports {
		if port < 1 || port > 65535 {
			return "", orgOIDCEgressRule{}, fmt.Errorf("port %d is out of range", port)
		}
		compiled.ports[port] = true
	}
	if len(compiled.ports) == 0 {
		compiled.ports[443] = true
	}
	for _, raw := range rule.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return "", orgOIDCEgressRule{}, fmt.Errorf("cidr %q is invalid", raw)
		}
		prefix = prefix.Masked()
		// A rule may open only private or special-use space, and only inside one
		// listed block, so 0.0.0.0/0 or a public range is not a valid exception.
		inside := false
		for _, restricted := range orgOIDCRestrictedNets {
			if restricted.Contains(prefix.Addr()) && prefix.Bits() >= restricted.Bits() {
				inside = true
				break
			}
		}
		if !inside {
			return "", orgOIDCEgressRule{}, fmt.Errorf("cidr %s is not inside private or special-use space", prefix)
		}
		compiled.cidrs = append(compiled.cidrs, prefix)
	}
	return host, compiled, nil
}

// ValidateOrgOIDCEgressSetting reports the first invalid rule. The settings
// save path should call it so a bad rule is rejected instead of silently
// ignored at request time.
func ValidateOrgOIDCEgressSetting(setting system_setting.OrgOIDCEgressSetting) error {
	if setting.MaxRedirects < 0 || setting.MaxRedirects > orgOIDCMaxRedirects {
		return fmt.Errorf("max_redirects must be between 0 and %d", orgOIDCMaxRedirects)
	}
	for _, rule := range setting.Rules {
		if _, _, err := compileOrgOIDCRule(rule); err != nil {
			return fmt.Errorf("rule %q: %w", rule.Host, err)
		}
	}
	return nil
}

// currentOrgOIDCEgressPolicy compiles the live setting. A rule that fails to
// compile is dropped, so a bad setting narrows access rather than widening it.
func currentOrgOIDCEgressPolicy() *orgOIDCEgressPolicy {
	setting := *system_setting.GetOrgOIDCEgressSetting()
	policy := &orgOIDCEgressPolicy{rules: map[string]orgOIDCEgressRule{}, maxRedirects: min(max(setting.MaxRedirects, 0), orgOIDCMaxRedirects)}
	for _, rule := range setting.Rules {
		host, compiled, err := compileOrgOIDCRule(rule)
		if err != nil {
			common.SysLog(common.LogText("Org OIDC egress rule ignored: host=%q reason=%s", rule.Host, err.Error()))
			continue
		}
		policy.rules[host] = compiled
	}
	return policy
}

// authorize returns the addresses host:port may be dialed at. Every resolved
// address must pass: one forbidden answer rejects the whole host, so a mixed
// public/loopback DNS reply cannot be used for rebinding.
func (p *orgOIDCEgressPolicy) authorize(ctx context.Context, resolver orgOIDCResolver, host string, port int) ([]netip.Addr, error) {
	host, err := normalizeOrgOIDCHost(host)
	if err != nil {
		return nil, orgOIDCDenied("host")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil, orgOIDCDenied("forbidden address")
	}
	rule, hasRule := p.rules[host]
	if port != 443 && !(hasRule && rule.ports[port]) {
		return nil, orgOIDCDenied("port")
	}
	var addrs []netip.Addr
	if literal, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{literal}
	} else if addrs, err = resolver.LookupNetIP(ctx, "ip", host); err != nil || len(addrs) == 0 {
		return nil, orgOIDCDenied("resolve")
	}
	allowed := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		switch classifyOrgOIDCAddr(addr) {
		case orgOIDCAddrForbidden:
			return nil, orgOIDCDenied("forbidden address")
		case orgOIDCAddrRestricted:
			if !hasRule || !rule.ports[port] || !prefixesContain(rule.cidrs, addr.Unmap()) {
				return nil, orgOIDCDenied("restricted address")
			}
		}
		allowed = append(allowed, addr.Unmap())
	}
	return allowed, nil
}

func prefixesContain(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// orgOIDCResolver is the DNS lookup the policy uses; tests substitute it.
type orgOIDCResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// OrgOIDCClientOptions replaces parts of the client for tests. It is accepted
// only by NewOrgOIDCHTTPClientForTest, which refuses to run outside a test binary.
type OrgOIDCClientOptions struct {
	Resolver  orgOIDCResolver
	DialAddr  func(ctx context.Context, network, address string) (net.Conn, error)
	RootCAs   *x509.CertPool
	Telemetry func(host string, port int, addrs []netip.Addr)
}

type orgOIDCDialer struct {
	policy    func() *orgOIDCEgressPolicy
	resolver  orgOIDCResolver
	dialAddr  func(ctx context.Context, network, address string) (net.Conn, error)
	telemetry func(host string, port int, addrs []netip.Addr)
}

func (d *orgOIDCDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, orgOIDCDenied("address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, orgOIDCDenied("port")
	}
	policy := d.policy()
	addrs, err := policy.authorize(ctx, d.resolver, host, port)
	if err != nil {
		logOrgOIDCDenied(host, port, err)
		return nil, err
	}
	if d.telemetry != nil {
		d.telemetry(host, port, addrs)
	}
	// Only the checked addresses are dialed, so no second DNS lookup can swap
	// the destination between the check and the connection.
	var last error
	for _, addr := range addrs {
		if (network == "tcp4" && !addr.Is4()) || (network == "tcp6" && !addr.Is6()) {
			continue
		}
		target := net.JoinHostPort(addr.String(), portText)
		var conn net.Conn
		if d.dialAddr != nil {
			conn, err = d.dialAddr(ctx, network, target)
		} else {
			dialer := &net.Dialer{Timeout: orgOIDCDialTimeout, Control: orgOIDCControl}
			conn, err = dialer.DialContext(ctx, network, target)
		}
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = orgOIDCDenied("no usable address")
	}
	return nil, last
}

// orgOIDCControl re-checks the destination the socket is about to connect to,
// after the OS has finished any address selection of its own.
func orgOIDCControl(network, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return orgOIDCDenied("address")
	}
	if classifyOrgOIDCAddr(addrPort.Addr()) == orgOIDCAddrForbidden {
		return orgOIDCDenied("forbidden address")
	}
	return nil
}

func logOrgOIDCDenied(host string, port int, err error) {
	common.SysLog(common.LogText("Org OIDC outbound connection denied: host=%q port=%d reason=%s", host, port, err.Error()))
}

// orgOIDCRoundTripper validates the request before it reaches the transport
// and bounds the response size.
type orgOIDCRoundTripper struct {
	next http.RoundTripper
}

func (t *orgOIDCRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		return nil, orgOIDCDenied("scheme")
	}
	if req.URL.User != nil || req.URL.Hostname() == "" {
		return nil, orgOIDCDenied("url")
	}
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return nil, orgOIDCDenied("host header")
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > orgOIDCMaxBody {
		resp.Body.Close()
		return nil, ErrOrgOIDCResponseTooLarge
	}
	resp.Body = &orgOIDCLimitedBody{ReadCloser: resp.Body, remaining: orgOIDCMaxBody}
	return resp, nil
}

type orgOIDCLimitedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *orgOIDCLimitedBody) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return 0, ErrOrgOIDCResponseTooLarge
	}
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return n, ErrOrgOIDCResponseTooLarge
	}
	return n, err
}

// checkOrgOIDCRedirect refuses redirects unless the platform allows some. A
// permitted hop is a GET or HEAD to an https origin; its destination is checked
// again when it is dialed. Credentials are never carried to a different origin.
func checkOrgOIDCRedirect(policy func() *orgOIDCEgressPolicy) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		deny := func(reason string) error {
			return fmt.Errorf("%w: %w", ErrOrgOIDCRedirectDenied, orgOIDCDenied("redirect "+reason))
		}
		if len(via) > policy().maxRedirects {
			return deny("not allowed")
		}
		first := via[0]
		if first.Method != http.MethodGet && first.Method != http.MethodHead {
			return deny("method")
		}
		if req.URL.Scheme != "https" {
			return deny("scheme")
		}
		previous := via[len(via)-1]
		if !strings.EqualFold(previous.URL.Host, req.URL.Host) {
			// net/http compares the host name only; compare the whole origin.
			for _, header := range []string{"Authorization", "Cookie", "Cookie2", "Www-Authenticate", "Proxy-Authorization"} {
				req.Header.Del(header)
			}
		}
		return nil
	}
}

func newOrgOIDCHTTPClient(policy func() *orgOIDCEgressPolicy, opts OrgOIDCClientOptions) *http.Client {
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := &orgOIDCDialer{policy: policy, resolver: resolver, dialAddr: opts.DialAddr, telemetry: opts.Telemetry}
	transport := &http.Transport{
		// Proxy is deliberately nil: a proxy would resolve and connect on our
		// behalf and bypass the destination checks, including HTTPS_PROXY.
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		DisableKeepAlives:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs},
		TLSHandshakeTimeout:    orgOIDCDialTimeout,
		ResponseHeaderTimeout:  orgOIDCClientTimeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &http.Client{
		Transport:     &orgOIDCRoundTripper{next: transport},
		Timeout:       orgOIDCClientTimeout,
		CheckRedirect: checkOrgOIDCRedirect(policy),
	}
}

var (
	orgOIDCClientOnce sync.Once
	orgOIDCClient     *http.Client
)

// OrgOIDCHTTPClient is the shared restricted client for tenant IdP traffic. It
// reads the platform egress policy on every request, so a rule change applies
// at once and no organization input can alter it.
func OrgOIDCHTTPClient() *http.Client {
	orgOIDCClientOnce.Do(func() {
		orgOIDCClient = newOrgOIDCHTTPClient(currentOrgOIDCEgressPolicy, OrgOIDCClientOptions{})
	})
	return orgOIDCClient
}

// NewOrgOIDCHTTPClientForTest builds a client whose DNS lookup and TCP dial are
// replaced so a test can reach a local fake IdP. The destination policy still
// runs on the names and addresses the fake resolver returns. It panics outside
// a test binary, so production code cannot use it to relax the policy.
func NewOrgOIDCHTTPClientForTest(opts OrgOIDCClientOptions) *http.Client {
	if !testing.Testing() {
		panic("NewOrgOIDCHTTPClientForTest is available to tests only")
	}
	return newOrgOIDCHTTPClient(currentOrgOIDCEgressPolicy, opts)
}

var (
	orgOIDCProviders   sync.Map
	orgOIDCProvidersMu sync.Mutex
	orgOIDCProviderN   int
)

// GetOrgOIDCProvider returns the relying party of a stored organization
// provider, reusing one instance per distinct configuration so the discovery
// document and JWKS stay cached between logins. The key covers every field of
// the configuration, so an edited issuer, client or secret gets a new instance.
func GetOrgOIDCProvider(provider *model.CustomOAuthProvider, redirectURI string) (*oauth.OrgOIDCProvider, error) {
	cfg, err := oauth.NewOrgOIDCConfig(provider, redirectURI)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d", cfg.OrgID, cfg.ProviderID,
		cfg.Issuer, cfg.ClientID, cfg.ClientSecret, strings.Join(cfg.Scopes, " "), cfg.RedirectURI, cfg.AuthStyle)))
	key := hex.EncodeToString(sum[:])
	if cached, ok := orgOIDCProviders.Load(key); ok {
		return cached.(*oauth.OrgOIDCProvider), nil
	}
	created, err := oauth.NewOrgOIDCProvider(cfg, OrgOIDCHTTPClient())
	if err != nil {
		return nil, err
	}
	orgOIDCProvidersMu.Lock()
	defer orgOIDCProvidersMu.Unlock()
	if cached, ok := orgOIDCProviders.Load(key); ok {
		return cached.(*oauth.OrgOIDCProvider), nil
	}
	if orgOIDCProviderN >= orgOIDCProviderCache {
		orgOIDCProviders.Clear()
		orgOIDCProviderN = 0
	}
	orgOIDCProviders.Store(key, created)
	orgOIDCProviderN++
	return created, nil
}
