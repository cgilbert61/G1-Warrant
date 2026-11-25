package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

// Options controls dial-time SSRF protection and private-endpoint allowlisting.
type Options struct {
	// EnforceStrict blocks loopback, RFC1918, ULA, CGNAT, NAT64, 6to4, and Teredo addresses
	// unless the exact host:port or host is listed in AllowedPrivateHosts.
	// Cloud metadata IPs (169.254.169.254, 169.254.170.2, 168.63.129.16, 100.100.100.200, fd00:ec2::254)
	// are ALWAYS blocked regardless of EnforceStrict or AllowedPrivateHosts.
	EnforceStrict bool

	// AllowedPrivateHosts permits specific internal hosts or host:port pairs in strict mode
	// (e.g. "vault.internal:8200", "rekor.internal"). Never overrides cloud metadata blocks.
	AllowedPrivateHosts []string

	// DialTimeout bounds TCP dial latency. Defaults to 10s.
	DialTimeout time.Duration

	// KeepAlive bounds TCP keepalive interval. Defaults to 30s.
	KeepAlive time.Duration

	// MaxRedirects caps HTTP redirects. Defaults to 5.
	MaxRedirects int
}

var (
	metadataPrefixes = mustParsePrefixes(
		"169.254.169.254/32", // AWS / GCP / Azure / OpenStack IMDS
		"169.254.170.2/32",   // AWS ECS task metadata
		"168.63.129.16/32",   // Azure WireServer / IMDS helper
		"100.100.100.200/32", // Alibaba Cloud metadata
		"fd00:ec2::254/128",  // AWS IPv6 IMDS
	)

	blockedPrivatePrefixes = mustParsePrefixes(
		"0.0.0.0/8",          // "this" network
		"10.0.0.0/8",         // RFC1918
		"100.64.0.0/10",      // RFC6598 CGNAT
		"127.0.0.0/8",        // IPv4 loopback
		"169.254.0.0/16",     // IPv4 link-local
		"172.16.0.0/12",      // RFC1918
		"192.0.0.0/24",       // IETF protocol assignments
		"192.168.0.0/16",     // RFC1918
		"198.18.0.0/15",      // Benchmarking
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved / broadcast
		"::/128",             // IPv6 unspecified
		"::1/128",            // IPv6 loopback
		"64:ff9b::/96",       // NAT64 well-known prefix
		"64:ff9b:1::/48",     // NAT64 local-use prefix
		"100::/64",           // Discard-only
		"2001::/32",          // Teredo
		"2002::/16",          // 6to4
		"fc00::/7",           // IPv6 ULA
		"fe80::/10",          // IPv6 link-local
		"ff00::/8",           // IPv6 multicast
	)

	blockedMetadataHostnames = map[string]bool{
		"metadata.google.internal":        true,
		"metadata.goog":                   true,
		"instance-data":                   true,
		"instance-data.ec2.internal":      true,
		"metadata.azure.internal":         true,
		"metadata.tencentyun.com":         true,
		"metadata.packet.net":             true,
		"metadata.platformequinix.com":    true,
	}
)

func mustParsePrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// DefaultOptionsFromEnv derives SSRF dialer options from WARRANT_* environment variables.
// Strict mode is enabled automatically in live/kubernetes deployments or when WARRANT_SSRF_GUARD=strict.
func DefaultOptionsFromEnv() Options {
	ssrfMode := strings.ToLower(strings.TrimSpace(os.Getenv("WARRANT_SSRF_GUARD")))
	clusterDriver := strings.ToLower(strings.TrimSpace(os.Getenv("WARRANT_CLUSTER_DRIVER")))
	feedMode := strings.ToLower(strings.TrimSpace(os.Getenv("WARRANT_FEED_MODE")))

	strict := false
	switch ssrfMode {
	case "strict", "true", "1", "on":
		strict = true
	case "off", "false", "0":
		strict = false
	default:
		strict = clusterDriver == "kubernetes" || feedMode == "live"
	}

	var allow []string
	if raw := strings.TrimSpace(os.Getenv("WARRANT_ALLOWED_PRIVATE_ENDPOINTS")); raw != "" {
		for _, item := range strings.Split(raw, ",") {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				allow = append(allow, trimmed)
			}
		}
	}

	return Options{
		EnforceStrict:       strict,
		AllowedPrivateHosts: allow,
		DialTimeout:         10 * time.Second,
		KeepAlive:           30 * time.Second,
		MaxRedirects:        5,
	}
}

// IsMetadataHostname returns true if host is a well-known cloud metadata DNS name.
func IsMetadataHostname(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	return blockedMetadataHostnames[h]
}

// IsCloudMetadataIP returns true if ip is a cloud instance metadata endpoint
// (including IPv4-mapped IPv6 forms such as ::ffff:169.254.169.254).
func IsCloudMetadataIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	for _, p := range metadataPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ClassifyDisallowedIP checks whether ip falls into a metadata or non-global address range.
// Returns (reason, blocked). Metadata IPs are always flagged with "CLOUD_METADATA_IP_BLOCKED".
func ClassifyDisallowedIP(ip net.IP, enforceStrict bool) (string, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "INVALID_IP_ADDRESS", true
	}
	addr = addr.Unmap()

	for _, p := range metadataPrefixes {
		if p.Contains(addr) {
			return fmt.Sprintf("CLOUD_METADATA_IP_BLOCKED (%s)", addr.String()), true
		}
	}
	if !enforceStrict {
		return "", false
	}
	for _, p := range blockedPrivatePrefixes {
		if p.Contains(addr) {
			return fmt.Sprintf("NON_PUBLIC_IP_BLOCKED (%s in %s)", addr.String(), p.String()), true
		}
	}
	if !addr.IsGlobalUnicast() {
		return fmt.Sprintf("NON_GLOBAL_UNICAST_IP_BLOCKED (%s)", addr.String()), true
	}
	return "", false
}

func isHostAllowedPrivate(host, port string, allowlist []string) bool {
	hLow := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	hostPort := strings.ToLower(net.JoinHostPort(hLow, port))
	for _, entry := range allowlist {
		eLow := strings.ToLower(strings.TrimSpace(entry))
		if eLow == "" {
			continue
		}
		if eLow == hLow || eLow == hostPort {
			return true
		}
	}
	return false
}

// NewPinnedDialContext returns a DialContext function that resolves DNS once,
// validates every returned IP against metadata and (when strict) non-public ranges,
// and dials the validated IP literal directly to prevent DNS rebinding.
func NewPinnedDialContext(opts Options) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	keepAlive := opts.KeepAlive
	if keepAlive <= 0 {
		keepAlive = 30 * time.Second
	}
	baseDialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("SSRF_GUARD_INVALID_ADDRESS: %w", err)
		}
		if IsMetadataHostname(host) {
			return nil, fmt.Errorf("SSRF_GUARD_BLOCKED: cloud metadata hostname %q is forbidden", host)
		}

		// Determine if this host is explicitly allowlisted for private networking
		// (metadata IPs are still strictly blocked below).
		effectiveStrict := opts.EnforceStrict
		if effectiveStrict && isHostAllowedPrivate(host, port, opts.AllowedPrivateHosts) {
			effectiveStrict = false
		}

		// If host is already an IP literal, validate and dial directly.
		if ip := net.ParseIP(host); ip != nil {
			if reason, blocked := ClassifyDisallowedIP(ip, effectiveStrict); blocked {
				return nil, fmt.Errorf("SSRF_GUARD_BLOCKED: %s", reason)
			}
			return baseDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}

		// Resolve DNS once and validate all returned IPs before dialing the pinned IP literal.
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("SSRF_GUARD_DNS_LOOKUP_FAILED (%s): %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("SSRF_GUARD_DNS_EMPTY (%s)", host)
		}

		var validIPs []net.IP
		for _, ipAddr := range ips {
			if reason, blocked := ClassifyDisallowedIP(ipAddr.IP, effectiveStrict); blocked {
				return nil, fmt.Errorf("SSRF_GUARD_BLOCKED (%s): %s", host, reason)
			}
			validIPs = append(validIPs, ipAddr.IP)
		}

		var lastErr error
		for _, ip := range validIPs {
			conn, dErr := baseDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dErr == nil {
				return conn, nil
			}
			lastErr = dErr
		}
		if lastErr == nil {
			lastErr = errors.New("no valid IP addresses dialed")
		}
		return nil, lastErr
	}
}

// ValidateTargetURL checks scheme and hostname/literal IP before sending an HTTP request
// (used in CheckRedirect and pre-flight validation).
func ValidateTargetURL(rawURL string, opts Options) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("SSRF_GUARD_INVALID_URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("SSRF_GUARD_DISALLOWED_SCHEME: %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("SSRF_GUARD_EMPTY_HOST")
	}
	if IsMetadataHostname(host) {
		return fmt.Errorf("SSRF_GUARD_BLOCKED: cloud metadata hostname %q is forbidden", host)
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	effectiveStrict := opts.EnforceStrict
	if effectiveStrict && isHostAllowedPrivate(host, port, opts.AllowedPrivateHosts) {
		effectiveStrict = false
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason, blocked := ClassifyDisallowedIP(ip, effectiveStrict); blocked {
			return fmt.Errorf("SSRF_GUARD_BLOCKED: %s", reason)
		}
	}
	return nil
}

// NewPinnedTransport creates a cloned http.Transport with DialContext pinned via NewPinnedDialContext.
func NewPinnedTransport(opts Options) *http.Transport {
	var tr *http.Transport
	if def, ok := http.DefaultTransport.(*http.Transport); ok && def != nil {
		tr = def.Clone()
	} else {
		tr = &http.Transport{}
	}
	tr.DialContext = NewPinnedDialContext(opts)
	return tr
}

// NewSafeHTTPClient builds an *http.Client using PinnedDialContext (when baseTransport is nil)
// and redirect validation that blocks cloud metadata and non-public redirects.
func NewSafeHTTPClient(timeout time.Duration, baseTransport http.RoundTripper, opts ...Options) *http.Client {
	o := DefaultOptionsFromEnv()
	if len(opts) > 0 {
		o = opts[0]
	}
	maxRedir := o.MaxRedirects
	if maxRedir <= 0 {
		maxRedir = 5
	}
	rt := baseTransport
	if rt == nil {
		rt = NewPinnedTransport(o)
	}
	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedir {
				return fmt.Errorf("SSRF_GUARD_TOO_MANY_REDIRECTS: stopped after %d redirects", maxRedir)
			}
			return ValidateTargetURL(req.URL.String(), o)
		},
	}
}
