package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// connectorIDRegex is a compiled regex for validating connector IDs.
// Pre-compiled at package initialization for performance.
var connectorIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ValidateHTTPSURL validates that a URL uses HTTPS scheme.
// This is a reusable helper to enforce HTTPS across all endpoints.
//
// Example:
//
//	if err := ValidateHTTPSURL("https://example.com", "issuer"); err != nil {
//	    return err
//	}
func ValidateHTTPSURL(rawURL, context string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid %s URL: %w", context, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s must use HTTPS, got %s", context, u.Scheme)
	}
	return nil
}

// ValidateIssuerURL validates an OIDC issuer URL with SSRF protection.
// It enforces HTTPS and blocks private IP ranges to prevent Server-Side Request Forgery attacks.
//
// This is a convenience wrapper around ValidateExternalURL with "issuer URL" as the context.
//
// Security Considerations:
//   - HTTPS Enforcement: Prevents credential interception
//   - Private IP Blocking: Prevents SSRF against internal services (Kubernetes API, metadata services, etc.)
//   - Loopback Blocking: Prevents attacks against localhost services
//   - Link-local Blocking: Prevents metadata service attacks (169.254.169.254)
//
// Example:
//
//	if err := ValidateIssuerURL("https://dex.example.com"); err != nil {
//	    return fmt.Errorf("invalid issuer: %w", err)
//	}
func ValidateIssuerURL(issuerURL string) error {
	return ValidateExternalURL(issuerURL, "issuer URL")
}

// ValidateExternalURL validates an external URL with SSRF protection.
// It enforces HTTPS and blocks private IP ranges to prevent Server-Side Request Forgery attacks.
// This is a generic version of ValidateIssuerURL that accepts a context parameter for error messages.
//
// Security Considerations:
//   - HTTPS Enforcement: Prevents credential interception
//   - Private IP Blocking: Prevents SSRF against internal services (Kubernetes API, metadata services, etc.)
//   - Loopback Blocking: Prevents attacks against localhost services
//   - Link-local Blocking: Prevents metadata service attacks (169.254.169.254)
//
// Example:
//
//	if err := ValidateExternalURL("https://provider.example.com/.well-known/jwks", "JWKS URI"); err != nil {
//	    return fmt.Errorf("invalid JWKS URI: %w", err)
//	}
func ValidateExternalURL(rawURL, context string) error {
	// SECURITY: Enforce HTTPS to prevent credential leakage
	if err := ValidateHTTPSURL(rawURL, context); err != nil {
		return err
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", context, err)
	}

	// SECURITY: Validate hostname format
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%s must have a hostname", context)
	}

	// SECURITY: Block private IP ranges to prevent SSRF
	// Parse as IP address
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("%s must not point to loopback addresses", context)
		}
		if ip.IsPrivate() {
			return fmt.Errorf("%s must not point to private IP ranges", context)
		}
		if ip.IsLinkLocalUnicast() {
			return fmt.Errorf("%s must not point to link-local addresses", context)
		}
	}

	return nil
}

// ValidateConnectorID validates a Dex connector_id parameter.
// Connector IDs should be alphanumeric with hyphens/underscores only.
//
// Security Considerations:
//   - Character Whitelist: Prevents injection attacks
//   - Length Limit: Prevents DoS via extremely long values
//
// Example:
//
//	if err := ValidateConnectorID("github"); err != nil {
//	    return fmt.Errorf("invalid connector: %w", err)
//	}
func ValidateConnectorID(connectorID string) error {
	if connectorID == "" {
		return nil // Optional parameter
	}

	// Connector IDs should be alphanumeric with hyphens/underscores
	if !connectorIDRegex.MatchString(connectorID) {
		return fmt.Errorf("connector_id contains invalid characters (allowed: a-z, A-Z, 0-9, _, -)")
	}

	// SECURITY: Prevent DoS via extremely long values
	if len(connectorID) > 64 {
		return fmt.Errorf("connector_id exceeds maximum length of 64 characters")
	}

	return nil
}

// validateStringSlice validates a slice of strings for size and length constraints.
// This is a reusable helper to prevent DoS attacks via excessive or oversized items.
func validateStringSlice(items []string, context string, maxCount, maxLength int) error {
	if len(items) > maxCount {
		return fmt.Errorf("%s exceeds maximum of %d items (got %d)", context, maxCount, len(items))
	}

	for i, item := range items {
		if len(item) > maxLength {
			return fmt.Errorf("%s at index %d exceeds maximum length of %d characters", context, i, maxLength)
		}
	}

	return nil
}

// MaxScopeCount is the maximum number of scopes ValidateScopes accepts. It
// bounds the scope set a single authorization request can carry.
const MaxScopeCount = 50

// MaxScopeLength is the maximum length ValidateScopes accepts for one scope.
const MaxScopeLength = 256

// ValidateScopes validates OAuth scopes.
//
// Security Considerations:
//   - Array Size Limit: Prevents DoS from excessive scopes
//   - String Length Limit: Prevents memory exhaustion
//   - Empty Scope Detection: Prevents malformed requests
//
// Example:
//
//	scopes := []string{"openid", "profile", "email"}
//	if err := ValidateScopes(scopes); err != nil {
//	    return fmt.Errorf("invalid scopes: %w", err)
//	}
func ValidateScopes(scopes []string) error {
	// Check for empty scopes first
	for i, scope := range scopes {
		if scope == "" {
			return fmt.Errorf("scope at index %d is empty", i)
		}
	}

	// Validate size and length constraints
	return validateStringSlice(scopes, "scopes", MaxScopeCount, MaxScopeLength)
}

// Default limits for groups validation.
const (
	// DefaultMaxGroups is the default maximum number of groups accepted in an OIDC groups claim.
	// Set to 600 to accommodate enterprise environments (Active Directory, Azure AD, LDAP,
	// large GitHub organizations) where users commonly have 500+ group memberships.
	DefaultMaxGroups = 600

	// DefaultMaxGroupNameLength is the default maximum length of a single group name.
	DefaultMaxGroupNameLength = 256
)

// ValidateGroups validates and truncates an OIDC groups claim.
// If maxGroups is <= 0, DefaultMaxGroups (600) is used.
//
// Groups exceeding maxGroups are truncated (not rejected) so authentication
// can proceed. The second return value indicates whether truncation occurred.
// Individual group names exceeding DefaultMaxGroupNameLength are rejected
// with an error, as oversized names may indicate an injection attempt.
//
// Returns a defensive copy of the groups slice.
//
// Security Considerations:
//   - Array Size Limit: Prevents memory exhaustion from excessive groups
//   - String Length Limit: Prevents memory exhaustion from long group names
//
// Example:
//
//	validated, truncated, err := ValidateGroups(groups, 0)
//	if err != nil {
//	    return fmt.Errorf("invalid groups: %w", err)
//	}
//	if truncated {
//	    slog.Warn("groups truncated", "original", len(groups))
//	}
func ValidateGroups(groups []string, maxGroups int) ([]string, bool, error) {
	if maxGroups <= 0 {
		maxGroups = DefaultMaxGroups
	}

	for i, g := range groups {
		if len(g) > DefaultMaxGroupNameLength {
			return nil, false, fmt.Errorf("groups at index %d exceeds maximum length of %d characters", i, DefaultMaxGroupNameLength)
		}
	}

	truncated := len(groups) > maxGroups
	count := len(groups)
	if truncated {
		count = maxGroups
	}

	result := make([]string, count)
	copy(result, groups[:count])
	return result, truncated, nil
}

// isPrivateOrRestrictedIP checks if an IP address is private, loopback, link-local, or unspecified.
// This is used for DNS rebinding protection to validate resolved IPs.
//
// Blocked address types:
//   - Loopback: 127.0.0.0/8, ::1
//   - Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
//   - Link-local: 169.254.0.0/16, fe80::/10 (includes cloud metadata services)
//   - Unspecified: 0.0.0.0, :: (can be abused in some SSRF scenarios)
func isPrivateOrRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// SSRFSafeDialContext creates a DialContext function that validates resolved IPs
// to prevent DNS rebinding attacks. DNS rebinding occurs when an attacker controls
// a DNS server that initially returns a public IP (passing URL validation) but later
// returns a private IP (when the actual connection is made).
//
// Security Features:
//   - Validates each resolved IP before allowing connection
//   - Blocks loopback, private, and link-local addresses
//   - Prevents access to cloud metadata services (169.254.169.254)
//
// Example:
//
//	transport := &http.Transport{
//	    DialContext: SSRFSafeDialContext(&net.Dialer{Timeout: 10 * time.Second}),
//	}
//	client := &http.Client{Transport: transport}
func SSRFSafeDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Extract host from address (addr is "host:port")
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		// Resolve the hostname to IP addresses
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed for %q: %w", host, err)
		}

		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses found for %q", host)
		}

		// SECURITY: Validate ALL resolved IPs before attempting any connection
		// This prevents DNS rebinding attacks where the first IP is public but others are private
		for _, ip := range ips {
			if isPrivateOrRestrictedIP(ip) {
				return nil, fmt.Errorf("DNS rebinding attack detected: %q resolved to restricted IP %s", host, ip)
			}
		}

		// All IPs are safe, connect to the first one
		// We use the first IP since we've validated all are safe
		safeAddr := net.JoinHostPort(ips[0].String(), port)
		return dialer.DialContext(ctx, network, safeAddr)
	}
}

// NewSSRFSafeHTTPClient creates an HTTP client with DNS rebinding protection.
// This client validates that resolved IP addresses are not private/restricted
// at connection time, preventing DNS rebinding attacks.
//
// Which IP addresses the client may reach and which CA signs the certificate it
// trusts are independent: an IdP on a public address can still present a
// certificate from an internal CA, so rootCAs applies here exactly as it does on
// the permissive clients.
//
// Parameters:
//   - timeout: HTTP client timeout (0 uses default 10 seconds)
//   - rootCAs: CA pool the certificate is verified against; nil uses the system
//     pool. The pool replaces the system roots, so a caller that needs both must
//     pass a pool that already contains them.
//
// Security Features:
//   - DNS Rebinding Protection: Validates resolved IPs at connection time
//   - SSRF Protection: Blocks private, loopback, and link-local addresses
//   - TLS Verification: enforced (never InsecureSkipVerify)
//
// Example:
//
//	client := NewSSRFSafeHTTPClient(30*time.Second, nil)
//	resp, err := client.Get("https://example.com/jwks")
func NewSSRFSafeHTTPClient(timeout time.Duration, rootCAs *x509.CertPool) *http.Client {
	return newJWKSHTTPClient(timeout,
		func(d *net.Dialer) dialContextFunc { return SSRFSafeDialContext(d) },
		false, // pinHost: SSRF dial guard already blocks cross-host redirects to private IPs
		rootCAs,
	)
}

// dialContextFunc is the DialContext signature shared by the JWKS HTTP clients.
type dialContextFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

// newJWKSHTTPClient builds the JWKS HTTP clients from their three differing
// dimensions, keeping the transport/timeout block and the TLS decision in one
// place. dialFor selects the dial posture (SSRF-safe, private-IP, host-scoped);
// pinHost adds the cross-host redirect guard (needed when the dialer cannot
// itself filter private IPs); rootCAs, when non-nil, is the explicit CA pool the
// client verifies against (for an internal-CA IdP) — nil keeps the default
// (system pool) verification. Only RootCAs is set on the TLS config, never
// InsecureSkipVerify, so the "never InsecureSkipVerify" invariant holds even on
// the permissive clients where the SSRF dial guard is relaxed.
func newJWKSHTTPClient(timeout time.Duration, dialFor func(*net.Dialer) dialContextFunc, pinHost bool, rootCAs *x509.CertPool) *http.Client {
	if timeout == 0 {
		timeout = DefaultHTTPTimeout
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: DefaultDialerKeepAlive,
	}

	transport := &http.Transport{
		DialContext:           dialFor(dialer),
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          DefaultMaxIdleConns,
		IdleConnTimeout:       DefaultIdleConnTimeout,
	}
	if rootCAs != nil {
		transport.TLSClientConfig = &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	if pinHost {
		client.CheckRedirect = blockCrossHostRedirect
	}
	return client
}

// NewPrivateIPAllowedHTTPClient creates an HTTP client without SSRF protection.
// This client allows connections to private IP addresses, which is necessary
// for private IdP deployments (e.g., internal Dex).
//
// WARNING: This reduces SSRF protection. Only use when connecting to trusted
// internal services where the IdP legitimately runs on private networks.
//
// Parameters:
//   - timeout: HTTP client timeout (0 uses default 10 seconds)
//
// Security Features:
//   - TLS Verification: enforced (never InsecureSkipVerify). Verifies against
//     the provided rootCAs pool (for an internal-CA IdP), or the system pool
//     when rootCAs is nil.
//   - No SSRF Protection: Private, loopback, and link-local addresses are ALLOWED
//   - Host-pinned redirects: a redirect to a different host is refused. Because
//     this client cannot filter private IPs, it pins requests to the host that was
//     originally dialed so a discovery/JWKS endpoint cannot 302 the fetch to an
//     arbitrary internal target.
//
// Use Cases:
//   - Home lab deployments with internal Dex
//   - Air-gapped environments
//   - Enterprise deployments with private IdPs
//
// Parameters:
//   - timeout: HTTP client timeout (0 uses default 10 seconds)
//   - rootCAs: CA pool to verify the IdP's certificate against; nil uses the
//     system pool. Pass the internal CA when the private IdP presents a
//     certificate from a CA not in the system pool.
//
// Example:
//
//	client := NewPrivateIPAllowedHTTPClient(30 * time.Second, dexCAPool)
//	resp, err := client.Get("https://dex.internal/keys")
func NewPrivateIPAllowedHTTPClient(timeout time.Duration, rootCAs *x509.CertPool) *http.Client {
	return newJWKSHTTPClient(timeout,
		// Standard dialer without SSRF protection (allows private IPs).
		func(d *net.Dialer) dialContextFunc { return d.DialContext },
		true, // pinHost: dialer cannot filter private IPs, so guard cross-host redirects
		rootCAs,
	)
}

func guardSSRF(host string, ips []net.IP) error {
	for _, ip := range ips {
		if isPrivateOrRestrictedIP(ip) {
			return fmt.Errorf("DNS rebinding attack detected: %q resolved to restricted IP %s", host, ip)
		}
	}
	return nil
}

// HostScopedPrivateIPDialContext creates a DialContext that allows private IP
// resolution only for the explicitly listed hostnames; all other hosts are
// subject to the normal SSRF/DNS-rebinding guard.
func HostScopedPrivateIPDialContext(dialer *net.Dialer, allowedHosts []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, h := range allowedHosts {
		allowed[h] = struct{}{}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed for %q: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses found for %q", host)
		}

		_, isAllowed := allowed[host]
		if !isAllowed {
			if err := guardSSRF(host, ips); err != nil {
				return nil, err
			}
		}

		safeAddr := net.JoinHostPort(ips[0].String(), port)
		return dialer.DialContext(ctx, network, safeAddr)
	}
}

// NewHostScopedPrivateIPHTTPClient creates an HTTP client that allows private
// IP resolution only for the explicitly listed hostnames. All other hosts go
// through the normal SSRF/DNS-rebinding guard. Use this instead of
// NewPrivateIPAllowedHTTPClient when the private endpoint is a known in-cluster
// service — it narrows the SSRF escape hatch to only the expected host.
//
// rootCAs, when non-nil, is the CA pool the client verifies the IdP's
// certificate against; nil uses the system pool.
func NewHostScopedPrivateIPHTTPClient(allowedHosts []string, timeout time.Duration, rootCAs *x509.CertPool) *http.Client {
	return newJWKSHTTPClient(timeout,
		func(d *net.Dialer) dialContextFunc { return HostScopedPrivateIPDialContext(d, allowedHosts) },
		true, // pinHost: private IPs allowed for the listed hosts, so guard cross-host redirects
		rootCAs,
	)
}

// blockCrossHostRedirect refuses a redirect whose target host or port differs
// from the endpoint originally requested, and bounds the chain at the net/http
// default of 10 hops. Setting CheckRedirect replaces that default cap, so it is
// reapplied here. Pinning the port as well as the host blocks a same-host pivot
// to a different internal service (e.g. a metadata or admin port) and a scheme
// downgrade to plaintext.
func blockCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	origin := via[0].URL
	if !strings.EqualFold(req.URL.Hostname(), origin.Hostname()) || effectivePort(req.URL) != effectivePort(origin) {
		return fmt.Errorf("refusing cross-host redirect to %q (request endpoint %q)", req.URL.Host, origin.Host)
	}
	if len(via) >= 10 {
		return fmt.Errorf("stopped after %d redirects", len(via))
	}
	return nil
}

// effectivePort returns the URL's port, resolving the scheme default when the
// port is implicit, so https://h and https://h:443 compare equal.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}
