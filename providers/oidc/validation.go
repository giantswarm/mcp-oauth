package oidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
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
	return validateStringSlice(scopes, "scopes", 50, 256)
}

// Default limits for groups validation.
const (
	// DefaultMaxGroups is the default maximum number of groups accepted in an OIDC groups claim.
	// Set to 500 to accommodate enterprise environments (Active Directory, Azure AD, LDAP)
	// where users commonly have hundreds of group memberships.
	DefaultMaxGroups = 500

	// DefaultMaxGroupNameLength is the default maximum length of a single group name.
	DefaultMaxGroupNameLength = 256
)

// ValidateGroups validates groups claim from userinfo.
// It rejects the entire groups list if it exceeds DefaultMaxGroups or
// if any group name exceeds DefaultMaxGroupNameLength.
//
// For authentication flows where partial group data is acceptable,
// use SanitizeGroups which truncates instead of rejecting.
//
// Security Considerations:
//   - Array Size Limit: Prevents memory exhaustion from excessive groups
//   - String Length Limit: Prevents memory exhaustion from long group names
//
// Example:
//
//	groups := []string{"admin", "developers"}
//	if err := ValidateGroups(groups); err != nil {
//	    return fmt.Errorf("invalid groups: %w", err)
//	}
func ValidateGroups(groups []string) error {
	return ValidateGroupsWithLimit(groups, DefaultMaxGroups)
}

// ValidateGroupsWithLimit validates groups claim with a custom maximum count.
// It rejects the entire list if the count exceeds maxCount or any name
// exceeds DefaultMaxGroupNameLength.
//
// Use this when you need stricter limits than DefaultMaxGroups (500).
//
// Example:
//
//	if err := ValidateGroupsWithLimit(groups, 100); err != nil {
//	    return fmt.Errorf("invalid groups: %w", err)
//	}
func ValidateGroupsWithLimit(groups []string, maxCount int) error {
	return validateStringSlice(groups, "groups", maxCount, DefaultMaxGroupNameLength)
}

// SanitizeGroups validates and truncates a groups claim instead of rejecting it.
// If the number of groups exceeds maxCount, the list is truncated to maxCount entries
// and the second return value is true. If maxCount is <= 0, DefaultMaxGroups is used.
//
// Individual group names that exceed DefaultMaxGroupNameLength are still rejected
// with an error, as oversized names may indicate an injection attempt.
//
// This function is preferred over ValidateGroups in authentication flows where
// partial group data is acceptable and a hard failure would block the user entirely.
//
// Example:
//
//	sanitized, truncated, err := SanitizeGroups(groups, 500)
//	if err != nil {
//	    return fmt.Errorf("invalid groups: %w", err)
//	}
//	if truncated {
//	    slog.Warn("groups truncated", "original", len(groups), "limit", 500)
//	}
func SanitizeGroups(groups []string, maxCount int) ([]string, bool, error) {
	if maxCount <= 0 {
		maxCount = DefaultMaxGroups
	}

	// Validate all group name lengths, including those beyond the truncation
	// boundary. An oversized name anywhere in the list may indicate an injection
	// attempt and should be rejected regardless of whether it would be truncated.
	for i, g := range groups {
		if len(g) > DefaultMaxGroupNameLength {
			return nil, false, fmt.Errorf("groups at index %d exceeds maximum length of %d characters", i, DefaultMaxGroupNameLength)
		}
	}

	truncated := len(groups) > maxCount
	count := len(groups)
	if truncated {
		count = maxCount
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
// Parameters:
//   - timeout: HTTP client timeout (0 uses default 10 seconds)
//
// Security Features:
//   - DNS Rebinding Protection: Validates resolved IPs at connection time
//   - SSRF Protection: Blocks private, loopback, and link-local addresses
//   - TLS Verification: Uses default TLS settings (no InsecureSkipVerify)
//
// Example:
//
//	client := NewSSRFSafeHTTPClient(30 * time.Second)
//	resp, err := client.Get("https://example.com/jwks")
func NewSSRFSafeHTTPClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = DefaultHTTPTimeout
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: DefaultDialerKeepAlive,
	}

	transport := &http.Transport{
		DialContext:           SSRFSafeDialContext(dialer),
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          DefaultMaxIdleConns,
		IdleConnTimeout:       DefaultIdleConnTimeout,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
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
//   - TLS Verification: Uses default TLS settings (no InsecureSkipVerify)
//   - No SSRF Protection: Private, loopback, and link-local addresses are ALLOWED
//
// Use Cases:
//   - Home lab deployments with internal Dex
//   - Air-gapped environments
//   - Enterprise deployments with private IdPs
//
// Example:
//
//	client := NewPrivateIPAllowedHTTPClient(30 * time.Second)
//	resp, err := client.Get("https://dex.internal/keys")
func NewPrivateIPAllowedHTTPClient(timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = DefaultHTTPTimeout
	}

	// Use standard dialer without SSRF protection (allows private IPs)
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: DefaultDialerKeepAlive,
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          DefaultMaxIdleConns,
		IdleConnTimeout:       DefaultIdleConnTimeout,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
