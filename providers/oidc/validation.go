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
	// SECURITY: Enforce HTTPS to prevent credential leakage
	if err := ValidateHTTPSURL(issuerURL, "issuer URL"); err != nil {
		return err
	}

	u, err := url.Parse(issuerURL)
	if err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}

	// SECURITY: Validate hostname format
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("issuer URL must have a hostname")
	}

	// SECURITY: Block private IP ranges to prevent SSRF
	// Parse as IP address
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("issuer URL must not point to loopback addresses")
		}
		if ip.IsPrivate() {
			return fmt.Errorf("issuer URL must not point to private IP ranges")
		}
		if ip.IsLinkLocalUnicast() {
			return fmt.Errorf("issuer URL must not point to link-local addresses")
		}
	}

	return nil
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

// ValidateGroups validates groups claim from userinfo.
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
	// SECURITY: Prevent memory exhaustion from excessive groups and long group names
	return validateStringSlice(groups, "groups", 100, 256)
}

// isPrivateOrRestrictedIP checks if an IP address is private, loopback, or link-local.
// This is used for DNS rebinding protection to validate resolved IPs.
func isPrivateOrRestrictedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
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
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:           SSRFSafeDialContext(dialer),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}
