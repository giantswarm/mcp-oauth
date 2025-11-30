package oidc

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
)

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
	u, err := url.Parse(issuerURL)
	if err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}

	// SECURITY: Enforce HTTPS to prevent credential leakage
	if u.Scheme != "https" {
		return fmt.Errorf("issuer URL must use HTTPS, got %s", u.Scheme)
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
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(connectorID) {
		return fmt.Errorf("connector_id contains invalid characters (allowed: a-z, A-Z, 0-9, _, -)")
	}

	// SECURITY: Prevent DoS via extremely long values
	if len(connectorID) > 64 {
		return fmt.Errorf("connector_id exceeds maximum length of 64 characters")
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
	if len(scopes) > 50 {
		return fmt.Errorf("too many scopes (max 50, got %d)", len(scopes))
	}

	for i, scope := range scopes {
		if scope == "" {
			return fmt.Errorf("scope at index %d is empty", i)
		}
		if len(scope) > 256 {
			return fmt.Errorf("scope at index %d exceeds maximum length of 256 characters", i)
		}
	}

	return nil
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
	// SECURITY: Prevent memory exhaustion from excessive groups
	if len(groups) > 100 {
		return fmt.Errorf("groups claim exceeds maximum of 100 groups (got %d)", len(groups))
	}

	for i, group := range groups {
		// SECURITY: Prevent memory exhaustion from long group names
		if len(group) > 256 {
			return fmt.Errorf("group at index %d exceeds maximum length of 256 characters", i)
		}
	}

	return nil
}
