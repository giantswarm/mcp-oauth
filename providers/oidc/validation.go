package oidc

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
)

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
