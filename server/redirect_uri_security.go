package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// isLinkLocalIP checks if an IP address is link-local (unicast or multicast).
// This includes:
// - IPv4 link-local: 169.254.0.0/16 (also catches cloud metadata 169.254.169.254)
// - IPv6 link-local unicast: fe80::/10
// - IPv6 link-local multicast: ff02::/16
//
// Link-local addresses are a significant security concern in cloud environments
// as they can access instance metadata services (AWS, GCP, Azure).
func isLinkLocalIP(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// Redirect URI validation stage constants for metrics.
const (
	// RedirectURIStageRegistration indicates validation during client registration.
	RedirectURIStageRegistration = "registration"
	// RedirectURIStageAuthorization indicates validation during authorization request.
	RedirectURIStageAuthorization = "authorization"
)

// RedirectURISecurityError represents a redirect URI validation error
// with detailed information for operators while keeping error messages generic for clients.
type RedirectURISecurityError struct {
	// Category is the error category for logging/metrics
	Category string
	// URI is the offending redirect URI (sanitized for logging)
	URI string
	// Reason is the detailed internal reason (for logs, not returned to client)
	Reason string
	// ClientMessage is the message safe to return to clients
	ClientMessage string
}

func (e *RedirectURISecurityError) Error() string {
	return e.ClientMessage
}

// newRedirectURISecurityError creates a new RedirectURISecurityError with automatic URI sanitization.
// This constructor ensures that URIs are always sanitized for logging, reducing code duplication
// and preventing accidental exposure of sensitive URI components (query params, credentials).
func newRedirectURISecurityError(category, rawURI, reason, clientMessage string) *RedirectURISecurityError {
	return &RedirectURISecurityError{
		Category:      category,
		URI:           sanitizeURIForLogging(rawURI),
		Reason:        reason,
		ClientMessage: clientMessage,
	}
}

// Redirect URI security error categories for metrics and logging.
const (
	RedirectURIErrorCategoryBlockedScheme   = "blocked_scheme"
	RedirectURIErrorCategoryPrivateIP       = "private_ip"
	RedirectURIErrorCategoryLinkLocal       = "link_local"
	RedirectURIErrorCategoryLoopback        = "loopback_not_allowed"
	RedirectURIErrorCategoryHTTPNotAllowed  = "http_not_allowed"
	RedirectURIErrorCategoryDNSPrivateIP    = "dns_resolves_to_private_ip"
	RedirectURIErrorCategoryDNSLinkLocal    = "dns_resolves_to_link_local"
	RedirectURIErrorCategoryDNSFailure      = "dns_resolution_failed"
	RedirectURIErrorCategoryInvalidFormat   = "invalid_format"
	RedirectURIErrorCategoryFragment        = "fragment_not_allowed"
	RedirectURIErrorCategoryUnspecifiedAddr = "unspecified_address"
)

// ValidateRedirectURIForRegistration performs comprehensive security validation
// on a redirect URI during client registration. This is the primary entry point
// for redirect URI validation with full security controls.
//
// This implements OAuth 2.0 Security BCP Section 4.1 and addresses:
// - SSRF attacks via private IP addresses
// - XSS attacks via dangerous schemes (javascript:, data:)
// - Open redirect vulnerabilities
// - Cloud metadata service access via link-local addresses
//
// The validation is configurable via Config to support different deployment scenarios:
// - Production SaaS: Strict validation (default)
// - Internal/VPN: Allow private IPs
// - Development: Relaxed validation
func (s *Server) ValidateRedirectURIForRegistration(ctx context.Context, redirectURI string) error {
	err := s.validateRedirectURIInternal(ctx, redirectURI)
	if err != nil {
		// Record security metric for monitoring/alerting
		category := GetRedirectURIErrorCategory(err)
		if category != "" {
			s.recordRedirectURISecurityMetric(ctx, category, RedirectURIStageRegistration)
		}
	}
	return err
}

// validateRedirectURIInternal performs the actual redirect URI validation.
// This is separated from ValidateRedirectURIForRegistration to allow metrics
// recording at the appropriate stage (registration vs authorization).
func (s *Server) validateRedirectURIInternal(ctx context.Context, redirectURI string) error {
	// Parse the redirect URI first
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return newRedirectURISecurityError(
			RedirectURIErrorCategoryInvalidFormat,
			redirectURI,
			fmt.Sprintf("URL parse error: %v", err),
			"redirect_uri: invalid URI format",
		)
	}

	// OAuth 2.0 Security BCP Section 4.1.3: redirect_uri MUST NOT contain fragments
	// Fragments could be used for XSS attacks
	if parsed.Fragment != "" {
		return newRedirectURISecurityError(
			RedirectURIErrorCategoryFragment,
			redirectURI,
			"URI contains fragment which is prohibited by OAuth 2.0 Security BCP",
			"redirect_uri: fragments are not allowed (OAuth 2.0 Security BCP)",
		)
	}

	scheme := strings.ToLower(parsed.Scheme)

	// Step 1: Check for blocked schemes (always blocked, regardless of mode)
	if err := s.validateSchemeNotBlocked(scheme, redirectURI); err != nil {
		return err
	}

	// Step 2: Handle HTTP/HTTPS schemes
	if scheme == SchemeHTTP || scheme == SchemeHTTPS {
		return s.validateHTTPRedirectURI(ctx, parsed, redirectURI)
	}

	// Step 3: Handle custom schemes (for native apps)
	// Custom schemes are validated separately via validateCustomScheme in validation.go
	if err := validateCustomScheme(scheme, s.Config.AllowedCustomSchemes); err != nil {
		return newRedirectURISecurityError(
			RedirectURIErrorCategoryBlockedScheme,
			redirectURI,
			err.Error(),
			fmt.Sprintf("redirect_uri: scheme '%s' is not allowed", scheme),
		)
	}

	return nil
}

// validateSchemeNotBlocked checks if a URI scheme is in the blocked list.
// Blocked schemes are never allowed regardless of configuration (security invariant).
// The scheme parameter should already be lowercase (caller's responsibility).
// The rawURI parameter is sanitized automatically when creating the error.
func (s *Server) validateSchemeNotBlocked(scheme, rawURI string) error {
	for _, blocked := range s.Config.BlockedRedirectSchemes {
		if scheme == strings.ToLower(blocked) {
			return newRedirectURISecurityError(
				RedirectURIErrorCategoryBlockedScheme,
				rawURI,
				fmt.Sprintf("scheme '%s' is in blocked list", blocked),
				fmt.Sprintf("redirect_uri: scheme '%s' is blocked for security reasons", scheme),
			)
		}
	}
	return nil
}

// validateHTTPRedirectURI validates HTTP/HTTPS redirect URIs with full security checks.
// This is the core validation logic that applies ProductionMode rules.
// The rawURI parameter is sanitized automatically when creating errors.
func (s *Server) validateHTTPRedirectURI(ctx context.Context, parsed *url.URL, rawURI string) error {
	scheme := strings.ToLower(parsed.Scheme)
	hostname := parsed.Hostname()

	// Check if it's a loopback address
	isLoopback := isLoopbackAddress(hostname)

	// Step 1: Handle loopback addresses (localhost, 127.x.x.x, ::1)
	if isLoopback {
		if !s.Config.AllowLocalhostRedirectURIs {
			return newRedirectURISecurityError(
				RedirectURIErrorCategoryLoopback,
				rawURI,
				"loopback addresses disabled via AllowLocalhostRedirectURIs=false",
				"redirect_uri: loopback addresses are not allowed",
			)
		}
		// Loopback is allowed - RFC 8252 Section 7.3 allows HTTP for loopback
		return nil
	}

	// Step 2: In ProductionMode, non-loopback HTTP is not allowed
	if s.Config.ProductionMode && scheme == SchemeHTTP {
		return newRedirectURISecurityError(
			RedirectURIErrorCategoryHTTPNotAllowed,
			rawURI,
			"ProductionMode=true requires HTTPS for non-loopback URIs",
			"redirect_uri: HTTPS is required in production (HTTP only allowed for localhost)",
		)
	}

	// Step 3: Check if hostname is an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		return s.validateIPAddress(ip, rawURI)
	}

	// Step 4: Hostname-based validation (optionally with DNS resolution)
	if s.Config.DNSValidation {
		return s.validateHostnameWithDNS(ctx, hostname, rawURI)
	}

	return nil
}

// validateIPAddress checks if an IP address is allowed based on security configuration.
// This prevents SSRF attacks to internal networks and cloud metadata services.
// The rawURI parameter is sanitized automatically when creating errors.
func (s *Server) validateIPAddress(ip net.IP, rawURI string) error {
	// Check for unspecified addresses (0.0.0.0, ::)
	// These are always blocked as they can bind to all interfaces or have undefined behavior
	if ip.IsUnspecified() {
		return newRedirectURISecurityError(
			RedirectURIErrorCategoryUnspecifiedAddr,
			rawURI,
			fmt.Sprintf("IP %s is unspecified (0.0.0.0 or ::)", ip.String()),
			"redirect_uri: unspecified addresses (0.0.0.0, ::) are not allowed",
		)
	}

	// Check for private IP ranges (RFC 1918)
	if ip.IsPrivate() {
		if !s.Config.AllowPrivateIPRedirectURIs {
			return newRedirectURISecurityError(
				RedirectURIErrorCategoryPrivateIP,
				rawURI,
				fmt.Sprintf("IP %s is in private range (RFC 1918)", ip.String()),
				"redirect_uri: private IP addresses are not allowed (SSRF protection)",
			)
		}
	}

	// Check for link-local addresses (169.254.x.x, fe80::/10) and link-local multicast
	// This is critical for cloud security - blocks access to metadata services (169.254.169.254)
	if isLinkLocalIP(ip) && !s.Config.AllowLinkLocalRedirectURIs {
		return newRedirectURISecurityError(
			RedirectURIErrorCategoryLinkLocal,
			rawURI,
			fmt.Sprintf("IP %s is link-local (could target cloud metadata services)", ip.String()),
			"redirect_uri: link-local addresses are not allowed (cloud SSRF protection)",
		)
	}

	return nil
}

// validateHostnameWithDNS resolves a hostname and validates the resulting IP addresses.
// This provides defense against DNS rebinding attacks where an attacker controls DNS
// to initially resolve to a public IP (for validation) but later to an internal IP.
//
// Behavior on DNS failure:
// - DNSValidationStrict=false (default): Log warning and allow registration (fail-open)
// - DNSValidationStrict=true: Block registration (fail-closed)
//
// SECURITY NOTE (TOCTOU): DNS validation at registration time does not fully prevent
// DNS rebinding attacks. An attacker could:
// 1. Register with a hostname resolving to a public IP
// 2. Later change DNS to resolve to an internal IP
// For full protection, enable ValidateRedirectURIAtAuthorization to re-validate
// at authorization time.
func (s *Server) validateHostnameWithDNS(ctx context.Context, hostname, rawURI string) error {
	// Create timeout context for DNS resolution
	resolveCtx, cancel := context.WithTimeout(ctx, s.Config.DNSValidationTimeout)
	defer cancel()

	// Use configured resolver or default
	resolver := s.Config.DNSResolver
	if resolver == nil {
		resolver = &defaultDNSResolver{}
	}

	// Resolve hostname
	ips, err := resolver.LookupIP(resolveCtx, "ip", hostname)
	if err != nil {
		// DNS resolution failed
		if s.Config.DNSValidationStrict {
			// Strict mode: fail-closed - block registration on DNS failure
			s.Logger.Warn("DNS resolution failed during redirect URI validation (strict mode - blocking)",
				"hostname", hostname,
				"error", err,
				"action", "blocking_registration",
				"mode", "strict")
			return newRedirectURISecurityError(
				RedirectURIErrorCategoryDNSFailure,
				rawURI,
				fmt.Sprintf("DNS resolution failed for hostname '%s': %v (strict mode)", hostname, err),
				"redirect_uri: hostname could not be resolved (DNS validation required)",
			)
		}
		// Default mode: fail-open - log warning but allow registration
		// This prevents false positives for legitimate hostnames with temporary DNS issues
		s.Logger.Warn("DNS resolution failed during redirect URI validation (allowing registration)",
			"hostname", hostname,
			"error", err,
			"action", "allowing_registration",
			"mode", "permissive",
			"recommendation", "Enable DNSValidationStrict=true for fail-closed behavior")
		return nil
	}

	// Check each resolved IP
	for _, ip := range ips {
		// Check for private IPs
		if ip.IsPrivate() && !s.Config.AllowPrivateIPRedirectURIs {
			return newRedirectURISecurityError(
				RedirectURIErrorCategoryDNSPrivateIP,
				rawURI,
				fmt.Sprintf("hostname '%s' resolves to private IP %s", hostname, ip.String()),
				"redirect_uri: hostname resolves to private IP address (DNS rebinding protection)",
			)
		}

		// Check for link-local IPs (unicast and multicast)
		if isLinkLocalIP(ip) && !s.Config.AllowLinkLocalRedirectURIs {
			return newRedirectURISecurityError(
				RedirectURIErrorCategoryDNSLinkLocal,
				rawURI,
				fmt.Sprintf("hostname '%s' resolves to link-local IP %s", hostname, ip.String()),
				"redirect_uri: hostname resolves to link-local address (cloud SSRF protection)",
			)
		}
	}

	return nil
}

// ValidateRedirectURIsForRegistration validates multiple redirect URIs for client registration.
// Returns an error for the first invalid URI found.
func (s *Server) ValidateRedirectURIsForRegistration(ctx context.Context, redirectURIs []string) error {
	if len(redirectURIs) == 0 {
		return fmt.Errorf("redirect_uri: at least one redirect URI is required")
	}

	for _, uri := range redirectURIs {
		if err := s.ValidateRedirectURIForRegistration(ctx, uri); err != nil {
			return err
		}
	}

	return nil
}

// sanitizeURIForLogging removes potentially sensitive information from URIs for logging.
// This prevents leaking credentials or tokens in logs while still providing useful context.
func sanitizeURIForLogging(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		// If we can't parse it, truncate for safety
		if len(uri) > 100 {
			return uri[:100] + "...[truncated]"
		}
		return uri
	}

	// Remove query parameters and fragment
	parsed.RawQuery = ""
	parsed.Fragment = ""

	// Remove userinfo (user:password in URLs)
	parsed.User = nil

	return parsed.String()
}

// IsRedirectURISecurityError checks if an error is a redirect URI security validation error.
// Uses errors.As to properly handle wrapped errors.
func IsRedirectURISecurityError(err error) bool {
	var secErr *RedirectURISecurityError
	return errors.As(err, &secErr)
}

// GetRedirectURIErrorCategory returns the error category if the error is a RedirectURISecurityError.
// Uses errors.As to properly handle wrapped errors.
func GetRedirectURIErrorCategory(err error) string {
	var secErr *RedirectURISecurityError
	if errors.As(err, &secErr) {
		return secErr.Category
	}
	return ""
}

// recordRedirectURISecurityMetric records a redirect URI security rejection metric.
// This is called internally when validation fails.
func (s *Server) recordRedirectURISecurityMetric(ctx context.Context, category, stage string) {
	if s.Instrumentation != nil && s.Instrumentation.Metrics() != nil {
		s.Instrumentation.Metrics().RecordRedirectURISecurityRejected(ctx, category, stage)
	}
}

// ValidateRedirectURIAtAuthorizationTime performs security validation on a redirect URI
// during the authorization request. This is a secondary validation point that provides
// defense against TOCTOU (Time-of-Check to Time-of-Use) attacks.
//
// This method is only called when Config.ValidateRedirectURIAtAuthorization=true.
//
// Security context:
// The primary validation happens at client registration (ValidateRedirectURIForRegistration).
// However, DNS rebinding attacks can bypass registration-time validation:
// 1. Attacker registers with hostname "evil.com" resolving to public IP 1.2.3.4
// 2. After registration, attacker changes DNS to resolve to internal IP 10.0.0.1
// 3. Authorization request redirects to internal network (SSRF)
//
// By re-validating at authorization time, we catch DNS rebinding attacks.
// The trade-off is additional latency for DNS lookups during authorization.
//
// Note: This only applies security validation. The registered redirect_uri matching
// is still performed separately by validateRedirectURI().
func (s *Server) ValidateRedirectURIAtAuthorizationTime(ctx context.Context, redirectURI string) error {
	// Skip if authorization-time validation is disabled
	if !s.Config.ValidateRedirectURIAtAuthorization {
		return nil
	}

	// Reuse the same validation logic as registration
	// This ensures consistent security checks at both stages
	err := s.validateRedirectURIInternal(ctx, redirectURI)
	if err != nil {
		// Record security metric with authorization stage
		category := GetRedirectURIErrorCategory(err)
		if category != "" {
			s.recordRedirectURISecurityMetric(ctx, category, RedirectURIStageAuthorization)
		}
	}
	return err
}

// HighSecurityRedirectURIConfig returns a Config with strict redirect URI security settings.
// This is a convenience function for high-security deployments.
//
// Settings enabled:
// - ProductionMode=true: HTTPS required for non-loopback
// - AllowLocalhostRedirectURIs=true: RFC 8252 native app support
// - AllowPrivateIPRedirectURIs=false: Block SSRF to internal networks
// - AllowLinkLocalRedirectURIs=false: Block cloud metadata SSRF
// - DNSValidation=true: Resolve hostnames to check IPs
// - DNSValidationStrict=true: Fail-closed on DNS failures
// - ValidateRedirectURIAtAuthorization=true: Catch DNS rebinding
//
// Use this as a starting point and adjust for your environment:
//
//	config := server.HighSecurityRedirectURIConfig()
//	config.Issuer = "https://auth.example.com"
//	config.AllowPrivateIPRedirectURIs = true  // For internal deployments
func HighSecurityRedirectURIConfig() *Config {
	return &Config{
		ProductionMode:                     true,
		AllowLocalhostRedirectURIs:         true, // RFC 8252 native app support
		AllowPrivateIPRedirectURIs:         false,
		AllowLinkLocalRedirectURIs:         false,
		DNSValidation:                      true,
		DNSValidationStrict:                true,
		ValidateRedirectURIAtAuthorization: true,
	}
}
