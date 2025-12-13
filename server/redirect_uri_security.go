// Package server provides the OAuth 2.1 authorization server implementation.
package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
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

// Redirect URI security error categories for metrics and logging.
const (
	RedirectURIErrorCategoryBlockedScheme   = "blocked_scheme"
	RedirectURIErrorCategoryPrivateIP       = "private_ip"
	RedirectURIErrorCategoryLinkLocal       = "link_local"
	RedirectURIErrorCategoryLoopback        = "loopback_not_allowed"
	RedirectURIErrorCategoryHTTPNotAllowed  = "http_not_allowed"
	RedirectURIErrorCategoryDNSPrivateIP    = "dns_resolves_to_private_ip"
	RedirectURIErrorCategoryDNSLinkLocal    = "dns_resolves_to_link_local"
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
	// Parse the redirect URI first
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return &RedirectURISecurityError{
			Category:      RedirectURIErrorCategoryInvalidFormat,
			URI:           sanitizeURIForLogging(redirectURI),
			Reason:        fmt.Sprintf("URL parse error: %v", err),
			ClientMessage: "redirect_uri: invalid URI format",
		}
	}

	// OAuth 2.0 Security BCP Section 4.1.3: redirect_uri MUST NOT contain fragments
	// Fragments could be used for XSS attacks
	if parsed.Fragment != "" {
		return &RedirectURISecurityError{
			Category:      RedirectURIErrorCategoryFragment,
			URI:           sanitizeURIForLogging(redirectURI),
			Reason:        "URI contains fragment which is prohibited by OAuth 2.0 Security BCP",
			ClientMessage: "redirect_uri: fragments are not allowed (OAuth 2.0 Security BCP)",
		}
	}

	scheme := strings.ToLower(parsed.Scheme)

	// Step 1: Check for blocked schemes (always blocked, regardless of mode)
	if err := s.validateSchemeNotBlocked(scheme); err != nil {
		return err
	}

	// Step 2: Handle HTTP/HTTPS schemes
	if scheme == SchemeHTTP || scheme == SchemeHTTPS {
		return s.validateHTTPRedirectURI(ctx, parsed)
	}

	// Step 3: Handle custom schemes (for native apps)
	// Custom schemes are validated separately via validateCustomScheme in validation.go
	if err := validateCustomScheme(scheme, s.Config.AllowedCustomSchemes); err != nil {
		return &RedirectURISecurityError{
			Category:      RedirectURIErrorCategoryBlockedScheme,
			URI:           sanitizeURIForLogging(redirectURI),
			Reason:        err.Error(),
			ClientMessage: fmt.Sprintf("redirect_uri: scheme '%s' is not allowed", scheme),
		}
	}

	return nil
}

// validateSchemeNotBlocked checks if a URI scheme is in the blocked list.
// Blocked schemes are never allowed regardless of configuration (security invariant).
func (s *Server) validateSchemeNotBlocked(scheme string) error {
	schemeLower := strings.ToLower(scheme)
	for _, blocked := range s.Config.BlockedRedirectSchemes {
		if schemeLower == strings.ToLower(blocked) {
			return &RedirectURISecurityError{
				Category:      RedirectURIErrorCategoryBlockedScheme,
				URI:           "",
				Reason:        fmt.Sprintf("scheme '%s' is in blocked list", scheme),
				ClientMessage: fmt.Sprintf("redirect_uri: scheme '%s' is blocked for security reasons", scheme),
			}
		}
	}
	return nil
}

// validateHTTPRedirectURI validates HTTP/HTTPS redirect URIs with full security checks.
// This is the core validation logic that applies ProductionMode rules.
func (s *Server) validateHTTPRedirectURI(ctx context.Context, parsed *url.URL) error {
	scheme := strings.ToLower(parsed.Scheme)
	hostname := parsed.Hostname()

	// Check if it's a loopback address
	isLoopback := isLoopbackAddress(hostname)

	// Step 1: Handle loopback addresses (localhost, 127.x.x.x, ::1)
	if isLoopback {
		if !s.Config.AllowLocalhostRedirectURIs {
			return &RedirectURISecurityError{
				Category:      RedirectURIErrorCategoryLoopback,
				URI:           sanitizeURIForLogging(parsed.String()),
				Reason:        "loopback addresses disabled via AllowLocalhostRedirectURIs=false",
				ClientMessage: "redirect_uri: loopback addresses are not allowed",
			}
		}
		// Loopback is allowed - RFC 8252 Section 7.3 allows HTTP for loopback
		return nil
	}

	// Step 2: In ProductionMode, non-loopback HTTP is not allowed
	if s.Config.ProductionMode && scheme == SchemeHTTP {
		return &RedirectURISecurityError{
			Category:      RedirectURIErrorCategoryHTTPNotAllowed,
			URI:           sanitizeURIForLogging(parsed.String()),
			Reason:        "ProductionMode=true requires HTTPS for non-loopback URIs",
			ClientMessage: "redirect_uri: HTTPS is required in production (HTTP only allowed for localhost)",
		}
	}

	// Step 3: Check if hostname is an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		return s.validateIPAddress(ip, hostname)
	}

	// Step 4: Hostname-based validation (optionally with DNS resolution)
	if s.Config.DNSValidation {
		return s.validateHostnameWithDNS(ctx, hostname, parsed.String())
	}

	return nil
}

// validateIPAddress checks if an IP address is allowed based on security configuration.
// This prevents SSRF attacks to internal networks and cloud metadata services.
func (s *Server) validateIPAddress(ip net.IP, hostname string) error {
	// Check for unspecified addresses (0.0.0.0, ::)
	// These are always blocked as they can bind to all interfaces or have undefined behavior
	if ip.IsUnspecified() {
		return &RedirectURISecurityError{
			Category:      RedirectURIErrorCategoryUnspecifiedAddr,
			URI:           "",
			Reason:        fmt.Sprintf("IP %s is unspecified (0.0.0.0 or ::)", hostname),
			ClientMessage: "redirect_uri: unspecified addresses (0.0.0.0, ::) are not allowed",
		}
	}

	// Check for private IP ranges (RFC 1918)
	if ip.IsPrivate() {
		if !s.Config.AllowPrivateIPRedirectURIs {
			return &RedirectURISecurityError{
				Category:      RedirectURIErrorCategoryPrivateIP,
				URI:           "",
				Reason:        fmt.Sprintf("IP %s is in private range (RFC 1918)", hostname),
				ClientMessage: "redirect_uri: private IP addresses are not allowed (SSRF protection)",
			}
		}
	}

	// Check for link-local addresses (169.254.x.x, fe80::/10)
	// This is critical for cloud security - blocks access to metadata services
	if ip.IsLinkLocalUnicast() {
		if !s.Config.AllowLinkLocalRedirectURIs {
			return &RedirectURISecurityError{
				Category:      RedirectURIErrorCategoryLinkLocal,
				URI:           "",
				Reason:        fmt.Sprintf("IP %s is link-local (could target cloud metadata services)", hostname),
				ClientMessage: "redirect_uri: link-local addresses are not allowed (cloud SSRF protection)",
			}
		}
	}

	// Also check for link-local multicast
	if ip.IsLinkLocalMulticast() {
		if !s.Config.AllowLinkLocalRedirectURIs {
			return &RedirectURISecurityError{
				Category:      RedirectURIErrorCategoryLinkLocal,
				URI:           "",
				Reason:        fmt.Sprintf("IP %s is link-local multicast", hostname),
				ClientMessage: "redirect_uri: link-local addresses are not allowed",
			}
		}
	}

	return nil
}

// validateHostnameWithDNS resolves a hostname and validates the resulting IP addresses.
// This provides defense against DNS rebinding attacks where an attacker controls DNS
// to initially resolve to a public IP (for validation) but later to an internal IP.
func (s *Server) validateHostnameWithDNS(ctx context.Context, hostname, fullURI string) error {
	// Create timeout context for DNS resolution
	resolveCtx, cancel := context.WithTimeout(ctx, s.Config.DNSValidationTimeout)
	defer cancel()

	// Resolve hostname
	ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", hostname)
	if err != nil {
		// DNS resolution failed - log warning but don't block
		// This prevents false positives for legitimate hostnames with temporary DNS issues
		s.Logger.Warn("DNS resolution failed during redirect URI validation",
			"hostname", hostname,
			"error", err,
			"action", "allowing_registration",
			"recommendation", "Monitor for abuse")
		return nil
	}

	// Check each resolved IP
	for _, ip := range ips {
		// Check for private IPs
		if ip.IsPrivate() && !s.Config.AllowPrivateIPRedirectURIs {
			return &RedirectURISecurityError{
				Category:      RedirectURIErrorCategoryDNSPrivateIP,
				URI:           sanitizeURIForLogging(fullURI),
				Reason:        fmt.Sprintf("hostname '%s' resolves to private IP %s", hostname, ip.String()),
				ClientMessage: "redirect_uri: hostname resolves to private IP address (DNS rebinding protection)",
			}
		}

		// Check for link-local IPs
		if ip.IsLinkLocalUnicast() && !s.Config.AllowLinkLocalRedirectURIs {
			return &RedirectURISecurityError{
				Category:      RedirectURIErrorCategoryDNSLinkLocal,
				URI:           sanitizeURIForLogging(fullURI),
				Reason:        fmt.Sprintf("hostname '%s' resolves to link-local IP %s", hostname, ip.String()),
				ClientMessage: "redirect_uri: hostname resolves to link-local address (cloud SSRF protection)",
			}
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
func IsRedirectURISecurityError(err error) bool {
	_, ok := err.(*RedirectURISecurityError)
	return ok
}

// GetRedirectURIErrorCategory returns the error category if the error is a RedirectURISecurityError.
func GetRedirectURIErrorCategory(err error) string {
	if secErr, ok := err.(*RedirectURISecurityError); ok {
		return secErr.Category
	}
	return ""
}
