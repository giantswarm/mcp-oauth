package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/giantswarm/mcp-oauth/internal/util"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Note: PKCE and URI validation constants are intentionally duplicated from constants.go
// to avoid circular imports (root package imports server, server can't import root).
// Keep these in sync with constants.go.

// PKCE validation constants (RFC 7636)
const (
	MinCodeVerifierLength = 43
	MaxCodeVerifierLength = 128
	PKCEMethodS256        = "S256"
	PKCEMethodPlain       = "plain"
)

// Resource parameter validation constants (RFC 8707)
const (
	// MaxResourceLength is the maximum allowed length for resource parameter
	// RFC 3986 suggests 2048 characters as a reasonable URI length limit
	MaxResourceLength = 2048
)

// Note: SchemeHTTP and SchemeHTTPS constants are defined in config.go

var (
	// AllowedHTTPSchemes lists allowed HTTP-based redirect URI schemes
	AllowedHTTPSchemes = []string{SchemeHTTP, SchemeHTTPS}

	// DefaultBlockedRedirectSchemes is the canonical list of URI schemes that are blocked
	// for redirect URIs. These schemes can be used for XSS attacks (javascript:, data:)
	// or local file access (file:). This is the single source of truth for blocked schemes.
	// Used by Config.BlockedRedirectSchemes default and validateCustomScheme.
	DefaultBlockedRedirectSchemes = []string{"javascript", "data", "file", "vbscript", "about", "ftp"}

	// DangerousSchemes is an alias for backward compatibility.
	// Deprecated: Use DefaultBlockedRedirectSchemes instead.
	DangerousSchemes = DefaultBlockedRedirectSchemes

	// DefaultRFC3986SchemePattern is the default regex pattern for custom URI schemes (RFC 3986)
	DefaultRFC3986SchemePattern = []string{"^[a-z][a-z0-9+.-]*$"}
)

// validateHTTPSEnforcement ensures that the OAuth server is running over HTTPS
// in production environments. This is a critical security requirement as OAuth
// over HTTP exposes all tokens, authorization codes, and client credentials to
// network interception and man-in-the-middle attacks.
//
// The validation logic:
// - HTTPS URLs: Always allowed (secure)
// - HTTP on localhost: Allowed with warning (development)
// - HTTP on non-localhost: Blocked unless AllowInsecureHTTP=true (production)
//
// This follows OAuth 2.1 security requirements which mandate HTTPS for all
// OAuth endpoints except localhost development.
func (s *Server) validateHTTPSEnforcement() error {
	// Skip validation if Issuer is empty (will fail elsewhere with more appropriate error)
	if s.Config.Issuer == "" {
		return nil
	}

	issuerURL, err := url.Parse(s.Config.Issuer)
	if err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}

	// HTTPS is always secure - no validation needed
	if issuerURL.Scheme == "https" {
		return nil
	}

	// Check if using HTTP (insecure)
	if issuerURL.Scheme == "http" {
		hostname := issuerURL.Hostname()

		// Allow localhost for development (with warning)
		if isLocalhostHostname(hostname) {
			if !s.Config.AllowInsecureHTTP {
				s.Logger.Warn("⚠️  DEVELOPMENT WARNING: Running OAuth over HTTP on localhost",
					"issuer", s.Config.Issuer,
					"risk", "Credentials exposed on local network",
					"recommendation", "Use HTTPS even in development for production-like testing",
					"to_suppress", "Set AllowInsecureHTTP=true in Config",
					"learn_more", oauth21SecurityBestPracticesURL)
			}
			return nil
		}

		// Non-localhost HTTP is blocked unless explicitly allowed
		if !s.Config.AllowInsecureHTTP {
			return fmt.Errorf(
				"SECURITY ERROR: Issuer must use HTTPS in production (got %s://%s). "+
					"OAuth over HTTP exposes tokens and credentials to interception. "+
					"To run on localhost for development, set AllowInsecureHTTP=true. "+
					"For production, use HTTPS",
				issuerURL.Scheme,
				hostname,
			)
		}

		// Log critical warning if HTTP is explicitly allowed on non-localhost
		s.Logger.Error("🚨 CRITICAL SECURITY WARNING: Running OAuth server over HTTP",
			"issuer", s.Config.Issuer,
			"hostname", hostname,
			"risk", "All tokens and credentials exposed to network sniffing and MITM attacks",
			"action_required", "Switch to HTTPS immediately",
			"compliance", "OAuth 2.1 requires HTTPS for all production endpoints",
			"learn_more", oauth21SecurityBestPracticesURL)

		return nil
	}

	// Unknown scheme (not http or https)
	return fmt.Errorf("invalid issuer URL scheme: %s (must be http or https)", issuerURL.Scheme)
}

const (
	oauth21SecurityBestPracticesURL = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10#section-4.1.1"
)

// isLocalhostHostname checks if a hostname refers to the local machine.
// This includes IPv4 loopback (entire 127.0.0.0/8 range per RFC 1122),
// IPv6 loopback (::1), localhost hostname, and 0.0.0.0 (bind-all in dev).
// Used to determine if HTTP is acceptable for development purposes.
func isLocalhostHostname(hostname string) bool {
	// Direct hostname checks
	if hostname == "localhost" || hostname == "0.0.0.0" {
		return true
	}

	// Strip brackets from IPv6 addresses for parsing
	// net.ParseIP doesn't handle brackets, but url.Hostname() may include them
	cleanHostname := hostname
	if len(hostname) > 2 && hostname[0] == '[' && hostname[len(hostname)-1] == ']' {
		cleanHostname = hostname[1 : len(hostname)-1]
	}

	// Parse as IP and check if it's a loopback address
	// This correctly handles:
	// - 127.0.0.1 through 127.255.255.255 (entire 127.0.0.0/8 range)
	// - ::1 (IPv6 loopback)
	// - ::ffff:127.0.0.1 (IPv4-mapped IPv6 loopback)
	if ip := net.ParseIP(cleanHostname); ip != nil {
		return ip.IsLoopback()
	}

	return false
}

// validateRedirectURI validates that a redirect URI is registered and secure
func (s *Server) validateRedirectURI(client *storage.Client, redirectURI string) error {
	// First check if URI is registered
	found := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("redirect URI not registered for client")
	}

	// Perform security validation on the URI with custom scheme support
	return validateRedirectURISecurityEnhanced(redirectURI, s.Config.Issuer, s.Config.AllowedCustomSchemes)
}

// validateScopes validates that requested scopes are allowed
func (s *Server) validateScopes(scope string) error {
	// If no scopes configured, allow all
	if len(s.Config.SupportedScopes) == 0 {
		return nil
	}

	if scope == "" {
		return nil // Empty scope is allowed
	}

	// Split scope string into individual scopes
	requestedScopes := strings.Fields(scope)

	// Check each requested scope against supported scopes
	for _, reqScope := range requestedScopes {
		found := false
		for _, supportedScope := range s.Config.SupportedScopes {
			if reqScope == supportedScope {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unsupported scope: %s", reqScope)
		}
	}

	return nil
}

// validateClientScopes validates that requested scopes are allowed for the specific client.
// This provides client-level scope restriction on top of server-level scope validation.
//
// OAuth 2.0 Security: Clients should only be granted tokens with scopes they are authorized
// to request. This prevents scope escalation attacks where a compromised client could obtain
// unauthorized access to resources.
//
// Behavior:
// - If client.Scopes is empty or nil: Allow all scopes (backward compatibility)
// - If client.Scopes is non-empty: Requested scopes MUST be a subset of allowed scopes
// - Empty requested scope string is always allowed
//
// Example:
//
//	client.Scopes = ["read:user", "write:user"]
//	validateClientScopes("read:user", client.Scopes)           // OK
//	validateClientScopes("read:user write:user", client.Scopes) // OK
//	validateClientScopes("admin:all", client.Scopes)           // ERROR
func (s *Server) validateClientScopes(requestedScope string, clientScopes []string) error {
	// If client has no scope restrictions, allow all scopes
	// This maintains backward compatibility with clients registered without scope restrictions
	if len(clientScopes) == 0 {
		return nil
	}

	// Empty scope request is always allowed
	if requestedScope == "" {
		return nil
	}

	// Split requested scope string into individual scopes
	requestedScopes := strings.Fields(requestedScope)

	// Validate each requested scope against client's allowed scopes
	for _, reqScope := range requestedScopes {
		found := false
		for _, allowedScope := range clientScopes {
			if reqScope == allowedScope {
				found = true
				break
			}
		}
		if !found {
			// SECURITY: Don't reveal which specific scopes are unauthorized to prevent enumeration
			// Return completely generic error per OAuth 2.0 Security Best Practices (RFC 6749)
			// This prevents attackers from fingerprinting allowed scopes
			return fmt.Errorf("client is not authorized for one or more requested scopes")
		}
	}

	return nil
}

// validateStateParameter validates the state parameter for security requirements.
// This function enforces:
// 1. Minimum length to ensure sufficient entropy and prevent timing attacks
// 2. Non-empty validation
//
// SECURITY: The minimum length requirement helps prevent timing attacks by
// ensuring state parameters have sufficient entropy. Short state values could
// be brute-forced using timing side-channels. By enforcing a minimum length,
// we ensure that even if timing information leaks, the search space is large
// enough to make attacks infeasible.
//
// The constant-time comparison of state values happens later in the flow
// (see server/flows.go HandleProviderCallback) using subtle.ConstantTimeCompare.
func (s *Server) validateStateParameter(state string) error {
	// Allow empty state if configured (for clients that don't support state parameter)
	// WARNING: This weakens CSRF protection
	if state == "" {
		if s.Config.AllowNoStateParameter {
			return nil
		}
		return fmt.Errorf("state parameter is required for CSRF protection")
	}

	if len(state) < s.Config.MinStateLength {
		return fmt.Errorf("state parameter must be at least %d characters for security", s.Config.MinStateLength)
	}

	return nil
}

// validatePKCE validates the PKCE code verifier against the challenge per RFC 7636
func (s *Server) validatePKCE(challenge, method, verifier string) error {
	if challenge == "" {
		// No PKCE required for this flow
		return nil
	}

	if verifier == "" {
		return fmt.Errorf("code_verifier is required when code_challenge is present")
	}

	// RFC 7636: code_verifier must be 43-128 characters
	if len(verifier) < MinCodeVerifierLength {
		return fmt.Errorf("code_verifier must be at least %d characters (RFC 7636)", MinCodeVerifierLength)
	}
	if len(verifier) > MaxCodeVerifierLength {
		return fmt.Errorf("code_verifier must be at most %d characters (RFC 7636)", MaxCodeVerifierLength)
	}

	// RFC 7636: code_verifier can only contain [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	// This prevents injection attacks and ensures cryptographic quality
	// Security: Also prevents null bytes, control characters, or Unicode that could cause issues
	for _, ch := range verifier {
		isValid := (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '.' || ch == '_' || ch == '~'
		if !isValid {
			return fmt.Errorf("code_verifier contains invalid characters (must be [A-Za-z0-9-._~])")
		}
	}

	var computedChallenge string

	// Compute challenge based on method
	switch method {
	case PKCEMethodS256:
		// Recommended: SHA256 hash of verifier
		hash := sha256.Sum256([]byte(verifier))
		computedChallenge = base64.RawURLEncoding.EncodeToString(hash[:])

	case PKCEMethodPlain:
		// Deprecated but allowed if configured for backward compatibility
		if !s.Config.AllowPKCEPlain {
			return fmt.Errorf("'%s' code_challenge_method is not allowed (configure AllowPKCEPlain=true if needed for legacy clients)", PKCEMethodPlain)
		}
		computedChallenge = verifier
		s.Logger.Warn("Using insecure 'plain' PKCE method",
			"recommendation", "Upgrade client to use S256")

	default:
		return fmt.Errorf("unsupported code_challenge_method: %s (supported: S256%s)", method, func() string {
			if s.Config.AllowPKCEPlain {
				return ", plain"
			}
			return ""
		}())
	}

	// Constant-time comparison to prevent timing attacks
	// Using subtle.ConstantTimeCompare to prevent side-channel attacks
	if subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(challenge)) != 1 {
		return fmt.Errorf("code_verifier does not match code_challenge")
	}

	return nil
}

// validateCustomScheme validates a custom URI scheme against allowed patterns
// Returns error if the scheme is dangerous or not in the allowed list
func validateCustomScheme(scheme string, allowedSchemes []string) error {
	schemeLower := strings.ToLower(scheme)

	// Check against dangerous schemes first
	for _, dangerous := range DangerousSchemes {
		if schemeLower == dangerous {
			return fmt.Errorf("redirect_uri scheme '%s' is not allowed for security reasons", scheme)
		}
	}

	// If no allowed schemes configured, allow all RFC 3986 compliant schemes
	if len(allowedSchemes) == 0 {
		// Default RFC 3986 pattern: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
		allowedSchemes = DefaultRFC3986SchemePattern
	}

	// Validate against allowed patterns
	for _, pattern := range allowedSchemes {
		// Use regex pattern matching
		matched, err := regexp.MatchString(pattern, schemeLower)
		if err != nil {
			return fmt.Errorf("invalid scheme pattern '%s': %w", pattern, err)
		}
		if matched {
			return nil // Scheme is valid
		}
	}

	return fmt.Errorf("redirect_uri scheme '%s' does not match allowed patterns (must match one of: %v)",
		scheme, allowedSchemes)
}

// isLoopbackAddress checks if a hostname is a true loopback address.
// This includes the entire 127.0.0.0/8 range (RFC 1122) and IPv6 ::1.
// Expects hostname without port (as returned by url.URL.Hostname()).
//
// Note: This function does NOT consider 0.0.0.0 as loopback (it's "unspecified").
// For development HTTP allowance that includes 0.0.0.0, use isLocalhostHostname.
func isLoopbackAddress(hostname string) bool {
	// Handle "localhost" hostname directly
	if hostname == "localhost" {
		return true
	}

	// Normalize hostname (strip brackets from IPv6 like [::1])
	cleanHostname := strings.Trim(hostname, "[]")
	cleanHostname = strings.TrimSpace(cleanHostname)

	// Parse as IP and use stdlib's IsLoopback for correct handling of:
	// - 127.0.0.0/8 range (all 16M addresses)
	// - ::1 (IPv6 loopback)
	// - ::ffff:127.0.0.1 (IPv4-mapped IPv6 loopback)
	if ip := net.ParseIP(cleanHostname); ip != nil {
		return ip.IsLoopback()
	}

	return false
}

// validateRedirectURISecurityEnhanced performs comprehensive security validation on redirect URIs
// per OAuth 2.0 Security Best Current Practice (BCP) with enhanced custom scheme support
func validateRedirectURISecurityEnhanced(redirectURI, serverIssuer string, allowedCustomSchemes []string) error {
	// Parse the redirect URI
	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect_uri format: %w", err)
	}

	// OAuth 2.0 Security BCP Section 4.1.3: redirect_uri MUST NOT contain fragments
	if parsed.Fragment != "" {
		return fmt.Errorf("redirect_uri must not contain fragments (security risk)")
	}

	scheme := strings.ToLower(parsed.Scheme)

	// Check if it's an HTTP(S) scheme
	isHTTP := false
	for _, httpScheme := range AllowedHTTPSchemes {
		if scheme == httpScheme {
			isHTTP = true
			break
		}
	}

	if isHTTP {
		// HTTP/HTTPS redirect URI validation
		hostname := strings.ToLower(parsed.Hostname())

		// Check if it's a loopback address (allowed for development)
		isLoopback := isLoopbackAddress(hostname)

		// For production (non-loopback), require HTTPS
		if !isLoopback && scheme != SchemeHTTPS {
			// Check if server itself is HTTPS
			if serverParsed, err := url.Parse(serverIssuer); err == nil {
				if serverParsed.Scheme == SchemeHTTPS {
					return fmt.Errorf("redirect_uri must use HTTPS in production (got %s://)", scheme)
				}
			}
		}
	} else {
		// Custom scheme (for native/mobile apps)
		if err := validateCustomScheme(scheme, allowedCustomSchemes); err != nil {
			return err
		}
	}

	return nil
}

// validateResourceParameter validates the resource parameter per RFC 8707
// The resource parameter must be an absolute HTTPS URI identifying the target resource server
// This prevents token theft and replay attacks across different resource servers
// Note: Caller must ensure resource is non-empty before calling this function
func (s *Server) validateResourceParameter(resource string) error {
	// SECURITY: Validate resource length to prevent DoS via extremely long URIs
	// RFC 3986 suggests 2048 characters as a reasonable limit
	if len(resource) > MaxResourceLength {
		return fmt.Errorf("resource exceeds maximum length of %d characters", MaxResourceLength)
	}

	// Parse as URL
	resourceURL, err := url.Parse(resource)
	if err != nil {
		return fmt.Errorf("resource must be a valid URI: %w", err)
	}

	// RFC 8707 Section 2: Resource parameter must be an absolute URI
	if !resourceURL.IsAbs() {
		return fmt.Errorf("resource must be an absolute URI with scheme and host")
	}

	// SECURITY: Resource must use HTTPS (or HTTP for localhost development only)
	if resourceURL.Scheme != SchemeHTTPS {
		if resourceURL.Scheme == SchemeHTTP {
			// Allow localhost for development
			if !isLocalhostHostname(resourceURL.Hostname()) {
				return fmt.Errorf("resource must use HTTPS (HTTP only allowed for localhost)")
			}
			// Warn about HTTP even on localhost
			s.Logger.Warn("Resource parameter using HTTP on localhost",
				"resource", resource,
				"recommendation", "Use HTTPS in production")
		} else {
			return fmt.Errorf("resource must use https:// or http:// scheme (got %s://)", resourceURL.Scheme)
		}
	}

	// Validate hostname is not empty
	if resourceURL.Host == "" {
		return fmt.Errorf("resource must include a host (e.g., https://api.example.com)")
	}

	// RFC 8707 Section 6: Resource MUST NOT include fragment
	if resourceURL.Fragment != "" {
		return fmt.Errorf("resource must not contain fragment identifier")
	}

	return nil
}

// validateResourceConsistency validates resource parameter consistency between authorization and token requests
// Per RFC 8707, if the authorization request included a resource parameter, the token request must include
// the same resource parameter value
func (s *Server) validateResourceConsistency(resource string, authCode *storage.AuthorizationCode, clientID, code string) error {
	// If neither authorization nor token request has resource, validation passes
	if resource == "" && authCode.Resource == "" {
		return nil
	}

	// Validate resource format if provided in token request
	if resource != "" {
		if err := s.validateResourceParameter(resource); err != nil {
			return s.logAuthCodeValidationFailure("invalid_resource_format", clientID, authCode.UserID, util.SafeTruncate(code, 8))
		}
	}

	// Validate resource matches authorization code's resource
	// Normalize URLs to handle trailing slash differences
	// RFC 8707 doesn't specify trailing slash handling, but practical clients
	// may send resource identifiers with or without trailing slashes
	normalizedResource := util.NormalizeURL(resource)
	normalizedExpected := util.NormalizeURL(authCode.Resource)
	if normalizedResource != normalizedExpected {
		// Rate limit logging to prevent DoS via repeated resource mismatch attempts
		if s.SecurityEventRateLimiter == nil || s.SecurityEventRateLimiter.Allow(authCode.UserID+":"+clientID+":resource_mismatch") {
			s.Logger.Debug("Resource parameter mismatch",
				"expected", authCode.Resource,
				"provided", resource,
				"client_id", clientID,
				"user_id", authCode.UserID)
		}
		if s.Auditor != nil {
			s.Auditor.LogEvent(security.Event{
				Type:     security.EventResourceMismatch,
				UserID:   authCode.UserID,
				ClientID: clientID,
				Details: map[string]any{
					"expected_resource": authCode.Resource,
					"provided_resource": resource,
					"severity":          "high",
				},
			})
		}
		return s.logAuthCodeValidationFailure("resource_mismatch", clientID, authCode.UserID, util.SafeTruncate(code, 8))
	}

	return nil
}
