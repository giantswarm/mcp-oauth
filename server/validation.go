package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/giantswarm/mcp-oauth/storage"
)

// PKCE validation constants
const (
	// MinCodeVerifierLength is the minimum length for PKCE code_verifier (RFC 7636)
	MinCodeVerifierLength = 43

	// MaxCodeVerifierLength is the maximum length for PKCE code_verifier (RFC 7636)
	MaxCodeVerifierLength = 128

	// PKCEMethodS256 is the SHA256 code challenge method (recommended, OAuth 2.1)
	PKCEMethodS256 = "S256"

	// PKCEMethodPlain is the plain code challenge method (deprecated, insecure)
	PKCEMethodPlain = "plain"
)

// Redirect URI validation constants
const (
	// SchemeHTTP is the HTTP URI scheme
	SchemeHTTP = "http"

	// SchemeHTTPS is the HTTPS URI scheme
	SchemeHTTPS = "https"
)

var (
	// AllowedHTTPSchemes lists allowed HTTP-based redirect URI schemes
	AllowedHTTPSchemes = []string{"http", "https"}

	// DangerousSchemes lists URI schemes that must never be allowed for security
	DangerousSchemes = []string{"javascript", "data", "file", "vbscript", "about"}

	// DefaultRFC3986SchemePattern is the default regex pattern for custom URI schemes (RFC 3986)
	DefaultRFC3986SchemePattern = []string{"^[a-z][a-z0-9+.-]*$"}

	// LoopbackAddresses lists recognized loopback addresses for development
	LoopbackAddresses = []string{"localhost", "127.0.0.1", "::1", "[::1]"}
)

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

// isLoopbackAddress checks if a hostname is a loopback address
func isLoopbackAddress(hostname string) bool {
	// Normalize hostname (remove brackets for IPv6)
	hostname = strings.Trim(hostname, "[]")
	hostname = strings.TrimSpace(hostname)

	// Check against recognized loopback addresses
	for _, loopback := range LoopbackAddresses {
		if hostname == loopback {
			return true
		}
	}

	// Also check for 127.x.x.x range and localhost with port
	return strings.HasPrefix(hostname, "127.") || strings.HasPrefix(hostname, "localhost:")
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
