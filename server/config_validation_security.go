package server

import (
	"log/slog"
	"strings"
	"time"
)

// applySecurityDefaults sets secure defaults for security-related configuration.
// This follows the principle: secure by default, explicit opt-out for less security.
//
// Security features enabled by default:
//   - RequirePKCE=true (OAuth 2.1 compliance)
//   - AllowRefreshTokenRotation=true (prevents refresh token theft)
//   - ProductionMode=true (HTTPS required for non-loopback)
//   - DNSValidation=true (SSRF protection)
//   - DNSValidationStrict=true (fail-closed DNS validation)
//   - ValidateRedirectURIAtAuthorization=true (TOCTOU protection)
func applySecurityDefaults(config *Config, logger *slog.Logger) {
	// Apply secure defaults: enable security features that default to true
	// Note: Due to Go's zero value for bools being false, we can't distinguish
	// between unset and explicitly set to false. We apply defaults and then log
	// warnings for any insecure configuration.
	if !config.AllowRefreshTokenRotation {
		config.AllowRefreshTokenRotation = true
	}
	if !config.RequirePKCE {
		config.RequirePKCE = true
	}
	if config.MinStateLength == 0 {
		config.MinStateLength = 32 // OAuth 2.1: 128+ bits entropy recommended, 32 chars = 192 bits
	}

	// Redirect URI security defaults - SECURE BY DEFAULT
	// These security features are enabled by default following the library's principle
	// of "secure by default, explicit opt-out for less security."
	//
	// Users who need to disable security features must use the explicit Disable* fields.
	// This pattern works with Go's zero-value (false = secure default).
	//
	// Security features enabled unless explicitly disabled:
	if !config.DisableProductionMode {
		config.ProductionMode = true
	}
	if !config.DisableDNSValidation {
		config.DNSValidation = true
	}
	if !config.DisableDNSValidationStrict {
		config.DNSValidationStrict = true
	}
	if !config.DisableAuthorizationTimeValidation {
		config.ValidateRedirectURIAtAuthorization = true
	}

	// Default blocked schemes (always dangerous) - use canonical list from validation.go
	if len(config.BlockedRedirectSchemes) == 0 {
		config.BlockedRedirectSchemes = DefaultBlockedRedirectSchemes
	}

	// SECURITY: Enable StrictSchemeMatching by default when TrustedPublicRegistrationSchemes is configured.
	// This ensures ALL redirect URIs must use trusted schemes for unauthenticated registration,
	// preventing attackers from mixing trusted and untrusted schemes to bypass authentication.
	// Use DisableStrictSchemeMatching=true to explicitly opt-out (not recommended).
	if len(config.TrustedPublicRegistrationSchemes) > 0 && !config.DisableStrictSchemeMatching {
		config.StrictSchemeMatching = true
	}

	// Apply DNS validation timeout defaults and bounds
	applyDNSTimeoutDefaults(config, logger)

	// SECURITY: Enforce absolute minimum state length to ensure CSRF protection entropy
	// OAuth 2.1 recommends at least 128 bits (16 bytes) of entropy
	// 32 characters provides 192 bits of entropy in base64, which exceeds OAuth 2.1 recommendations
	// and provides sufficient margin for high-security deployments.
	const absoluteMinStateLength = 32
	if config.MinStateLength < absoluteMinStateLength {
		logger.Warn("SECURITY WARNING: MinStateLength below recommended minimum, enforcing floor",
			"configured", config.MinStateLength,
			"enforced_minimum", absoluteMinStateLength,
			"risk", "reduced CSRF protection entropy")
		config.MinStateLength = absoluteMinStateLength
	}

	// Log warnings for insecure settings (whether explicitly set or not)
	logSecurityWarnings(config, logger)
}

// applyDNSTimeoutDefaults applies DNS validation timeout defaults and validates bounds.
// Default: 2 seconds - fast enough for good UX, slow enough for most DNS servers
// Maximum: 30 seconds - prevents misconfiguration that could cause DoS via slow registration
func applyDNSTimeoutDefaults(config *Config, logger *slog.Logger) {
	const (
		defaultDNSTimeout = 2 * time.Second
		maxDNSTimeout     = 30 * time.Second
	)

	if config.DNSValidationTimeout == 0 {
		config.DNSValidationTimeout = defaultDNSTimeout
	} else if config.DNSValidationTimeout > maxDNSTimeout {
		logger.Warn("DNS validation timeout exceeds maximum, capping to prevent slow registrations",
			"configured", config.DNSValidationTimeout,
			"corrected_to", maxDNSTimeout,
			"risk", "very long timeouts can cause slow client registrations and potential DoS")
		config.DNSValidationTimeout = maxDNSTimeout
	} else if config.DNSValidationTimeout < 0 {
		logger.Warn("DNS validation timeout cannot be negative, using default",
			"configured", config.DNSValidationTimeout,
			"corrected_to", defaultDNSTimeout)
		config.DNSValidationTimeout = defaultDNSTimeout
	}
}

// validateWWWAuthenticateConfig validates WWW-Authenticate header configuration
// for security best practices.
func validateWWWAuthenticateConfig(config *Config, logger *slog.Logger) {
	// SECURITY: Warn if WWW-Authenticate metadata is disabled
	if config.DisableWWWAuthenticateMetadata {
		logger.Warn("SECURITY WARNING: WWW-Authenticate metadata is DISABLED",
			"risk", "MCP 2025-11-25 non-compliance, reduced client discovery",
			"recommendation", "Set DisableWWWAuthenticateMetadata=false for spec compliance",
			"learn_more", "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization")
	}

	// Recommendation 1: Warn about very large scope lists (header size limits)
	// Some proxies/servers have HTTP header size limits (typically 8KB)
	const maxRecommendedScopes = 50
	if len(config.DefaultChallengeScopes) > maxRecommendedScopes {
		logger.Warn("CONFIGURATION WARNING: Very large DefaultChallengeScopes configured",
			"count", len(config.DefaultChallengeScopes),
			"max_recommended", maxRecommendedScopes,
			"risk", "May exceed HTTP header size limits in some proxies/servers",
			"recommendation", "Consider reducing scope count or using broader scopes")
	}

	// Validate scope entries don't contain invalid characters
	// This provides defense-in-depth (escaping already prevents injection)
	validateChallengeScopeCharacters(config.DefaultChallengeScopes, logger)

	// Log info about WWW-Authenticate metadata configuration
	if !config.DisableWWWAuthenticateMetadata && len(config.DefaultChallengeScopes) > 0 {
		logger.Debug("WWW-Authenticate metadata enabled",
			"challenge_scopes_count", len(config.DefaultChallengeScopes),
			"resource_metadata_url", config.ProtectedResourceMetadataEndpoint())
	}
}

// validateChallengeScopeCharacters validates that challenge scopes don't contain
// characters that could cause issues in HTTP headers.
func validateChallengeScopeCharacters(scopes []string, logger *slog.Logger) {
	for i, scope := range scopes {
		if strings.Contains(scope, `"`) {
			logger.Warn("CONFIGURATION WARNING: Invalid character in DefaultChallengeScopes",
				"index", i,
				"scope", scope,
				"invalid_char", `"`,
				"risk", "Scope contains double-quote character",
				"recommendation", "Use alphanumeric characters, hyphens, underscores, colons, and slashes only")
		}
		if strings.Contains(scope, ",") {
			logger.Warn("CONFIGURATION WARNING: Invalid character in DefaultChallengeScopes",
				"index", i,
				"scope", scope,
				"invalid_char", ",",
				"risk", "Scope contains comma character",
				"recommendation", "Use alphanumeric characters, hyphens, underscores, colons, and slashes only")
		}
		if strings.Contains(scope, `\`) {
			logger.Warn("CONFIGURATION WARNING: Invalid character in DefaultChallengeScopes",
				"index", i,
				"scope", scope,
				"invalid_char", `\`,
				"risk", "Scope contains backslash character",
				"recommendation", "Use alphanumeric characters, hyphens, underscores, colons, and slashes only")
		}
	}
}

// logSecurityWarnings logs warnings for insecure configuration settings.
// This is called after applying defaults to warn about any insecure configuration.
func logSecurityWarnings(config *Config, logger *slog.Logger) {
	// Core OAuth security warnings
	logCoreSecurityWarnings(config, logger)

	// Validate WWW-Authenticate configuration
	validateWWWAuthenticateConfig(config, logger)

	// Redirect URI security logging
	logRedirectURISecurityStatus(config, logger)
}

// logCoreSecurityWarnings logs warnings for core OAuth security settings.
func logCoreSecurityWarnings(config *Config, logger *slog.Logger) {
	if !config.RequirePKCE {
		logger.Warn("SECURITY WARNING: PKCE is DISABLED",
			"risk", "Authorization code interception attacks",
			"recommendation", "Set RequirePKCE=true for OAuth 2.1 compliance",
			"learn_more", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10#section-7.6")
	}
	if config.AllowPKCEPlain {
		logger.Warn("SECURITY WARNING: Plain PKCE method is ALLOWED",
			"risk", "Weak code challenge protection",
			"recommendation", "Set AllowPKCEPlain=false to require S256",
			"learn_more", "https://datatracker.ietf.org/doc/html/rfc7636#section-4.2")
	}
	if config.TrustProxy {
		logger.Warn("SECURITY NOTICE: Trusting proxy headers",
			"risk", "IP spoofing if proxy is not properly configured",
			"recommendation", "Only enable behind trusted reverse proxies",
			"config", "TrustedProxyCount should match your proxy chain length")
	}
	if config.AllowPublicClientRegistration {
		logger.Warn("SECURITY WARNING: Public client registration is ENABLED",
			"risk", "DoS attacks via unlimited client registration",
			"recommendation", "Set AllowPublicClientRegistration=false and use RegistrationAccessToken")
	}
	if config.AllowNoStateParameter {
		logger.Warn("SECURITY WARNING: State parameter is NOT REQUIRED",
			"risk", "CSRF attacks possible without state parameter",
			"recommendation", "Set AllowNoStateParameter=false unless required for client compatibility")
	}
	if !config.AllowPublicClientRegistration && config.RegistrationAccessToken == "" {
		logger.Warn("CONFIGURATION WARNING: RegistrationAccessToken not configured",
			"risk", "Client registration will fail",
			"recommendation", "Set RegistrationAccessToken or enable AllowPublicClientRegistration")
	}
	if config.AllowInsecureHTTP {
		logger.Error("CRITICAL SECURITY WARNING: HTTP is explicitly allowed",
			"risk", "All OAuth tokens and credentials exposed to network interception",
			"recommendation", "Use HTTPS in all environments",
			"compliance", "OAuth 2.1 requires HTTPS for all endpoints",
			"learn_more", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10#section-4.1.1")
	}
}

// logRedirectURISecurityStatus logs the redirect URI security configuration status.
func logRedirectURISecurityStatus(config *Config, logger *slog.Logger) {
	// Log current security status
	logger.Info("Redirect URI security status",
		"production_mode", config.ProductionMode,
		"dns_validation", config.DNSValidation,
		"dns_validation_strict", config.DNSValidationStrict,
		"authorization_time_validation", config.ValidateRedirectURIAtAuthorization,
		"dns_timeout", config.DNSValidationTimeout)

	// Warn about explicitly disabled security features
	if config.DisableProductionMode {
		logger.Warn("SECURITY WARNING: ProductionMode is DISABLED",
			"risk", "HTTP allowed on non-loopback hosts, relaxed redirect URI validation",
			"recommendation", "Only disable for local development environments",
			"learn_more", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.1")
	}
	if config.DisableDNSValidation {
		logger.Warn("SECURITY WARNING: DNS validation is DISABLED",
			"risk", "DNS rebinding attacks possible - hostnames not validated",
			"recommendation", "Only disable if DNS lookup latency is unacceptable",
			"learn_more", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")
	}
	if config.DisableDNSValidationStrict {
		logger.Warn("SECURITY WARNING: DNS validation strict mode is DISABLED",
			"risk", "DNS failures allow registration (fail-open) - potential bypass",
			"recommendation", "Only disable if DNS reliability issues cause problems")
	}
	if config.DisableAuthorizationTimeValidation {
		logger.Warn("SECURITY WARNING: Authorization-time validation is DISABLED",
			"risk", "DNS rebinding attacks possible after registration (TOCTOU)",
			"recommendation", "Only disable if authorization latency is critical")
	}

	// Info about Allow* escape hatches
	if config.AllowLocalhostRedirectURIs {
		logger.Info("Localhost redirect URIs are ALLOWED (RFC 8252 native app support)",
			"note", "HTTP allowed on loopback for native apps",
			"learn_more", "https://datatracker.ietf.org/doc/html/rfc8252#section-7.3")
	}
	if config.AllowPrivateIPRedirectURIs {
		logger.Warn("SECURITY WARNING: Private IP redirect URIs are ALLOWED",
			"risk", "SSRF attacks to internal networks (10.x, 172.16.x, 192.168.x)",
			"recommendation", "Only enable for internal/VPN deployments with proper network controls",
			"learn_more", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")
	}
	if config.AllowLinkLocalRedirectURIs {
		logger.Warn("SECURITY WARNING: Link-local redirect URIs are ALLOWED",
			"risk", "SSRF to cloud metadata services (169.254.169.254 - AWS/GCP/Azure)",
			"recommendation", "Disable unless specifically required",
			"impact", "Could expose cloud instance credentials and sensitive metadata",
			"learn_more", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")
	}
}
