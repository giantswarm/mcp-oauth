package server

import (
	"log/slog"
)

// Config holds OAuth server configuration
type Config struct {
	// Issuer is the server's issuer identifier (base URL)
	Issuer string

	// AuthorizationCodeTTL is how long authorization codes are valid
	AuthorizationCodeTTL int64 // seconds, default: 600 (10 minutes)

	// AccessTokenTTL is how long access tokens are valid
	AccessTokenTTL int64 // seconds, default: 3600 (1 hour)

	// RefreshTokenTTL is how long refresh tokens are valid
	RefreshTokenTTL int64 // seconds, default: 7776000 (90 days)

	// AllowRefreshTokenRotation enables refresh token rotation (OAuth 2.1)
	// Default: true (secure by default)
	AllowRefreshTokenRotation bool // default: true

	// TrustProxy enables trusting X-Forwarded-For and X-Real-IP headers
	// WARNING: Only enable if behind a trusted reverse proxy (nginx, HAProxy, etc.)
	// When false, uses direct connection IP (secure by default)
	// Default: false
	TrustProxy bool // default: false

	// TrustedProxyCount is the number of trusted proxies in front of this server
	// Used with TrustProxy to correctly extract client IP from X-Forwarded-For
	// Example: If you have 2 proxies (CloudFlare + nginx), set this to 2
	// The client IP will be extracted as: ips[len(ips) - TrustedProxyCount - 1]
	// Default: 1
	TrustedProxyCount int // default: 1

	// MaxClientsPerIP limits client registrations per IP address
	// Prevents DoS via mass client registration
	// Default: 10
	MaxClientsPerIP int // default: 10

	// MaxRegistrationsPerHour limits client registrations per IP address per hour
	// This is a time-windowed rate limit that prevents resource exhaustion
	// through repeated registration/deletion cycles
	// Default: 10
	MaxRegistrationsPerHour int // default: 10

	// RegistrationRateLimitWindow is the time window for client registration rate limiting
	// Default: 1 hour
	RegistrationRateLimitWindow int64 // seconds, default: 3600 (1 hour)

	// ClockSkewGracePeriod is the grace period for token expiration checks (in seconds)
	// This prevents false expiration errors due to time synchronization issues
	// Default: 5 seconds
	ClockSkewGracePeriod int64 // seconds, default: 5

	// ProviderRevocationTimeout is the timeout PER TOKEN for revoking tokens at the provider (Google/GitHub/etc)
	// during security events (code reuse, token reuse detection).
	// This prevents blocking indefinitely if the provider is slow or unreachable.
	// Default: 10 seconds per token (allows for network latency and rate limits)
	ProviderRevocationTimeout int64 // seconds, default: 10

	// ProviderRevocationMaxRetries is the maximum number of retry attempts for provider revocation
	// Retries use exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms
	// Default: 3 retries (total max time per token: ~10s + ~3s retries = ~13s)
	ProviderRevocationMaxRetries int // default: 3

	// ProviderRevocationFailureThreshold is the maximum acceptable failure rate (0.0 to 1.0)
	// If more than this percentage of provider revocations fail, the entire operation fails
	// to ensure tokens aren't left valid at the provider during security events.
	// Default: 0.5 (50% - at least half must succeed)
	ProviderRevocationFailureThreshold float64 // default: 0.5

	// RevokedFamilyRetentionDays is the number of days to retain revoked token family metadata
	// for forensics and security auditing. After this period, revoked family metadata is deleted.
	// Longer retention enables better security incident investigation but uses more memory.
	// Default: 90 days (recommended for security compliance and forensics)
	RevokedFamilyRetentionDays int64 // days, default: 90

	// SupportedScopes lists the scopes that are allowed for clients
	// If empty, all scopes are allowed
	SupportedScopes []string

	// AllowPKCEPlain allows the 'plain' code_challenge_method (NOT RECOMMENDED)
	// WARNING: The 'plain' method is insecure and deprecated in OAuth 2.1
	// Only enable for backward compatibility with legacy clients
	// When false, only S256 method is accepted (secure by default)
	// Default: false
	AllowPKCEPlain bool // default: false

	// RequirePKCE enforces PKCE for all authorization requests
	// WARNING: Disabling this significantly weakens security
	// Only disable for backward compatibility with very old clients
	// When true, code_challenge parameter is mandatory (secure by default)
	// Default: true
	RequirePKCE bool // default: true

	// AllowPublicClientsWithoutPKCE allows public clients to authenticate without PKCE
	// WARNING: This creates a significant security vulnerability to authorization code theft attacks
	// Public clients (mobile apps, SPAs) cannot securely store credentials, making them vulnerable
	// to authorization code interception if PKCE is not used (OAuth 2.1 Section 7.6)
	// Only enable this for backward compatibility with legacy clients that cannot be updated
	// SECURITY: Even when RequirePKCE=false, public clients MUST use PKCE unless this is explicitly enabled
	// Default: false (PKCE is REQUIRED for public clients per OAuth 2.1)
	AllowPublicClientsWithoutPKCE bool // default: false

	// MinStateLength is the minimum length for state parameters to prevent
	// timing attacks and ensure sufficient entropy for CSRF protection.
	// OAuth 2.1 recommends at least 128 bits (16 bytes) of entropy.
	// Default: 32 characters (192 bits of entropy)
	MinStateLength int // default: 32

	// AllowPublicClientRegistration allows unauthenticated dynamic client registration
	// WARNING: This can lead to DoS attacks via unlimited client registration
	// When false, client registration requires a registration access token
	// Default: false (authentication REQUIRED for security)
	AllowPublicClientRegistration bool // default: false

	// RegistrationAccessToken is the token required for client registration
	// Only checked if AllowPublicClientRegistration is false
	// Generate a secure random token and share it only with trusted client developers
	RegistrationAccessToken string

	// AllowedCustomSchemes is a list of allowed custom URI scheme patterns (regex)
	// Used for validating custom redirect URIs (e.g., myapp://, com.example.app://)
	// Empty list allows all RFC 3986 compliant schemes
	// Default: ["^[a-z][a-z0-9+.-]*$"] (RFC 3986 compliant schemes)
	AllowedCustomSchemes []string

	// AllowInsecureHTTP allows running OAuth server over HTTP (INSECURE - development only)
	// WARNING: OAuth over HTTP exposes all tokens and credentials to network interception
	// This should ONLY be enabled for local development (localhost, 127.0.0.1)
	// When false (default), the server enforces HTTPS for non-localhost deployments
	// Security: must be explicitly enabled to allow HTTP
	AllowInsecureHTTP bool
}

// applySecureDefaults applies secure-by-default configuration values
// This follows the principle: secure by default, opt-in for less secure options
func applySecureDefaults(config *Config, logger *slog.Logger) *Config {
	// Validate provider revocation config BEFORE applying defaults (to detect invalid values)
	validateProviderRevocationConfig(config, logger)

	// Apply time-based defaults
	applyTimeDefaults(config)

	// Apply security defaults and log warnings for insecure settings
	applySecurityDefaults(config, logger)

	return config
}

// applyTimeDefaults sets default values for time-based configuration
func applyTimeDefaults(config *Config) {
	if config.AuthorizationCodeTTL == 0 {
		config.AuthorizationCodeTTL = 600 // 10 minutes
	}
	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = 3600 // 1 hour
	}
	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 7776000 // 90 days
	}
	if config.TrustedProxyCount == 0 {
		config.TrustedProxyCount = 1
	}
	if config.ClockSkewGracePeriod == 0 {
		config.ClockSkewGracePeriod = 5
	}
	if config.ProviderRevocationTimeout == 0 {
		config.ProviderRevocationTimeout = 10 // 10 seconds per token (allows retries within reasonable time)
	} else if config.ProviderRevocationTimeout < 1 {
		// Validate minimum timeout to prevent misconfiguration
		config.ProviderRevocationTimeout = 5 // Minimum 5 seconds
	}

	if config.ProviderRevocationMaxRetries == 0 {
		config.ProviderRevocationMaxRetries = 3 // 3 retries with exponential backoff
	} else if config.ProviderRevocationMaxRetries < 0 {
		// Negative retries don't make sense - use default
		config.ProviderRevocationMaxRetries = 3
	}

	if config.ProviderRevocationFailureThreshold == 0 {
		config.ProviderRevocationFailureThreshold = 0.5 // 50% must succeed
	} else if config.ProviderRevocationFailureThreshold < 0.0 || config.ProviderRevocationFailureThreshold > 1.0 {
		// Threshold must be between 0.0 and 1.0 - use safe default
		config.ProviderRevocationFailureThreshold = 0.5
	}

	if config.RevokedFamilyRetentionDays == 0 {
		config.RevokedFamilyRetentionDays = 90 // 90 days (recommended for security auditing and forensics)
	} else if config.RevokedFamilyRetentionDays < 1 {
		// Minimum 1 day retention for forensics
		config.RevokedFamilyRetentionDays = 7 // Minimum 1 week
	}
	if config.MaxClientsPerIP == 0 {
		config.MaxClientsPerIP = 10
	}
	if config.MaxRegistrationsPerHour == 0 {
		config.MaxRegistrationsPerHour = 10
	}
	if config.RegistrationRateLimitWindow == 0 {
		config.RegistrationRateLimitWindow = 3600 // 1 hour
	}
}

// validateProviderRevocationConfig validates provider revocation configuration and logs warnings
func validateProviderRevocationConfig(config *Config, logger *slog.Logger) {
	// Capture original values for logging
	origTimeout := config.ProviderRevocationTimeout
	origRetries := config.ProviderRevocationMaxRetries
	origThreshold := config.ProviderRevocationFailureThreshold
	origRetention := config.RevokedFamilyRetentionDays

	hasInvalidValues := false

	// Validate and correct timeout
	if origTimeout != 0 && origTimeout < 1 {
		logger.Warn("⚠️  CONFIGURATION WARNING: Invalid ProviderRevocationTimeout corrected",
			"provided_value", origTimeout,
			"corrected_to", config.ProviderRevocationTimeout,
			"reason", "timeout must be at least 1 second")
		hasInvalidValues = true
	}

	// Validate and correct retries
	if origRetries < 0 {
		logger.Warn("⚠️  CONFIGURATION WARNING: Invalid ProviderRevocationMaxRetries corrected",
			"provided_value", origRetries,
			"corrected_to", config.ProviderRevocationMaxRetries,
			"reason", "retries cannot be negative")
		hasInvalidValues = true
	}

	// Validate and correct threshold
	if origThreshold != 0 && (origThreshold < 0.0 || origThreshold > 1.0) {
		logger.Warn("⚠️  CONFIGURATION WARNING: Invalid ProviderRevocationFailureThreshold corrected",
			"provided_value", origThreshold,
			"corrected_to", config.ProviderRevocationFailureThreshold,
			"reason", "threshold must be between 0.0 and 1.0")
		hasInvalidValues = true
	}

	// Validate and correct retention
	if origRetention != 0 && origRetention < 1 {
		logger.Warn("⚠️  CONFIGURATION WARNING: Invalid RevokedFamilyRetentionDays corrected",
			"provided_value", origRetention,
			"corrected_to", config.RevokedFamilyRetentionDays,
			"reason", "retention must be at least 1 day")
		hasInvalidValues = true
	}

	// Log final configuration if everything is valid
	if !hasInvalidValues {
		logger.Debug("Provider revocation configuration validated",
			"timeout_seconds", config.ProviderRevocationTimeout,
			"max_retries", config.ProviderRevocationMaxRetries,
			"failure_threshold", config.ProviderRevocationFailureThreshold,
			"retention_days", config.RevokedFamilyRetentionDays)
	}
}

// applySecurityDefaults sets secure defaults for security-related configuration
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

	// Log warnings for insecure settings (whether explicitly set or not)
	logSecurityWarnings(config, logger)
}

// logSecurityWarnings logs warnings for insecure configuration settings
func logSecurityWarnings(config *Config, logger *slog.Logger) {
	if !config.RequirePKCE {
		logger.Warn("⚠️  SECURITY WARNING: PKCE is DISABLED",
			"risk", "Authorization code interception attacks",
			"recommendation", "Set RequirePKCE=true for OAuth 2.1 compliance",
			"learn_more", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10#section-7.6")
	}
	if config.AllowPKCEPlain {
		logger.Warn("⚠️  SECURITY WARNING: Plain PKCE method is ALLOWED",
			"risk", "Weak code challenge protection",
			"recommendation", "Set AllowPKCEPlain=false to require S256",
			"learn_more", "https://datatracker.ietf.org/doc/html/rfc7636#section-4.2")
	}
	if config.TrustProxy {
		logger.Warn("⚠️  SECURITY NOTICE: Trusting proxy headers",
			"risk", "IP spoofing if proxy is not properly configured",
			"recommendation", "Only enable behind trusted reverse proxies",
			"config", "TrustedProxyCount should match your proxy chain length")
	}
	if config.AllowPublicClientRegistration {
		logger.Warn("⚠️  SECURITY WARNING: Public client registration is ENABLED",
			"risk", "DoS attacks via unlimited client registration",
			"recommendation", "Set AllowPublicClientRegistration=false and use RegistrationAccessToken")
	}
	if !config.AllowPublicClientRegistration && config.RegistrationAccessToken == "" {
		logger.Warn("⚠️  CONFIGURATION WARNING: RegistrationAccessToken not configured",
			"risk", "Client registration will fail",
			"recommendation", "Set RegistrationAccessToken or enable AllowPublicClientRegistration")
	}
	if config.AllowInsecureHTTP {
		logger.Error("🚨 CRITICAL SECURITY WARNING: HTTP is explicitly allowed",
			"risk", "All OAuth tokens and credentials exposed to network interception",
			"recommendation", "Use HTTPS in all environments",
			"compliance", "OAuth 2.1 requires HTTPS for all endpoints",
			"learn_more", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10#section-4.1.1")
	}
}
