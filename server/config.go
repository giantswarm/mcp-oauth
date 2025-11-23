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

	// ClockSkewGracePeriod is the grace period for token expiration checks (in seconds)
	// This prevents false expiration errors due to time synchronization issues
	// Default: 5 seconds
	ClockSkewGracePeriod int64 // seconds, default: 5

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
}

// applySecureDefaults applies secure-by-default configuration values
// This follows the principle: secure by default, opt-in for less secure options
func applySecureDefaults(config *Config, logger *slog.Logger) *Config {
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
	if config.MaxClientsPerIP == 0 {
		config.MaxClientsPerIP = 10
	}
}

// applySecurityDefaults sets secure defaults for security-related configuration
// Uses a heuristic to detect if config is new (all security bools false) vs explicitly configured
func applySecurityDefaults(config *Config, logger *slog.Logger) {
	// Heuristic: if all security bools are false, it's likely a fresh config
	isDefaultConfig := !config.AllowRefreshTokenRotation &&
		!config.RequirePKCE &&
		!config.AllowPKCEPlain &&
		!config.TrustProxy

	if isDefaultConfig {
		// Apply secure defaults for fresh config
		config.AllowRefreshTokenRotation = true
		config.RequirePKCE = true
		config.AllowPKCEPlain = false
		config.TrustProxy = false
		return
	}

	// User has explicitly configured security - log warnings for insecure settings
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
}
