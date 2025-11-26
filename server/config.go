package server

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// URI scheme constants (shared with validation.go)
const (
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
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

	// TokenRefreshThreshold is the time before token expiry (in seconds) when proactive
	// refresh should be attempted during token validation. If a token will expire within
	// this threshold and has a refresh token available, ValidateToken will attempt to
	// refresh it proactively to avoid validation failures.
	// This improves user experience by preventing expired token errors when refresh is possible.
	// Default: 300 seconds (5 minutes)
	TokenRefreshThreshold int64 // seconds, default: 300

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

	// MaxScopeLength is the maximum allowed length for the scope parameter string
	// This prevents potential DoS attacks via extremely long scope strings.
	// The scope string is space-delimited, so this limits the total length including
	// all scopes and spaces, not individual scope names.
	// Default: 1000 characters (sufficient for most use cases)
	// Example: "openid profile email" = 22 characters
	MaxScopeLength int // default: 1000

	// DefaultChallengeScopes are the scopes to include in WWW-Authenticate challenges
	// When a 401 Unauthorized response is returned, these scopes indicate what
	// permissions would be needed to access the resource.
	// Per MCP 2025-11-25, this helps clients determine which scopes to request.
	// If empty, no scope parameter is included in WWW-Authenticate headers.
	DefaultChallengeScopes []string

	// DisableWWWAuthenticateMetadata disables resource_metadata and discovery parameters
	// in WWW-Authenticate headers for backward compatibility with legacy OAuth clients.
	// When false (default): Full MCP 2025-11-25 compliance with enhanced discovery support
	//   - Includes resource_metadata URL for authorization server discovery
	//   - Includes scope parameter (if DefaultChallengeScopes configured)
	//   - Includes error and error_description parameters
	// When true: Minimal WWW-Authenticate headers for backward compatibility
	//   - Only includes "Bearer" scheme without parameters
	//   - Compatible with older OAuth clients that may not expect parameters
	// Default: false (metadata ENABLED for secure by default, MCP 2025-11-25 compliant)
	//
	// WARNING: Only enable if you have legacy OAuth clients that cannot handle
	// parameters in WWW-Authenticate headers. Modern clients will ignore unknown
	// parameters per HTTP specifications.
	//
	// Use case for enabling (disabling metadata):
	//   - Testing with legacy OAuth clients
	//   - Gradual migration period for clients updating to MCP 2025-11-25
	//   - Troubleshooting client compatibility issues
	DisableWWWAuthenticateMetadata bool // default: false (metadata ENABLED)

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

	// AllowPublicClientRegistration controls two security aspects of client registration:
	// 1. Whether the DCR endpoint (/oauth/register) requires authentication (Bearer token)
	// 2. Whether public clients (native apps, CLIs with token_endpoint_auth_method="none") can be registered
	//
	// When false (SECURE DEFAULT):
	//   - DCR endpoint REQUIRES a valid RegistrationAccessToken in Authorization header
	//   - Public client registration is DENIED (only confidential clients can be registered)
	//   - This prevents both DoS attacks and unauthorized public client creation
	//
	// When true (PERMISSIVE, for development only):
	//   - DCR endpoint allows UNAUTHENTICATED registration (⚠️  DoS risk)
	//   - Public clients CAN be registered by any requester
	//   - Should only be used in trusted development environments
	//
	// SECURITY RECOMMENDATION: Keep this false in production. Use RegistrationAccessToken
	// to authenticate trusted client developers, and only enable public clients if your
	// use case requires native/mobile apps.
	//
	// Default: false (authentication REQUIRED, public clients DENIED)
	AllowPublicClientRegistration bool // default: false

	// RegistrationAccessToken is the Bearer token required for client registration
	// when AllowPublicClientRegistration is false (recommended for production).
	//
	// Generate a cryptographically secure random token and share it ONLY with
	// trusted developers who need to register OAuth clients.
	//
	// Example generation: openssl rand -base64 32
	//
	// The token is validated using constant-time comparison to prevent timing attacks.
	// If AllowPublicClientRegistration is false but this is empty, ALL registration
	// attempts will fail (misconfiguration).
	//
	// Default: "" (no token configured)
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

	// Storage and cleanup configuration
	StorageCleanupInterval     time.Duration // How often to clean up expired tokens/codes (default: 1 minute)
	RateLimiterCleanupInterval time.Duration // How often to clean up idle rate limiters (default: 5 minutes)

	// CORS settings for browser-based clients
	CORS CORSConfig

	// Instrumentation settings for observability
	Instrumentation InstrumentationConfig

	// ResourceIdentifier is the canonical URI that identifies this MCP resource server (RFC 8707)
	// Used for audience validation to ensure tokens are only accepted by their intended resource server
	// If empty, defaults to Issuer value
	// Example: "https://mcp.example.com" or "https://api.example.com/mcp"
	// Security: This prevents token theft and replay attacks to different resource servers
	ResourceIdentifier string

	// EnableClientIDMetadataDocuments enables URL-based client_id support per MCP 2025-11-25
	// When enabled, clients can use HTTPS URLs as client identifiers, and the authorization
	// server will fetch client metadata from that URL following draft-ietf-oauth-client-id-metadata-document-00
	// This addresses the common MCP scenario where servers and clients have no pre-existing relationship.
	// Default: false (disabled for backward compatibility)
	EnableClientIDMetadataDocuments bool

	// ClientMetadataFetchTimeout is the timeout for fetching client metadata from URL-based client_ids
	// This prevents indefinite blocking if a metadata URL is slow or unresponsive
	// Default: 10 seconds
	ClientMetadataFetchTimeout time.Duration

	// ClientMetadataCacheTTL is how long to cache fetched client metadata
	// Caching reduces latency and prevents repeated fetches for the same client
	// HTTP Cache-Control headers may override this value
	// Default: 5 minutes
	ClientMetadataCacheTTL time.Duration
}

// InstrumentationConfig holds configuration for OpenTelemetry instrumentation
type InstrumentationConfig struct {
	// Enabled controls whether instrumentation is active
	// When false, uses no-op providers (zero overhead)
	// Default: false (disabled)
	Enabled bool

	// ServiceName is the name of the service for telemetry
	// Default: "mcp-oauth"
	ServiceName string

	// ServiceVersion is the version of the service for telemetry
	// Default: "unknown"
	ServiceVersion string

	// LogClientIPs controls whether client IP addresses are included in traces and metrics
	// When false, client IP attributes will be omitted from observability data
	// This can help with GDPR and privacy compliance in strict jurisdictions
	// Default: false (disabled for privacy by default)
	//
	// Privacy Note: Client IP addresses may be considered Personally Identifiable
	// Information (PII) under GDPR and other privacy regulations. Enable IP
	// logging only if required for security monitoring and you have appropriate
	// legal basis and data protection measures in place.
	LogClientIPs bool

	// IncludeClientIDInMetrics controls whether client_id is included in metric labels
	// When true, provides detailed per-client metrics but increases cardinality
	// When false, reduces cardinality (recommended for >1000 clients)
	// Default: true (include client_id for detailed metrics)
	//
	// Cardinality Warning: Each unique client_id creates a new time series.
	// With 10,000+ clients, this can cause memory and performance issues.
	// Set to false for high-scale deployments.
	IncludeClientIDInMetrics bool

	// MetricsExporter controls which metrics exporter to use
	// Options: "prometheus", "stdout", "none" (default: "none")
	// - "prometheus": Export metrics in Prometheus format (use inst.PrometheusExporter())
	// - "stdout": Print metrics to stdout (useful for development/debugging)
	// - "none": Use no-op provider (zero overhead)
	// Default: "none" (disabled)
	MetricsExporter string

	// TracesExporter controls which traces exporter to use
	// Options: "otlp", "stdout", "none" (default: "none")
	// - "otlp": Export traces via OTLP HTTP (requires OTLPEndpoint)
	// - "stdout": Print traces to stdout (useful for development/debugging)
	// - "none": Use no-op provider (zero overhead)
	// Default: "none" (disabled)
	TracesExporter string

	// OTLPEndpoint is the endpoint for OTLP trace export
	// Required when TracesExporter="otlp"
	// Example: "localhost:4318" (default OTLP HTTP port)
	// Default: "" (not set)
	OTLPEndpoint string

	// OTLPInsecure controls whether to use insecure HTTP for OTLP export
	// When false (default), uses TLS for secure transport
	// Set to true only for local development or testing
	// Default: false (uses TLS)
	// WARNING: Never use in production - traces contain user metadata
	OTLPInsecure bool
}

// CORSConfig holds CORS (Cross-Origin Resource Sharing) configuration for browser-based clients
// CORS is disabled by default for security. Only enable for browser-based MCP clients.
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origin URLs for CORS requests.
	// Examples: ["https://app.example.com", "https://dashboard.example.com"]
	// Use "*" to allow all origins (requires AllowWildcardOrigin=true).
	// Empty list means CORS is disabled (default, secure).
	AllowedOrigins []string

	// AllowWildcardOrigin explicitly enables wildcard (*) origin support.
	// WARNING: This allows ANY website to make cross-origin requests to your OAuth server.
	// This creates significant CSRF attack surface and is NOT RECOMMENDED for production.
	// Only enable for development or when you fully understand the security implications.
	// Must be explicitly set to true when using "*" in AllowedOrigins.
	// Default: false (wildcard origins are rejected)
	AllowWildcardOrigin bool

	// AllowCredentials enables the Access-Control-Allow-Credentials header.
	// Required if your browser client needs to send cookies or authorization headers.
	// Must be true for OAuth flows that require Bearer tokens.
	// SECURITY: Cannot be used with wildcard origin (per CORS specification).
	// Default: false
	AllowCredentials bool

	// MaxAge is the maximum time (in seconds) browsers can cache preflight responses.
	// Default: 3600 (1 hour)
	MaxAge int
}

// AuthorizationEndpoint returns the full URL to the authorization endpoint
func (c *Config) AuthorizationEndpoint() string {
	return c.Issuer + "/oauth/authorize"
}

// TokenEndpoint returns the full URL to the token endpoint
func (c *Config) TokenEndpoint() string {
	return c.Issuer + "/oauth/token"
}

// RegistrationEndpoint returns the full URL to the dynamic client registration endpoint
func (c *Config) RegistrationEndpoint() string {
	return c.Issuer + "/oauth/register"
}

// ProtectedResourceMetadataEndpoint returns the full URL to the RFC 9728 Protected Resource Metadata endpoint
// This endpoint is used in WWW-Authenticate headers to help MCP clients discover authorization server information
func (c *Config) ProtectedResourceMetadataEndpoint() string {
	return c.Issuer + "/.well-known/oauth-protected-resource"
}

// GetResourceIdentifier returns the resource identifier for this server
// If ResourceIdentifier is explicitly configured, returns that value
// Otherwise, defaults to the Issuer value (secure default)
// Per RFC 8707, this identifier is used for token audience binding
func (c *Config) GetResourceIdentifier() string {
	if c.ResourceIdentifier != "" {
		return c.ResourceIdentifier
	}
	return c.Issuer
}

// applySecureDefaults applies secure-by-default configuration values
// This follows the principle: secure by default, opt-in for less secure options
func applySecureDefaults(config *Config, logger *slog.Logger) *Config {
	// Validate provider revocation config BEFORE applying defaults (to detect invalid values)
	validateProviderRevocationConfig(config, logger)

	// Validate CORS configuration BEFORE applying defaults (to detect invalid values)
	validateCORSConfig(config, logger)

	// Validate Client ID Metadata Documents configuration (MCP 2025-11-25)
	validateClientIDMetadataDocumentsConfig(config, logger)

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
	if config.TokenRefreshThreshold == 0 {
		config.TokenRefreshThreshold = 300 // 5 minutes
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
	if config.MaxScopeLength == 0 {
		config.MaxScopeLength = 1000 // 1000 characters
	}
	if config.StorageCleanupInterval == 0 {
		config.StorageCleanupInterval = time.Minute // 1 minute
	}
	if config.RateLimiterCleanupInterval == 0 {
		config.RateLimiterCleanupInterval = 5 * time.Minute // 5 minutes
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

// validateCORSConfig validates CORS configuration for security and correctness
func validateCORSConfig(config *Config, logger *slog.Logger) {
	// Skip validation if CORS is not configured (secure default)
	if len(config.CORS.AllowedOrigins) == 0 {
		return
	}

	// CRITICAL SECURITY: Wildcard with credentials is invalid per CORS specification
	// Browsers will reject this combination, so we should fail fast at startup
	if config.CORS.AllowCredentials {
		for _, origin := range config.CORS.AllowedOrigins {
			if origin == "*" {
				panic("CORS: cannot use wildcard '*' with AllowCredentials=true (violates CORS specification)")
			}
		}
	}

	// Validate each origin format
	for _, origin := range config.CORS.AllowedOrigins {
		// SECURITY: Wildcard requires explicit opt-in via AllowWildcardOrigin
		// This ensures operators consciously accept the security implications
		if origin == "*" {
			if !config.CORS.AllowWildcardOrigin {
				panic("CORS: wildcard origin '*' requires AllowWildcardOrigin=true to be explicitly set. " +
					"This allows ANY website to make cross-origin requests to your OAuth server. " +
					"Set AllowWildcardOrigin=true only if you understand the security implications, " +
					"or use specific origins (e.g., https://app.example.com) instead.")
			}
			logger.Warn("⚠️  CORS: Wildcard origin (*) enabled via AllowWildcardOrigin=true",
				"risk", "Allows ANY website to make requests to this server",
				"security_impact", "Increased CSRF attack surface",
				"recommendation", "Use specific origins (e.g., https://app.example.com) in production")
			continue
		}

		// Must be a valid URL with scheme and host
		u, err := url.Parse(origin)
		if err != nil || u.Scheme == "" || u.Host == "" {
			panic(fmt.Sprintf("CORS: invalid origin format '%s' (must be scheme://host, e.g., https://app.example.com)", origin))
		}

		// Warn about trailing slash (can cause matching issues)
		if strings.HasSuffix(origin, "/") {
			panic(fmt.Sprintf("CORS: origin '%s' should not have trailing slash (use %s)", origin, strings.TrimSuffix(origin, "/")))
		}

		// Enforce HTTPS in production (unless AllowInsecureHTTP is explicitly enabled)
		if !config.AllowInsecureHTTP && u.Scheme == SchemeHTTP {
			hostname := u.Hostname()
			// Allow localhost for development
			if hostname != "localhost" && hostname != "127.0.0.1" && !strings.HasPrefix(hostname, "192.168.") && !strings.HasPrefix(hostname, "10.") {
				panic(fmt.Sprintf("CORS: HTTP origin '%s' not allowed (use HTTPS or set AllowInsecureHTTP=true for development)", origin))
			}
			logger.Warn("⚠️  CORS: HTTP origin allowed for localhost/development",
				"origin", origin,
				"recommendation", "Use HTTPS origins in production")
		}
	}

	logger.Debug("CORS configuration validated",
		"allowed_origins_count", len(config.CORS.AllowedOrigins),
		"allow_credentials", config.CORS.AllowCredentials,
		"max_age", config.CORS.MaxAge)
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

	// SECURITY: Enforce absolute minimum state length to ensure CSRF protection entropy
	// OAuth 2.1 recommends at least 128 bits (16 bytes) of entropy
	// 16 characters in base64 = 96 bits, but this is an absolute floor
	const absoluteMinStateLength = 16
	if config.MinStateLength < absoluteMinStateLength {
		logger.Warn("⚠️  SECURITY WARNING: MinStateLength below recommended minimum, enforcing floor",
			"configured", config.MinStateLength,
			"enforced_minimum", absoluteMinStateLength,
			"recommended", 32,
			"risk", "reduced CSRF protection entropy")
		config.MinStateLength = absoluteMinStateLength
	}

	// Log warnings for insecure settings (whether explicitly set or not)
	logSecurityWarnings(config, logger)
}

// validateWWWAuthenticateConfig validates WWW-Authenticate header configuration
// for security best practices
func validateWWWAuthenticateConfig(config *Config, logger *slog.Logger) {
	// SECURITY: Warn if WWW-Authenticate metadata is disabled
	if config.DisableWWWAuthenticateMetadata {
		logger.Warn("⚠️  SECURITY WARNING: WWW-Authenticate metadata is DISABLED",
			"risk", "MCP 2025-11-25 non-compliance, reduced client discovery",
			"recommendation", "Set DisableWWWAuthenticateMetadata=false for spec compliance",
			"learn_more", "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization")
	}

	// Recommendation 1: Warn about very large scope lists (header size limits)
	// Some proxies/servers have HTTP header size limits (typically 8KB)
	const maxRecommendedScopes = 50
	if len(config.DefaultChallengeScopes) > maxRecommendedScopes {
		logger.Warn("⚠️  CONFIGURATION WARNING: Very large DefaultChallengeScopes configured",
			"count", len(config.DefaultChallengeScopes),
			"max_recommended", maxRecommendedScopes,
			"risk", "May exceed HTTP header size limits in some proxies/servers",
			"recommendation", "Consider reducing scope count or using broader scopes")
	}

	// Recommendation 3: Validate scope entries don't contain invalid characters
	// This provides defense-in-depth (escaping already prevents injection)
	for i, scope := range config.DefaultChallengeScopes {
		if strings.Contains(scope, `"`) {
			logger.Warn("⚠️  CONFIGURATION WARNING: Invalid character in DefaultChallengeScopes",
				"index", i,
				"scope", scope,
				"invalid_char", `"`,
				"risk", "Scope contains double-quote character",
				"recommendation", "Use alphanumeric characters, hyphens, underscores, colons, and slashes only")
		}
		if strings.Contains(scope, ",") {
			logger.Warn("⚠️  CONFIGURATION WARNING: Invalid character in DefaultChallengeScopes",
				"index", i,
				"scope", scope,
				"invalid_char", ",",
				"risk", "Scope contains comma character",
				"recommendation", "Use alphanumeric characters, hyphens, underscores, colons, and slashes only")
		}
		if strings.Contains(scope, `\`) {
			logger.Warn("⚠️  CONFIGURATION WARNING: Invalid character in DefaultChallengeScopes",
				"index", i,
				"scope", scope,
				"invalid_char", `\`,
				"risk", "Scope contains backslash character",
				"recommendation", "Use alphanumeric characters, hyphens, underscores, colons, and slashes only")
		}
	}

	// Log info about WWW-Authenticate metadata configuration
	if !config.DisableWWWAuthenticateMetadata && len(config.DefaultChallengeScopes) > 0 {
		logger.Debug("WWW-Authenticate metadata enabled",
			"challenge_scopes_count", len(config.DefaultChallengeScopes),
			"resource_metadata_url", config.ProtectedResourceMetadataEndpoint())
	}
}

// validateClientIDMetadataDocumentsConfig validates Client ID Metadata Documents configuration
// for security and correctness (MCP 2025-11-25, draft-ietf-oauth-client-id-metadata-document-00)
func validateClientIDMetadataDocumentsConfig(config *Config, logger *slog.Logger) {
	// Only validate if feature is enabled
	if !config.EnableClientIDMetadataDocuments {
		return
	}

	// SECURITY: Validate ClientMetadataCacheTTL is within reasonable bounds
	// - Minimum: 1 minute (prevents cache bypass DoS via rapid expiry)
	// - Maximum: 1 hour (prevents stale metadata from being cached too long)
	const minTTL = 1 * time.Minute
	const maxTTL = 1 * time.Hour

	if config.ClientMetadataCacheTTL < 0 {
		logger.Error("⚠️  CONFIGURATION ERROR: ClientMetadataCacheTTL cannot be negative",
			"value", config.ClientMetadataCacheTTL,
			"risk", "Invalid configuration could cause unexpected behavior",
			"fix", "Set ClientMetadataCacheTTL to a positive duration or 0 for default (5 minutes)")
		// Set to default to prevent issues
		config.ClientMetadataCacheTTL = 5 * time.Minute
	}

	if config.ClientMetadataCacheTTL > 0 && config.ClientMetadataCacheTTL < minTTL {
		logger.Warn("⚠️  CONFIGURATION WARNING: ClientMetadataCacheTTL is very short",
			"value", config.ClientMetadataCacheTTL,
			"minimum_recommended", minTTL,
			"risk", "Excessive metadata fetches may cause performance issues and rate limiting",
			"recommendation", fmt.Sprintf("Set ClientMetadataCacheTTL to at least %v", minTTL))
	}

	if config.ClientMetadataCacheTTL > maxTTL {
		logger.Warn("⚠️  CONFIGURATION WARNING: ClientMetadataCacheTTL is very long",
			"value", config.ClientMetadataCacheTTL,
			"maximum_recommended", maxTTL,
			"risk", "Stale client metadata may be cached for extended periods",
			"recommendation", fmt.Sprintf("Set ClientMetadataCacheTTL to at most %v", maxTTL))
	}

	// SECURITY: Validate ClientMetadataFetchTimeout is reasonable
	// - Minimum: 1 second (prevents immediate timeout)
	// - Maximum: 30 seconds (prevents hanging connections)
	const minTimeout = 1 * time.Second
	const maxTimeout = 30 * time.Second

	if config.ClientMetadataFetchTimeout < 0 {
		logger.Error("⚠️  CONFIGURATION ERROR: ClientMetadataFetchTimeout cannot be negative",
			"value", config.ClientMetadataFetchTimeout,
			"risk", "Invalid configuration could cause unexpected behavior",
			"fix", "Set ClientMetadataFetchTimeout to a positive duration or 0 for default (10 seconds)")
		// Set to default to prevent issues
		config.ClientMetadataFetchTimeout = 10 * time.Second
	}

	if config.ClientMetadataFetchTimeout > 0 && config.ClientMetadataFetchTimeout < minTimeout {
		logger.Warn("⚠️  CONFIGURATION WARNING: ClientMetadataFetchTimeout is very short",
			"value", config.ClientMetadataFetchTimeout,
			"minimum_recommended", minTimeout,
			"risk", "Metadata fetches may timeout prematurely for slow servers",
			"recommendation", fmt.Sprintf("Set ClientMetadataFetchTimeout to at least %v", minTimeout))
	}

	if config.ClientMetadataFetchTimeout > maxTimeout {
		logger.Warn("⚠️  CONFIGURATION WARNING: ClientMetadataFetchTimeout is very long",
			"value", config.ClientMetadataFetchTimeout,
			"maximum_recommended", maxTimeout,
			"risk", "Slow or malicious servers may cause connection hangs",
			"recommendation", fmt.Sprintf("Set ClientMetadataFetchTimeout to at most %v", maxTimeout))
	}

	// Log successful validation
	logger.Debug("Client ID Metadata Documents configuration validated",
		"cache_ttl", config.ClientMetadataCacheTTL,
		"fetch_timeout", config.ClientMetadataFetchTimeout,
		"enabled", config.EnableClientIDMetadataDocuments)
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
	// Validate WWW-Authenticate configuration
	validateWWWAuthenticateConfig(config, logger)
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
