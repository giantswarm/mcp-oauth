package server

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/util"
)

// applySecureDefaults applies secure-by-default configuration values
// This follows the principle: secure by default, opt-in for less secure options
func applySecureDefaults(config *Config, logger *slog.Logger) *Config {
	// Validate provider revocation config BEFORE applying defaults (to detect invalid values)
	validateProviderRevocationConfig(config, logger)

	// Validate CORS configuration BEFORE applying defaults (to detect invalid values)
	validateCORSConfig(config, logger)

	// Validate Client ID Metadata Documents configuration (MCP 2025-11-25)
	validateClientIDMetadataDocumentsConfig(config, logger)

	// Validate endpoint scope requirements (MCP 2025-11-25)
	validateEndpointScopeRequirements(config, logger)

	// Validate protected resource metadata configuration (RFC 9728, MCP 2025-11-25)
	validateResourceMetadataByPath(config, logger)

	// Validate interstitial page configuration (RFC 8252 Section 7.1)
	validateInterstitialConfig(config, logger)

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
			if hostname != localhostHostname && hostname != localhostIPv4Loopback && !strings.HasPrefix(hostname, "192.168.") && !strings.HasPrefix(hostname, "10.") {
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
	//
	// Default blocked schemes (always dangerous) - use canonical list from validation.go
	if len(config.BlockedRedirectSchemes) == 0 {
		config.BlockedRedirectSchemes = DefaultBlockedRedirectSchemes
	}
	// DNS validation timeout default
	if config.DNSValidationTimeout == 0 {
		config.DNSValidationTimeout = 2 * time.Second
	}

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

// validateEndpointScopeRequirements validates the EndpointScopeRequirements and
// EndpointMethodScopeRequirements configuration for security and correctness.
// It validates scope format per RFC 6749 Section 3.3.
func validateEndpointScopeRequirements(config *Config, logger *slog.Logger) {
	// Validate EndpointScopeRequirements
	for path, scopes := range config.EndpointScopeRequirements {
		for _, scope := range scopes {
			if err := validateScopeFormat(scope); err != nil {
				logger.Warn("Invalid scope format in EndpointScopeRequirements",
					"path", path,
					"scope", scope,
					"error", err,
					"rfc", "RFC 6749 Section 3.3")
			}
		}
	}

	// Validate EndpointMethodScopeRequirements
	for path, methodMap := range config.EndpointMethodScopeRequirements {
		for method, scopes := range methodMap {
			// Validate method is uppercase (standard HTTP method format)
			if method != "*" && method != strings.ToUpper(method) {
				logger.Warn("HTTP method should be uppercase in EndpointMethodScopeRequirements",
					"path", path,
					"method", method,
					"recommendation", "Use uppercase method names (GET, POST, DELETE, etc.)")
			}
			for _, scope := range scopes {
				if err := validateScopeFormat(scope); err != nil {
					logger.Warn("Invalid scope format in EndpointMethodScopeRequirements",
						"path", path,
						"method", method,
						"scope", scope,
						"error", err,
						"rfc", "RFC 6749 Section 3.3")
				}
			}
		}
	}
}

// validateScopeFormat validates a single scope string per RFC 6749 Section 3.3.
// Per the RFC, scope tokens must consist of printable ASCII characters excluding
// space, double-quote, and backslash: %x21 / %x23-5B / %x5D-7E
// This is: ! and # through [ and ] through ~
func validateScopeFormat(scope string) error {
	if scope == "" {
		return fmt.Errorf("scope cannot be empty")
	}

	for i, c := range scope {
		// RFC 6749 Section 3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
		// Valid characters:
		// - %x21 = ! (exclamation mark)
		// - %x23-5B = # through [ (includes letters, digits, most punctuation)
		// - %x5D-7E = ] through ~ (includes more punctuation, letters)
		// Invalid characters:
		// - %x20 = space (used as delimiter between scopes)
		// - %x22 = " (double-quote)
		// - %x5C = \ (backslash)
		if c == ' ' {
			return fmt.Errorf("scope cannot contain space at position %d (use separate scopes instead)", i)
		}
		if c == '"' {
			return fmt.Errorf("scope cannot contain double-quote at position %d", i)
		}
		if c == '\\' {
			return fmt.Errorf("scope cannot contain backslash at position %d", i)
		}
		// Check for printable ASCII range (0x21 to 0x7E, excluding 0x22 and 0x5C)
		if c < 0x21 || c > 0x7E {
			return fmt.Errorf("scope contains invalid character at position %d (only printable ASCII allowed)", i)
		}
	}

	return nil
}

// validBearerMethods defines the valid RFC 6750 bearer token transmission methods.
// Defined at package level to avoid re-creating this map on every validation iteration.
var validBearerMethods = map[string]bool{
	"header": true,
	"body":   true,
	"query":  true,
}

// validateResourceMetadataByPath validates the ResourceMetadataByPath configuration
// for security, correctness, and RFC 9728 compliance.
func validateResourceMetadataByPath(config *Config, logger *slog.Logger) {
	if len(config.ResourceMetadataByPath) == 0 {
		return
	}

	for pathKey, pathConfig := range config.ResourceMetadataByPath {
		// Validate path format using shared validation logic
		if err := util.ValidateMetadataPath(pathKey); err != nil {
			logger.Warn("Invalid path in ResourceMetadataByPath",
				"path", pathKey,
				"error", err,
				"recommendation", "Use clean paths without traversal sequences")
		}

		// Validate scopes format per RFC 6749 Section 3.3
		for _, scope := range pathConfig.ScopesSupported {
			if err := validateScopeFormat(scope); err != nil {
				logger.Warn("Invalid scope format in ResourceMetadataByPath",
					"path", pathKey,
					"scope", scope,
					"error", err,
					"rfc", "RFC 6749 Section 3.3")
			}
		}

		// Validate authorization server URLs
		for i, authServer := range pathConfig.AuthorizationServers {
			u, err := url.Parse(authServer)
			if err != nil || u.Scheme == "" || u.Host == "" {
				logger.Warn("Invalid authorization server URL in ResourceMetadataByPath",
					"path", pathKey,
					"index", i,
					"url", authServer,
					"error", "must be a valid URL with scheme and host")
			} else if u.Scheme != SchemeHTTPS && u.Scheme != SchemeHTTP {
				logger.Warn("Authorization server URL should use HTTPS",
					"path", pathKey,
					"url", authServer,
					"scheme", u.Scheme,
					"recommendation", "Use HTTPS for security")
			}
		}

		// Validate bearer methods per RFC 6750
		for _, method := range pathConfig.BearerMethodsSupported {
			if !validBearerMethods[method] {
				logger.Warn("Unknown bearer method in ResourceMetadataByPath",
					"path", pathKey,
					"method", method,
					"valid_methods", []string{"header", "body", "query"},
					"rfc", "RFC 6750")
			}
			// Warn about insecure methods
			if method == "query" || method == "body" {
				logger.Warn("Insecure bearer method configured in ResourceMetadataByPath",
					"path", pathKey,
					"method", method,
					"risk", "Bearer tokens in query or body can be logged or cached",
					"recommendation", "Use 'header' method for security")
			}
		}

		// Validate resource identifier if provided
		if pathConfig.ResourceIdentifier != "" {
			u, err := url.Parse(pathConfig.ResourceIdentifier)
			if err != nil || u.Scheme == "" || u.Host == "" {
				logger.Warn("Invalid resource identifier in ResourceMetadataByPath",
					"path", pathKey,
					"resource_identifier", pathConfig.ResourceIdentifier,
					"error", "must be a valid URL with scheme and host",
					"rfc", "RFC 8707")
			}
		}
	}

	logger.Debug("ResourceMetadataByPath configuration validated",
		"paths_configured", len(config.ResourceMetadataByPath))
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
	if config.AllowNoStateParameter {
		logger.Warn("⚠️  SECURITY WARNING: State parameter is NOT REQUIRED",
			"risk", "CSRF attacks possible without state parameter",
			"recommendation", "Set AllowNoStateParameter=false unless required for client compatibility")
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

	// Redirect URI security logging
	// Security features are enabled by default. Warn when Disable* fields are used.
	logger.Info("Redirect URI security status",
		"production_mode", config.ProductionMode,
		"dns_validation", config.DNSValidation,
		"dns_validation_strict", config.DNSValidationStrict,
		"authorization_time_validation", config.ValidateRedirectURIAtAuthorization,
		"dns_timeout", config.DNSValidationTimeout)

	// Warn about explicitly disabled security features
	if config.DisableProductionMode {
		logger.Warn("⚠️  SECURITY WARNING: ProductionMode is DISABLED",
			"risk", "HTTP allowed on non-loopback hosts, relaxed redirect URI validation",
			"recommendation", "Only disable for local development environments",
			"learn_more", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.1")
	}
	if config.DisableDNSValidation {
		logger.Warn("⚠️  SECURITY WARNING: DNS validation is DISABLED",
			"risk", "DNS rebinding attacks possible - hostnames not validated",
			"recommendation", "Only disable if DNS lookup latency is unacceptable",
			"learn_more", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")
	}
	if config.DisableDNSValidationStrict {
		logger.Warn("⚠️  SECURITY WARNING: DNS validation strict mode is DISABLED",
			"risk", "DNS failures allow registration (fail-open) - potential bypass",
			"recommendation", "Only disable if DNS reliability issues cause problems")
	}
	if config.DisableAuthorizationTimeValidation {
		logger.Warn("⚠️  SECURITY WARNING: Authorization-time validation is DISABLED",
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
		logger.Warn("⚠️  SECURITY WARNING: Private IP redirect URIs are ALLOWED",
			"risk", "SSRF attacks to internal networks (10.x, 172.16.x, 192.168.x)",
			"recommendation", "Only enable for internal/VPN deployments with proper network controls",
			"learn_more", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")
	}
	if config.AllowLinkLocalRedirectURIs {
		logger.Warn("⚠️  SECURITY WARNING: Link-local redirect URIs are ALLOWED",
			"risk", "SSRF to cloud metadata services (169.254.169.254 - AWS/GCP/Azure)",
			"recommendation", "Disable unless specifically required",
			"impact", "Could expose cloud instance credentials and sensitive metadata",
			"learn_more", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery")
	}
}
