package server

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/util"
)

// applySecureDefaults applies secure-by-default configuration values.
// This follows the principle: secure by default, opt-in for less secure options.
//
// This is the main entry point for configuration validation and default application.
// It delegates to specialized validation functions for different configuration areas.
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

// applyTimeDefaults sets default values for time-based configuration.
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

	applyProviderRevocationDefaults(config)
	applyRateLimitDefaults(config)
	applyCleanupIntervalDefaults(config)
}

// applyProviderRevocationDefaults sets defaults for provider revocation configuration.
func applyProviderRevocationDefaults(config *Config) {
	if config.ProviderRevocationTimeout == 0 {
		config.ProviderRevocationTimeout = 10 // 10 seconds per token
	} else if config.ProviderRevocationTimeout < 1 {
		config.ProviderRevocationTimeout = 5 // Minimum 5 seconds
	}

	if config.ProviderRevocationMaxRetries == 0 {
		config.ProviderRevocationMaxRetries = 3 // 3 retries with exponential backoff
	} else if config.ProviderRevocationMaxRetries < 0 {
		config.ProviderRevocationMaxRetries = 3
	}

	if config.ProviderRevocationFailureThreshold == 0 {
		config.ProviderRevocationFailureThreshold = 0.5 // 50% must succeed
	} else if config.ProviderRevocationFailureThreshold < 0.0 || config.ProviderRevocationFailureThreshold > 1.0 {
		config.ProviderRevocationFailureThreshold = 0.5
	}

	if config.RevokedFamilyRetentionDays == 0 {
		config.RevokedFamilyRetentionDays = 90 // 90 days
	} else if config.RevokedFamilyRetentionDays < 1 {
		config.RevokedFamilyRetentionDays = 7 // Minimum 1 week
	}
}

// applyRateLimitDefaults sets defaults for rate limiting configuration.
func applyRateLimitDefaults(config *Config) {
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
}

// applyCleanupIntervalDefaults sets defaults for cleanup interval configuration.
func applyCleanupIntervalDefaults(config *Config) {
	if config.StorageCleanupInterval == 0 {
		config.StorageCleanupInterval = time.Minute // 1 minute
	}
	if config.RateLimiterCleanupInterval == 0 {
		config.RateLimiterCleanupInterval = 5 * time.Minute // 5 minutes
	}
}

// validateProviderRevocationConfig validates provider revocation configuration and logs warnings.
func validateProviderRevocationConfig(config *Config, logger *slog.Logger) {
	// Capture original values for logging
	origTimeout := config.ProviderRevocationTimeout
	origRetries := config.ProviderRevocationMaxRetries
	origThreshold := config.ProviderRevocationFailureThreshold
	origRetention := config.RevokedFamilyRetentionDays

	hasInvalidValues := false

	// Validate and correct timeout
	if origTimeout != 0 && origTimeout < 1 {
		logger.Warn("CONFIGURATION WARNING: Invalid ProviderRevocationTimeout corrected",
			"provided_value", origTimeout,
			"corrected_to", config.ProviderRevocationTimeout,
			"reason", "timeout must be at least 1 second")
		hasInvalidValues = true
	}

	// Validate and correct retries
	if origRetries < 0 {
		logger.Warn("CONFIGURATION WARNING: Invalid ProviderRevocationMaxRetries corrected",
			"provided_value", origRetries,
			"corrected_to", config.ProviderRevocationMaxRetries,
			"reason", "retries cannot be negative")
		hasInvalidValues = true
	}

	// Validate and correct threshold
	if origThreshold != 0 && (origThreshold < 0.0 || origThreshold > 1.0) {
		logger.Warn("CONFIGURATION WARNING: Invalid ProviderRevocationFailureThreshold corrected",
			"provided_value", origThreshold,
			"corrected_to", config.ProviderRevocationFailureThreshold,
			"reason", "threshold must be between 0.0 and 1.0")
		hasInvalidValues = true
	}

	// Validate and correct retention
	if origRetention != 0 && origRetention < 1 {
		logger.Warn("CONFIGURATION WARNING: Invalid RevokedFamilyRetentionDays corrected",
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

// validateClientIDMetadataDocumentsConfig validates Client ID Metadata Documents configuration
// for security and correctness (MCP 2025-11-25, draft-ietf-oauth-client-id-metadata-document-00).
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
		logger.Error("CONFIGURATION ERROR: ClientMetadataCacheTTL cannot be negative",
			"value", config.ClientMetadataCacheTTL,
			"risk", "Invalid configuration could cause unexpected behavior",
			"fix", "Set ClientMetadataCacheTTL to a positive duration or 0 for default (5 minutes)")
		// Set to default to prevent issues
		config.ClientMetadataCacheTTL = 5 * time.Minute
	}

	if config.ClientMetadataCacheTTL > 0 && config.ClientMetadataCacheTTL < minTTL {
		logger.Warn("CONFIGURATION WARNING: ClientMetadataCacheTTL is very short",
			"value", config.ClientMetadataCacheTTL,
			"minimum_recommended", minTTL,
			"risk", "Excessive metadata fetches may cause performance issues and rate limiting",
			"recommendation", fmt.Sprintf("Set ClientMetadataCacheTTL to at least %v", minTTL))
	}

	if config.ClientMetadataCacheTTL > maxTTL {
		logger.Warn("CONFIGURATION WARNING: ClientMetadataCacheTTL is very long",
			"value", config.ClientMetadataCacheTTL,
			"maximum_recommended", maxTTL,
			"risk", "Stale client metadata may be cached for extended periods",
			"recommendation", fmt.Sprintf("Set ClientMetadataCacheTTL to at most %v", maxTTL))
	}

	// SECURITY: Validate ClientMetadataFetchTimeout is reasonable
	validateClientMetadataFetchTimeout(config, logger)

	// Log successful validation
	logger.Debug("Client ID Metadata Documents configuration validated",
		"cache_ttl", config.ClientMetadataCacheTTL,
		"fetch_timeout", config.ClientMetadataFetchTimeout,
		"enabled", config.EnableClientIDMetadataDocuments)
}

// validateClientMetadataFetchTimeout validates the fetch timeout configuration.
func validateClientMetadataFetchTimeout(config *Config, logger *slog.Logger) {
	const minTimeout = 1 * time.Second
	const maxTimeout = 30 * time.Second

	if config.ClientMetadataFetchTimeout < 0 {
		logger.Error("CONFIGURATION ERROR: ClientMetadataFetchTimeout cannot be negative",
			"value", config.ClientMetadataFetchTimeout,
			"risk", "Invalid configuration could cause unexpected behavior",
			"fix", "Set ClientMetadataFetchTimeout to a positive duration or 0 for default (10 seconds)")
		config.ClientMetadataFetchTimeout = 10 * time.Second
	}

	if config.ClientMetadataFetchTimeout > 0 && config.ClientMetadataFetchTimeout < minTimeout {
		logger.Warn("CONFIGURATION WARNING: ClientMetadataFetchTimeout is very short",
			"value", config.ClientMetadataFetchTimeout,
			"minimum_recommended", minTimeout,
			"risk", "Metadata fetches may timeout prematurely for slow servers",
			"recommendation", fmt.Sprintf("Set ClientMetadataFetchTimeout to at least %v", minTimeout))
	}

	if config.ClientMetadataFetchTimeout > maxTimeout {
		logger.Warn("CONFIGURATION WARNING: ClientMetadataFetchTimeout is very long",
			"value", config.ClientMetadataFetchTimeout,
			"maximum_recommended", maxTimeout,
			"risk", "Slow or malicious servers may cause connection hangs",
			"recommendation", fmt.Sprintf("Set ClientMetadataFetchTimeout to at most %v", maxTimeout))
	}
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
		validateResourceMetadataPathConfig(pathKey, pathConfig, logger)
	}

	logger.Debug("ResourceMetadataByPath configuration validated",
		"paths_configured", len(config.ResourceMetadataByPath))
}

// validateResourceMetadataPathConfig validates a single resource metadata path configuration.
func validateResourceMetadataPathConfig(pathKey string, pathConfig ProtectedResourceConfig, logger *slog.Logger) {
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
