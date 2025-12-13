package server

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
)

// validateCORSConfig validates CORS configuration for security and correctness.
// This is called during server initialization to catch configuration errors early.
//
// Validates:
//   - Wildcard origin requires explicit opt-in (security)
//   - Wildcard cannot be used with credentials (CORS spec)
//   - Origins must be valid URLs with scheme and host
//   - HTTPS required in production (unless AllowInsecureHTTP)
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
		validateCORSOrigin(origin, config, logger)
	}

	logger.Debug("CORS configuration validated",
		"allowed_origins_count", len(config.CORS.AllowedOrigins),
		"allow_credentials", config.CORS.AllowCredentials,
		"max_age", config.CORS.MaxAge)
}

// validateCORSOrigin validates a single CORS origin for security and correctness.
func validateCORSOrigin(origin string, config *Config, logger *slog.Logger) {
	// SECURITY: Wildcard requires explicit opt-in via AllowWildcardOrigin
	// This ensures operators consciously accept the security implications
	if origin == "*" {
		if !config.CORS.AllowWildcardOrigin {
			panic("CORS: wildcard origin '*' requires AllowWildcardOrigin=true to be explicitly set. " +
				"This allows ANY website to make cross-origin requests to your OAuth server. " +
				"Set AllowWildcardOrigin=true only if you understand the security implications, " +
				"or use specific origins (e.g., https://app.example.com) instead.")
		}
		logger.Warn("CORS: Wildcard origin (*) enabled via AllowWildcardOrigin=true",
			"risk", "Allows ANY website to make requests to this server",
			"security_impact", "Increased CSRF attack surface",
			"recommendation", "Use specific origins (e.g., https://app.example.com) in production")
		return
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
		logger.Warn("CORS: HTTP origin allowed for localhost/development",
			"origin", origin,
			"recommendation", "Use HTTPS origins in production")
	}
}
