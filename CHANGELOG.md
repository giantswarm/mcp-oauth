# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **CORS (Cross-Origin Resource Sharing) support for browser-based clients (#28)**
  - Added `CORSConfig` to server configuration with `AllowedOrigins`, `AllowCredentials`, and `MaxAge` settings
  - Implemented `setCORSHeaders()` method to apply CORS headers to all HTTP responses
  - Added `isAllowedOrigin()` helper for origin validation with exact matching
  - Implemented `ServePreflightRequest()` handler for OPTIONS preflight requests
  - CORS headers automatically applied to all OAuth endpoints:
    - Authorization server metadata, protected resource metadata
    - Authorization, callback, token endpoints
    - Token revocation, client registration, token introspection
  - Features:
    - Opt-in by default (disabled when `AllowedOrigins` is empty) for backward compatibility
    - Support for multiple allowed origins with exact matching (case-sensitive)
    - Wildcard `*` support with security warning for development
    - Configurable credentials support for OAuth flows
    - Configurable preflight cache duration
  - Security considerations:
    - Only echoes back allowed origins (no arbitrary reflection)
    - Logs security warning when wildcard `*` is used
    - Respects CORS specification for credentials and preflight requests
  - Comprehensive test coverage:
    - CORS disabled by default
    - Allowed/disallowed origin validation
    - Wildcard origin support
    - Preflight request handling
    - Credentials configuration
    - Custom max age
  - **Impact**: No breaking changes - CORS is opt-in and disabled by default
  - **Documentation**: Added CORS configuration guide to README with security best practices
  - **Example**: Updated production example with commented CORS configuration

- **Proactive token refresh during validation to prevent expiry failures (#27)**
  - Added `TokenRefreshThreshold` configuration (default: 300 seconds = 5 minutes)
  - `ValidateToken()` now checks if provider token will expire within threshold
  - Automatically refreshes token with provider if refresh token is available
  - Graceful fallback: continues with validation if refresh fails (no user-facing error)
  - Benefits:
    - Improved UX: prevents "token expired" errors when refresh is possible
    - Reduces failed validation attempts and provider API calls
    - Configurable threshold for different deployment scenarios
  - Comprehensive test coverage:
    - Proactive refresh when token near expiry (multiple time windows)
    - Graceful fallback when refresh fails
    - Custom threshold configuration (1 min, 5 min, 10 min, 15 min)
    - No refresh when threshold not reached or refresh token unavailable
  - Audit logging for refresh events (`token_proactively_refreshed`, `proactive_refresh_failed`)
  - **Impact**: No breaking changes - backward compatible, opt-in via configuration
  - **Performance**: Reduces provider API errors and improves token validation reliability

### Changed

- **Refactored proactive refresh implementation for better maintainability**
  - Extracted nested refresh logic into dedicated helper functions (`shouldProactivelyRefresh`, `attemptProactiveRefresh`)
  - Improved test isolation by moving mock setup into per-test closures
  - Added descriptive test constants for better code clarity
  - **Impact**: Internal refactoring only - no functional changes or breaking changes
  - **Benefit**: Reduced cyclomatic complexity, improved testability and code readability

### Security

- **Implemented LRU eviction in rate limiter to prevent memory exhaustion (#23)**
  - Added configurable `MaxEntries` limit (default: 10,000 unique identifiers)
  - Implemented LRU (Least Recently Used) eviction strategy using `container/list`
  - When limit reached, automatically evicts least recently used entries
  - Added `NewRateLimiterWithConfig()` for custom max entries configuration
  - Added `GetStats()` method for monitoring:
    - `CurrentEntries`: Number of tracked identifiers
    - `MaxEntries`: Configured limit (0 = unlimited)
    - `TotalEvictions`: Number of LRU evictions performed
    - `TotalCleanups`: Number of cleanup operations completed
    - `MemoryPressure`: Percentage of max capacity used (0-100)
  - Enhanced cleanup to maintain consistency between map and LRU list
  - Added comprehensive test suite covering:
    - Max entries enforcement
    - LRU eviction order correctness
    - Concurrent access with eviction
    - Memory bounds under high load (500+ unique identifiers)
    - Unlimited mode (maxEntries = 0) for backward compatibility
    - Stats reporting accuracy
  - Added benchmarks for large-scale usage (10k+ entries)
  - Created security package documentation (doc.go) with:
    - Memory management behavior explanation
    - Monitoring and alerting guidelines
    - Security considerations and best practices
    - Example usage patterns
  - **Impact**: No breaking changes - backward compatible with safe defaults
  - **Security**: Prevents memory exhaustion from distributed attacks while maintaining rate limiting effectiveness
- **Added client-specific scope validation to prevent scope escalation attacks (#26)**
  - Implemented `validateClientScopes()` to validate requested scopes against client's allowed scopes
  - Validation occurs at TWO points for defense-in-depth:
    1. Authorization flow start - early rejection of unauthorized scope requests
    2. Token exchange - final validation before issuing tokens (prevents bypasses)
  - Clients with empty/nil `Scopes` field allow all scopes (backward compatibility)
  - Clients with non-empty `Scopes` field are restricted to their allowed scopes only
  - **Security hardening**: Fully generic error messages prevent scope enumeration attacks
    - Error messages do NOT reveal specific unauthorized scope names
    - Prevents attackers from fingerprinting allowed scopes
    - Consistent with RFC 6749 and OAuth 2.0 Security Best Practices
  - Comprehensive audit logging for security monitoring:
    - `scope_escalation_attempt` events (high severity) for unauthorized scope requests
    - `scope_validation_failed` events for tracking validation failures
    - Detailed event metadata for incident response and forensics
  - Added security monitoring documentation in SECURITY.md:
    - Alert thresholds and recommended response procedures
    - Example queries for log aggregation systems (Prometheus, ELK)
    - Guidance on extracting metrics from audit logs
    - Custom metrics collector implementation examples
  - Added comprehensive test suite covering:
    - Single and multiple scope validation
    - Scope escalation attempts
    - Unauthorized scope detection
    - Backward compatibility with unrestricted clients
    - Integration tests for authorization flow and token exchange
    - Security scenario testing (read-only client escalation, admin attempts)
  - **Impact**: No breaking changes - enhanced OAuth 2.0 security
  - **Security**: Prevents compromised clients from obtaining tokens with unauthorized scopes
- **Added local token expiry validation before provider check (#24)**
  - `ValidateToken` now checks token expiry locally before calling provider
  - Prevents expired tokens from being accepted if provider's clock is skewed
  - Respects `ClockSkewGracePeriod` configuration (default 5 seconds)
  - Defense in depth: checks expiry locally before external API call
  - Falls back to provider validation if token not found locally
  - Added comprehensive test suite for expiry validation and clock skew scenarios
  - **Impact**: No breaking changes - enhanced security validation
- **Implemented explicit entropy validation for token generation (#21)**
  - Replaced `oauth2.GenerateVerifier()` with `crypto/rand` for better control
  - Generates 32 bytes (256 bits) of cryptographically secure entropy
  - Base64url encoding produces 43-character tokens (RFC 4648)
  - Panics on RNG failure to prevent weak token generation
  - Affects all security-critical tokens (auth codes, access/refresh tokens, state values, client credentials)
  - Added comprehensive test suite and benchmarks
  - **Impact**: No breaking changes - same format, improved security guarantee
- **Fixed timing attack vulnerability in state parameter validation (#19)**
  - Added minimum length validation (32 characters) for state parameters
  - State validation now enforces sufficient entropy for CSRF protection
  - Constant-time comparison already in place for state value validation
  - Added comprehensive tests for timing attack resistance
  - Updated all tests to use secure state parameters
  - Refactored validation logic to follow DRY principle and architectural patterns
  - State validation now centralized in server layer with handler doing input validation
  - Added compile-time test to ensure constant synchronization between packages
  - **Impact**: Short state parameters (< 32 chars) are now rejected
  - **Migration**: Ensure client applications generate state parameters with at least 32 characters
- **[BREAKING]** Added runtime HTTPS enforcement for OAuth server (#18, #49)
  - New `AllowInsecureHTTP` config flag (default: `false`)
  - Production deployments now require HTTPS by default
  - HTTP allowed only on localhost (127.0.0.0/8, ::1, 0.0.0.0) for development
  - Non-localhost HTTP deployments blocked unless explicitly allowed
  - Clear error messages guide developers to secure configuration
  - OAuth 2.1 compliance: HTTPS required for all production endpoints
  - **Migration**: 
    - For localhost development: Add `AllowInsecureHTTP: true` to suppress warnings
    - For production HTTP (not recommended): Add `AllowInsecureHTTP: true` and review security risks
    - **Recommended**: Switch to HTTPS for all environments
- **Enforced mandatory PKCE for public clients to prevent authorization code theft (#22)**
  - Public clients (mobile apps, SPAs) now MUST use PKCE per OAuth 2.1 specification by default
  - Authorization code exchange fails for public clients without PKCE (secure by default)
  - Confidential clients can still optionally use PKCE (backward compatible)
  - Prevents authorization code interception attacks on public clients
  - Added comprehensive security event logging for PKCE enforcement failures
  - Added extensive test coverage for public and confidential client scenarios
  - **New Config Option**: `AllowPublicClientsWithoutPKCE` (default: `false`)
    - Set to `true` to allow legacy public clients without PKCE support
    - **WARNING**: Enabling this creates authorization code theft vulnerability
    - Only use for backward compatibility with unmaintained legacy clients
    - Logs warning events when public clients authenticate without PKCE
  - **Impact**: Public clients without PKCE will receive `invalid_grant` error by default
  - **Migration**: Ensure all public clients (mobile apps, SPAs) implement PKCE with S256 method
  - **Legacy Compatibility**: Set `AllowPublicClientsWithoutPKCE: true` if you cannot update legacy clients
  - **Security Rationale**: Public clients cannot securely store credentials, making PKCE essential for binding authorization codes to specific client instances

### Added
- Initial open-source release
- Comprehensive README with usage examples
- Apache 2.0 LICENSE
- CONTRIBUTING.md with development guidelines
- SECURITY.md with security policy
- Example applications in `examples/` directory
- GitHub workflows for CI/CD
- Issue and PR templates

## [1.0.0] - 2025-11-23

### Added
- OAuth 2.1 Authorization Server implementation (proxying to Google)
- OAuth 2.1 Resource Server implementation (token validation)
- Protected Resource Metadata (RFC 9728)
- Authorization Server Metadata (RFC 8414)
- Dynamic Client Registration (RFC 7591)
- Token Revocation (RFC 7009)
- PKCE support with S256 method enforcement
- Token encryption at rest with AES-256-GCM
- Refresh token rotation with reuse detection
- Comprehensive audit logging with sensitive data hashing
- Rate limiting (per-IP and per-user)
- Client type validation (public vs confidential)
- Google OAuth integration for Gmail, Drive, Calendar, etc.
- Cryptographically secure token generation
- HTTP middleware for token validation
- Custom HTTP client support
- Structured logging with slog
- Extensive test coverage
- Godoc documentation

### Security
- Enforces HTTPS in production (localhost exception for development)
- Disables plain PKCE method (S256 only)
- Hashes all sensitive data before logging (SHA-256)
- Validates redirect URIs with scheme restrictions
- Implements bcrypt for client secret hashing
- Adds clock skew grace period (5 seconds)
- Rate limiting to prevent DoS and brute force attacks
- Token expiration with automatic cleanup

## Release History

### Version Numbering

We use [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

### Supported Versions

| Version | Release Date | End of Life | Status |
|---------|--------------|-------------|--------|
| 1.0.x   | 2025-11-23   | TBD         | Active |

### Upgrade Guide

#### From Pre-1.0 to 1.0

This is the first stable release.

If upgrading from internal/unreleased versions:

1. Update import path to `github.com/giantswarm/mcp-oauth`
2. Review security configuration (defaults are now secure by default)
3. Enable token encryption for production deployments
4. Review rate limiting configuration
5. Update to new structured Config type
6. Check audit log integration

### Migration Notes

#### Breaking Changes in 1.0

N/A - First release

### Future Roadmap

Planned features for future releases:

- [ ] Support for additional OAuth providers (GitHub, Microsoft, etc.)
- [ ] Token introspection endpoint (RFC 7662)
- [ ] Device authorization grant (RFC 8628)
- [ ] JWT access tokens (RFC 9068)
- [ ] Persistent storage adapters (Redis, PostgreSQL, etc.)
- [ ] Metrics and observability improvements
- [ ] OpenTelemetry integration
- [ ] mTLS client authentication
- [ ] DPoP (RFC 9449) support
- [ ] FAPI 2.0 compliance

### Deprecation Policy

We maintain backwards compatibility within major versions. Deprecated features:

1. **Announcement**: Marked as deprecated in release notes and godoc
2. **Grace Period**: Supported for at least 2 minor versions
3. **Removal**: Only in next major version

Currently deprecated features: None

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

## License

This project is licensed under the Apache License 2.0 - see [LICENSE](LICENSE) for details.

