# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **RFC 8707 Resource Parameter for Token Audience Binding (MCP 2025-11-25)**
  - **Feature**: Implemented RFC 8707 Resource Indicators to bind access tokens to their intended resource server
  - **MCP Compliance**: MUST requirement for MCP 2025-11-25 specification
  - **Security**: Prevents token theft and replay attacks across different resource servers
  - **Implementation**:
    - Authorization endpoint accepts `resource` parameter to specify target resource server
    - Token endpoint accepts `resource` parameter and validates consistency with authorization code
    - Audience validation ensures tokens are only accepted by their intended resource server
    - Resource binding stored with authorization codes and tokens
  - **Configuration**: New `ResourceIdentifier` field in `server.Config` (defaults to `Issuer` if not set)
  - **Backward Compatibility**: Resource parameter is optional to maintain compatibility with existing clients
  - **Storage Changes**: 
    - Added `Resource` field to `storage.AuthorizationState`
    - Added `Resource` and `Audience` fields to `storage.AuthorizationCode`
  - **Validation**: Resource must be absolute HTTPS URI (or HTTP for localhost development)
  - **Audit Events**: New `EventResourceMismatch` for resource parameter validation failures
  - **Testing**: All existing tests updated, maintains 80%+ coverage

### Security

- **Scope string deep copy in Google provider to prevent race conditions**
  - **Problem**: Provider was using shallow copy when passing scopes to oauth2.Config, potentially allowing concurrent modifications to shared slice references
  - **Risk**: Low risk in current implementation (scopes only set at initialization), but future code changes could introduce race conditions
  - **Solution**: Implemented deep copy of scope slices to eliminate shared references
  - **Impact**: Prevents potential data races and unexpected scope modifications in concurrent scenarios
  - **Testing**: Added comprehensive test coverage for deep copy safety and concurrent modification scenarios

- **Scope string length validation to prevent DoS attacks**
  - **Problem**: No limit on scope parameter length could allow DoS attacks via extremely long scope strings
  - **Risk**: Potential resource exhaustion through processing and validating arbitrarily long scope strings
  - **Solution**: 
    - Added `MaxScopeLength` configuration parameter (default: 1000 characters)
    - Scope length validated early in authorization flow before parsing/processing
    - Clear error messages when limit exceeded
  - **Impact**: Prevents potential DoS attacks while allowing legitimate use cases (1000 chars supports ~50+ typical scopes)
  - **Configuration**: `server.Config.MaxScopeLength` (default: 1000, automatically set if 0)
  - **Error**: Returns `invalid_scope` with clear message when limit exceeded
  - **Audit**: Scope length violations are logged via audit system
  - **Testing**: Added tests for boundary conditions (at limit, exceeds limit, empty scopes)

### Fixed

- **OAuth callback now properly passes client-requested scopes to Google provider (#82)**
  - **Problem**: Scopes from client authorization requests were not being passed to Google during provider authorization redirect
  - **Impact**: Google returned tokens without user info (no scopes = no permissions = no data), causing userID extraction to fail and token storage to fail with "userID cannot be empty" errors
  - **Root Cause**: The Provider interface's `AuthorizationURL` method didn't accept scopes parameter, so only provider's hardcoded scopes were used
  - **Solution**: 
    - Modified `Provider.AuthorizationURL()` interface to accept `scopes []string` parameter
    - Updated Google provider to use client-requested scopes when provided, falling back to configured defaults when empty
    - Updated server flows to parse and pass client scopes to provider
  - **Breaking Change**: 🔴 **YES** - Provider interface method signature changed
    - **Before**: `AuthorizationURL(state, codeChallenge, codeChallengeMethod string) string`
    - **After**: `AuthorizationURL(state, codeChallenge, codeChallengeMethod string, scopes []string) string`
    - **Migration**: Add `scopes` parameter to any custom provider implementations
  - **Behavior**:
    - When client provides scopes in authorization request → those scopes are used
    - When client provides no scopes → provider's configured default scopes are used
    - Empty scopes array → provider defaults used
  - **Testing**: Added comprehensive tests for dynamic scope behavior

- **WWW-Authenticate metadata now defaults to enabled (secure by default)**
  - **Problem**: Field naming made it unclear whether metadata was enabled or disabled by default
  - **Impact**: Initial implementation had confusing semantics around defaults
  - **Solution**: Renamed to `DisableWWWAuthenticateMetadata` following the library's "secure by default" principle
  - **Field change**: `EnableWWWAuthenticateMetadata` → `DisableWWWAuthenticateMetadata` (inverted logic)
  - **Default behavior**: 
    - `DisableWWWAuthenticateMetadata: false` (default) → Full metadata ENABLED (secure by default)
    - `DisableWWWAuthenticateMetadata: true` → Minimal headers for backward compatibility
  - **Breaking Change**: 🔴 **YES** - Field renamed for clarity
    - **Before**: `config.EnableWWWAuthenticateMetadata = false` to disable
    - **After**: `config.DisableWWWAuthenticateMetadata = true` to disable
    - **Migration**: Replace field name and invert boolean value
  - **Why this matters**:
    - Clear naming: "Disable" prefix indicates opt-out, not opt-in
    - Consistent with library philosophy: secure by default
    - MCP 2025-11-25 compliance out of the box
    - Modern OAuth clients ignore unknown header parameters (safe for most clients)
  - **Configuration changes**:
    - Renamed field for clarity
    - Added security warning log when feature is disabled
    - Removed confusing default-forcing logic (zero value = enabled)
  - **Testing**: All existing tests updated to use new field name

- **Dynamic Client Registration (DCR) now respects `token_endpoint_auth_method` parameter (#70)**
  - **Problem**: DCR always created confidential clients with secrets, even when native/CLI apps requested public clients
  - **Solution**: Implement OAuth 2.1 / RFC 7591 compliant DCR that respects the `token_endpoint_auth_method` field
  - **Key Changes**:
    - When `token_endpoint_auth_method: "none"` is requested, creates a public client (no secret)
    - When `token_endpoint_auth_method: "client_secret_basic"` or `"client_secret_post"`, creates a confidential client (with secret)
    - Auth method parameter overrides client_type when both are provided
    - Added validation to reject unsupported auth methods
  - **Security Enhancements**:
    - Public clients still require PKCE for all flows (OAuth 2.1 compliance)
    - **CRITICAL**: Added enforcement of `AllowPublicClientRegistration` policy for public client creation
    - Public client registration is now denied when `AllowPublicClientRegistration=false`, even with valid registration token
    - Reduced information leakage in auth method error messages (supported methods not revealed in error responses)
    - Comprehensive audit logging for public client registration attempts
  - **Configuration Clarification**:
    - `AllowPublicClientRegistration` now explicitly controls TWO aspects:
      1. DCR endpoint authentication (whether Bearer token is required)
      2. Public client creation (whether clients with `token_endpoint_auth_method="none"` can be registered)
    - Updated documentation to clearly explain secure vs. permissive configurations
  - **Use Case**: Enables native applications (like mcp-debug) to properly register as public clients
  - **Testing**: Added comprehensive unit and integration tests for all auth method combinations and policy enforcement
  - **Constants**: Added `TokenEndpointAuthMethod*` constants for type safety

### Added

- **MCP 2025-11-25: WWW-Authenticate header with resource_metadata for discovery (#73)**
  - Implemented MCP 2025-11-25 specification requirement for Protected Resource Metadata discovery
  - **What changed**: All 401 Unauthorized responses now include enhanced WWW-Authenticate headers
  - **Header format** (per RFC 6750 and RFC 9728):
    ```http
    WWW-Authenticate: Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource",
                             scope="files:read user:profile",
                             error="invalid_token",
                             error_description="Token has expired"
    ```
  - **Discovery mechanism**: Helps MCP clients automatically discover:
    - Authorization server location via `resource_metadata` URL
    - Required scopes via optional `scope` parameter
    - Error details for debugging and retry logic
  - **Configuration**:
    - `DefaultChallengeScopes`: Configure default scopes to include in WWW-Authenticate challenges
    - Example: `config.DefaultChallengeScopes = []string{"mcp:access", "files:read"}`
    - `DisableWWWAuthenticateMetadata`: Opt-out flag for backward compatibility (default: false = enabled)
  - **Backward compatibility**:
    - Feature enabled by default for MCP 2025-11-25 compliance (secure by default)
    - Can be disabled for legacy clients: `config.DisableWWWAuthenticateMetadata = true`
    - When disabled, returns minimal `WWW-Authenticate: Bearer` header
    - Standard HTTP behavior: clients ignore headers they don't understand
    - No breaking changes to existing client implementations
  - **Automatic behavior**:
    - All existing 401 responses automatically get proper WWW-Authenticate headers
    - No code changes needed in existing handlers
    - Scope parameter only included if configured (optional)
  - **Specification compliance**:
    - MCP 2025-11-25: MUST include resource_metadata in WWW-Authenticate (✓)
    - RFC 6750 Section 3: Bearer token challenge format (✓)
    - RFC 9728: Protected Resource Metadata discovery (✓)
  - **Security improvements**:
    - Enhanced escaping in error descriptions: properly handles backslashes and quotes
    - Follows RFC 2616/7230 quoted-string rules for HTTP header values
    - Prevents header injection from malformed error messages
  - **Code quality improvements**:
    - Extracted repeated test strings to constants (DRY principle)
    - Added edge case tests for long scope lists and special characters
    - Improved test maintainability with test helper constants
  - **Testing**: Comprehensive unit tests for header formatting, integration, backward compatibility mode, and security edge cases (100% coverage)
  - **Configuration validation** (security hardening):
    - Validates `DefaultChallengeScopes` for invalid characters (quotes, commas, backslashes)
    - Warns when scope count exceeds 50 (HTTP header size limit protection)
    - Defense-in-depth: validation complements existing escaping
    - Comprehensive test coverage for validation edge cases
  - **Documentation**:
    - Added security considerations section to README
    - Documents information disclosure policy (intentional per OAuth specs)
    - Guidance on scope configuration best practices
    - Clear warnings about header size limits

- **OAuth 2.1 PKCE for provider leg - Enhanced security for confidential clients (#68)**
  - Implemented full OAuth 2.1 PKCE support on the OAuth server → Provider leg
  - **Why this matters**: OAuth 2.1 recommends PKCE for ALL client types (public AND confidential) to protect against Authorization Code Injection attacks
  - **Two-layer PKCE architecture**:
    1. MCP client → OAuth server: Uses client-provided PKCE (already working)
    2. OAuth server → Google: Now uses server-generated PKCE (NEW)
  - **Security benefits**:
    - Defense-in-depth against Authorization Code Injection
    - Cryptographic binding between authorization and token exchange
    - Protection even if state parameter is compromised
    - OAuth 2.1 compliance for confidential client security
  - **Implementation details**:
    - Added `ProviderCodeVerifier` field to `AuthorizationState`
    - Server generates independent PKCE pair for provider communication
    - Google provider now accepts and validates PKCE parameters
    - Both client_secret AND PKCE provide layered security
  - **Testing**: Updated provider and integration tests to verify PKCE flow
  - **Documentation**: Added `SECURITY_ARCHITECTURE.md` explaining the security model

- **Comprehensive security architecture documentation**
  - New `SECURITY_ARCHITECTURE.md` document explaining:
    - Two-layer authentication architecture (MCP client ↔ OAuth server ↔ Provider)
    - PKCE implementation at both layers with security rationale
    - Dual-layer state protection strategy
    - Attack mitigation strategies (code injection, CSRF, timing attacks, etc.)
    - Production deployment security checklist
    - Monitoring and auditing best practices
  - Detailed threat model analysis
  - References to OAuth 2.1 and RFC 7636 specifications

### Fixed

- **Google provider OAuth flow now fully OAuth 2.1 compliant (#68)**
  - Fixed: "Missing code verifier" errors when using Google OAuth
  - Root cause: Provider was forwarding MCP client's PKCE to Google without corresponding verifier
  - Solution: Implemented proper two-layer PKCE where server generates its own PKCE for provider leg
  - Impact: Fixes complete OAuth flow failure while enhancing security beyond original implementation
  - Migration: No breaking changes - PKCE is generated and handled automatically

### Security

- **Typed storage errors for security-sensitive error handling**
  - Added sentinel errors (`ErrTokenNotFound`, `ErrTokenExpired`, `ErrClientNotFound`, `ErrAuthorizationCodeNotFound`, `ErrAuthorizationCodeUsed`, `ErrAuthorizationStateNotFound`) to distinguish transient errors from security events
  - Added helper functions `IsNotFoundError()`, `IsExpiredError()`, `IsCodeReuseError()` for consistent error type checking
  - Enables proper detection of token reuse attacks without false positives from transient storage failures

- **CORS wildcard origin now requires explicit opt-in**
  - New `AllowWildcardOrigin` field must be set to `true` to use `"*"` in `AllowedOrigins`
  - Prevents accidental CSRF exposure in production deployments
  - Configuration will panic with clear instructions if wildcard is used without opt-in

- **Constant-time comparison for registration access token**
  - Uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks on the registration endpoint
  - Attackers cannot guess the token character by character through response time analysis

- **MinStateLength floor enforcement**
  - Absolute minimum of 16 characters enforced regardless of configuration
  - Ensures adequate CSRF protection entropy even if misconfigured
  - Logs warning when configured value is below the floor

- **Enhanced SECURITY.md documentation**
  - Added production logging configuration guidance (disable DEBUG in production)
  - Added security-sensitive log entries reference table
  - Extended production deployment checklist with logging, CORS, and state length checks

### Changed

- **OpenTelemetry instrumentation infrastructure for comprehensive observability (#37)**
  - Added new `instrumentation` package providing metrics, traces, and logging integration
  - Features:
    - Metrics: Counters, histograms, and gauges for all OAuth operations
    - Traces: Distributed tracing spans for request flows across components
    - Structured logging integration with trace context
    - Zero overhead when disabled (uses no-op providers)
    - Thread-safe concurrent access
    - Graceful shutdown handling
  - Configuration:
    - Added `InstrumentationConfig` to server configuration
    - Opt-in via `Enabled` flag (default: false)
    - Configurable service name and version
  - Metrics provided:
    - HTTP layer: requests, duration
    - OAuth flows: authorization, callback, code exchange, token refresh/revocation, client registration
    - Security: rate limits, PKCE validation, code/token reuse detection
    - Storage: operation counts, duration, size
    - Provider: API calls, duration, errors
    - Audit events, encryption operations
  - Integration:
    - Server automatically initializes instrumentation when enabled
    - Shutdown integrates with server graceful shutdown
    - Ready for layer-by-layer adoption in future PRs
  - Testing:
    - 83% test coverage on instrumentation package
    - Concurrent access tests
    - No-op provider verification
    - Metric recording correctness
    - Span lifecycle management
  - **Security & Privacy:**
    - Comprehensive security warnings against logging sensitive credentials
    - GDPR/privacy compliance documentation
    - Clear guidance on data collection and retention policies
    - Reserved attribute constants to prevent credential leakage
    - Security-reviewed implementation with no sensitive data logging
  - **Impact**: No breaking changes - instrumentation is opt-in and disabled by default
  - **Future work**: Layer-by-layer instrumentation adoption (HTTP, storage, provider, security)
  - **Documentation**: Comprehensive package documentation with security best practices

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

### Fixed

- **Added registration_endpoint to OAuth Authorization Server Metadata (#66)**
  - Fixed missing `registration_endpoint` field in `/.well-known/oauth-authorization-server` response
  - OAuth clients can now automatically discover Dynamic Client Registration endpoint via RFC 8414 metadata
  - The `/oauth/register` endpoint was working but not advertised in metadata
  - **Conditional Advertising**: Field is only included when client registration is actually available
    - Included when `RegistrationAccessToken` is set OR `AllowPublicClientRegistration=true`
    - Excluded when neither is configured (defense-in-depth)
  - **Impact**: Enables automatic client discovery for RFC 8414-compliant OAuth clients
  - **Standards**: Complies with RFC 8414 Section 3.1 requirement for `registration_endpoint` field
  - **Security**: Added comprehensive documentation explaining metadata security model
  - **Testing**: Enhanced metadata tests to verify conditional inclusion/exclusion behavior

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

