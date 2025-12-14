# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Client ID Metadata Documents (CIMD) Documentation and Example**
  - **Feature**: Comprehensive documentation and example for Client ID Metadata Documents support
  - **Documentation**: New `docs/cimd.md` with complete reference covering:
    - What CIMD is and when to use it
    - Configuration options (`EnableClientIDMetadataDocuments`, `ClientMetadataFetchTimeout`, `ClientMetadataCacheTTL`)
    - Client metadata document format and field reference
    - How the authorization flow works with CIMD
    - Security features (SSRF protection, negative caching, rate limiting)
    - Caching behavior and troubleshooting guide
  - **Example**: New `examples/cimd/` directory with:
    - Complete server implementation with CIMD enabled
    - Sample `client.json` metadata document
    - Detailed README with setup and usage instructions
  - **README Updates**: Added CIMD to main README features, documentation table, and examples list
  - **Issue**: [#145](https://github.com/giantswarm/mcp-oauth/issues/145)

- **Trusted Public Registration Schemes (Cursor/IDE Compatibility)**
  - **Feature**: Allow unauthenticated client registration for clients using trusted custom URI schemes (`cursor://`, `vscode://`, etc.)
  - **Use Case**: MCP clients like Cursor that don't support registration tokens can now register without authentication when using custom URI schemes
  - **Security**: Two-layer protection: PKCE (primary defense) + custom URI scheme OS-level registration
  - **Configuration**:
    - `TrustedPublicRegistrationSchemes`: List of schemes allowed for token-free registration (e.g., `["cursor", "vscode"]`)
    - `DisableStrictSchemeMatching`: Explicit opt-out for mixed scheme support (not recommended); strict matching is enabled by default
  - **Security Hardening**:
    - HTTP/HTTPS schemes are automatically blocked from trusted schemes (they can be hijacked by any attacker with a web server)
    - Dangerous schemes (`javascript:`, `data:`, `file:`, etc.) are automatically filtered out
    - Pre-computed trusted schemes map for O(1) lookup performance
    - Documentation clarifies that PKCE is the primary security control, with platform-specific scheme protection as defense-in-depth
  - **Audit Logging**: New event type `client_registered_via_trusted_scheme` for security monitoring
  - **Documentation**: Updated security guide with Cursor compatibility section and platform security considerations
  - **Issue**: [#141](https://github.com/giantswarm/mcp-oauth/issues/141)

### Fixed

- **CIMD: Authorization flow now uses getOrFetchClient**
  - **Bug**: URL-based client IDs were not working in authorization flow because `StartAuthorizationFlow` and `ExchangeAuthorizationCode` used direct `clientStore.GetClient()` instead of `getOrFetchClient()` ([#143](https://github.com/giantswarm/mcp-oauth/issues/143))
  - **Root Cause**: When `EnableClientIDMetadataDocuments` was enabled, the authorization flow bypassed the CIMD-aware client lookup function
  - **Fix**: Changed `clientStore.GetClient()` to `getOrFetchClient()` in `flows.go` at lines 338 and 705
  - **Impact**: MCP clients using URL-based client IDs per MCP 2025-11-25 spec now work correctly in the full OAuth flow
  - **Testing**: Added unit tests for `getOrFetchClient` behavior with non-URL clients, CIMD disabled, cache hits, and negative cache hits

- **Token Encryption Preserves Extra Field**
  - **Bug**: Token encryption was losing the `Extra` field (`id_token`, `scope`) from `oauth2.Token`, breaking downstream OIDC authentication ([#133](https://github.com/giantswarm/mcp-oauth/issues/133))
  - **Root Cause**: `encryptToken()` and `decryptToken()` created new tokens without copying the private `raw` field
  - **Fix**: Extract known extra fields (`id_token`, `scope`, `expires_in`) before encryption and restore them using `WithExtra()` after encryption/decryption
  - **Affected Components**: `storage/memory/memory.go`, `storage/valkey/store.go`
  - **Testing**: Added regression tests for Extra field preservation with and without encryption enabled

### Security

- **ID Token Encryption at Rest**
  - **Enhancement**: The `id_token` is now encrypted at rest when token encryption is enabled
  - **Rationale**: The `id_token` contains PII (user email, name, subject) that should be protected
  - **Implementation**: Added `SensitiveExtraFields` allowlist in `storage/token.go` with `EncryptExtraFields()` and `DecryptExtraFields()` helpers
  - **Scope/Expires_in**: Non-sensitive fields like `scope` and `expires_in` are preserved but not encrypted

### Added

- **Valkey Storage Provider**
  - **Feature**: New distributed storage backend using Valkey (Redis-compatible) in `storage/valkey/`
  - **Use Case**: Production deployments requiring distributed storage, persistence, and horizontal scaling
  - **Interfaces**: Implements all storage interfaces (`TokenStore`, `ClientStore`, `FlowStore`, `RefreshTokenFamilyStore`, `TokenRevocationStore`)
  - **Key Schema**: Configurable prefix (default `mcp:`) for multi-tenant deployments
  - **Atomic Operations**: Lua scripts ensure atomicity for security-critical operations
    - `AtomicCheckAndMarkAuthCodeUsed`: Prevents authorization code replay attacks
    - `AtomicGetAndDeleteRefreshToken`: Prevents refresh token reuse attacks
  - **TTL Management**: Automatic TTL-based expiration for all keys
  - **TLS Support**: Optional TLS configuration for encrypted connections
  - **Security Features**:
    - Constant-time bcrypt comparison for client secret validation
    - Token family tracking for OAuth 2.1 reuse detection
    - Configurable revoked family retention for security forensics (default: 90 days)
    - Optional token encryption at rest via `SetEncryptor()` using AES-256-GCM
    - Input size validation to prevent DoS attacks (max token: 512 bytes, max ID: 256 bytes)
    - Generic error messages prevent information leakage (no client IDs or counts in errors)
  - **IP Rate Limiting**: Built-in DoS protection via IP-based client registration limits
  - **Documentation**: Comprehensive package documentation with usage examples
  - **Testing**: Skip-based tests for environments without Valkey available, concurrency tests for atomic operations

- **GitHub OAuth Provider with Organization Access Control**
  - **Feature**: New dedicated GitHub OAuth provider in `providers/github/`
  - **Use Case**: Direct GitHub authentication without requiring Dex or other OIDC proxies
  - **Scopes**: Default scopes `user:email` and `read:user` for profile and email access
  - **Organization Restriction**: Optional `AllowedOrganizations` config to restrict login to specific organizations
    - Automatically adds `read:org` scope when organizations are configured
    - Case-insensitive organization name matching
    - Users not in allowed organizations receive clear error (`ErrOrganizationRequired`)
  - **Email Handling**: Robust email retrieval with fallback to `/user/emails` endpoint for private emails
  - **PKCE Support**: Full OAuth 2.1 PKCE support for enhanced security
  - **Health Check**: Uses GitHub's `/rate_limit` endpoint for lightweight health monitoring
  - **Token Behavior**: Gracefully handles GitHub's non-expiring tokens (`ErrRefreshNotSupported`)
  - **Token Revocation**: Graceful degradation (returns nil) since GitHub lacks server-side revocation
  - **Helper Methods**: 
    - `GetUserOrganizations()` for listing user's organizations
    - `GetProviderToken()` for creating tokens for additional GitHub API calls
  - **Documentation**: Comprehensive `doc.go`, example application, and README with setup instructions
  - **Testing**: 87.2% test coverage with comprehensive unit tests
  - **Example**: New `examples/github/` demonstrating organization-based access control

## [0.2.0] - 2025-11-27

### Added

- **Multi-Tenant Authorization Server Discovery (MCP 2025-11-25)**
  - **Feature**: Automatic registration of multiple discovery endpoints for multi-tenant deployments
  - **Implementation**: New `RegisterAuthorizationServerMetadataRoutes()` method that detects path-based issuers
  - **Endpoints Registered**:
    - For single-tenant (no path): Standard OAuth and OIDC endpoints
    - For multi-tenant (path-based issuer like `https://auth.example.com/tenant1`):
      * OAuth path insertion: `/.well-known/oauth-authorization-server/tenant1`
      * OIDC path insertion: `/.well-known/openid-configuration/tenant1`
      * OIDC path appending: `/tenant1/.well-known/openid-configuration`
      * Standard endpoints (backward compatibility)
  - **Benefits**:
    - Supports complex multi-tenant architectures with path-based tenant isolation
    - Fully compliant with MCP 2025-11-25 discovery requirements
    - Automatic detection based on issuer configuration
    - Backward compatible with existing deployments
  - **Testing**: Comprehensive test coverage for single-tenant, multi-tenant, and nested path scenarios
  - **Examples**: All examples updated to use new registration method
  - **Use Case**: Enterprise deployments with multiple tenants using path-based issuer URLs

- **CIMD Negative Caching for Failed Metadata Fetches**
  - **Feature**: Cache failed Client ID Metadata Document (CIMD) fetch attempts to prevent rapid retries
  - **Security**: Mitigates cache poisoning attacks by preventing attackers from repeatedly hammering the server with requests for known-bad client IDs
  - **Configuration**: Default TTL of 5 minutes for negative entries, separate from positive cache entries
  - **Backoff**: Repeated failures extend the negative cache TTL up to 2x the default (progressive backoff)
  - **Recovery**: Successful fetches automatically clear negative cache entries, allowing recovery after fixes
  - **Metrics**: New cache metrics for negative cache hits, cached entries, and evictions

### Changed

- **Increased Minimum State Parameter Length** (OAuth 2.1 Security)
  - **Change**: Raised the absolute minimum `MinStateLength` floor from 16 to 32 characters
  - **Rationale**: 32 characters provides 192 bits of entropy in base64, exceeding OAuth 2.1's recommended 128+ bits
  - **Security**: Provides sufficient margin for high-security deployments and better CSRF protection
  - **Backward Compatible**: Existing configurations with MinStateLength >= 32 are unaffected

- **Defense-in-Depth Scope Sanitization in WWW-Authenticate Headers**
  - **Change**: Added escaping of backslash and quote characters in scope parameter
  - **Rationale**: While RFC 6749 restricts scope to a limited character set, defense-in-depth escaping prevents potential header injection attacks
  - **RFC Compliance**: Follows RFC 2616/7230 quoted-string rules for HTTP headers

- **ContextWithUserInfo Function for Testing**
  - **Feature**: Export `ContextWithUserInfo` function to create contexts with user info for testing
  - **Problem Solved**: Library consumers couldn't write unit tests for code depending on authenticated user context because `userInfoKey` was unexported
  - **Usage**: `ctx := oauth.ContextWithUserInfo(context.Background(), &providers.UserInfo{ID: "user-123", Email: "test@example.com"})`
  - **Follows Go Patterns**: Similar to `grpc.NewContextWithServerTransportStream` and other standard library context setters
  - **Security**: Includes explicit warning in documentation that this function is for testing only and should not be used to bypass authentication in production

- **Sub-Path Protected Resource Metadata Discovery** (MCP 2025-11-25, RFC 9728)
  - **Feature**: Enable different protected resources on the same domain to advertise different authorization requirements
  - **New Configuration**: `ResourceMetadataByPath` in `server.Config` allows per-path metadata configuration
  - **ProtectedResourceConfig Type**: New configuration type with fields:
    * `ScopesSupported` - Path-specific scopes
    * `AuthorizationServers` - Path-specific authorization server URLs
    * `BearerMethodsSupported` - Path-specific bearer token methods
    * `ResourceIdentifier` - Path-specific resource identifier (RFC 8707)
  - **Path Matching**: Uses longest-prefix matching to find the most specific configuration
  - **Automatic Route Registration**: Paths configured in `ResourceMetadataByPath` are automatically registered as discovery endpoints
  - **Backward Compatible**: Root endpoint and explicit `mcpPath` registration continue to work as before
  - **Example Usage**:
    ```go
    config := &server.Config{
        Issuer: "https://auth.example.com",
        ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
            "/mcp/files": {ScopesSupported: []string{"files:read", "files:write"}},
            "/mcp/admin": {ScopesSupported: []string{"admin:access"}},
        },
    }
    // Registers:
    // - /.well-known/oauth-protected-resource (default metadata)
    // - /.well-known/oauth-protected-resource/mcp/files (files-specific metadata)
    // - /.well-known/oauth-protected-resource/mcp/admin (admin-specific metadata)
    ```
  - **Configuration Validation**: Path format, scope format, authorization server URLs, and bearer methods are validated at startup
  - **Tests**: Comprehensive unit tests for sub-path discovery, path matching, and route registration

- **Success Interstitial Page for Custom URL Schemes** (RFC 8252)
  - **Feature**: Serve an HTML "success interstitial" page instead of direct 302 redirects for custom URL schemes (`cursor://`, `vscode://`, `slack://`, etc.)
  - **Problem Solved**: Browsers often fail silently on 302 redirects to custom URL schemes, leaving users on a blank page with a spinning indicator even though authentication succeeded
  - **Solution**: Per RFC 8252 Section 7.1, native apps should handle the case where browsers cannot redirect to custom schemes. The new interstitial page:
    * Shows "Authorization Successful!" message confirming authentication worked
    * Attempts JavaScript redirect after ~500ms delay
    * Provides manual "Open [App Name]" button as fallback
    * Shows "You can close this window" instruction
  - **App Recognition**: Recognizes common MCP client applications and displays friendly names:
    * Cursor, Visual Studio Code, VSCodium, Slack, Notion, Obsidian
    * Discord, Figma, Linear, Raycast, Warp, Zed, Windsurf, and more
    * Unknown schemes show capitalized scheme name
  - **UX Design**: Modern, clean styling with success checkmark animation
  - **Security**: 
    * Uses `html/template` with proper escaping for XSS prevention
    * Hash-based Content-Security-Policy (CSP Level 2) for inline script allowlisting
    * Static inline script reads redirect URL from DOM to maintain stable SHA-256 hash
    * All standard security headers included (X-Frame-Options, X-Content-Type-Options, etc.)
  - **Backward Compatibility**: HTTP/HTTPS redirect URIs continue to use standard 302 redirects
  - **Tests**: Comprehensive unit tests for URL scheme detection, app name mapping, and interstitial rendering

- **Configurable Interstitial Page Branding**
  - **Feature**: Allow library users to customize the interstitial page with their own branding
  - **Configuration**: Three levels of customization via `server.InterstitialConfig`:
    * **Custom Handler**: Full control with `CustomHandler func(w http.ResponseWriter, r *http.Request)` - user is responsible for all security headers
    * **Custom Template**: Provide a custom HTML template via `CustomTemplate string` using Go's `html/template` syntax
    * **Branding Config**: Simple customization via `InterstitialBranding` struct for logo, colors, text, and CSS
  - **Branding Options** (`InterstitialBranding`):
    * `LogoURL` - Custom logo image URL (HTTPS required)
    * `LogoAlt` - Alt text for accessibility
    * `Title` - Custom page title
    * `Message` - Custom success message
    * `ButtonText` - Custom button text
    * `PrimaryColor` - CSS color for buttons/highlights
    * `BackgroundGradient` - CSS background value
    * `CustomCSS` - Additional CSS to inject
  - **Security Validation**:
    * Logo URLs validated to require HTTPS (unless `AllowInsecureHTTP` is set for development)
    * CSS values validated against injection attacks (expression(), javascript:, behavior:, etc.)
    * CustomCSS validated to prevent `</style>` tag injection
  - **Context Helpers**: For custom handlers, helper functions provide access to OAuth context:
    * `oauth.InterstitialRedirectURL(ctx)` - Get the redirect URL
    * `oauth.InterstitialAppName(ctx)` - Get the human-readable app name
  - **Tests**: Comprehensive tests for branding, custom template, custom handler, and security validation

- **Comprehensive MCP 2025-11-25 Documentation**
  - **Feature**: Complete documentation package for MCP 2025-11-25 specification compliance
  - **New Documentation**:
    - `docs/mcp-2025-11-25.md` - Comprehensive migration guide covering all new features:
      * Protected Resource Metadata Discovery (RFC 9728)
      * Enhanced WWW-Authenticate headers (RFC 6750)
      * Scope Selection Strategy
      * Resource Parameter (RFC 8707) for token audience binding
      * Client ID Metadata Documents
      * Insufficient Scope error handling
    - `docs/discovery.md` - Complete guide to OAuth discovery mechanisms:
      * Protected Resource Metadata endpoints
      * Authorization Server Metadata
      * WWW-Authenticate header discovery
      * Client ID Metadata Documents
      * Discovery flow examples and best practices
  - **Updated Documentation**:
    - `README.md`:
      * Added MCP Specification Compliance table showing support status
      * Added links to new documentation resources
      * Enhanced WWW-Authenticate section with references to detailed guides
      * Updated specification compliance references
    - `SECURITY_ARCHITECTURE.md`:
      * Added Resource Parameter Security section with token audience validation
      * Added Token Audience Validation section explaining OAuth 2.0 claims
      * Added WWW-Authenticate Information Disclosure security analysis
      * Updated References section with MCP 2025-11-25 and all relevant RFCs
      * Added links to new documentation resources
  - **Examples**:
    - `examples/mcp-2025-11-25/` - New comprehensive example demonstrating:
      * All MCP 2025-11-25 features configured
      * Endpoint-specific scope requirements
      * Method-specific scope requirements
      * Discovery endpoint setup
      * Complete testing instructions
      * Detailed README with testing scenarios
    - `examples/basic/main.go` - Enhanced with:
      * Detailed comments explaining discovery endpoints
      * MCP 2025-11-25 feature highlights
      * Discovery flow examples
  - **Migration Support**:
    - Backward compatibility notes (no breaking changes)
    - Step-by-step migration path from previous versions
    - Configuration examples for each new feature
    - Security considerations for new features
    - Testing and validation guidelines
  - **Compliance**: Full documentation coverage for MCP 2025-11-25 specification requirements
  - **Developer Experience**: Clear examples, migration guides, and best practices for adopting new features

- **Endpoint-Specific Scope Challenges in WWW-Authenticate Headers (MCP 2025-11-25)**
  - **Feature**: Implemented endpoint-specific scope guidance in WWW-Authenticate headers for 401 Unauthorized responses
  - **MCP Compliance**: Implements MCP 2025-11-25 scope selection strategy specification
  - **Use Case**: Helps clients discover exactly which scopes are required for specific endpoints, improving authorization UX
  - **Implementation**:
    - Added `getChallengeScopes()` helper that resolves scopes with priority: endpoint-specific → DefaultChallengeScopes → none
    - Added `writeUnauthorizedError()` method for 401 responses with endpoint-aware scope challenges
    - Updated `ValidateToken` middleware to use endpoint-specific scopes in WWW-Authenticate headers
    - Integrates seamlessly with existing `EndpointScopeRequirements` and `EndpointMethodScopeRequirements` configurations
  - **Scope Resolution Priority**:
    1. `EndpointMethodScopeRequirements` - method and path specific (e.g., POST /api/files/*)
    2. `EndpointScopeRequirements` - path specific (e.g., /api/files/*)
    3. `DefaultChallengeScopes` - configured fallback scopes
    4. No scope parameter if nothing configured
  - **Example**: When accessing `/api/files/test.txt` without auth, WWW-Authenticate header includes `scope="files:read files:write"` instead of generic default scopes
  - **Backward Compatibility**: Fully backward compatible - uses existing endpoint scope configuration, no breaking changes
  - **Testing**: Added comprehensive unit and integration tests (7 test scenarios, 3 test suites)
  - **Performance**: Minimal overhead - reuses existing scope resolution logic

- **Client ID Metadata Documents Support (draft-ietf-oauth-client-id-metadata-document, MCP 2025-11-25)**
  - **Feature**: Implemented URL-based client identifiers with automatic metadata fetching
  - **MCP Compliance**: SHOULD requirement for MCP 2025-11-25 specification
  - **Use Case**: Enables OAuth flows where servers and clients have no pre-existing relationship
  - **Implementation**:
    - URL detection: Automatically detects HTTPS URLs as client_id and fetches metadata
    - Metadata fetching: HTTP client with configurable timeout (default: 10s) and 1MB size limit
    - SSRF protection: Blocks private IP ranges (10.x, 172.16-31.x, 192.168.x), loopback, and link-local addresses
    - Caching: In-memory LRU cache with TTL support (default: 5 minutes) and HTTP Cache-Control respect
    - Validation: Ensures client_id in document matches URL exactly (security requirement)
    - Integration: Transparent integration with existing authorization flow via `GetClient()`
  - **Configuration**: 
    - `EnableClientIDMetadataDocuments` - Enable feature (default: false for backward compatibility)
    - `ClientMetadataFetchTimeout` - Timeout for metadata fetch (default: 10s)
    - `ClientMetadataCacheTTL` - Cache TTL (default: 5m)
  - **Discovery**: Authorization Server Metadata advertises support via `client_id_metadata_document_supported: true`
  - **Security**:
    - HTTPS-only enforcement for metadata URLs
    - Comprehensive SSRF protection against internal network access
    - Client_id validation prevents impersonation attacks
    - Localhost redirect URI warnings per spec recommendations
  - **Testing**: Comprehensive unit tests covering URL detection, SSRF protection, caching, and metadata validation
  - **Performance**: LRU cache with configurable size (default: 1000 entries) prevents memory exhaustion

- **Enhanced Protected Resource Metadata (RFC 9728, MCP 2025-11-25)**
  - **Feature**: Enhanced Protected Resource Metadata with `scopes_supported` field and sub-path discovery
  - **MCP Compliance**: High-priority enhancement for MCP 2025-11-25 specification
  - **Implementation**:
    - Added `scopes_supported` field to Protected Resource Metadata response when `SupportedScopes` is configured
    - Implemented sub-path metadata endpoint support (e.g., `/.well-known/oauth-protected-resource/mcp`)
    - Added `RegisterProtectedResourceMetadataRoutes()` helper function for easy route registration
    - Supports both root (`/.well-known/oauth-protected-resource`) and sub-path endpoints
  - **Discovery**: Clients can now discover available scopes and access metadata at service-specific sub-paths
  - **Helper Function**: Simplifies registration of both root and sub-path metadata endpoints with a single call
  - **Testing**: Added comprehensive unit tests for all scenarios (scopes inclusion, sub-path routing, path normalization)
  - **Documentation**: Updated README and examples to demonstrate new functionality

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

- **RFC 8707 Security Enhancements**
  - **Resource Length Validation**: Added maximum length limit (2048 characters) for resource parameter to prevent DoS attacks via extremely long URIs (RFC 3986 recommended limit)
  - **Constant-Time Audience Comparison**: Implemented constant-time comparison for token audience validation to prevent timing attacks (defense-in-depth best practice)
  - **Rate Limiting on Resource Mismatch**: Added rate limiting for repeated resource mismatch attempts to prevent reconnaissance attacks and log flooding
  - **Impact**: Enhanced defense-in-depth for RFC 8707 implementation, preventing potential DoS and timing-based attacks
  - **Testing**: Added comprehensive test coverage for length validation and rate limiting behavior

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
  - Implemented MCP 2025-11-25 specification support for Protected Resource Metadata discovery
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
    - MCP 2025-11-25: One of two discovery mechanisms (WWW-Authenticate OR well-known paths) (✓)
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

- [x] Support for additional OAuth providers (GitHub - completed in v0.2.8, Microsoft - planned)
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

