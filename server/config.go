package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// DNSResolver is an interface for DNS resolution, allowing for dependency injection
// in testing. The default implementation uses net.DefaultResolver.
//
// This interface is intentionally minimal - it only exposes the method needed
// for redirect URI validation.
type DNSResolver interface {
	// LookupIP looks up host using the local resolver.
	// It returns a slice of that host's IPv4 and IPv6 addresses.
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// defaultDNSResolver wraps net.DefaultResolver to implement DNSResolver.
type defaultDNSResolver struct{}

func (d *defaultDNSResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

// URI scheme constants (shared with validation.go)
const (
	SchemeHTTP  = "http"
	SchemeHTTPS = "https"
)

// OAuth endpoint paths
const (
	// EndpointPathAuthorize is the authorization endpoint path
	EndpointPathAuthorize = "/oauth/authorize"

	// EndpointPathToken is the token endpoint path
	EndpointPathToken = "/oauth/token" // #nosec G101 -- This is a URL path, not a credential

	// EndpointPathRegister is the dynamic client registration endpoint path (RFC 7591)
	EndpointPathRegister = "/oauth/register"

	// EndpointPathRevoke is the token revocation endpoint path (RFC 7009)
	EndpointPathRevoke = "/oauth/revoke"

	// EndpointPathIntrospect is the token introspection endpoint path (RFC 7662)
	EndpointPathIntrospect = "/oauth/introspect"

	// EndpointPathProtectedResourceMetadata is the Protected Resource Metadata discovery path (RFC 9728)
	EndpointPathProtectedResourceMetadata = "/.well-known/oauth-protected-resource"
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
	// Set to 0 or use DisableProactiveRefresh to disable this feature.
	TokenRefreshThreshold int64 // seconds, default: 300

	// DisableProactiveRefresh disables the proactive token refresh feature entirely.
	// When true, tokens will NOT be refreshed proactively during validation, even if they
	// are near expiry and have a refresh token available.
	//
	// IMPORTANT: Enable this when MCP clients (e.g., Cursor, Claude Desktop) handle their own
	// token refresh directly with the OIDC provider. In this scenario, the mcp-oauth server's
	// stored refresh token may become stale after the client refreshes tokens with the provider,
	// because the provider issues a new refresh token and invalidates the old one.
	//
	// When proactive refresh is enabled (default) and the client has already refreshed tokens
	// with the provider, the server's attempt to refresh will fail with "refresh token already
	// claimed", which may trigger false-positive refresh token reuse detection and revoke all
	// tokens for the user+client pair.
	//
	// Recommended settings when MCP clients handle token refresh:
	//   - Set DisableProactiveRefresh: true
	//   - OR increase OIDC provider token expiry to exceed typical session duration
	//
	// Default: false (proactive refresh is enabled)
	DisableProactiveRefresh bool // default: false

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

	// ResourceMetadataByPath enables per-path Protected Resource Metadata (RFC 9728).
	// This allows different protected resources to advertise different authorization
	// requirements. When a client requests /.well-known/oauth-protected-resource/<path>,
	// the server returns metadata specific to that path.
	//
	// Keys are path prefixes (e.g., "/mcp/files", "/mcp/admin").
	// If a request path matches multiple prefixes, the longest match is used.
	// If no match is found, the default server-wide metadata is returned.
	//
	// Example:
	//   ResourceMetadataByPath: map[string]ProtectedResourceConfig{
	//       "/mcp/files": {ScopesSupported: []string{"files:read", "files:write"}},
	//       "/mcp/admin": {ScopesSupported: []string{"admin:access"}},
	//   }
	//
	// Discovery endpoints registered:
	//   - /.well-known/oauth-protected-resource (default metadata)
	//   - /.well-known/oauth-protected-resource/mcp/files (files-specific metadata)
	//   - /.well-known/oauth-protected-resource/mcp/admin (admin-specific metadata)
	ResourceMetadataByPath map[string]ProtectedResourceConfig

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

	// EndpointScopeRequirements maps HTTP paths to required scopes for MCP 2025-11-25 scope validation.
	// When a protected endpoint is accessed, the token's scopes are validated against these requirements.
	// If the token lacks required scopes, a 403 with insufficient_scope error is returned.
	//
	// Path Matching:
	//   - Exact match: "/api/files" matches only "/api/files"
	//   - Prefix match: "/api/files/*" matches "/api/files/..." (any sub-path)
	//
	// Example:
	//   EndpointScopeRequirements: map[string][]string{
	//     "/api/files/*":    {"files:read", "files:write"},
	//     "/api/admin/*":    {"admin:access"},
	//     "/api/user/profile": {"user:profile"},
	//   }
	//
	// Scope Validation Logic:
	//   - If no requirements configured for a path, access is allowed (no scope check)
	//   - If requirements exist, ALL required scopes must be present in the token
	//   - Scope validation follows OAuth 2.0 semantics (exact string matching)
	//
	// Default: nil (no endpoint-specific scope requirements)
	EndpointScopeRequirements map[string][]string

	// EndpointMethodScopeRequirements maps HTTP paths AND methods to required scopes.
	// This extends EndpointScopeRequirements with method-aware scope checking.
	// Useful when different HTTP methods require different scopes (e.g., GET vs POST).
	//
	// Path Matching (same as EndpointScopeRequirements):
	//   - Exact match: "/api/files" matches only "/api/files"
	//   - Prefix match: "/api/files/*" matches "/api/files/..." (any sub-path)
	//
	// Method Matching:
	//   - Use "*" as method to match any HTTP method (fallback)
	//   - Method names are case-sensitive and should be uppercase (GET, POST, etc.)
	//
	// Example:
	//   EndpointMethodScopeRequirements: map[string]map[string][]string{
	//     "/api/files/*": {
	//       "GET":    {"files:read"},
	//       "POST":   {"files:write"},
	//       "DELETE": {"files:delete", "admin:access"},
	//       "*":      {"files:read"},  // fallback for other methods
	//     },
	//   }
	//
	// Precedence:
	//   1. EndpointMethodScopeRequirements with exact method match
	//   2. EndpointMethodScopeRequirements with "*" method (fallback)
	//   3. EndpointScopeRequirements (method-agnostic)
	//   4. No requirements (access allowed)
	//
	// Default: nil (no method-specific scope requirements)
	EndpointMethodScopeRequirements map[string]map[string][]string

	// HideEndpointPathInErrors controls whether endpoint paths are included in error messages.
	// When true, error messages will not include the specific endpoint path, providing
	// defense against information disclosure.
	//
	// When false (default): Error messages include the path for debugging
	//   "Token lacks required scopes for endpoint /api/admin/users"
	//
	// When true: Error messages use a generic message
	//   "Token lacks required scopes for this endpoint"
	//
	// Security Consideration:
	// Including paths in error messages aids debugging but could reveal internal
	// API structure to attackers. Enable this in production if path disclosure is a concern.
	//
	// Default: false (paths included in errors for easier debugging)
	HideEndpointPathInErrors bool

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

	// AllowNoStateParameter allows authorization requests without the state parameter.
	// WARNING: Disabling state parameter validation weakens CSRF protection!
	// The state parameter is REQUIRED by OAuth 2.1 for CSRF attack prevention.
	// Only enable this for compatibility with clients that don't support state (e.g., some MCP clients).
	// Default: false (state is REQUIRED for security)
	AllowNoStateParameter bool // default: false

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
	//   - DCR endpoint allows UNAUTHENTICATED registration (DoS risk)
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
	// attempts will fail (misconfiguration) unless TrustedPublicRegistrationSchemes
	// is configured and the client uses trusted redirect URI schemes.
	//
	// Default: "" (no token configured)
	RegistrationAccessToken string

	// TrustedPublicRegistrationSchemes lists URI schemes that are allowed for
	// unauthenticated client registration. Clients registering with redirect URIs
	// using ONLY these schemes do NOT need a RegistrationAccessToken.
	//
	// This enables compatibility with MCP clients like Cursor that don't support
	// registration tokens, while maintaining security for other clients.
	//
	// Security: Custom URI schemes (cursor://, vscode://) can only be intercepted
	// by the application that registered the scheme with the OS. This makes them
	// inherently safe for public registration - an attacker cannot register a
	// malicious client with cursor:// because they can't receive the callback.
	//
	// Scheme matching is case-insensitive (per RFC 3986 Section 3.1).
	// Schemes are normalized to lowercase during configuration validation.
	//
	// Example: ["cursor", "vscode", "vscode-insiders", "windsurf"]
	// Default: [] (all registrations require token unless AllowPublicClientRegistration=true)
	TrustedPublicRegistrationSchemes []string

	// trustedSchemesMap is a pre-computed map for O(1) lookup of trusted schemes.
	// This is populated during configuration validation from TrustedPublicRegistrationSchemes.
	// All schemes are normalized to lowercase for case-insensitive matching.
	// This field is internal and should not be set directly by users.
	trustedSchemesMap map[string]bool

	// DisableStrictSchemeMatching explicitly disables strict scheme matching for deployments
	// that need to support clients with mixed redirect URI schemes (e.g., cursor:// AND https://).
	//
	// Strict scheme matching (enabled by default when TrustedPublicRegistrationSchemes is configured):
	//   - All redirect URIs MUST use schemes from TrustedPublicRegistrationSchemes
	//   - A mix of trusted and untrusted schemes requires a registration token
	//   - Provides maximum security by preventing token leakage to untrusted URIs
	//
	// When disabled (permissive mode):
	//   - If ANY redirect URI uses a trusted scheme, registration is allowed
	//   - Other redirect URIs can use any scheme (including https://)
	//   - Use case: Clients that need both custom scheme and web-based callbacks
	//   - A security warning is logged when this mode is used
	//
	// WARNING: Disabling strict matching allows clients to register with untrusted redirect URIs
	// alongside trusted ones. While PKCE mitigates code interception, this reduces security.
	// Only set this to true if you have specific requirements for mixed scheme clients.
	// Default: false (strict matching is enabled when TrustedPublicRegistrationSchemes is configured)
	DisableStrictSchemeMatching bool

	// AllowedCustomSchemes is a list of allowed custom URI scheme patterns (regex)
	// Used for validating custom redirect URIs (e.g., myapp://, com.example.app://)
	// Empty list allows all RFC 3986 compliant schemes
	// Default: ["^[a-z][a-z0-9+.-]*$"] (RFC 3986 compliant schemes)
	AllowedCustomSchemes []string

	// ======================== REDIRECT URI SECURITY (RFC 6749, OAuth 2.1 BCP) ========================
	// These settings control security validation of redirect URIs during client registration
	// and authorization flows. They address SSRF and open redirect vulnerabilities.

	// ProductionMode enforces strict security validation for redirect URIs:
	// - HTTPS required for all redirect URIs (except loopback when AllowLocalhostRedirectURIs=true)
	// - Private IP addresses blocked in redirect URIs (unless AllowPrivateIPRedirectURIs=true)
	// - Link-local addresses blocked (unless AllowLinkLocalRedirectURIs=true)
	// - Dangerous URI schemes blocked (javascript:, data:, file:, etc.)
	// Default: true (secure by default - set automatically by applySecurityDefaults)
	// To disable for development, set DisableProductionMode=true instead.
	ProductionMode bool

	// DisableProductionMode explicitly disables ProductionMode for development environments.
	// WARNING: Disabling ProductionMode significantly weakens redirect URI security.
	// Only set this to true for local development where you need HTTP on non-loopback hosts.
	// Default: false (ProductionMode is enabled)
	DisableProductionMode bool

	// AllowLocalhostRedirectURIs allows http://localhost and http://127.0.0.1 redirect URIs
	// even in ProductionMode. Required for native apps per RFC 8252.
	// Also allows loopback IPv6 addresses (::1, [::1]).
	// Default: false (Go zero-value; set to true for native app support per RFC 8252 Section 7.3)
	AllowLocalhostRedirectURIs bool

	// AllowPrivateIPRedirectURIs allows redirect URIs that resolve to private IP addresses
	// (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 per RFC 1918).
	// WARNING: Enables SSRF attacks to internal networks if not properly secured.
	// Only enable for internal/VPN deployments where clients legitimately use private IPs.
	// Default: false (blocked for security)
	AllowPrivateIPRedirectURIs bool

	// AllowLinkLocalRedirectURIs allows link-local addresses (169.254.0.0/16, fe80::/10).
	// WARNING: Could enable access to cloud metadata services (SSRF to 169.254.169.254).
	// This is a significant security risk in cloud environments (AWS, GCP, Azure).
	// Only enable if you have specific requirements for link-local addresses.
	// Default: false (blocked for security)
	AllowLinkLocalRedirectURIs bool

	// BlockedRedirectSchemes lists URI schemes that are always rejected for security.
	// These schemes can be used for XSS attacks (javascript:, data:, blob:) or local file/app access (file:, ms-appx:).
	// This is applied in ALL modes (production and development).
	// Default: ["javascript", "data", "file", "vbscript", "about", "ftp", "blob", "ms-appx", "ms-appx-web"]
	// Override to customize blocked schemes (empty list uses defaults).
	BlockedRedirectSchemes []string

	// DNSValidation enables DNS resolution of redirect URI hostnames to validate
	// they don't resolve to private/internal IPs (defense against DNS rebinding attacks).
	// When enabled, hostnames are resolved and the resulting IP is checked.
	// Default: true (secure by default - set automatically by applySecurityDefaults)
	// To disable, set DisableDNSValidation=true instead.
	DNSValidation bool

	// DisableDNSValidation explicitly disables DNS validation for redirect URI hostnames.
	// WARNING: Disabling DNS validation allows potential DNS rebinding attacks.
	// Only set this to true if DNS lookup latency during client registration is unacceptable.
	// Default: false (DNSValidation is enabled)
	DisableDNSValidation bool

	// DNSValidationStrict enables fail-closed behavior for DNS validation.
	// When true AND DNSValidation=true:
	// - DNS resolution failures BLOCK client registration (fail-closed)
	// - This prevents attackers from bypassing validation by causing DNS failures
	// When false:
	// - DNS resolution failures are logged but registration is allowed (fail-open)
	// - This may allow bypass of DNS validation via intentional DNS failures
	// Default: true (secure by default - set automatically by applySecurityDefaults)
	// To disable strict mode, set DisableDNSValidationStrict=true instead.
	DNSValidationStrict bool

	// DisableDNSValidationStrict explicitly disables fail-closed DNS validation.
	// WARNING: Disabling strict mode allows potential DNS validation bypass via intentional failures.
	// Only set this to true if DNS reliability issues cause unacceptable registration failures.
	// Default: false (DNSValidationStrict is enabled)
	DisableDNSValidationStrict bool

	// DNSValidationTimeout is the timeout for DNS resolution when DNSValidation=true.
	// Prevents slow DNS from blocking registration.
	// Default: 2 seconds
	DNSValidationTimeout time.Duration

	// DNSResolver is the resolver used for DNS lookups during redirect URI validation.
	// This is primarily for testing - allows injecting a mock resolver.
	// If nil, the default net.DefaultResolver is used.
	// Default: nil (uses net.DefaultResolver)
	DNSResolver DNSResolver

	// ValidateRedirectURIAtAuthorization enables re-validation of redirect URIs during
	// authorization requests, not just at client registration time.
	// This provides defense against TOCTOU (Time-of-Check to Time-of-Use) attacks where:
	// 1. Attacker registers with a hostname resolving to a public IP
	// 2. Later changes DNS to resolve to an internal IP (DNS rebinding)
	// When enabled, the same security checks applied at registration are repeated
	// at authorization time, catching DNS rebinding attacks.
	// Default: true (secure by default - set automatically by applySecurityDefaults)
	// To disable, set DisableAuthorizationTimeValidation=true instead.
	ValidateRedirectURIAtAuthorization bool

	// DisableAuthorizationTimeValidation explicitly disables redirect URI validation at authorization time.
	// WARNING: Disabling this allows DNS rebinding attacks between registration and use.
	// Only set this to true if authorization latency is critical and you accept the TOCTOU risk.
	// Default: false (ValidateRedirectURIAtAuthorization is enabled)
	DisableAuthorizationTimeValidation bool

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

	// Interstitial configures the OAuth success interstitial page for custom URL schemes.
	// Per RFC 8252 Section 7.1, browsers may fail silently on 302 redirects to custom
	// URL schemes (cursor://, vscode://, etc.). The interstitial page provides visual
	// feedback and a manual fallback button.
	// Optional: if nil, the default interstitial page is used.
	Interstitial *InterstitialConfig

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

	// EnableRevocationEndpoint controls whether the OAuth 2.0 Token Revocation endpoint (RFC 7009)
	// is advertised in Authorization Server Metadata and available for use.
	// When true: revocation_endpoint will be included in /.well-known/oauth-authorization-server
	// When false: revocation_endpoint will NOT be advertised (endpoint not yet implemented)
	// SECURITY: Only enable when you have implemented the actual revocation endpoint handler
	// Default: false (not yet implemented)
	EnableRevocationEndpoint bool

	// EnableIntrospectionEndpoint controls whether the OAuth 2.0 Token Introspection endpoint (RFC 7662)
	// is advertised in Authorization Server Metadata and available for use.
	// When true: introspection_endpoint will be included in /.well-known/oauth-authorization-server
	// When false: introspection_endpoint will NOT be advertised (endpoint not yet implemented)
	// SECURITY: Only enable when you have implemented the actual introspection endpoint handler
	// Default: false (not yet implemented)
	EnableIntrospectionEndpoint bool

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

// InterstitialConfig configures the OAuth success interstitial page
// displayed when redirecting to custom URL schemes (cursor://, vscode://, etc.)
//
// Per RFC 8252 Section 7.1, browsers may fail silently on 302 redirects to custom
// URL schemes. The interstitial page provides visual feedback and a manual fallback.
//
// Configuration Priority:
//  1. CustomHandler - if set, takes full control of the response
//  2. CustomTemplate - if set, uses the provided HTML template
//  3. Branding - if set, customizes the default template's appearance
//  4. Default - uses the built-in template with standard styling
type InterstitialConfig struct {
	// CustomHandler allows complete control over the interstitial response.
	// When set, this handler is called instead of rendering any template.
	// The handler receives the redirect URL and app name as request context values.
	// Use oauth.InterstitialRedirectURL(ctx) and oauth.InterstitialAppName(ctx) to extract them.
	//
	// SECURITY: The handler MUST set appropriate security headers.
	// Use security.SetInterstitialSecurityHeaders() as a baseline.
	// If you include custom inline scripts, you must update CSP headers accordingly.
	//
	// Example:
	//   CustomHandler: func(w http.ResponseWriter, r *http.Request) {
	//       redirectURL := oauth.InterstitialRedirectURL(r.Context())
	//       appName := oauth.InterstitialAppName(r.Context())
	//       security.SetInterstitialSecurityHeaders(w, "https://auth.example.com")
	//       // Serve your custom response...
	//   }
	CustomHandler func(w http.ResponseWriter, r *http.Request)

	// CustomTemplate is a custom HTML template string using Go's html/template syntax.
	// Available template variables:
	//   - {{.RedirectURL}} - The OAuth callback redirect URL (marked safe for href)
	//   - {{.AppName}} - Human-readable application name (e.g., "Cursor", "Visual Studio Code")
	//   - All InterstitialBranding fields ({{.LogoURL}}, {{.Title}}, etc.)
	//
	// SECURITY: The template is parsed using html/template which auto-escapes HTML.
	// If you include inline scripts, you must update CSP headers accordingly.
	// Consider using security.SetInterstitialSecurityHeaders() with custom script hashes.
	//
	// Ignored if CustomHandler is set.
	CustomTemplate string

	// Branding allows customization of the default template's appearance.
	// This is the simplest way to add your organization's branding without
	// providing a complete custom template.
	//
	// Ignored if CustomHandler or CustomTemplate is set.
	Branding *InterstitialBranding
}

// ProtectedResourceConfig holds per-path configuration for Protected Resource Metadata (RFC 9728).
// This allows different protected resources on the same domain to advertise different
// authorization requirements (scopes, authorization servers, etc.).
//
// Per MCP 2025-11-25, sub-path discovery enables clients to understand the specific
// requirements for different endpoints on the same resource server.
//
// Example:
//
//	ResourceMetadataByPath: map[string]ProtectedResourceConfig{
//	    "/mcp/files": {
//	        ScopesSupported: []string{"files:read", "files:write"},
//	    },
//	    "/mcp/admin": {
//	        ScopesSupported: []string{"admin:access"},
//	    },
//	}
type ProtectedResourceConfig struct {
	// ScopesSupported lists the scopes required/supported for this specific resource path.
	// If empty, falls back to the server's default SupportedScopes configuration.
	// Per RFC 9728, this helps clients determine what access they need to request.
	ScopesSupported []string

	// AuthorizationServers lists the authorization server URLs for this resource.
	// If empty, defaults to the server's Issuer.
	// This allows different resource paths to point to different authorization servers.
	AuthorizationServers []string

	// BearerMethodsSupported specifies how bearer tokens can be sent.
	// Default: ["header"] (Authorization header only).
	// Options: "header", "body", "query" (per RFC 6750).
	// Note: "body" and "query" are discouraged for security reasons.
	BearerMethodsSupported []string

	// ResourceIdentifier is the canonical identifier for this specific resource.
	// If empty, derived from the server's ResourceIdentifier or Issuer + path.
	// Used for audience validation per RFC 8707.
	ResourceIdentifier string
}

// InterstitialBranding configures visual elements of the default interstitial page.
// All fields are optional - unset fields use the default values.
//
// Security Best Practices:
//   - LogoURL must use HTTPS (enforced at startup)
//   - Host logos on trusted CDNs or your own infrastructure
//   - Use immutable/versioned URLs for logos (e.g., include hash in filename)
//   - Note: Browsers don't support Subresource Integrity (SRI) for images,
//     so HTTPS and trusted hosting are your primary security controls
type InterstitialBranding struct {
	// LogoURL is an optional URL to a logo image (PNG, SVG, JPEG).
	// Must be HTTPS for security (validated at startup). HTTP is only allowed
	// when AllowInsecureHTTP is enabled for local development.
	// Leave empty to use the default animated checkmark icon.
	// Recommended size: 80x80 pixels or larger (displayed at 80px height).
	//
	// Security: Host on a trusted CDN with immutable URLs. The image is loaded
	// with crossorigin="anonymous" for better security isolation.
	LogoURL string

	// LogoAlt is the alt text for the logo image.
	// Required for accessibility if LogoURL is set.
	// Default: "Logo" (if LogoURL is set)
	LogoAlt string

	// Title replaces the "Authorization Successful" heading.
	// Example: "Connected to Acme Corp"
	Title string

	// Message replaces the default success message.
	// Use {{.AppName}} placeholder for the application name.
	// Example: "You have been authenticated with {{.AppName}}. You can now close this window."
	// Default: "You have been authenticated successfully. Return to {{.AppName}} to continue."
	Message string

	// ButtonText replaces the "Open [AppName]" button text.
	// Use {{.AppName}} placeholder for the application name.
	// Example: "Return to {{.AppName}}"
	// Default: "Open {{.AppName}}"
	ButtonText string

	// PrimaryColor is the primary/accent color for buttons and highlights.
	// Must be a valid CSS color value (hex, rgb, hsl, or named color).
	// Examples: "#4F46E5", "rgb(79, 70, 229)", "indigo"
	// Default: "#00d26a" (green)
	PrimaryColor string

	// BackgroundGradient is the body background CSS value.
	// Can be a solid color, gradient, or any valid CSS background value.
	// Example: "linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%)"
	// Default: "linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)"
	BackgroundGradient string

	// CustomCSS is additional CSS to inject into the page.
	// This CSS is added after the default styles, allowing overrides.
	// SECURITY: Must not contain "</style>" to prevent injection attacks.
	// Validated at startup - server will panic if invalid.
	// Example: ".container { max-width: 600px; }"
	CustomCSS string
}

// AuthorizationEndpoint returns the full URL to the authorization endpoint
func (c *Config) AuthorizationEndpoint() string {
	return c.Issuer + EndpointPathAuthorize
}

// TokenEndpoint returns the full URL to the token endpoint
func (c *Config) TokenEndpoint() string {
	return c.Issuer + EndpointPathToken
}

// RegistrationEndpoint returns the full URL to the dynamic client registration endpoint
func (c *Config) RegistrationEndpoint() string {
	return c.Issuer + EndpointPathRegister
}

// ProtectedResourceMetadataEndpoint returns the full URL to the RFC 9728 Protected Resource Metadata endpoint
// This endpoint is used in WWW-Authenticate headers to help MCP clients discover authorization server information
func (c *Config) ProtectedResourceMetadataEndpoint() string {
	return c.Issuer + EndpointPathProtectedResourceMetadata
}

// RevocationEndpoint returns the full URL to the RFC 7009 token revocation endpoint
func (c *Config) RevocationEndpoint() string {
	return c.Issuer + EndpointPathRevoke
}

// IntrospectionEndpoint returns the full URL to the RFC 7662 token introspection endpoint
func (c *Config) IntrospectionEndpoint() string {
	return c.Issuer + EndpointPathIntrospect
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

// SetTrustedSchemesMap builds the pre-computed trusted schemes map from the given schemes.
// This is primarily used for testing purposes. In production, the map is built
// automatically by validateTrustedPublicRegistrationSchemes during config validation.
// Schemes are normalized to lowercase for case-insensitive matching.
func (c *Config) SetTrustedSchemesMap(schemes []string) {
	if len(schemes) == 0 {
		c.trustedSchemesMap = nil
		return
	}
	c.trustedSchemesMap = make(map[string]bool, len(schemes))
	for _, scheme := range schemes {
		// Normalize to lowercase for case-insensitive matching (RFC 3986)
		c.trustedSchemesMap[strings.ToLower(scheme)] = true
	}
}
