package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/util"
)

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

	// ======================== REDIRECT URI SECURITY (RFC 6749, OAuth 2.1 BCP) ========================
	// These settings control security validation of redirect URIs during client registration
	// and authorization flows. They address SSRF and open redirect vulnerabilities.

	// ProductionMode enforces strict security validation for redirect URIs:
	// - HTTPS required for all redirect URIs (except loopback when AllowLocalhostRedirectURIs=true)
	// - Private IP addresses blocked in redirect URIs (unless AllowPrivateIPRedirectURIs=true)
	// - Link-local addresses blocked (unless AllowLinkLocalRedirectURIs=true)
	// - Dangerous URI schemes blocked (javascript:, data:, file:, etc.)
	// When false, relaxed validation for development (still enforces dangerous scheme blocking).
	// Default: false (Go zero-value; set to true explicitly for production deployments)
	// WARNING: A security warning is logged when ProductionMode=false to remind operators.
	ProductionMode bool

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
	// These schemes can be used for XSS attacks (javascript:, data:) or local file access (file:).
	// This is applied in ALL modes (production and development).
	// Default: ["javascript", "data", "file", "vbscript", "about", "ftp"]
	// Override to customize blocked schemes (empty list uses defaults).
	BlockedRedirectSchemes []string

	// DNSValidation enables DNS resolution of redirect URI hostnames to validate
	// they don't resolve to private/internal IPs (defense against DNS rebinding attacks).
	// When enabled, hostnames are resolved and the resulting IP is checked.
	// WARNING: DNS lookups add latency to client registration and can fail.
	// Consider using this for high-security environments with reliable DNS.
	// Default: false (DNS lookup can have performance implications)
	DNSValidation bool

	// DNSValidationStrict enables fail-closed behavior for DNS validation.
	// When true AND DNSValidation=true:
	// - DNS resolution failures BLOCK client registration (fail-closed)
	// - This prevents attackers from bypassing validation by causing DNS failures
	// When false (default):
	// - DNS resolution failures are logged but registration is allowed (fail-open)
	// - This prevents false positives for legitimate hostnames with temporary DNS issues
	// SECURITY: Enable this for high-security environments where DNS is reliable.
	// WARNING: May cause legitimate registration failures during DNS outages.
	// Default: false (fail-open for availability)
	DNSValidationStrict bool

	// DNSValidationTimeout is the timeout for DNS resolution when DNSValidation=true.
	// Prevents slow DNS from blocking registration.
	// Default: 2 seconds
	DNSValidationTimeout time.Duration

	// ValidateRedirectURIAtAuthorization enables re-validation of redirect URIs during
	// authorization requests, not just at client registration time.
	// This provides defense against TOCTOU (Time-of-Check to Time-of-Use) attacks where:
	// 1. Attacker registers with a hostname resolving to a public IP
	// 2. Later changes DNS to resolve to an internal IP (DNS rebinding)
	// When enabled, the same security checks applied at registration are repeated
	// at authorization time, catching DNS rebinding attacks.
	// SECURITY: Recommended for high-security environments.
	// WARNING: Adds latency to authorization requests (DNS lookups if DNSValidation=true).
	// Default: false (validation only at registration for performance)
	ValidateRedirectURIAtAuthorization bool

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

	// Redirect URI security defaults
	// Note: ProductionMode and AllowLocalhostRedirectURIs default to false (Go zero-values).
	// We can't distinguish between unset and explicitly set to false in Go, so we log
	// security warnings in logSecurityWarnings to alert operators about insecure configurations.
	// Operators should explicitly set ProductionMode=true for production deployments.
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

// validateInterstitialConfig validates the InterstitialConfig for security and correctness.
// It checks branding values for injection attacks and logs warnings for custom handlers/templates.
func validateInterstitialConfig(config *Config, logger *slog.Logger) {
	// Skip validation if no interstitial configuration
	if config.Interstitial == nil {
		return
	}

	interstitial := config.Interstitial

	// SECURITY: Warn about custom handler - user is responsible for security
	if interstitial.CustomHandler != nil {
		logger.Warn("Custom interstitial handler configured",
			"responsibility", "You are responsible for setting security headers",
			"recommendation", "Use security.SetInterstitialSecurityHeaders() as a baseline",
			"csp_note", "If using inline scripts, update CSP headers with script hash")
	}

	// SECURITY: Warn about custom template - user is responsible for CSP
	if interstitial.CustomTemplate != "" {
		logger.Warn("Custom interstitial template configured",
			"template_length", len(interstitial.CustomTemplate),
			"csp_note", "If using inline scripts, ensure CSP headers include appropriate hashes")
	}

	// Validate branding configuration
	if interstitial.Branding != nil {
		validateInterstitialBranding(interstitial.Branding, config, logger)
	}
}

// validateInterstitialBranding validates the InterstitialBranding configuration
func validateInterstitialBranding(branding *InterstitialBranding, config *Config, logger *slog.Logger) {
	// SECURITY: Validate LogoURL is HTTPS or empty
	if branding.LogoURL != "" {
		u, err := url.Parse(branding.LogoURL)
		if err != nil {
			panic(fmt.Sprintf("Interstitial: invalid LogoURL '%s': %v", branding.LogoURL, err))
		}

		// Must be HTTPS (unless AllowInsecureHTTP is enabled for development)
		if u.Scheme != SchemeHTTPS {
			if config.AllowInsecureHTTP && u.Scheme == SchemeHTTP {
				logger.Warn("⚠️  Interstitial: HTTP LogoURL allowed for development",
					"logo_url", branding.LogoURL,
					"recommendation", "Use HTTPS LogoURL in production")
			} else {
				panic(fmt.Sprintf("Interstitial: LogoURL must use HTTPS scheme, got '%s' (or set AllowInsecureHTTP=true for development)", u.Scheme))
			}
		}

		// Warn if LogoAlt is not set (accessibility)
		if branding.LogoAlt == "" {
			logger.Warn("⚠️  Interstitial: LogoAlt not set for LogoURL",
				"logo_url", branding.LogoURL,
				"accessibility", "Consider setting LogoAlt for screen readers")
		}
	}

	// SECURITY: Validate CustomCSS doesn't contain injection vectors
	if branding.CustomCSS != "" {
		// Check for </style> tag injection
		if strings.Contains(strings.ToLower(branding.CustomCSS), "</style>") {
			panic("Interstitial: CustomCSS cannot contain '</style>' tag (injection risk)")
		}

		// Check for potentially dangerous CSS values
		if pattern, found := containsDangerousCSSPattern(branding.CustomCSS); found {
			panic(fmt.Sprintf("Interstitial: CustomCSS contains potentially dangerous pattern '%s'", pattern))
		}

		logger.Debug("Interstitial CustomCSS configured",
			"css_length", len(branding.CustomCSS))
	}

	// SECURITY: Validate color values are safe CSS (basic validation)
	if branding.PrimaryColor != "" {
		if err := validateCSSColorValue(branding.PrimaryColor); err != nil {
			panic(fmt.Sprintf("Interstitial: invalid PrimaryColor: %v", err))
		}
	}

	// SECURITY: Validate background gradient (basic validation)
	if branding.BackgroundGradient != "" {
		if err := validateCSSBackgroundValue(branding.BackgroundGradient); err != nil {
			panic(fmt.Sprintf("Interstitial: invalid BackgroundGradient: %v", err))
		}
	}

	logger.Debug("Interstitial branding configuration validated",
		"has_logo", branding.LogoURL != "",
		"has_title", branding.Title != "",
		"has_message", branding.Message != "",
		"has_button_text", branding.ButtonText != "",
		"has_primary_color", branding.PrimaryColor != "",
		"has_background", branding.BackgroundGradient != "",
		"has_custom_css", branding.CustomCSS != "")
}

// dangerousCSSPatterns contains patterns that indicate potential CSS injection attacks.
// These patterns are checked across all CSS value validations.
var dangerousCSSPatterns = []string{
	"expression(",  // IE CSS expression (JavaScript execution)
	"javascript:",  // JavaScript URL scheme
	"behavior:",    // IE CSS behavior
	"-moz-binding", // Firefox XBL binding (deprecated but still dangerous)
}

// containsDangerousCSSPattern checks if the value contains any dangerous CSS patterns.
// Returns the matched pattern and true if a dangerous pattern is found.
func containsDangerousCSSPattern(value string, additionalPatterns ...string) (string, bool) {
	lowerValue := strings.ToLower(value)

	// Check common dangerous patterns
	for _, pattern := range dangerousCSSPatterns {
		if strings.Contains(lowerValue, pattern) {
			return pattern, true
		}
	}

	// Check additional patterns specific to the context
	for _, pattern := range additionalPatterns {
		if strings.Contains(lowerValue, pattern) {
			return pattern, true
		}
	}

	return "", false
}

// validateCSSColorValue validates a CSS color value is safe
func validateCSSColorValue(color string) error {
	// Check for dangerous patterns (including url() which is not valid in color values)
	if pattern, found := containsDangerousCSSPattern(color, "url("); found {
		return fmt.Errorf("color value contains dangerous pattern '%s'", pattern)
	}

	// Basic format validation - must match common CSS color formats
	// Hex: #RGB, #RRGGBB, #RGBA, #RRGGBBAA
	// RGB/RGBA: rgb(), rgba()
	// HSL/HSLA: hsl(), hsla()
	// Named colors: allow alphanumeric
	colorPattern := regexp.MustCompile(`^(#[0-9a-fA-F]{3,8}|rgba?\([^)]+\)|hsla?\([^)]+\)|[a-zA-Z]+)$`)
	if !colorPattern.MatchString(strings.TrimSpace(color)) {
		return fmt.Errorf("invalid CSS color format: '%s'", color)
	}

	return nil
}

// validateCSSBackgroundValue validates a CSS background value is safe
func validateCSSBackgroundValue(bg string) error {
	// Check for dangerous patterns
	if pattern, found := containsDangerousCSSPattern(bg); found {
		return fmt.Errorf("background value contains dangerous pattern '%s'", pattern)
	}

	// Allow url() only for HTTPS URLs
	lowerBg := strings.ToLower(bg)
	if strings.Contains(lowerBg, "url(") {
		// Extract URL from url() and validate it's HTTPS
		urlPattern := regexp.MustCompile(`url\(['"]?([^'")]+)['"]?\)`)
		matches := urlPattern.FindAllStringSubmatch(bg, -1)
		for _, match := range matches {
			if len(match) > 1 {
				u, err := url.Parse(match[1])
				if err != nil || (u.Scheme != "" && u.Scheme != SchemeHTTPS) {
					return fmt.Errorf("url() in background must use HTTPS: '%s'", match[1])
				}
			}
		}
	}

	return nil
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

	// Redirect URI security warnings
	if !config.ProductionMode {
		logger.Warn("⚠️  SECURITY WARNING: ProductionMode is DISABLED",
			"risk", "Relaxed redirect URI validation allows insecure configurations",
			"recommendation", "Set ProductionMode=true for production deployments",
			"learn_more", "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.1")
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
	if config.DNSValidation {
		mode := "permissive (fail-open)"
		if config.DNSValidationStrict {
			mode = "strict (fail-closed)"
		}
		logger.Info("DNS validation enabled for redirect URIs",
			"timeout", config.DNSValidationTimeout,
			"mode", mode,
			"benefit", "Defense against DNS rebinding attacks",
			"caveat", "May add latency to client registration")
		if !config.DNSValidationStrict {
			logger.Warn("DNS validation is fail-open (DNSValidationStrict=false)",
				"risk", "DNS failures allow registration (potential bypass)",
				"recommendation", "Set DNSValidationStrict=true for high-security environments")
		}
	}
	if config.ValidateRedirectURIAtAuthorization {
		logger.Info("Authorization-time redirect URI validation enabled",
			"benefit", "Defense against TOCTOU/DNS rebinding attacks",
			"caveat", "Adds latency to authorization requests")
	} else if config.DNSValidation {
		logger.Info("Authorization-time redirect URI validation is DISABLED",
			"risk", "DNS rebinding attacks possible after registration",
			"recommendation", "Set ValidateRedirectURIAtAuthorization=true for TOCTOU protection")
	}
	// Only log localhost blocking when ProductionMode is enabled (strict security)
	// In development mode, localhost is expected to be controlled differently
	if config.ProductionMode && !config.AllowLocalhostRedirectURIs {
		logger.Info("Localhost redirect URIs are BLOCKED (strict mode)",
			"impact", "Native apps (RFC 8252) will not work",
			"recommendation", "Set AllowLocalhostRedirectURIs=true for native app support",
			"learn_more", "https://datatracker.ietf.org/doc/html/rfc8252#section-7.3")
	}
}
