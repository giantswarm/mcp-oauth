package oauth

import "time"

// OAuth token and code timeouts
const (
	// DefaultRefreshTokenTTL is the default time-to-live for refresh tokens (90 days)
	DefaultRefreshTokenTTL = 90 * 24 * time.Hour

	// DefaultAuthorizationCodeTTL is how long authorization codes are valid (10 minutes)
	DefaultAuthorizationCodeTTL = 10 * time.Minute

	// DefaultAccessTokenTTL is the default access token expiry (1 hour)
	DefaultAccessTokenTTL = 1 * time.Hour

	// DefaultCleanupInterval is how often to cleanup expired tokens (1 minute)
	DefaultCleanupInterval = 1 * time.Minute

	// DefaultRateLimitCleanupInterval is how often to cleanup inactive rate limiters
	DefaultRateLimitCleanupInterval = 5 * time.Minute

	// InactiveLimiterCleanupWindow is the time after which inactive limiters are removed
	InactiveLimiterCleanupWindow = 10 * time.Minute

	// TokenRefreshThreshold is how soon before expiry to attempt token refresh
	TokenRefreshThreshold = 5 * time.Minute

	// TokenExpiringThreshold is the minimum time before a token is considered expiring
	TokenExpiringThreshold = 60 // seconds

	// ClockSkewGrace is the grace period (in seconds) for clock skew when validating token expiration
	//
	// Security Rationale:
	//   - Prevents false expiration errors due to minor time differences between systems
	//   - Balances security (minimize token lifetime extension) with usability
	//   - 5 seconds is a conservative value that handles typical NTP drift
	//
	// Trade-offs:
	//   - Allows tokens to be used up to 5 seconds beyond their true expiration
	//   - This is acceptable for most use cases and improves reliability
	//   - For high-security scenarios, consider reducing or removing this grace period
	ClockSkewGrace = 5 // seconds
)

// OAuth client and security defaults
const (
	// DefaultMaxClientsPerIP is the default limit for client registrations per IP
	DefaultMaxClientsPerIP = 10

	// DefaultRateLimitRate is the default requests per second per IP
	DefaultRateLimitRate = 10

	// DefaultRateLimitBurst is the default burst size for rate limiting
	DefaultRateLimitBurst = 20

	// DefaultTokenEndpointAuthMethod is the default client authentication method
	DefaultTokenEndpointAuthMethod = "client_secret_basic"
)

// PKCE and token generation constants
const (
	// MinCodeVerifierLength is the minimum length for PKCE code_verifier (RFC 7636)
	MinCodeVerifierLength = 43

	// MaxCodeVerifierLength is the maximum length for PKCE code_verifier (RFC 7636)
	MaxCodeVerifierLength = 128

	// ClientIDTokenLength is the length of generated client IDs
	ClientIDTokenLength = 32

	// ClientSecretTokenLength is the length of generated client secrets
	ClientSecretTokenLength = 48

	// AccessTokenLength is the length of generated access tokens
	AccessTokenLength = 48

	// RefreshTokenLength is the length of generated refresh tokens
	RefreshTokenLength = 48

	// StateTokenLength is the length of generated state parameters
	StateTokenLength = 32
)

// Redirect URI validation constants
var (
	// AllowedHTTPSchemes lists allowed HTTP-based redirect URI schemes
	AllowedHTTPSchemes = []string{"http", "https"}

	// DangerousSchemes lists URI schemes that must never be allowed for security
	DangerousSchemes = []string{"javascript", "data", "file", "vbscript", "about"}

	// DefaultRFC3986SchemePattern is the default regex pattern for custom URI schemes (RFC 3986)
	DefaultRFC3986SchemePattern = []string{"^[a-z][a-z0-9+.-]*$"}

	// LoopbackAddresses lists recognized loopback addresses for development
	LoopbackAddresses = []string{"localhost", "127.0.0.1", "::1", "[::1]"}
)

// OAuth grant types and response types
var (
	// DefaultGrantTypes are the grant types supported by default
	DefaultGrantTypes = []string{"authorization_code", "refresh_token"}

	// DefaultResponseTypes are the response types supported by default
	DefaultResponseTypes = []string{"code"}

	// SupportedCodeChallengeMethods are the PKCE methods we support
	// Security: Only S256 is allowed. "plain" method is insecure and violates OAuth 2.1
	SupportedCodeChallengeMethods = []string{"S256"}

	// SupportedTokenAuthMethods are the supported token endpoint auth methods
	SupportedTokenAuthMethods = []string{"client_secret_basic", "client_secret_post", "none"}
)

// OAuth client types
const (
	// ClientTypeConfidential represents a confidential OAuth client
	ClientTypeConfidential = "confidential"

	// ClientTypePublic represents a public OAuth client
	ClientTypePublic = "public"
)

// PKCE code challenge methods
const (
	// PKCEMethodS256 is the SHA256 code challenge method (recommended, OAuth 2.1)
	PKCEMethodS256 = "S256"

	// PKCEMethodPlain is the plain code challenge method (deprecated, insecure)
	PKCEMethodPlain = "plain"
)

// URI schemes
const (
	// SchemeHTTP is the HTTP URI scheme
	SchemeHTTP = "http"

	// SchemeHTTPS is the HTTPS URI scheme
	SchemeHTTPS = "https"
)
