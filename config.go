package oauth

import (
	"log/slog"
	"net/http"
	"time"
)

// Config holds the OAuth handler configuration
// Structured using composition for better organization and maintainability
type Config struct {
	// Resource is the MCP server resource identifier for RFC 8707
	// This should be the base URL of the MCP server
	Resource string

	// SupportedScopes are all available Google API scopes
	SupportedScopes []string

	// Google OAuth credentials and settings
	GoogleAuth GoogleAuthConfig

	// Rate limiting configuration
	RateLimit RateLimitConfig

	// Security settings (secure by default)
	Security SecurityConfig

	// CleanupInterval is how often to cleanup expired tokens
	// Default: 1 minute
	CleanupInterval time.Duration

	// Logger for structured logging (optional, uses default if not provided)
	Logger *slog.Logger

	// HTTPClient is a custom HTTP client for OAuth requests
	// If not provided, uses the default HTTP client
	// Can be used to add timeouts, logging, metrics, etc.
	HTTPClient *http.Client
}

// GoogleAuthConfig holds Google OAuth proxy configuration
type GoogleAuthConfig struct {
	// ClientID is the Google OAuth Client ID
	// REQUIRED for OAuth proxy mode - used to authenticate with Google
	ClientID string

	// ClientSecret is the Google OAuth Client Secret
	// REQUIRED for OAuth proxy mode - used to authenticate with Google
	ClientSecret string

	// RedirectURL is the callback URL for Google OAuth flow
	// This is where Google redirects after user authentication
	// Default: {Resource}/oauth/google/callback
	RedirectURL string
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	// Rate is the number of requests per second allowed per IP (0 = no limit)
	Rate int

	// Burst is the maximum burst size allowed per IP
	Burst int

	// CleanupInterval is how often to cleanup inactive rate limiters
	// Default: 5 minutes
	CleanupInterval time.Duration

	// UserRate is the number of requests per second allowed per authenticated user (0 = no limit)
	// This is in addition to IP-based rate limiting
	UserRate int

	// UserBurst is the maximum burst size allowed per authenticated user
	UserBurst int

	// TrustProxy indicates whether to trust X-Forwarded-For and X-Real-IP headers
	// Only set to true if the server is behind a trusted proxy
	// Default: false (secure by default)
	TrustProxy bool
}

// SecurityConfig holds OAuth security settings (secure by default)
type SecurityConfig struct {
	// AllowInsecureAuthWithoutState allows authorization requests without state parameter
	// WARNING: Disabling this weakens CSRF protection and is NOT recommended
	// Only enable if you have clients that don't support state parameter
	// Default: false (state is REQUIRED for security)
	AllowInsecureAuthWithoutState bool

	// DisableRefreshTokenRotation disables automatic refresh token rotation
	// WARNING: Disabling this violates OAuth 2.1 security best practices
	// Stolen refresh tokens can be used indefinitely without rotation
	// Default: false (rotation is ENABLED for security)
	DisableRefreshTokenRotation bool

	// AllowPublicClientRegistration allows unauthenticated dynamic client registration
	// WARNING: This can lead to DoS attacks via unlimited client registration
	// When false, client registration requires a registration access token
	// Default: false (authentication REQUIRED for security)
	AllowPublicClientRegistration bool

	// RegistrationAccessToken is the token required for client registration
	// Only checked if AllowPublicClientRegistration is false
	// Generate a secure random token and share it only with trusted client developers
	RegistrationAccessToken string

	// RefreshTokenTTL is the time-to-live for refresh tokens (0 = never expire)
	// Recommended: 30-90 days for security vs usability balance
	// Default: 90 days
	RefreshTokenTTL time.Duration

	// MaxClientsPerIP limits the number of clients that can be registered per IP
	// Prevents DoS attacks via mass client registration
	// 0 = no limit (not recommended)
	// Default: 10
	MaxClientsPerIP int

	// AllowCustomRedirectSchemes allows non-http/https redirect URIs (e.g., myapp://)
	// When false, only http/https schemes are allowed
	// When true, custom schemes are validated against AllowedCustomSchemes pattern
	// Default: true (for native app support)
	AllowCustomRedirectSchemes bool

	// AllowedCustomSchemes is a list of allowed custom scheme patterns (regex)
	// Only used if AllowCustomRedirectSchemes is true
	// Default: ["^[a-z][a-z0-9+.-]*$"] (RFC 3986 compliant schemes)
	AllowedCustomSchemes []string

	// EncryptionKey is the AES-256 key for encrypting tokens at rest (32 bytes)
	// If nil or empty, tokens are stored unencrypted in memory
	// For production, provide a 32-byte key from secure storage (KMS, Vault, etc.)
	// Use oauth.GenerateEncryptionKey() to create a new key
	// Use oauth.EncryptionKeyFromBase64() to load from env var
	// Default: nil (encryption disabled)
	EncryptionKey []byte

	// EnableAuditLogging enables comprehensive security audit logging
	// Logs authentication events, token operations, and security violations
	// All sensitive data is hashed before logging
	// Default: true (enabled for security)
	EnableAuditLogging bool
}
