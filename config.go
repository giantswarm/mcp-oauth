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
	// ClientID is the Google OAuth Client ID (required).
	ClientID string

	// ClientSecret is the Google OAuth Client Secret (required).
	ClientSecret string

	// RedirectURL is where Google redirects after authentication.
	RedirectURL string
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	// Rate is requests per second allowed per IP. Zero disables limiting.
	Rate int

	// Burst is the maximum burst size allowed per IP.
	Burst int

	// CleanupInterval is how often to cleanup inactive rate limiters.
	CleanupInterval time.Duration

	// UserRate is requests per second allowed per authenticated user.
	// Applied in addition to IP-based limiting. Zero disables.
	UserRate int

	// UserBurst is the maximum burst size per authenticated user.
	UserBurst int

	// TrustProxy enables trusting X-Forwarded-For and X-Real-IP headers.
	// Only enable behind a trusted reverse proxy.
	TrustProxy bool
}

// SecurityConfig holds OAuth security settings (secure by default)
type SecurityConfig struct {
	// AllowInsecureAuthWithoutState permits auth requests without state parameter.
	// WARNING: Weakens CSRF protection. Only for legacy clients.
	AllowInsecureAuthWithoutState bool

	// DisableRefreshTokenRotation disables automatic refresh token rotation.
	// WARNING: Violates OAuth 2.1. Stolen tokens remain valid indefinitely.
	DisableRefreshTokenRotation bool

	// AllowPublicClientRegistration permits unauthenticated client registration.
	// WARNING: Can enable DoS via mass registration.
	AllowPublicClientRegistration bool

	// RegistrationAccessToken is required for client registration when
	// AllowPublicClientRegistration is false.
	RegistrationAccessToken string

	// RefreshTokenTTL is how long refresh tokens remain valid.
	// Recommended: 30-90 days. Zero means never expire.
	RefreshTokenTTL time.Duration

	// MaxClientsPerIP limits registrations per IP to prevent DoS.
	// Zero means no limit (not recommended).
	MaxClientsPerIP int

	// AllowCustomRedirectSchemes permits non-http/https URIs (e.g., myapp://).
	// Custom schemes are validated against AllowedCustomSchemes patterns.
	AllowCustomRedirectSchemes bool

	// AllowedCustomSchemes lists allowed custom URI scheme regex patterns.
	// Default: RFC 3986 compliant schemes.
	AllowedCustomSchemes []string

	// EncryptionKey is the AES-256 key (32 bytes) for token encryption at rest.
	// Nil disables encryption. Generate with oauth.GenerateEncryptionKey().
	EncryptionKey []byte

	// EnableAuditLogging enables security audit logging.
	// Logs auth events, token operations, and violations (sensitive data hashed).
	EnableAuditLogging bool
}
