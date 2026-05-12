package oauth

import (
	"log/slog"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Server is the OAuth 2.1 authorization server. See [server.Server].
type Server = server.Server

// ServerConfig is the OAuth server configuration. See [server.Config].
type ServerConfig = server.Config

// ServerOption configures a Server during construction. See [server.Option].
type ServerOption = server.Option

// ForwardedIDTokenAcceptance is the verified result of accepting a JWT
// forwarded from a trusted upstream identity provider.
type ForwardedIDTokenAcceptance = server.ForwardedIDTokenAcceptance

// ErrTrustedAudienceMismatch is returned by [Server.AcceptForwardedIDToken]
// when the bearer token's `aud` claim does not match any entry in
// Config.TrustedAudiences. Callers typically respond with 401.
var ErrTrustedAudienceMismatch = server.ErrTrustedAudienceMismatch

// WithEncryptor configures the token encryptor and propagates it to the
// token store. See [server.WithEncryptor].
func WithEncryptor(enc *security.Encryptor) ServerOption {
	return server.WithEncryptor(enc)
}

// WithAuditor configures the security auditor. See [server.WithAuditor].
func WithAuditor(aud *security.Auditor) ServerOption { return server.WithAuditor(aud) }

// WithRateLimiter configures the IP-based rate limiter.
// See [server.WithRateLimiter].
func WithRateLimiter(rl *security.RateLimiter) ServerOption {
	return server.WithRateLimiter(rl)
}

// WithUserRateLimiter configures the user-based rate limiter for
// authenticated requests. See [server.WithUserRateLimiter].
func WithUserRateLimiter(rl *security.RateLimiter) ServerOption {
	return server.WithUserRateLimiter(rl)
}

// WithSecurityEventRateLimiter configures the rate limiter that bounds
// security-event log emission. See [server.WithSecurityEventRateLimiter].
func WithSecurityEventRateLimiter(rl *security.RateLimiter) ServerOption {
	return server.WithSecurityEventRateLimiter(rl)
}

// WithClientRegistrationRateLimiter configures the registration rate limiter.
// See [server.WithClientRegistrationRateLimiter].
func WithClientRegistrationRateLimiter(rl *security.ClientRegistrationRateLimiter) ServerOption {
	return server.WithClientRegistrationRateLimiter(rl)
}

// WithMetadataFetchRateLimiter configures the per-domain rate limiter
// for client-metadata-document fetches.
// See [server.WithMetadataFetchRateLimiter].
func WithMetadataFetchRateLimiter(rl *security.RateLimiter) ServerOption {
	return server.WithMetadataFetchRateLimiter(rl)
}

// WithSessionCreationHandler registers a callback that fires when a new
// token family is created. See [server.WithSessionCreationHandler].
func WithSessionCreationHandler(h server.SessionCreationHandler) ServerOption {
	return server.WithSessionCreationHandler(h)
}

// WithSessionRevocationHandler registers a callback that fires when a
// token family is revoked. See [server.WithSessionRevocationHandler].
func WithSessionRevocationHandler(h server.SessionRevocationHandler) ServerOption {
	return server.WithSessionRevocationHandler(h)
}

// WithTokenRefreshHandler registers a callback that fires after a provider
// token is refreshed. See [server.WithTokenRefreshHandler].
func WithTokenRefreshHandler(h server.TokenRefreshHandler) ServerOption {
	return server.WithTokenRefreshHandler(h)
}

// WithInstrumentation installs an OpenTelemetry pipeline on the server.
// Build it with instrumentation.New and pass it here.
// See [server.WithInstrumentation].
func WithInstrumentation(inst *instrumentation.Instrumentation) ServerOption {
	return server.WithInstrumentation(inst)
}

// NewServer creates a new OAuth server. See [server.New].
func NewServer(
	provider providers.Provider,
	tokenStore storage.TokenStore,
	clientStore storage.ClientStore,
	flowStore storage.FlowStore,
	config *ServerConfig,
	logger *slog.Logger,
	opts ...ServerOption,
) (*Server, error) {
	return server.New(provider, tokenStore, clientStore, flowStore, config, logger, opts...)
}

// NewServerWithCombined is a convenience wrapper for [server.NewWithCombined]
// — the additive constructor that takes a [storage.Combined] backend instead
// of three separate store arguments. Use it when your backend (memory, valkey,
// or anything else) implements all three storage interfaces.
func NewServerWithCombined(
	provider providers.Provider,
	store storage.Combined,
	config *ServerConfig,
	logger *slog.Logger,
	opts ...ServerOption,
) (*Server, error) {
	return server.NewWithCombined(provider, store, config, logger, opts...)
}
