package server

import (
	"fmt"
	"log/slog"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// safeTruncate safely truncates a string to maxLen characters without panicking.
// Returns the original string if it's shorter than maxLen, otherwise returns
// the first maxLen characters. This prevents index out of bounds errors when logging.
func safeTruncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// Server implements the OAuth 2.1 server logic (provider-agnostic).
// It coordinates the OAuth flow using a Provider and storage backends.
type Server struct {
	provider                 providers.Provider
	tokenStore               storage.TokenStore
	clientStore              storage.ClientStore
	flowStore                storage.FlowStore
	Encryptor                *security.Encryptor
	Auditor                  *security.Auditor
	RateLimiter              *security.RateLimiter // IP-based rate limiter
	UserRateLimiter          *security.RateLimiter // User-based rate limiter (authenticated requests)
	SecurityEventRateLimiter *security.RateLimiter // Rate limiter for security event logging (DoS prevention)
	Logger                   *slog.Logger
	Config                   *Config
}

// New creates a new OAuth server
func New(
	provider providers.Provider,
	tokenStore storage.TokenStore,
	clientStore storage.ClientStore,
	flowStore storage.FlowStore,
	config *Config,
	logger *slog.Logger,
) (*Server, error) {
	if provider == nil {
		return nil, fmt.Errorf("provider is required")
	}
	if tokenStore == nil {
		return nil, fmt.Errorf("token store is required")
	}
	if clientStore == nil {
		return nil, fmt.Errorf("client store is required")
	}
	if flowStore == nil {
		return nil, fmt.Errorf("flow store is required")
	}
	if config == nil {
		config = &Config{}
	}

	if logger == nil {
		logger = slog.Default()
	}

	// Apply secure defaults
	config = applySecureDefaults(config, logger)

	srv := &Server{
		provider:    provider,
		tokenStore:  tokenStore,
		clientStore: clientStore,
		flowStore:   flowStore,
		Config:      config,
		Logger:      logger,
	}

	// Validate HTTPS enforcement (OAuth 2.1 security requirement)
	if err := srv.validateHTTPSEnforcement(); err != nil {
		return nil, err
	}

	// Configure storage retention if storage supports it
	type retentionSetter interface {
		SetRevokedFamilyRetentionDays(days int64)
	}
	if setter, ok := tokenStore.(retentionSetter); ok {
		setter.SetRevokedFamilyRetentionDays(config.RevokedFamilyRetentionDays)
	}

	return srv, nil
}

// SetEncryptor sets the token encryptor for server and storage
func (s *Server) SetEncryptor(enc *security.Encryptor) {
	s.Encryptor = enc

	// Also set encryptor on storage if it's a memory store
	type encryptorSetter interface {
		SetEncryptor(*security.Encryptor)
	}
	if setter, ok := s.tokenStore.(encryptorSetter); ok {
		setter.SetEncryptor(enc)
	}
}

// SetAuditor sets the security auditor
func (s *Server) SetAuditor(aud *security.Auditor) {
	s.Auditor = aud
}

// SetRateLimiter sets the IP-based rate limiter
func (s *Server) SetRateLimiter(rl *security.RateLimiter) {
	s.RateLimiter = rl
}

// SetUserRateLimiter sets the user-based rate limiter for authenticated requests
func (s *Server) SetUserRateLimiter(rl *security.RateLimiter) {
	s.UserRateLimiter = rl
}

// SetSecurityEventRateLimiter sets the rate limiter for security event logging
// This prevents DoS attacks via log flooding from repeated security events
func (s *Server) SetSecurityEventRateLimiter(rl *security.RateLimiter) {
	s.SecurityEventRateLimiter = rl
}

// generateRandomToken generates a cryptographically secure random token.
// This is an alias for oauth2.GenerateVerifier() which produces a URL-safe,
// base64-encoded random string suitable for tokens, state parameters, etc.
func generateRandomToken() string {
	return oauth2.GenerateVerifier()
}
