package server

import (
	"fmt"
	"log/slog"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Server implements the OAuth 2.1 server logic (provider-agnostic).
// It coordinates the OAuth flow using a Provider and storage backends.
type Server struct {
	provider        providers.Provider
	tokenStore      storage.TokenStore
	clientStore     storage.ClientStore
	flowStore       storage.FlowStore
	Encryptor       *security.Encryptor
	Auditor         *security.Auditor
	RateLimiter     *security.RateLimiter // IP-based rate limiter
	UserRateLimiter *security.RateLimiter // User-based rate limiter (authenticated requests)
	Logger          *slog.Logger
	Config          *Config
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

	return &Server{
		provider:    provider,
		tokenStore:  tokenStore,
		clientStore: clientStore,
		flowStore:   flowStore,
		Config:      config,
		Logger:      logger,
	}, nil
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

// generateRandomToken generates a cryptographically secure random token
// For PKCE verifiers, use oauth2.GenerateVerifier() instead
func generateRandomToken() string {
	// Uses same method as oauth2.GenerateVerifier() for consistency
	return oauth2.GenerateVerifier()
}

// minInt returns the minimum of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
