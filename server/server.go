package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"

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

const (
	// MinTokenBytes is the minimum number of random bytes required for secure tokens.
	// 32 bytes = 256 bits of entropy, which exceeds NIST recommendations for
	// cryptographic keys and is sufficient to prevent brute-force attacks.
	// Base64url encoding without padding produces 43 characters from 32 bytes.
	MinTokenBytes = 32
)

// generateRandomToken generates a cryptographically secure random token with
// explicit entropy validation. This function is used for all security-critical
// tokens including:
//   - Authorization codes (one-time use codes)
//   - Access tokens and refresh tokens
//   - Token family IDs (for refresh token rotation tracking)
//   - Provider state values (CSRF protection)
//   - Client IDs and client secrets
//
// Security Properties:
//   - Uses crypto/rand.Read() for cryptographically secure randomness
//   - Generates exactly 32 bytes (256 bits) of entropy
//   - Base64url encodes without padding (RFC 4648) producing 43 characters
//   - Panics if crypto/rand fails (indicates system-level security failure)
//
// The function panics rather than returning an error because token generation
// failure represents a critical security failure that should halt execution
// immediately rather than risk generating weak or predictable tokens.
//
// Returns: A 43-character base64url-encoded string (no padding)
func generateRandomToken() string {
	// Allocate buffer for random bytes
	b := make([]byte, MinTokenBytes)

	// Read cryptographically secure random bytes
	// crypto/rand.Read only returns an error if the system's random number
	// generator fails, which indicates a severe system-level problem
	n, err := rand.Read(b)
	if err != nil {
		// CRITICAL: System random number generator failed
		// This is a security-critical failure - we must not proceed
		panic(fmt.Sprintf("CRITICAL SECURITY FAILURE: crypto/rand.Read failed: %v", err))
	}

	// Validate that we got the expected number of bytes
	// This should never happen (rand.Read guarantees to fill the buffer or return error),
	// but we validate to ensure we have sufficient entropy
	if n != MinTokenBytes {
		panic(fmt.Sprintf("CRITICAL SECURITY FAILURE: crypto/rand.Read returned %d bytes, expected %d", n, MinTokenBytes))
	}

	// Encode using base64url without padding (RFC 4648)
	// This produces a 43-character URL-safe string from 32 bytes
	token := base64.RawURLEncoding.EncodeToString(b)

	// Validate encoded token length
	// 32 bytes base64url-encoded (no padding) = 43 characters
	// ceil(32 * 8 / 6) = ceil(42.67) = 43
	if len(token) < 43 {
		// This should never happen with correct base64 encoding
		panic(fmt.Sprintf("CRITICAL SECURITY FAILURE: generated token has insufficient length: %d chars (expected 43+)", len(token)))
	}

	return token
}
