package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/giantswarm/mcp-oauth/instrumentation"
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
	provider                      providers.Provider
	tokenStore                    storage.TokenStore
	clientStore                   storage.ClientStore
	flowStore                     storage.FlowStore
	Encryptor                     *security.Encryptor
	Auditor                       *security.Auditor
	RateLimiter                   *security.RateLimiter                   // IP-based rate limiter
	UserRateLimiter               *security.RateLimiter                   // User-based rate limiter (authenticated requests)
	SecurityEventRateLimiter      *security.RateLimiter                   // Rate limiter for security event logging (DoS prevention)
	ClientRegistrationRateLimiter *security.ClientRegistrationRateLimiter // Time-windowed rate limiter for client registrations
	Instrumentation               *instrumentation.Instrumentation        // OpenTelemetry instrumentation
	tracer                        trace.Tracer                            // OpenTelemetry tracer for server operations
	Logger                        *slog.Logger
	Config                        *Config
	shutdownOnce                  sync.Once // Ensures Shutdown is called only once
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

	// Initialize instrumentation if enabled
	if config.Instrumentation.Enabled {
		instConfig := instrumentation.Config{
			Enabled:        true,
			ServiceName:    config.Instrumentation.ServiceName,
			ServiceVersion: config.Instrumentation.ServiceVersion,
			LogClientIPs:   config.Instrumentation.LogClientIPs,
		}
		if instConfig.ServiceName == "" {
			instConfig.ServiceName = "mcp-oauth"
		}
		if instConfig.ServiceVersion == "" {
			instConfig.ServiceVersion = "unknown"
		}

		inst, err := instrumentation.New(instConfig)
		if err != nil {
			logger.Warn("Failed to initialize instrumentation, continuing without it", "error", err)
		} else {
			srv.Instrumentation = inst
			srv.tracer = inst.Tracer("server")

			// Propagate instrumentation to storage layers
			type instrumentationSetter interface {
				SetInstrumentation(*instrumentation.Instrumentation)
			}
			if setter, ok := tokenStore.(instrumentationSetter); ok {
				setter.SetInstrumentation(inst)
			}
			if setter, ok := clientStore.(instrumentationSetter); ok {
				setter.SetInstrumentation(inst)
			}
			if setter, ok := flowStore.(instrumentationSetter); ok {
				setter.SetInstrumentation(inst)
			}

			logger.Info("Instrumentation initialized",
				"service_name", instConfig.ServiceName,
				"service_version", instConfig.ServiceVersion)
		}
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

// SetClientRegistrationRateLimiter sets the time-windowed rate limiter for client registrations
// This prevents resource exhaustion through repeated registration/deletion cycles
func (s *Server) SetClientRegistrationRateLimiter(rl *security.ClientRegistrationRateLimiter) {
	s.ClientRegistrationRateLimiter = rl
}

// SetInstrumentation sets the OpenTelemetry instrumentation for server and storage
func (s *Server) SetInstrumentation(inst *instrumentation.Instrumentation) {
	s.Instrumentation = inst
	if inst != nil {
		s.tracer = inst.Tracer("server")

		// Also set instrumentation on storage if it supports it
		type instrumentationSetter interface {
			SetInstrumentation(*instrumentation.Instrumentation)
		}
		if setter, ok := s.tokenStore.(instrumentationSetter); ok {
			setter.SetInstrumentation(inst)
		}
		if setter, ok := s.clientStore.(instrumentationSetter); ok {
			setter.SetInstrumentation(inst)
		}
		if setter, ok := s.flowStore.(instrumentationSetter); ok {
			setter.SetInstrumentation(inst)
		}
	}
}

const (
	// MinTokenBytes is the minimum number of random bytes required for secure tokens.
	// 32 bytes = 256 bits of entropy, which exceeds NIST recommendations for
	// cryptographic keys and is sufficient to prevent brute-force attacks.
	// Base64url encoding without padding produces 43 characters from 32 bytes.
	MinTokenBytes = 32
)

// generateRandomToken generates a cryptographically secure random token.
// It uses crypto/rand to generate 32 bytes (256 bits) of entropy and
// encodes them as a 43-character base64url string without padding.
//
// This function is used for all security-critical tokens:
//   - Authorization codes, access tokens, refresh tokens
//   - Token family IDs (for refresh token rotation)
//   - Provider state values (CSRF protection)
//   - Client IDs and secrets
//
// The function panics if the system's random number generator fails,
// which indicates a critical system-level security failure.
func generateRandomToken() string {
	b := make([]byte, MinTokenBytes)
	if _, err := rand.Read(b); err != nil {
		// CRITICAL: System RNG failure - cannot generate secure tokens
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Shutdown gracefully shuts down the server and all its components.
// It stops rate limiters, closes storage connections, and cleans up resources.
// Safe to call multiple times - only the first call will execute shutdown.
//
// The context parameter controls the shutdown timeout. If the context is cancelled
// or times out before shutdown completes, Shutdown returns the context error.
//
// IMPORTANT: This method only stops background goroutines (rate limiters, cleanup tasks).
// It does NOT handle in-flight HTTP requests. For production deployments, you should:
//
//  1. Stop accepting new connections (e.g., http.Server.Shutdown())
//  2. Wait for in-flight requests to complete
//  3. Call this method to clean up background processes
//
// Recommended production shutdown sequence:
//
//	// Step 1: Stop accepting new requests (with timeout)
//	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := httpServer.Shutdown(shutdownCtx); err != nil {
//	    log.Printf("HTTP server shutdown error: %v", err)
//	}
//
//	// Step 2: Clean up OAuth server background processes
//	if err := oauthServer.Shutdown(shutdownCtx); err != nil {
//	    log.Printf("OAuth server shutdown error: %v", err)
//	}
//
// Simple example for non-production use:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := server.Shutdown(ctx); err != nil {
//	    log.Printf("Shutdown error: %v", err)
//	}
func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErr error

	s.shutdownOnce.Do(func() {
		s.Logger.Info("Starting graceful shutdown...")

		// Create a channel to signal when shutdown is complete
		done := make(chan struct{})

		go func() {
			defer close(done)

			// Stop rate limiters
			if s.RateLimiter != nil {
				s.Logger.Debug("Stopping IP rate limiter...")
				s.RateLimiter.Stop()
			}
			if s.UserRateLimiter != nil {
				s.Logger.Debug("Stopping user rate limiter...")
				s.UserRateLimiter.Stop()
			}
			if s.SecurityEventRateLimiter != nil {
				s.Logger.Debug("Stopping security event rate limiter...")
				s.SecurityEventRateLimiter.Stop()
			}
			if s.ClientRegistrationRateLimiter != nil {
				s.Logger.Debug("Stopping client registration rate limiter...")
				s.ClientRegistrationRateLimiter.Stop()
			}

			// Shutdown instrumentation
			if s.Instrumentation != nil {
				s.Logger.Debug("Shutting down instrumentation...")
				if err := s.Instrumentation.Shutdown(ctx); err != nil {
					s.Logger.Warn("Failed to shutdown instrumentation", "error", err)
				}
			}

			// Stop storage cleanup goroutines if the store supports it
			type stoppableStore interface {
				Stop()
			}
			if store, ok := s.tokenStore.(stoppableStore); ok {
				s.Logger.Debug("Stopping storage cleanup...")
				store.Stop()
			}

			s.Logger.Info("Graceful shutdown completed")
		}()

		// Wait for shutdown to complete or context to be cancelled
		select {
		case <-done:
			// Shutdown completed successfully
		case <-ctx.Done():
			// Context cancelled or timed out
			shutdownErr = fmt.Errorf("shutdown cancelled: %w", ctx.Err())
			s.Logger.Warn("Shutdown timed out or was cancelled", "error", shutdownErr)
		}
	})

	return shutdownErr
}

// ShutdownWithTimeout is a convenience wrapper around Shutdown that creates
// a context with the specified timeout.
//
// Example usage:
//
//	if err := server.ShutdownWithTimeout(30 * time.Second); err != nil {
//	    log.Printf("Shutdown error: %v", err)
//	}
func (s *Server) ShutdownWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.Shutdown(ctx)
}
