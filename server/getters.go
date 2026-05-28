package server

import (
	"log/slog"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
)

// Auditor returns the server's security event auditor.
func (s *Server) Auditor() *security.Auditor { return s.auditor }

// RateLimiter returns the IP-based rate limiter, or nil if not configured.
func (s *Server) RateLimiter() *security.RateLimiter { return s.rateLimiter }

// UserRateLimiter returns the per-user (client_id) rate limiter, or nil if not configured.
func (s *Server) UserRateLimiter() *security.RateLimiter { return s.userRateLimiter }

// SecurityEventRateLimiter returns the rate limiter for security event logging, or nil if not configured.
func (s *Server) SecurityEventRateLimiter() *security.RateLimiter { return s.securityEventRateLimiter }

// ClientRegistrationRateLimiter returns the time-windowed client registration rate limiter, or nil if not configured.
func (s *Server) ClientRegistrationRateLimiter() *security.ClientRegistrationRateLimiter {
	return s.clientRegistrationRateLimiter
}

// Instrumentation returns the OpenTelemetry instrumentation bundle. Never nil after New().
func (s *Server) Instrumentation() *instrumentation.Instrumentation { return s.instrumentation }

// Logger returns the server's structured logger.
func (s *Server) Logger() *slog.Logger { return s.logger }
