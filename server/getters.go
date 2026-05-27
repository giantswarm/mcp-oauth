package server

import (
	"log/slog"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
)

func (s *Server) Auditor() *security.Auditor { return s.auditor }

func (s *Server) RateLimiter() *security.RateLimiter { return s.rateLimiter }

func (s *Server) UserRateLimiter() *security.RateLimiter { return s.userRateLimiter }

func (s *Server) SecurityEventRateLimiter() *security.RateLimiter { return s.securityEventRateLimiter }

func (s *Server) ClientRegistrationRateLimiter() *security.ClientRegistrationRateLimiter {
	return s.clientRegistrationRateLimiter
}

func (s *Server) Instrumentation() *instrumentation.Instrumentation { return s.instrumentation }

func (s *Server) Logger() *slog.Logger { return s.logger }

func (s *Server) Config() *Config { return s.config }
