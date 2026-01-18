package oidc

import "time"

// Default configuration constants for OIDC clients.
const (
	// DefaultCacheTTL is the default time-to-live for cached JWKS and discovery documents.
	DefaultCacheTTL = 1 * time.Hour

	// DefaultHTTPTimeout is the default timeout for HTTP requests to OIDC endpoints.
	DefaultHTTPTimeout = 10 * time.Second
)

// timeProvider is an interface for time operations to enable deterministic testing.
// This allows tests to control time without using time.Sleep or other non-deterministic methods.
type timeProvider interface {
	Now() time.Time
	Since(time.Time) time.Duration
}

// realTime implements timeProvider using actual system time.
// This is the default implementation used in production.
type realTime struct{}

func (realTime) Now() time.Time                  { return time.Now() }
func (realTime) Since(t time.Time) time.Duration { return time.Since(t) }
