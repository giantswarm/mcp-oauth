package oidc

import "time"

// Default configuration constants for OIDC clients.
const (
	// DefaultCacheTTL is the default time-to-live for cached JWKS and discovery documents.
	DefaultCacheTTL = 1 * time.Hour

	// DefaultHTTPTimeout is the default timeout for HTTP requests to OIDC endpoints.
	DefaultHTTPTimeout = 10 * time.Second

	// DefaultClockSkewLeeway is the default leeway for JWT time validation (exp, nbf, iat).
	// This accounts for clock drift between the token issuer and this server.
	// 30 seconds is a reasonable default that handles minor clock skew without
	// creating a significant security window.
	//
	// Security consideration: A larger leeway increases the window during which
	// an expired token might be accepted, but too small a leeway may cause
	// legitimate tokens to be rejected due to clock drift.
	DefaultClockSkewLeeway = 30 * time.Second
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
