package server

import (
	"net"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Option configures a Server during construction.
type Option func(*Server)

// WithAuditor sets the security auditor used for OAuth audit events.
// Passing nil panics; use security.NewAuditor(nil, false) for a noop.
func WithAuditor(aud *security.Auditor) Option {
	if aud == nil {
		panic("WithAuditor: nil auditor; use security.NewAuditor(nil, false) for a noop")
	}
	return func(s *Server) { s.auditor = aud }
}

// WithRateLimiter sets the IP-based rate limiter consulted on every
// authenticated request.
func WithRateLimiter(rl *security.RateLimiter) Option {
	return func(s *Server) { s.rateLimiter = rl }
}

// WithUserRateLimiter sets the user-based rate limiter applied after
// authentication. Use alongside WithRateLimiter for layered protection.
func WithUserRateLimiter(rl *security.RateLimiter) Option {
	return func(s *Server) { s.userRateLimiter = rl }
}

// WithSecurityEventRateLimiter sets the rate limiter that bounds the
// emission of security-event log lines. Prevents log flooding from
// repeated failures (e.g. a malformed-token attack against /oauth/token).
func WithSecurityEventRateLimiter(rl *security.RateLimiter) Option {
	return func(s *Server) { s.securityEventRateLimiter = rl }
}

// WithClientRegistrationRateLimiter sets the time-windowed rate limiter
// for /oauth/register. Prevents resource exhaustion via repeated
// registration / deletion cycles.
func WithClientRegistrationRateLimiter(rl *security.ClientRegistrationRateLimiter) Option {
	return func(s *Server) { s.clientRegistrationRateLimiter = rl }
}

// WithMetadataFetchRateLimiter sets the per-domain rate limiter for
// Client ID Metadata Document fetches. Prevents abuse via repeated
// metadata fetches from many distinct URLs.
func WithMetadataFetchRateLimiter(rl *security.RateLimiter) Option {
	return func(s *Server) { s.metadataFetchRateLimiter = rl }
}

// WithSessionCreationHandler registers a callback that fires synchronously
// when a new token family is created during authorization-code exchange.
// The handler is only invoked when the token store implements
// storage.RefreshTokenFamilyStore; a startup warning is logged if the
// configured store does not support families.
func WithSessionCreationHandler(handler SessionCreationHandler) Option {
	return func(s *Server) {
		s.sessionCreationHandler = handler
		if handler == nil {
			return
		}
		if _, ok := s.tokenStore.(storage.RefreshTokenFamilyStore); !ok {
			s.logger.Warn("SessionCreationHandler registered but token store does not support refresh token families -- handler will never fire")
		}
	}
}

// WithSessionRevocationHandler registers a callback that fires when a
// token family is revoked (e.g. on logout or reuse detection). Lets
// consumers clean up per-session state keyed on the family ID.
func WithSessionRevocationHandler(handler SessionRevocationHandler) Option {
	return func(s *Server) { s.sessionRevocationHandler = handler }
}

// WithTokenRefreshHandler registers a callback that fires after a
// provider token is refreshed (proactively near expiry, or reactively
// when an expired token is encountered during validation). userID and
// familyID are populated only when the token store implements
// storage.TokenMetadataGetter; a startup warning is logged otherwise.
func WithTokenRefreshHandler(handler TokenRefreshHandler) Option {
	return func(s *Server) {
		s.tokenRefreshHandler = handler
		if handler == nil {
			return
		}
		if _, ok := s.tokenStore.(storage.TokenMetadataGetter); !ok {
			s.logger.Warn("TokenRefreshHandler registered but token store does not support TokenMetadataGetter -- handler will not receive userID/familyID")
		}
	}
}

// WithTrustedIssuers registers an OIDCValidator built from issuers for
// urn:ietf:params:oauth:token-type:id_token,
// urn:ietf:params:oauth:token-type:access_token, and
// urn:ietf:params:oauth:token-type:jwt subject_token_type values.
// All three types are registered against the same validator, so workload JWT
// exchange (projected SA tokens, GHA OIDC) is implicitly enabled for every
// issuer listed here. Use TrustedIssuer.AllowedClaims to restrict which tokens
// are accepted per issuer. These validators are consulted by the RFC 8693
// token-exchange handler.
func WithTrustedIssuers(issuers []TrustedIssuer) Option {
	return func(s *Server) {
		v, err := NewOIDCValidator(issuers)
		if err != nil {
			s.logger.Error("failed to initialise trusted issuer validator", "error", err)
			return
		}
		if s.subjectValidators == nil {
			s.subjectValidators = make(map[string]SubjectTokenValidator)
		}
		s.subjectValidators[SubjectTokenTypeIDToken] = v
		s.subjectValidators[SubjectTokenTypeAccessToken] = v
		s.subjectValidators[SubjectTokenTypeJWT] = v
	}
}

// WithSubjectTokenValidator registers a custom SubjectTokenValidator for the
// given subject_token_type URN. Use this to register a custom validator
// alongside or instead of OIDCValidator.
func WithSubjectTokenValidator(tokenType string, v SubjectTokenValidator) Option {
	return func(s *Server) {
		if s.subjectValidators == nil {
			s.subjectValidators = make(map[string]SubjectTokenValidator)
		}
		s.subjectValidators[tokenType] = v
	}
}

// WithDPoPReplayCache sets the DPoP proof replay cache. When set, the server
// uses this cache to detect replayed DPoP proofs across requests. When not
// set, each request creates a transient in-memory cache with no cross-request
// replay protection — use NewMemoryDPoPReplayCache() for single-process
// deployments, or a Valkey-backed implementation for multi-instance deployments.
func WithDPoPReplayCache(cache DPoPReplayCache) Option {
	return func(s *Server) {
		s.dpopReplayCache = cache
	}
}

// WithDPoPNonceProvider enables RFC 9449 §8 nonce enforcement. When set,
// [ValidateDPoPProof] requires every DPoP proof to carry a currently-valid
// server-issued nonce; proofs without one are rejected with [ErrDPoPNonceInvalid].
// Pass [NewHMACNonceProvider] for a stateless HMAC-based implementation.
func WithDPoPNonceProvider(provider DPoPNonceProvider) Option {
	return func(s *Server) {
		s.dpopNonceProvider = provider
	}
}

// WithTrustedProxyCIDRs registers the CIDRs from which X-Forwarded-Proto and
// X-Forwarded-Host headers are trusted for DPoP htu URL reconstruction. Required
// when the server runs behind agw, Envoy, or any reverse proxy that terminates TLS.
// Leave unset (or pass nil) when the server is directly exposed.
func WithTrustedProxyCIDRs(cidrs []*net.IPNet) Option {
	return func(s *Server) {
		s.trustedProxyCIDRs = cidrs
	}
}

// WithInstrumentation installs an OpenTelemetry pipeline on the server.
// Build the *instrumentation.Instrumentation with instrumentation.New and
// pass it here. The same instance should be passed to the storage constructor
// (memory.WithInstrumentation / valkey.WithInstrumentation) so both the
// server and the store share one pipeline.
func WithInstrumentation(inst *instrumentation.Instrumentation) Option {
	return func(s *Server) {
		s.instrumentation = inst
		if inst == nil {
			return
		}
		s.tracer = inst.Tracer("server")
	}
}
