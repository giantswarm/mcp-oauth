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
	return func(s *Server) { s.Auditor = aud }
}

// WithRateLimiter sets the IP-based rate limiter consulted on every
// authenticated request.
func WithRateLimiter(rl *security.RateLimiter) Option {
	return func(s *Server) { s.RateLimiter = rl }
}

// WithUserRateLimiter sets the user-based rate limiter applied after
// authentication. Use alongside WithRateLimiter for layered protection.
func WithUserRateLimiter(rl *security.RateLimiter) Option {
	return func(s *Server) { s.UserRateLimiter = rl }
}

// WithSecurityEventRateLimiter sets the rate limiter that bounds the
// emission of security-event log lines. Prevents log flooding from
// repeated failures (e.g. a malformed-token attack against /oauth/token).
func WithSecurityEventRateLimiter(rl *security.RateLimiter) Option {
	return func(s *Server) { s.SecurityEventRateLimiter = rl }
}

// WithClientRegistrationRateLimiter sets the time-windowed rate limiter
// for /oauth/register. Prevents resource exhaustion via repeated
// registration / deletion cycles.
func WithClientRegistrationRateLimiter(rl *security.ClientRegistrationRateLimiter) Option {
	return func(s *Server) { s.ClientRegistrationRateLimiter = rl }
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
			s.Logger.Warn("SessionCreationHandler registered but token store does not support refresh token families -- handler will never fire")
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
			s.Logger.Warn("TokenRefreshHandler registered but token store does not support TokenMetadataGetter -- handler will not receive userID/familyID")
		}
	}
}

// WithTrustedIssuers registers external JWT issuers whose tokens this server
// accepts. The same validator is consulted in two places:
//
//   - RFC 8693 token exchange: subject_token of type id_token, access_token,
//     or jwt is routed to the matching issuer entry.
//   - ValidateToken: a Bearer JWT at /mcp is accepted when its iss matches
//     a configured entry. Signature is verified via the entry's JWKS; aud
//     is checked against AllowedAudiences (defaulting to the server's
//     ResourceIdentifier when empty); the typ header is checked against
//     AcceptedTypHeaders (default RFC 9068 typ=at+jwt).
//
// Use TrustedIssuer.AllowedClaims to constrain accepted subjects per issuer.
// Empty list is a no-op.
func WithTrustedIssuers(issuers []TrustedIssuer) Option {
	return func(s *Server) {
		if len(issuers) == 0 {
			return
		}
		v, err := NewOIDCValidator(issuers)
		if err != nil {
			s.Logger.Error("failed to initialise trusted issuer validator", "error", err)
			return
		}
		if s.subjectValidators == nil {
			s.subjectValidators = make(map[string]SubjectTokenValidator)
		}
		s.subjectValidators[SubjectTokenTypeIDToken] = v
		s.subjectValidators[SubjectTokenTypeAccessToken] = v
		s.subjectValidators[SubjectTokenTypeJWT] = v
		s.trustedIssuerValidator = v
	}
}

// WithExchanger enables the brokered RFC 8693 token-exchange flow. When a
// client sends an `audience` parameter with the token-exchange grant, the
// server validates the subject token, enforces the per-client audience
// allowlist (Config.TokenExchangeClientAudiences), and delegates the
// downstream exchange to e. The host owns the audience→downstream-issuer
// mapping; mcp-oauth owns validation, policy, and audit.
//
// Without this option, requests carrying an audience parameter are rejected
// with invalid_target.
func WithExchanger(e Exchanger) Option {
	return func(s *Server) { s.exchanger = e }
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
		s.Instrumentation = inst
		if inst == nil {
			return
		}
		s.tracer = inst.Tracer("server")
	}
}
