package server

import (
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Option configures a Server during construction. Options are applied
// after the server has been wired with stores, the access-token issuer,
// and the metadata support goroutine — so option functions that propagate
// state to the storage backend (WithEncryptor, WithInstrumentation) can
// rely on the store being attached.
type Option func(*Server)

// WithEncryptor sets the token encryptor on the server and propagates it
// to the token store when the store implements an SetEncryptor hook.
// Token-at-rest encryption applies to upstream provider tokens stored in
// TokenStore — the bearer the client holds is never the encrypted payload.
func WithEncryptor(enc *security.Encryptor) Option {
	return func(s *Server) {
		s.Encryptor = enc
		type encryptorSetter interface {
			SetEncryptor(*security.Encryptor)
		}
		if setter, ok := s.tokenStore.(encryptorSetter); ok {
			setter.SetEncryptor(enc)
		}
	}
}

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

// WithTrustedIssuers registers an OIDCValidator built from issuers for both
// urn:ietf:params:oauth:token-type:id_token and
// urn:ietf:params:oauth:token-type:access_token subject_token_type values.
// These validators are consulted by the RFC 8693 token-exchange handler.
func WithTrustedIssuers(issuers []TrustedIssuer) Option {
	return func(s *Server) {
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
	}
}

// WithSubjectTokenValidator registers a custom SubjectTokenValidator for the
// given subject_token_type URN. Use this to register K8sSAValidator or any
// other validator alongside or instead of OIDCValidator.
func WithSubjectTokenValidator(tokenType string, v SubjectTokenValidator) Option {
	return func(s *Server) {
		if s.subjectValidators == nil {
			s.subjectValidators = make(map[string]SubjectTokenValidator)
		}
		s.subjectValidators[tokenType] = v
	}
}

// WithKubernetesSATrust registers a K8sSAValidator for projected ServiceAccount
// tokens from the given clusters under the SubjectTokenTypeJWT token type.
func WithKubernetesSATrust(trusts []KubernetesSATrust) Option {
	return func(s *Server) {
		v, err := NewK8sSAValidator(trusts)
		if err != nil {
			s.Logger.Error("failed to initialise Kubernetes SA validator", "error", err)
			return
		}
		if s.subjectValidators == nil {
			s.subjectValidators = make(map[string]SubjectTokenValidator)
		}
		s.subjectValidators[SubjectTokenTypeJWT] = v
	}
}

// WithDPoPReplayCache sets the DPoP proof replay cache. When set, the server
// uses this cache to detect replayed DPoP proofs across requests. When not
// set, each request creates a transient in-memory cache with no cross-request
// replay protection — use NewMemoryDPoPReplayCache() for single-process
// deployments, or a Redis/Valkey-backed implementation for multi-instance deployments.
func WithDPoPReplayCache(cache DPoPReplayCache) Option {
	return func(s *Server) {
		s.dpopReplayCache = cache
	}
}

// WithInstrumentation installs an OpenTelemetry pipeline on the server.
// Build the *instrumentation.Instrumentation with instrumentation.New and
// pass it here. The same instance can be shared with other components in
// the process — that's the reason the OAuth library does not own the
// pipeline construction. Propagates the instrumentation to storage
// backends that implement SetInstrumentation.
func WithInstrumentation(inst *instrumentation.Instrumentation) Option {
	return func(s *Server) {
		s.Instrumentation = inst
		if inst == nil {
			return
		}
		s.tracer = inst.Tracer("server")

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
