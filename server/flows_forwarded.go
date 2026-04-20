package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// ErrTrustedAudienceMismatch is returned by [Server.AcceptForwardedIDToken] when the
// bearer token's `aud` claim does not match any entry in Config.TrustedAudiences.
// Callers should typically respond with 401.
var ErrTrustedAudienceMismatch = errors.New("forwarded ID token audience does not match TrustedAudiences")

// ForwardedIDTokenAcceptance is the verified result of accepting a JWT forwarded
// from a trusted upstream identity provider. It is returned by
// [Server.AcceptForwardedIDToken] and is safe to use for downstream routing, session
// keying, and audit-log correlation.
type ForwardedIDTokenAcceptance struct {
	// SessionID is a deterministic identifier derived from the bearer token:
	//   default: "ext-" + hex(sha256(token))[:16]
	//   with Config.SessionIDHMACKey set: "ext-" + hex(hmac-sha256(key, token))[:16]
	//
	// Two MCP servers receiving the same token compute the same SessionID, which
	// gives cross-hop audit-log correlation when an aggregator fans a single
	// forwarded token out to multiple downstream servers. See Config.SessionIDHMACKey
	// for the isolation escape hatch and the operator caveat around key agreement.
	SessionID string

	// Subject is the validated `sub` claim from the JWT. It equals UserInfo.ID and
	// is surfaced as a top-level field for callers that only need the subject.
	Subject string

	// UserInfo carries the other validated claims (email, name, groups, etc.) and
	// has TokenSource = TokenSourceSSO.
	UserInfo *providers.UserInfo

	// Issuer is the validated `iss` claim from the JWT.
	Issuer string

	// Audience is the entry of Config.TrustedAudiences that matched the token's `aud`.
	Audience string

	// ExpiresAt is the JWT `exp` claim, for caller-side session-cache TTLs. The
	// library does not refresh forwarded tokens — when a token expires, the caller
	// must propagate 401 so the MCP client re-authenticates.
	ExpiresAt time.Time
}

// AcceptForwardedIDToken validates a JWT forwarded from a trusted upstream identity
// provider and returns its verified claims plus a deterministic session identifier.
// It is the companion of the ValidateToken fast-path (server/flows.go:265) for the
// direct "accept this forwarded token" use case exposed to aggregators and bridges
// (e.g., Bedrock AgentCore → muster).
//
// Preconditions (documented here because operators configuring a new bridge look at
// this godoc first):
//
//  1. The configured provider implements [providers.JWKSProvider]. GitHub's provider
//     does not qualify (it is OAuth 2.0 only). Validation returns a "no JWKS" error
//     when invoked against an OAuth-only provider.
//  2. Config.TrustedAudiences contains the audience the upstream IdP minted the
//     token for.
//  3. The provider's IssuerURL() matches the JWT's `iss` claim. The signature check
//     requires this anyway.
//
// Scope (deliberate — pure function, no side effects):
//
//   - Does NOT fire SessionCreationHandler. That handler is gated on the
//     RefreshTokenFamilyStore interface and the authorization-code family lifecycle,
//     neither of which applies to forwarded tokens. Callers that want a first-seen
//     hook for a given SessionID should build that on top using their own
//     seen-set keyed on acceptance.SessionID with TTL bounded by acceptance.ExpiresAt.
//
//   - Does NOT mirror the token into TokenStore. TokenStore is keyed by userID and
//     is owned by the authorization-code flow. Aggregators that need to retrieve
//     the forwarded token later (e.g., to attach it to downstream MCP calls) must
//     store it in a structure they own, keyed however they like.
//
// Idempotency: the function is pure. Repeat calls with the same token return the
// same SessionID and emit the same audit event. Any "first call vs repeat"
// semantics live with the caller.
//
// Token expiry: the library does not refresh forwarded tokens. When the JWT
// expires, this function returns an error and the caller must propagate 401.
//
// Returns [ErrTrustedAudienceMismatch] when the token's `aud` does not match any
// entry in Config.TrustedAudiences. Other errors (signature invalid, issuer
// mismatch, JWT expired, provider has no JWKS, parse error) are returned wrapped.
func (s *Server) AcceptForwardedIDToken(ctx context.Context, bearerToken string) (*ForwardedIDTokenAcceptance, error) {
	// Early parse-shape check to distinguish parse_error from later failure modes
	// in the metric. validateAndParseForwardedIDToken handles the real parse too.
	if _, err := oidc.ParseUnverifiedClaims(bearerToken); err != nil {
		s.recordForwardedIDTokenAccepted("", "", instrumentation.ForwardedIDTokenResultParseError)
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	// Check JWKSProvider up front so the no_jwks classification is explicit and
	// can't be swallowed into a generic sig_invalid downstream.
	jwksProvider, ok := s.provider.(providers.JWKSProvider)
	if !ok {
		s.recordForwardedIDTokenAccepted("", "", instrumentation.ForwardedIDTokenResultNoJWKS)
		return nil, fmt.Errorf("provider %s does not support JWKS validation (required for forwarded ID token acceptance)", s.provider.Name())
	}

	claims, matchedAudience, err := s.validateAndParseForwardedIDToken(ctx, bearerToken)
	if err != nil {
		s.recordForwardedIDTokenAccepted(jwksProvider.IssuerURL(), "", classifyValidationError(err))
		return nil, err
	}
	if claims == nil {
		// No trusted audience matched — the caller asked us to accept a forwarded
		// token, so an audience mismatch is a hard error here (unlike the
		// ValidateToken fast-path which falls back to userinfo).
		s.recordForwardedIDTokenAccepted(jwksProvider.IssuerURL(), "", instrumentation.ForwardedIDTokenResultAudMismatch)
		return nil, ErrTrustedAudienceMismatch
	}

	userInfo := s.idTokenClaimsToUserInfo(claims)
	issuer := claims.Issuer

	var expiresAt time.Time
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}

	acceptance := &ForwardedIDTokenAcceptance{
		SessionID: s.deriveForwardedSessionID(bearerToken),
		Subject:   claims.Subject,
		UserInfo:  userInfo,
		Issuer:    issuer,
		Audience:  matchedAudience,
		ExpiresAt: expiresAt,
	}

	s.logForwardedIDTokenAccepted(bearerToken, matchedAudience, jwksProvider.IssuerURL(), userInfo)
	s.recordForwardedIDTokenAccepted(issuer, matchedAudience, instrumentation.ForwardedIDTokenResultOK)

	return acceptance, nil
}

// deriveForwardedSessionID produces the deterministic "ext-<hex16>" session identifier.
// Uses HMAC-SHA-256 when Config.SessionIDHMACKey is set, otherwise plain SHA-256.
// See the Config.SessionIDHMACKey godoc and docs/security.md for the correlation
// property and operator caveat.
func (s *Server) deriveForwardedSessionID(bearerToken string) string {
	var digest []byte
	if len(s.Config.SessionIDHMACKey) > 0 {
		mac := hmac.New(sha256.New, s.Config.SessionIDHMACKey)
		_, _ = mac.Write([]byte(bearerToken))
		digest = mac.Sum(nil)
	} else {
		sum := sha256.Sum256([]byte(bearerToken))
		digest = sum[:]
	}
	return "ext-" + hex.EncodeToString(digest[:8])
}

// recordForwardedIDTokenAccepted emits the forwarded-ID-token metric. Safe when
// Instrumentation is unconfigured. `result` MUST be one of the
// instrumentation.ForwardedIDTokenResult* constants.
func (s *Server) recordForwardedIDTokenAccepted(issuer, audience, result string) {
	if s.Instrumentation == nil {
		return
	}
	s.Instrumentation.Metrics().RecordForwardedIDTokenAccepted(context.Background(), issuer, audience, result)
}

// classifyValidationError maps an error from validateAndParseForwardedIDToken to
// one of the bounded result-enum values. Never returns raw error strings — label
// cardinality matters.
func classifyValidationError(err error) string {
	if err == nil {
		return instrumentation.ForwardedIDTokenResultOK
	}
	if errors.Is(err, jwt.ErrTokenExpired) {
		return instrumentation.ForwardedIDTokenResultExpired
	}
	if errors.Is(err, jwt.ErrTokenNotValidYet) {
		return instrumentation.ForwardedIDTokenResultSigInvalid
	}
	// validateIssuer in providers/oidc/jwt.go:575 returns a formatted error without
	// a sentinel; a substring match keeps this classification deterministic.
	if msg := err.Error(); strings.Contains(msg, "issuer mismatch") {
		return instrumentation.ForwardedIDTokenResultIssMismatch
	}
	return instrumentation.ForwardedIDTokenResultSigInvalid
}
