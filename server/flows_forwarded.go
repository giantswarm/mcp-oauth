package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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

// errForwardedTokenParseFailed wraps the underlying parser error so
// [classifyForwardedTokenError] can distinguish "not a JWT" from later
// validation failures without a second parse.
var errForwardedTokenParseFailed = errors.New("forwarded ID token parse failed")

// Session-ID derivation: the library publishes a stable format for
// ForwardedIDTokenAcceptance.SessionID so downstream servers receiving the
// same token derive the same ID (cross-hop audit correlation). To keep the
// key reusable for other purposes later, the input is domain-separated with
// a versioned label.
const (
	// forwardedSessionIDLabel is the domain-separation label written BEFORE
	// the bearer token bytes into both the SHA-256 and HMAC-SHA-256
	// derivations. Versioned so a future format change can be distinguished.
	forwardedSessionIDLabel = "mcp-oauth/v1/forwarded-session-id"

	// sessionIDDigestBytes is the truncation length of the digest output
	// (64 bits → 16 hex chars). Chosen for audit-log correlation, not as a
	// security boundary: birthday collision is ~1-in-a-million at ~6.5k
	// concurrent distinct tokens, which is comfortable for per-server active
	// sessions. If a deployment needs stronger collision resistance, it
	// should raise this and coordinate the change across all servers sharing
	// SessionIDHMACKey.
	sessionIDDigestBytes = 8
)

// ForwardedIDTokenAcceptance is the verified result of accepting a JWT forwarded
// from a trusted upstream identity provider. It is returned by
// [Server.AcceptForwardedIDToken] and is safe to use for downstream routing, session
// keying, and audit-log correlation.
type ForwardedIDTokenAcceptance struct {
	// SessionID is a deterministic identifier of the form "ext-<16 hex chars>"
	// derived from a domain-separated hash of the bearer token:
	//   default: first sessionIDDigestBytes of sha256(forwardedSessionIDLabel || 0x00 || token)
	//   with Config.SessionIDHMACKey set: same input, HMAC-SHA-256 with the key
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

	// Issuer is the validated `iss` claim from the JWT. Equals the configured
	// provider's IssuerURL() — the signature check enforces that equality, so
	// this field never carries an unverified value.
	Issuer string

	// Audience is the entry of Config.TrustedAudiences that matched the token's
	// `aud` claim (not the raw aud claim itself, which may contain multiple
	// values). Suitable for metric labels and audit records.
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
// mismatch, JWT expired, JWT not yet valid, provider has no JWKS, parse error)
// are returned wrapped.
func (s *Server) AcceptForwardedIDToken(ctx context.Context, bearerToken string) (*ForwardedIDTokenAcceptance, error) {
	providerName := s.provider.Name()

	if bearerToken == "" {
		err := errors.New("forwarded ID token must not be empty")
		s.recordForwardedIDTokenAccepted(ctx, providerName, "", "", instrumentation.ForwardedIDTokenResultParseError)
		return nil, err
	}

	// Fail fast when the provider cannot verify JWTs. Using providers.IssuerOf
	// both matches the sibling fast-path's intent and exercises the in-tree
	// helper (instead of re-doing a type assertion here).
	expectedIssuer := providers.IssuerOf(s.provider)
	if expectedIssuer == "" {
		s.recordForwardedIDTokenAccepted(ctx, providerName, "", "", instrumentation.ForwardedIDTokenResultNoJWKS)
		return nil, fmt.Errorf("provider %s does not support JWKS validation (required for forwarded ID token acceptance)", providerName)
	}

	claims, matchedAudience, err := s.validateAndParseForwardedIDToken(ctx, bearerToken)
	if err != nil {
		s.recordForwardedIDTokenAccepted(ctx, providerName, expectedIssuer, "", classifyForwardedTokenError(err))
		return nil, err
	}
	if claims == nil {
		// No trusted audience matched — the caller asked us to accept a forwarded
		// token, so an audience mismatch is a hard error here (unlike the
		// ValidateToken fast-path which falls back to userinfo).
		s.recordForwardedIDTokenAccepted(ctx, providerName, expectedIssuer, "", instrumentation.ForwardedIDTokenResultAudMismatch)
		return nil, ErrTrustedAudienceMismatch
	}

	userInfo := s.idTokenClaimsToUserInfo(claims)

	var expiresAt time.Time
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Time
	}

	acceptance := &ForwardedIDTokenAcceptance{
		SessionID: s.deriveForwardedSessionID(bearerToken),
		Subject:   claims.Subject,
		UserInfo:  userInfo,
		Issuer:    claims.Issuer,
		Audience:  matchedAudience,
		ExpiresAt: expiresAt,
	}

	s.logForwardedIDTokenAccepted(bearerToken, matchedAudience, expectedIssuer, userInfo)
	s.recordForwardedIDTokenAccepted(ctx, providerName, claims.Issuer, matchedAudience, instrumentation.ForwardedIDTokenResultOK)

	return acceptance, nil
}

// deriveForwardedSessionID produces the deterministic "ext-<hex>" session
// identifier. See the SessionID field godoc and docs/security.md for the
// correlation property and the SessionIDHMACKey operator caveat.
//
// The input is domain-separated so Config.SessionIDHMACKey can be safely reused
// for other keyed derivations without risking cross-purpose collisions.
// hash.Hash.Write never returns an error — the doc on hash.Hash guarantees it —
// so the results are ignored.
func (s *Server) deriveForwardedSessionID(bearerToken string) string {
	var digest []byte
	if len(s.Config.SessionIDHMACKey) > 0 {
		mac := hmac.New(sha256.New, s.Config.SessionIDHMACKey)
		_, _ = mac.Write([]byte(forwardedSessionIDLabel))
		_, _ = mac.Write([]byte{0x00})
		_, _ = mac.Write([]byte(bearerToken))
		digest = mac.Sum(nil)
	} else {
		h := sha256.New()
		_, _ = h.Write([]byte(forwardedSessionIDLabel))
		_, _ = h.Write([]byte{0x00})
		_, _ = h.Write([]byte(bearerToken))
		digest = h.Sum(nil)
	}
	return "ext-" + hex.EncodeToString(digest[:sessionIDDigestBytes])
}

// recordForwardedIDTokenAccepted emits the forwarded-ID-token metric. Safe when
// Instrumentation is unconfigured. Threads ctx through so OTel trace correlation
// survives on the metric.
func (s *Server) recordForwardedIDTokenAccepted(ctx context.Context, provider, issuer, audience string, result instrumentation.ForwardedIDTokenResult) {
	if s.Instrumentation == nil {
		return
	}
	s.Instrumentation.Metrics().RecordForwardedIDTokenAccepted(ctx, provider, issuer, audience, result)
}

// classifyForwardedTokenError maps an error from the validator to one of the
// bounded result-enum values. Uses errors.Is sentinels throughout — no string
// matching — so the mapping survives upstream message tweaks.
func classifyForwardedTokenError(err error) instrumentation.ForwardedIDTokenResult {
	switch {
	case err == nil:
		return instrumentation.ForwardedIDTokenResultOK
	case errors.Is(err, errForwardedTokenParseFailed):
		return instrumentation.ForwardedIDTokenResultParseError
	case errors.Is(err, oidc.ErrIssuerMismatch):
		return instrumentation.ForwardedIDTokenResultIssMismatch
	case errors.Is(err, jwt.ErrTokenExpired):
		return instrumentation.ForwardedIDTokenResultExpired
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return instrumentation.ForwardedIDTokenResultNotYetValid
	default:
		return instrumentation.ForwardedIDTokenResultSigInvalid
	}
}
