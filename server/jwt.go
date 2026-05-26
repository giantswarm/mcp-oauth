package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// errBearerNotSelfIssuedJWT signals "this bearer is a JWT but not one we
// issued" so ValidateToken can fall through to the next validation branch
// (forwarded ID token / opaque storage). Wrapping it lets callers
// distinguish "skip to next branch" from "verified-bad and reject".
var errBearerNotSelfIssuedJWT = errors.New("bearer is not a self-issued access token")

// looksLikeSelfIssuedJWT does an unverified parse to peek at the iss claim.
// Returns true when the bearer's iss matches Config.Issuer — i.e. when this
// server (or another instance sharing the same issuer URL) signed it.
//
// The unverified parse is safe here because:
//   - We do not trust any field for an authorization decision based on this
//     peek; the verified parse below re-checks signature, iss, exp, aud.
//   - The peek decides only which validation branch to take.
//
// Returns false for non-JWT inputs and for JWTs whose iss is something else
// (forwarded ID tokens from upstream IdPs land here).
func (s *Server) looksLikeSelfIssuedJWT(tokenString string) bool {
	if !oidc.IsJWT(tokenString) {
		return false
	}
	claims, err := oidc.ParseUnverifiedClaims(tokenString)
	if err != nil {
		return false
	}
	iss, _ := claims["iss"].(string)
	return iss != "" && iss == s.Config.Issuer
}

// validateSelfIssuedJWT verifies a bearer that this server (or a peer
// sharing the same Config.Issuer and signing key) minted. The validation
// pipeline is the security boundary for JWT-mode access tokens:
//
//  1. Signature (alg+kid pinned to the configured signing key)
//  2. typ header == "at+jwt" (RFC 9068 §2.1; rejects id_token confusion)
//  3. iss claim == Config.Issuer
//  4. exp claim within ClockSkewGracePeriod
//  5. aud claim matches Config.GetResourceIdentifier or any TrustedAudience
//     (RFC 8707 audience binding, parity with the opaque branch)
//  6. jti not in RevokedTokenStore (RFC 7009 revocation)
//  7. family_id, when present, refers to a non-revoked token family
//     (defense in depth — invalidates in-flight access tokens when the
//     refresh-token family is revoked)
//
// Returns errBearerNotSelfIssuedJWT (wrapped) when the bearer is a JWT but
// fails one of the format checks that mean "not ours" (wrong iss, missing
// typ, signature mismatch). Returns the wrapped underlying error for hard
// rejections (revoked, expired, audience mismatch). Callers treat the
// former as "fall through" and the latter as "reject".
//
// Returns the verified claim map alongside the UserInfo so callers that
// need claim-level access (introspection, audit) don't need to re-parse +
// re-verify the token, which would risk drift between the two pipelines.
func (s *Server) validateSelfIssuedJWT(ctx context.Context, tokenString string) (*providers.UserInfo, map[string]any, error) {
	if !s.Config.IsJWTAccessTokenFormat() {
		return nil, nil, errBearerNotSelfIssuedJWT
	}

	header, claims, err := s.parseAndVerifyJWTSignature(tokenString)
	if err != nil {
		return nil, nil, err
	}

	if err := s.checkJWTHeaderAndIssuer(header, claims); err != nil {
		return nil, nil, err
	}
	if err := s.checkJWTExpiration(ctx, claims, tokenString); err != nil {
		return nil, nil, err
	}
	if err := s.checkJWTAudience(ctx, claims, tokenString); err != nil {
		return nil, nil, err
	}
	jti, _ := claims["jti"].(string)
	if err := s.checkJWTRevocation(ctx, jti, tokenString); err != nil {
		return nil, nil, err
	}
	if err := s.checkJWTFamily(ctx, claims, tokenString); err != nil {
		return nil, nil, err
	}

	userInfo := userInfoFromJWTClaims(claims)
	s.logSelfIssuedJWTAccepted(ctx, tokenString, userInfo, jti)
	return userInfo, claims, nil
}

// parseAndVerifyJWTSignature parses the JWT and verifies the signature
// against the configured public key. The algorithm allowlist passed to
// jose.ParseSigned is exactly the one configured algorithm — any other alg
// (notably HS256, which would enable the alg-confusion attack) is rejected
// at parse time. The kid header is matched against the configured kid so
// a token signed with the right alg but a different kid cannot be replayed
// against this server.
//
// Returns the verified header and the claim map. Errors are wrapped with
// errBearerNotSelfIssuedJWT so callers above can distinguish "fall through
// to the next branch" from "verified-bad and reject".
func (s *Server) parseAndVerifyJWTSignature(tokenString string) (jose.Header, map[string]any, error) {
	expectedAlg := jose.SignatureAlgorithm(s.Config.AccessTokenSigningAlgorithm)
	expectedKID := s.Config.AccessTokenSigningKeyID
	publicKey := s.Config.AccessTokenSigningKey.Public()

	parsed, err := josejwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{expectedAlg})
	if err != nil {
		return jose.Header{}, nil, fmt.Errorf("%w: %w", errBearerNotSelfIssuedJWT, err)
	}
	if len(parsed.Headers) != 1 {
		return jose.Header{}, nil, fmt.Errorf("%w: expected single signature, got %d", errBearerNotSelfIssuedJWT, len(parsed.Headers))
	}
	header := parsed.Headers[0]
	if header.KeyID != expectedKID {
		return jose.Header{}, nil, fmt.Errorf("%w: unexpected kid %q (expected %q)", errBearerNotSelfIssuedJWT, header.KeyID, expectedKID)
	}

	claims := map[string]any{}
	if err := parsed.Claims(publicKey, &claims); err != nil {
		return jose.Header{}, nil, fmt.Errorf("%w: %w", errBearerNotSelfIssuedJWT, err)
	}
	return header, claims, nil
}

// checkJWTHeaderAndIssuer enforces the typ header and iss claim. typ is
// RFC 9068 §2.1 (access tokens MUST carry "at+jwt") so a stolen id_token
// cannot be substituted as an access token. iss is RFC 7519 §4.1.1.
func (s *Server) checkJWTHeaderAndIssuer(header jose.Header, claims map[string]any) error {
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if typ != rfc9068TokenType {
		return fmt.Errorf("%w: typ header is %q (expected %q)", errBearerNotSelfIssuedJWT, typ, rfc9068TokenType)
	}
	iss, _ := claims["iss"].(string)
	if iss != s.Config.Issuer {
		return fmt.Errorf("%w: iss claim is %q (expected %q)", errBearerNotSelfIssuedJWT, iss, s.Config.Issuer)
	}
	return nil
}

// checkJWTExpiration enforces exp with the same ClockSkewGracePeriod the
// opaque path uses, so tokens behave identically across formats.
func (s *Server) checkJWTExpiration(ctx context.Context, claims map[string]any, tokenString string) error {
	expVal, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("missing or invalid exp claim")
	}
	exp := time.Unix(int64(expVal), 0)
	gracePeriod := time.Duration(s.Config.ClockSkewGracePeriod) * time.Second
	if security.IsTokenExpiredWithGracePeriod(exp, gracePeriod) {
		s.logSelfIssuedJWTAuthFailure(ctx, "token_expired", tokenString)
		return fmt.Errorf("access token expired")
	}
	return nil
}

// checkJWTAudience enforces RFC 8707 audience binding. The token's aud
// claim must equal the server's ResourceIdentifier OR appear in
// TrustedAudiences. Multi-valued aud (RFC 7519 §4.1.3) is handled via
// helpers.FindMatchingAudience, matching the SSO-forwarded-ID-token path.
func (s *Server) checkJWTAudience(ctx context.Context, claims map[string]any, tokenString string) error {
	audiences := audiencesFromClaim(claims["aud"])
	if len(audiences) == 0 {
		s.logSelfIssuedJWTAuthFailure(ctx, "missing_aud", tokenString)
		return fmt.Errorf("token missing audience claim")
	}
	if helpers.AudienceMatchesResourceOrTrusted(audiences, s.Config.GetResourceIdentifier(), s.Config.TrustedAudiences) {
		return nil
	}
	s.logSelfIssuedJWTAuthFailure(ctx, "audience_mismatch", tokenString)
	return fmt.Errorf("token not intended for this resource server (RFC 8707 audience mismatch)")
}

// checkJWTRevocation rejects tokens whose jti is on the denylist. A nil
// revokedTokenStore (no backend support) is treated as an open denylist —
// the warning was logged at startup; rejecting all JWTs in that case
// would defeat the feature.
func (s *Server) checkJWTRevocation(ctx context.Context, jti, tokenString string) error {
	if s.revokedTokenStore == nil || jti == "" {
		return nil
	}
	revoked, err := s.revokedTokenStore.IsJTIRevoked(ctx, jti)
	if err != nil {
		s.Logger.Warn("Failed to check JWT revocation list",
			"error", err,
			"token_suffix", helpers.TokenSuffix(tokenString, 8))
		return fmt.Errorf("revocation check failed: %w", err)
	}
	if revoked {
		s.logSelfIssuedJWTAuthFailure(ctx, "token_revoked", tokenString)
		return fmt.Errorf("access token has been revoked")
	}
	return nil
}

// checkJWTFamily enforces refresh-token-family revocation when the JWT
// carries a family_id claim. Lets a /oauth/revoke on the refresh token
// invalidate all in-flight access tokens in the family — the defense in
// depth that motivated carrying family_id in the first place.
//
// JWTs do not carry the refresh token, only family_id, so the lookup uses
// the optional RefreshTokenFamilyByIDStore interface. Backends without
// that interface skip the check (memory and valkey both implement it; the
// startup warning already discourages running JWT mode without them). A
// missing family_id claim is also silently skipped — issuance only sets
// the claim when the token store supports families.
//
// Storage errors are treated as hard rejections (parity with
// checkJWTRevocation): a transient backend failure must not silently
// re-enable a revoked family. ErrRefreshTokenFamilyNotFound is the only
// "not present" signal and is treated as legit absence.
func (s *Server) checkJWTFamily(ctx context.Context, claims map[string]any, tokenString string) error {
	familyID, _ := claims["family_id"].(string)
	if familyID == "" {
		return nil
	}
	indexed, ok := s.tokenStore.(storage.RefreshTokenFamilyByIDStore)
	if !ok {
		return nil
	}
	meta, err := indexed.GetRefreshTokenFamilyByID(ctx, familyID)
	if errors.Is(err, storage.ErrRefreshTokenFamilyNotFound) {
		return nil
	}
	if err != nil {
		s.Logger.Warn("Failed to check JWT family revocation",
			"error", err,
			"family_id", familyID,
			"token_suffix", helpers.TokenSuffix(tokenString, 8))
		return fmt.Errorf("family revocation check failed: %w", err)
	}
	if meta == nil {
		return nil
	}
	if meta.Revoked {
		s.logSelfIssuedJWTAuthFailure(ctx, "family_revoked", tokenString)
		return fmt.Errorf("access token family has been revoked")
	}
	return nil
}

// audiencesFromClaim normalizes the aud claim shape. RFC 7519 §4.1.3
// allows aud to be either a string or an array of strings; this helper
// flattens both to []string so callers can treat them uniformly.
func audiencesFromClaim(v any) []string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// userInfoFromJWTClaims reconstructs UserInfo from validated JWT claims.
// TokenSource is set to TokenSourceJWT so downstream consumers can dispatch
// correctly (no TokenStore lookup will succeed for a JWT bearer).
func userInfoFromJWTClaims(claims map[string]any) *providers.UserInfo {
	info := &providers.UserInfo{
		TokenSource: providers.TokenSourceJWT,
	}
	if v, ok := claims["sub"].(string); ok {
		info.ID = v
	}
	if v, ok := claims["email"].(string); ok {
		info.Email = v
	}
	if v, ok := claims["email_verified"].(bool); ok {
		info.EmailVerified = v
	}
	if v, ok := claims["name"].(string); ok {
		info.Name = v
	}
	switch g := claims["groups"].(type) {
	case []string:
		info.Groups = append(info.Groups, g...)
	case []any:
		for _, e := range g {
			if s, ok := e.(string); ok {
				info.Groups = append(info.Groups, s)
			}
		}
	}
	return info
}

// logSelfIssuedJWTAccepted records a success event for audit trails. The
// jti is logged in full because it is short-lived metadata, not a
// credential — operators correlating audit events across services need the
// complete identifier.
func (s *Server) logSelfIssuedJWTAccepted(ctx context.Context, tokenString string, userInfo *providers.UserInfo, jti string) {
	s.Logger.Debug("Self-issued JWT access token validated",
		"user_id", userInfo.ID,
		"jti", jti,
		"token_suffix", helpers.TokenSuffix(tokenString, 8))

	s.Auditor.LogEvent(ctx, security.Event{
		Type:   security.EventSelfIssuedJWTAccepted,
		UserID: userInfo.ID,
		Details: map[string]any{
			"validation_method": "self_issued_jwt",
			"jti":               jti,
		},
	})
}

// revokeSelfIssuedJWT extracts the jti and exp from a self-issued JWT and
// writes them to RevokedTokenStore. Returns true when the input was
// recognized as a self-issued JWT (regardless of whether the denylist
// write succeeded — RFC 7009 forbids surfacing the difference); returns
// false when the input is not a JWT or not one we issued, so the caller
// can fall through to opaque revocation.
func (s *Server) revokeSelfIssuedJWT(ctx context.Context, tokenString, clientID, clientIP string) bool {
	if !s.Config.IsJWTAccessTokenFormat() || !s.looksLikeSelfIssuedJWT(tokenString) {
		return false
	}
	if s.revokedTokenStore == nil {
		// Operator was warned at startup; we still consume the bearer so
		// the caller does not also try opaque revocation, which would log
		// a misleading "token not found" path.
		s.Logger.Warn("Cannot revoke self-issued JWT: RevokedTokenStore not configured",
			"token_suffix", helpers.TokenSuffix(tokenString, 8))
		return true
	}

	_, claims, err := s.parseAndVerifyJWTSignature(tokenString)
	if err != nil {
		// Bearer was peeked as self-issued but failed verification —
		// suspicious (forged or expired). Treat as success per RFC 7009.
		s.Logger.Debug("Self-issued JWT revocation: signature/parse failed",
			"error", err,
			"token_suffix", helpers.TokenSuffix(tokenString, 8))
		return true
	}
	jti, _ := claims["jti"].(string)
	expVal, _ := claims["exp"].(float64)
	if jti == "" || expVal == 0 {
		s.Logger.Debug("Self-issued JWT missing jti or exp during revocation",
			"token_suffix", helpers.TokenSuffix(tokenString, 8))
		return true
	}
	expiresAt := time.Unix(int64(expVal), 0)

	if err := s.revokedTokenStore.RevokeJTI(ctx, jti, expiresAt); err != nil {
		s.Logger.Warn("Failed to write revoked JWT jti to denylist",
			"error", err,
			"jti", jti,
			"token_suffix", helpers.TokenSuffix(tokenString, 8))
		return true
	}

	userID, _ := claims["sub"].(string)
	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventSelfIssuedJWTRevoked,
		UserID:   userID,
		ClientID: clientID,
		Details: map[string]any{
			"jti":        jti,
			"expires_at": expiresAt.Unix(),
			"ip":         clientIP,
		},
	})
	s.Logger.Debug("Self-issued JWT access token revoked",
		"jti", jti,
		"client_id", clientID,
		"ip", clientIP,
		"expires_at", expiresAt)
	return true
}

// logSelfIssuedJWTAuthFailure records a hard rejection for audit trails.
// reason is a short machine-friendly tag (token_expired, audience_mismatch,
// token_revoked, family_revoked, missing_aud) so dashboards can pivot on it.
func (s *Server) logSelfIssuedJWTAuthFailure(ctx context.Context, reason, tokenString string) {
	s.Logger.Debug("Self-issued JWT access token rejected",
		"reason", reason,
		"token_suffix", helpers.TokenSuffix(tokenString, 8))
	s.Auditor.LogAuthFailure(ctx, "", "", "", reason)
}
