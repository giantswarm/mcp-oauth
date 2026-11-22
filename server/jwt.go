package server

import (
	"context"
	"encoding/json"
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
	iss, _ := claims[claimIss].(string)
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
	jti, _ := claims[claimJTI].(string)
	if err := s.checkJWTRevocation(ctx, jti, tokenString); err != nil {
		return nil, nil, err
	}
	if err := s.checkJWTFamily(ctx, claims, tokenString); err != nil {
		return nil, nil, err
	}
	clientID, _ := claims[paramClientID].(string)
	if err := s.checkClientRevocation(ctx, clientID); err != nil {
		return nil, nil, err
	}

	userInfo, err := userInfoFromJWTClaims(claims)
	if err != nil {
		return nil, nil, err
	}
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
	iss, _ := claims[claimIss].(string)
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

// checkJWTAudience requires the resource identifier in the token's aud claim.
func (s *Server) checkJWTAudience(ctx context.Context, claims map[string]any, tokenString string) error {
	audiences := audiencesFromClaim(claims["aud"])
	if len(audiences) == 0 {
		s.logSelfIssuedJWTAuthFailure(ctx, "missing_aud", tokenString)
		return fmt.Errorf("token missing audience claim")
	}
	if helpers.FindMatchingAudience(audiences, []string{s.Config.GetResourceIdentifier()}) != "" {
		return nil
	}
	s.logSelfIssuedJWTAuthFailure(ctx, "audience_mismatch", tokenString)
	return fmt.Errorf("token not intended for this resource server (RFC 8707 audience mismatch)")
}

// checkJWTRevocation rejects tokens whose jti is on the denylist. A nil
// revokedTokenStore (no backend support) is treated as an open denylist —
// the warning was logged at startup; rejecting all JWTs in that case
// would defeat the feature. A denylist that cannot be read is
// ErrStorageUnavailable: the token is neither accepted nor rejected, so a
// transient backend failure never silently re-enables a revoked token and
// never reads as an invalid token either.
func (s *Server) checkJWTRevocation(ctx context.Context, jti, tokenString string) error {
	if s.revokedTokenStore == nil || jti == "" {
		return nil
	}
	revoked, err := s.revokedTokenStore.IsJTIRevoked(ctx, jti)
	if err != nil {
		return s.storageUnavailable(ctx, "check token revocation", "", "", err)
	}
	if revoked {
		s.logSelfIssuedJWTAuthFailure(ctx, "token_revoked", tokenString)
		return fmt.Errorf("access token has been revoked")
	}
	return nil
}

// checkJWTFamily rejects JWTs belonging to revoked refresh-token families.
// Storage failures remain retryable; absent family state is not a revocation.
func (s *Server) checkJWTFamily(ctx context.Context, claims map[string]any, tokenString string) error {
	familyID, _ := claims[logKeyFamilyID].(string)
	if familyID == "" {
		return nil
	}
	revoked, err := s.familyRevoked(ctx, familyID)
	if errors.Is(err, storage.ErrRefreshTokenFamilyNotFound) {
		return nil
	}
	if err != nil {
		return s.storageUnavailable(ctx, "check token family revocation", "", "", err)
	}
	if revoked {
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
func userInfoFromJWTClaims(claims map[string]any) (*providers.UserInfo, error) {
	clientID, err := clientIDFromJWTClaims(claims)
	if err != nil {
		return nil, err
	}
	info := &providers.UserInfo{
		TokenSource: providers.TokenSourceJWT,
		ClientID:    clientID,
	}
	info.Issuer, _ = claims[claimIss].(string)
	info.ID, _ = claims[claimSub].(string)
	if info.ID == "" {
		return nil, fmt.Errorf("access token has no subject")
	}
	if raw, present := claims["act"]; present {
		actor, err := actorFromJWTClaim(raw)
		if err != nil {
			return nil, err
		}
		info.ActorIssuer, info.ActorSubject, info.ActorChain = actor.Issuer, actor.Subject, actor.Chain()
	}
	info.Email, _ = claims[claimEmail].(string)
	info.EmailVerified, _ = claims["email_verified"].(bool)
	info.Name, _ = claims["name"].(string)
	if raw, ok := claims["scope"]; ok {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("scope claim: %w", err)
		}
		var scopes oidc.ScopeClaim
		if err := json.Unmarshal(encoded, &scopes); err != nil {
			return nil, err
		}
		info.Scopes = scopes
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
	return info, nil
}

func clientIDFromJWTClaims(claims map[string]any) (string, error) {
	value, present := claims[paramClientID]
	if !present {
		return "", nil
	}
	clientID, ok := value.(string)
	if !ok || clientID == "" {
		return "", fmt.Errorf("access token has invalid client_id")
	}
	return clientID, nil
}

func actorFromJWTClaim(raw any) (*oidc.ActorClaim, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("actor claim: %w", err)
	}
	var actor oidc.ActorClaim
	if err := json.Unmarshal(encoded, &actor); err != nil {
		return nil, fmt.Errorf("actor claim: %w", err)
	}
	for current, depth := &actor, 0; current != nil; current, depth = current.Act, depth+1 {
		if depth >= maxActorChainDepth || current.Issuer == "" || current.Subject == "" {
			return nil, fmt.Errorf("invalid actor claim")
		}
	}
	return &actor, nil
}

// logSelfIssuedJWTAccepted records a success event for audit trails. The
// jti is logged in full because it is short-lived metadata, not a
// credential — operators correlating audit events across services need the
// complete identifier.
func (s *Server) logSelfIssuedJWTAccepted(ctx context.Context, tokenString string, userInfo *providers.UserInfo, jti string) {
	s.Logger.Debug("Self-issued JWT access token validated",
		"user_id", userInfo.ID,
		claimJTI, jti,
		"token_suffix", helpers.TokenSuffix(tokenString, 8))

	s.Auditor.LogEvent(ctx, security.Event{
		Type:   security.EventSelfIssuedJWTAccepted,
		UserID: userInfo.ID,
		Details: map[string]any{
			logKeyValidationMethod: "self_issued_jwt",
			claimJTI:               jti,
		},
	})
}

// revokeSelfIssuedJWT extracts the jti and exp from a self-issued JWT and
// writes them to RevokedTokenStore. The boolean identifies self-issued JWTs;
// errors distinguish unavailable revocation storage from invalid tokens.
func (s *Server) revokeSelfIssuedJWT(ctx context.Context, tokenString, clientID, clientIP string) (bool, error) {
	if !s.Config.IsJWTAccessTokenFormat() || !s.looksLikeSelfIssuedJWT(tokenString) {
		return false, nil
	}

	_, claims, err := s.parseAndVerifyJWTSignature(tokenString)
	if err != nil {
		// Bearer was peeked as self-issued but failed verification —
		// suspicious (forged or expired). Treat as success per RFC 7009.
		s.Logger.Debug("Self-issued JWT revocation: signature/parse failed",
			logKeyError, err,
			"token_suffix", helpers.TokenSuffix(tokenString, 8))
		return true, nil
	}
	jti, _ := claims[claimJTI].(string)
	if owner, _ := claims[paramClientID].(string); owner == "" || owner != clientID {
		return true, nil
	}
	expVal, _ := claims["exp"].(float64)
	if jti == "" || expVal == 0 {
		s.Logger.Debug("Self-issued JWT missing jti or exp during revocation",
			"token_suffix", helpers.TokenSuffix(tokenString, 8))
		return true, nil
	}
	expiresAt := time.Unix(int64(expVal), 0).Add(time.Duration(s.Config.ClockSkewGracePeriod) * time.Second)
	if !expiresAt.After(time.Now()) {
		return true, nil
	}
	if s.revokedTokenStore == nil {
		return true, s.storageUnavailable(ctx, "revoke JWT", clientID, "", errors.New("JWT revocation store is not configured"))
	}

	if err := s.revokedTokenStore.RevokeJTI(ctx, jti, expiresAt); err != nil {
		return true, s.storageUnavailable(ctx, "revoke JWT", clientID, "", err)
	}

	userID, _ := claims[claimSub].(string)
	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventSelfIssuedJWTRevoked,
		UserID:   userID,
		ClientID: clientID,
		Details: map[string]any{
			claimJTI:     jti,
			"expires_at": expiresAt.Unix(),
			"ip":         clientIP,
		},
	})
	s.Logger.Debug("Self-issued JWT access token revoked",
		claimJTI, jti,
		paramClientID, clientID,
		"ip", clientIP,
		"expires_at", expiresAt)
	return true, nil
}

// logSelfIssuedJWTAuthFailure records a hard rejection for audit trails.
// reason is a short machine-friendly tag (token_expired, audience_mismatch,
// token_revoked, family_revoked, missing_aud) so dashboards can pivot on it.
func (s *Server) logSelfIssuedJWTAuthFailure(ctx context.Context, reason, tokenString string) {
	s.Logger.Debug("Self-issued JWT access token rejected",
		logKeyReason, reason,
		"token_suffix", helpers.TokenSuffix(tokenString, 8))
	s.Auditor.LogAuthFailure(ctx, "", "", "", reason)
}
