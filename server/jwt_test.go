package server

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// signForgeToken builds a forged JWT for negative-path tests using go-jose.
// claims is serialized verbatim (so callers can include arbitrary keys for
// the alg/typ/kid mutation tests). headerType is the typ extra header
// ("at+jwt" by default for valid shape; tests override to exercise rejection).
func signForgeToken(t *testing.T, alg jose.SignatureAlgorithm, key any, kid, headerType string, claims map[string]any) string {
	t.Helper()
	signingKey := jose.SigningKey{Algorithm: alg, Key: key}
	if signer, ok := key.(crypto.Signer); ok {
		signingKey.Key = jose.JSONWebKey{
			Key:       signer,
			KeyID:     kid,
			Algorithm: string(alg),
			Use:       "sig",
		}
	}
	opts := &jose.SignerOptions{}
	if headerType != "" {
		opts.WithType(jose.ContentType(headerType))
	}
	opts.WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(signingKey, opts)
	require.NoError(t, err)
	signed, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return signed
}

// setupJWTFlowTestServer is the JWT-mode counterpart of setupFlowTestServer
// (server/flows_test.go:37). It wires an RS256 signing key, a memory store
// (which implements RevokedTokenStore + RefreshTokenFamilyByIDStore), and a
// mock provider producing a deterministic UserInfo.
func setupJWTFlowTestServer(t *testing.T) (*Server, *memory.Store, *mock.Provider) {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	key := generateRSAKey(t)
	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          "https://api.example.com",
		SupportedScopes:             []string{"openid", "email", "profile"},
		AuthorizationCodeTTL:        600,
		AccessTokenTTL:              3600,
		RequirePKCE:                 true,
		AllowPKCEPlain:              false,
		ClockSkewGracePeriod:        5,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "test-kid-1",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
	}

	srv, err := New(provider, store, store, store, cfg, nil)
	require.NoError(t, err)
	return srv, store, provider
}

func TestValidateToken_SelfIssuedJWT_HappyPath(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)

	now := time.Now().UTC()
	tok, err := srv.accessTokenIssuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "user-1",
		ClientID:  "client-x",
		Audience:  srv.config.GetResourceIdentifier(),
		Scopes:    []string{"openid"},
		Email:     "u@example.com",
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	})
	require.NoError(t, err)

	userInfo, err := srv.ValidateToken(context.Background(), tok)
	require.NoError(t, err)
	require.NotNil(t, userInfo)
	require.Equal(t, "user-1", userInfo.ID)
	require.Equal(t, "u@example.com", userInfo.Email)
	require.Equal(t, providers.TokenSourceJWT, userInfo.TokenSource)
	require.True(t, userInfo.IsJWT())
}

func TestValidateToken_SelfIssuedJWT_AudienceMismatch(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)

	now := time.Now().UTC()
	tok, err := srv.accessTokenIssuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "user-1",
		Audience:  "https://other.example.com",
		ExpiresAt: now.Add(time.Minute),
	})
	require.NoError(t, err)

	_, err = srv.ValidateToken(context.Background(), tok)
	require.Error(t, err)
	require.Contains(t, err.Error(), "audience")
}

func TestValidateToken_SelfIssuedJWT_AudienceMatchesTrusted(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)
	srv.config.TrustedAudiences = []string{"trusted-aggregator"}

	now := time.Now().UTC()
	tok, err := srv.accessTokenIssuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "user-1",
		Audience:  "trusted-aggregator",
		ExpiresAt: now.Add(time.Minute),
	})
	require.NoError(t, err)

	userInfo, err := srv.ValidateToken(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, "user-1", userInfo.ID)
}

func TestValidateToken_SelfIssuedJWT_Expired(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)

	tok, err := srv.accessTokenIssuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "u",
		Audience:  srv.config.GetResourceIdentifier(),
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	require.NoError(t, err)

	_, err = srv.ValidateToken(context.Background(), tok)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")
}

func TestValidateToken_SelfIssuedJWT_AlgConfusionRejected(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)

	// Forge a JWT signed with HS256 using a 32+ byte secret (the alg-confusion
	// attack with the actual public key bytes as secret is exercised separately
	// in TestValidateToken_SelfIssuedJWT_AlgConfusionWithPublicKeySecret). The
	// validator must reject it because alg pinning enforces the configured
	// RS256 only.
	now := time.Now().UTC()
	mapClaims := map[string]any{
		"iss":       srv.config.Issuer,
		"sub":       "attacker",
		"aud":       srv.config.GetResourceIdentifier(),
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "forged-jti",
		"client_id": "any",
	}
	signed := signForgeToken(t, jose.HS256, []byte("any-shared-secret-of-sufficient-length-32+"), srv.config.AccessTokenSigningKeyID, rfc9068TokenType, mapClaims)

	_, err := srv.ValidateToken(context.Background(), signed)
	require.Error(t, err)
}

func TestValidateToken_SelfIssuedJWT_TypHeaderRejected(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)

	now := time.Now().UTC()
	mapClaims := map[string]any{
		"iss":       srv.config.Issuer,
		"sub":       "user",
		"aud":       srv.config.GetResourceIdentifier(),
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "j",
		"client_id": "c",
	}
	signed := signForgeToken(t, jose.RS256, srv.config.AccessTokenSigningKey, srv.config.AccessTokenSigningKeyID, "JWT", mapClaims)

	_, err := srv.ValidateToken(context.Background(), signed)
	require.Error(t, err)
}

func TestRevokeToken_SelfIssuedJWT(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)
	now := time.Now().UTC()
	tok, err := srv.accessTokenIssuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "user-1",
		Audience:  srv.config.GetResourceIdentifier(),
		ExpiresAt: now.Add(15 * time.Minute),
	})
	require.NoError(t, err)

	// Pre-revocation: validates fine
	_, err = srv.ValidateToken(context.Background(), tok)
	require.NoError(t, err)

	// Revoke
	require.NoError(t, srv.RevokeToken(context.Background(), tok, "client-x", "127.0.0.1"))

	// Post-revocation: rejected
	_, err = srv.ValidateToken(context.Background(), tok)
	require.Error(t, err)
	require.Contains(t, err.Error(), "revoked")
}

func TestRevokeToken_RevokingExpiredJWTIsNoop(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)
	tok, err := srv.accessTokenIssuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "user-1",
		Audience:  srv.config.GetResourceIdentifier(),
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	require.NoError(t, err)
	// Per RFC 7009, revoking an already-expired token must succeed.
	require.NoError(t, srv.RevokeToken(context.Background(), tok, "c", "ip"))
}

func TestPublicJWKS_OpaqueModeEmpty(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)
	jwks, err := srv.PublicJWKS()
	require.NoError(t, err)
	require.NotNil(t, jwks)
	require.Empty(t, jwks.Keys)
}

func TestPublicJWKS_JWTModeContainsKey(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)
	jwks, err := srv.PublicJWKS()
	require.NoError(t, err)
	require.NotNil(t, jwks)
	require.Len(t, jwks.Keys, 1)
	require.Equal(t, "test-kid-1", jwks.Keys[0].KeyID)
	require.Equal(t, "RS256", jwks.Keys[0].Algorithm)
	require.True(t, jwks.Keys[0].IsPublic())
}

func TestGenerateAndStoreTokens_JWTMode(t *testing.T) {
	srv, store, _ := setupJWTFlowTestServer(t)
	ctx := context.Background()

	// Pre-seed UserInfo so JWT claims are populated.
	require.NoError(t, store.SaveUserInfo(ctx, "user-1", &storage.UserInfo{
		ID:     "user-1",
		Email:  "user@example.com",
		Groups: []string{"admins"},
	}))

	authCode := &storage.AuthorizationCode{
		Code:     "test-code",
		ClientID: "client-x",
		Scope:    "openid email",
		UserID:   "user-1",
		Audience: "https://api.example.com",
		ProviderToken: &oauth2.Token{
			AccessToken: "p-at",
			Expiry:      time.Now().Add(time.Hour),
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	tokenResp, err := srv.generateAndStoreTokens(ctx, authCode, "client-x", "fam-1", "")
	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.AccessToken)
	require.NotEmpty(t, tokenResp.RefreshToken)
	require.True(t, isJWTShape(tokenResp.AccessToken), "JWT mode must produce a 3-segment access token")
	require.False(t, isJWTShape(tokenResp.RefreshToken), "refresh tokens stay opaque even in JWT mode")

	parsed, err := josejwt.ParseSigned(tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	var standard josejwt.Claims
	var private rfc9068Claims
	require.NoError(t, parsed.Claims(srv.config.AccessTokenSigningKey.Public(), &standard, &private))
	require.Equal(t, "user-1", standard.Subject)
	require.Equal(t, "user@example.com", private.Email)
	require.Equal(t, "fam-1", private.FamilyID)
	require.Equal(t, []string{"admins"}, private.Groups)
}

// erroringFamilyByIDStore wraps a memory.Store and forces
// GetRefreshTokenFamilyByID to return a transient backend error, so the
// fail-closed path in checkJWTFamily can be exercised without a real outage.
// The other methods promote through to the embedded store.
type erroringFamilyByIDStore struct {
	*memory.Store
	familyByIDErr error
}

func (e *erroringFamilyByIDStore) GetRefreshTokenFamilyByID(_ context.Context, _ string) (*storage.RefreshTokenFamilyMetadata, error) {
	return nil, e.familyByIDErr
}

// TestValidateToken_SelfIssuedJWT_FamilyCheckFailsClosedOnStorageError covers
// F2: a transient error from RefreshTokenFamilyByIDStore must reject the JWT
// rather than silently bypass the family-revocation defense (parity with
// checkJWTRevocation). ErrRefreshTokenFamilyNotFound stays a legit silent skip.
func TestValidateToken_SelfIssuedJWT_FamilyCheckFailsClosedOnStorageError(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })
	wrapped := &erroringFamilyByIDStore{
		Store:         store,
		familyByIDErr: fmt.Errorf("transient backend outage"),
	}

	provider := mock.NewProvider()
	key := generateRSAKey(t)
	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          "https://api.example.com",
		AccessTokenTTL:              3600,
		ClockSkewGracePeriod:        5,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "test-kid-1",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
	}

	srv, err := New(provider, wrapped, wrapped, wrapped, cfg, nil)
	require.NoError(t, err)

	now := time.Now().UTC()
	tok, err := srv.accessTokenIssuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "user-1",
		Audience:  srv.config.GetResourceIdentifier(),
		ExpiresAt: now.Add(15 * time.Minute),
		FamilyID:  "fam-transient-error",
	})
	require.NoError(t, err)

	_, err = srv.ValidateToken(context.Background(), tok)
	require.Error(t, err, "transient family-store error must reject the JWT (fail-closed)")
	require.Contains(t, err.Error(), "family revocation check failed")

	// ErrRefreshTokenFamilyNotFound is the legit silent-skip signal —
	// validation must accept the JWT in that case (no family ever existed).
	wrapped.familyByIDErr = storage.ErrRefreshTokenFamilyNotFound
	_, err = srv.ValidateToken(context.Background(), tok)
	require.NoError(t, err, "ErrRefreshTokenFamilyNotFound is silent-skip, not reject")
}

func TestFamilyRevocation_InvalidatesInFlightJWT(t *testing.T) {
	srv, store, _ := setupJWTFlowTestServer(t)
	ctx := context.Background()

	// Issue a JWT carrying family_id; ensure validation accepts it.
	now := time.Now().UTC()
	tok, err := srv.accessTokenIssuer.Issue(ctx, AccessTokenClaims{
		Subject:   "user-1",
		Audience:  srv.config.GetResourceIdentifier(),
		ExpiresAt: now.Add(15 * time.Minute),
		FamilyID:  "fam-revoke",
	})
	require.NoError(t, err)

	// Seed a refresh-token-family entry so RevokeRefreshTokenFamily has
	// something to mark as revoked. We use a real refresh token here
	// since the family store is keyed by it.
	require.NoError(t, store.SaveRefreshTokenWithFamily(ctx, "rt-1", "user-1", "client-x", "fam-revoke", 0, now.Add(time.Hour)))

	_, err = srv.ValidateToken(ctx, tok)
	require.NoError(t, err, "JWT should validate before family revocation")

	require.NoError(t, store.RevokeRefreshTokenFamily(ctx, "fam-revoke"))

	_, err = srv.ValidateToken(ctx, tok)
	require.Error(t, err, "JWT must be rejected after family revocation")
	require.Contains(t, err.Error(), "family")
}

func TestValidateToken_SelfIssuedJWT_AlgConfusionWithPublicKeySecret(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)

	// Faithful alg-confusion repro: an attacker who has the JWKS public key
	// signs HS256 using the DER-encoded public key bytes as the HMAC secret.
	// The validator must reject this regardless of the secret because
	// alg pinning fires before the secret is consulted.
	pubDER, err := x509.MarshalPKIXPublicKey(srv.config.AccessTokenSigningKey.Public())
	require.NoError(t, err)

	now := time.Now().UTC()
	mapClaims := map[string]any{
		"iss":       srv.config.Issuer,
		"sub":       "attacker",
		"aud":       srv.config.GetResourceIdentifier(),
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "alg-confusion-jti",
		"client_id": "any",
	}
	signed := signForgeToken(t, jose.HS256, pubDER, srv.config.AccessTokenSigningKeyID, rfc9068TokenType, mapClaims)

	_, err = srv.ValidateToken(context.Background(), signed)
	require.Error(t, err)
}

func TestValidateToken_SelfIssuedJWT_WrongKidRejected(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)

	now := time.Now().UTC()
	mapClaims := map[string]any{
		"iss":       srv.config.Issuer,
		"sub":       "user",
		"aud":       srv.config.GetResourceIdentifier(),
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "wrong-kid-jti",
		"client_id": "c",
	}
	signed := signForgeToken(t, jose.RS256, srv.config.AccessTokenSigningKey, "not-the-configured-kid", rfc9068TokenType, mapClaims)

	_, err := srv.ValidateToken(context.Background(), signed)
	require.Error(t, err)
}

func TestValidateToken_SelfIssuedJWT_MultiAudienceWithTrustedMatchAccepted(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)
	srv.config.TrustedAudiences = []string{"trusted-aggregator"}

	// Forge a JWT with the configured signing key but an array aud where
	// only the second value matches TrustedAudiences. Pre-fix this would
	// fail because checkJWTAudience only compared audiences[0] against the
	// trusted list. With the multi-audience helper it must accept.
	now := time.Now().UTC()
	mapClaims := map[string]any{
		"iss":       srv.config.Issuer,
		"sub":       "user-multi-aud",
		"aud":       []string{"unrelated", "trusted-aggregator"},
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "multi-aud-jti",
		"client_id": "c",
	}
	signed := signForgeToken(t, jose.RS256, srv.config.AccessTokenSigningKey, srv.config.AccessTokenSigningKeyID, rfc9068TokenType, mapClaims)

	userInfo, err := srv.ValidateToken(context.Background(), signed)
	require.NoError(t, err)
	require.Equal(t, "user-multi-aud", userInfo.ID)
}

// isJWTShape returns true when s has the three dot-separated segments of a
// JWT. Used to confirm refresh tokens stay opaque in JWT mode.
func isJWTShape(s string) bool {
	dots := 0
	for _, r := range s {
		if r == '.' {
			dots++
		}
	}
	return dots == 2
}
