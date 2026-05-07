package server

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

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
		AccessTokenTTL:               3600,
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
		Audience:  srv.Config.GetResourceIdentifier(),
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
	srv.Config.TrustedAudiences = []string{"trusted-aggregator"}

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
		Audience:  srv.Config.GetResourceIdentifier(),
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

	// Forge a JWT signed with HS256 using the public key bytes as the secret —
	// the classic alg-confusion attack. The validator must reject it because
	// alg pinning enforces the configured RS256 only.
	now := time.Now().UTC()
	mapClaims := jwt.MapClaims{
		"iss":      srv.Config.Issuer,
		"sub":      "attacker",
		"aud":      srv.Config.GetResourceIdentifier(),
		"exp":      now.Add(15 * time.Minute).Unix(),
		"iat":      now.Unix(),
		"jti":      "forged-jti",
		"client_id": "any",
	}
	t1 := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	t1.Header["typ"] = rfc9068TokenType
	t1.Header["kid"] = srv.Config.AccessTokenSigningKeyID
	signed, err := t1.SignedString([]byte("any-shared-secret"))
	require.NoError(t, err)

	_, err = srv.ValidateToken(context.Background(), signed)
	require.Error(t, err)
}

func TestValidateToken_SelfIssuedJWT_TypHeaderRejected(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)

	now := time.Now().UTC()
	mapClaims := jwt.MapClaims{
		"iss":       srv.Config.Issuer,
		"sub":       "user",
		"aud":       srv.Config.GetResourceIdentifier(),
		"exp":       now.Add(15 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "j",
		"client_id": "c",
	}
	t1 := jwt.NewWithClaims(jwt.SigningMethodRS256, mapClaims)
	t1.Header["typ"] = "JWT" // not at+jwt
	t1.Header["kid"] = srv.Config.AccessTokenSigningKeyID
	signed, err := t1.SignedString(srv.Config.AccessTokenSigningKey)
	require.NoError(t, err)

	_, err = srv.ValidateToken(context.Background(), signed)
	require.Error(t, err)
}

func TestRevokeToken_SelfIssuedJWT(t *testing.T) {
	srv, _, _ := setupJWTFlowTestServer(t)
	now := time.Now().UTC()
	tok, err := srv.accessTokenIssuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "user-1",
		Audience:  srv.Config.GetResourceIdentifier(),
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
		Audience:  srv.Config.GetResourceIdentifier(),
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
	require.NoError(t, store.SaveUserInfo(ctx, "user-1", &providers.UserInfo{
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

	tokenResp, err := srv.generateAndStoreTokens(ctx, authCode, "client-x", "fam-1")
	require.NoError(t, err)
	require.NotEmpty(t, tokenResp.AccessToken)
	require.NotEmpty(t, tokenResp.RefreshToken)
	require.True(t, isJWTShape(tokenResp.AccessToken), "JWT mode must produce a 3-segment access token")
	require.False(t, isJWTShape(tokenResp.RefreshToken), "refresh tokens stay opaque even in JWT mode")

	parsed, err := jwt.Parse(tokenResp.AccessToken, func(*jwt.Token) (any, error) {
		return srv.Config.AccessTokenSigningKey.Public(), nil
	})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	require.Equal(t, "user-1", claims["sub"])
	require.Equal(t, "user@example.com", claims["email"])
	require.Equal(t, "fam-1", claims["family_id"])
	groups, _ := claims["groups"].([]any)
	require.Equal(t, []any{"admins"}, groups)
}

func TestFamilyRevocation_InvalidatesInFlightJWT(t *testing.T) {
	srv, store, _ := setupJWTFlowTestServer(t)
	ctx := context.Background()

	// Issue a JWT carrying family_id; ensure validation accepts it.
	now := time.Now().UTC()
	tok, err := srv.accessTokenIssuer.Issue(ctx, AccessTokenClaims{
		Subject:   "user-1",
		Audience:  srv.Config.GetResourceIdentifier(),
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


