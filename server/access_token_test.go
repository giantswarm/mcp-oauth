package server

import (
	"context"
	"crypto/elliptic"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestOpaqueIssuer_IssueProducesRandomToken(t *testing.T) {
	o := opaqueIssuer{}
	a, err := o.Issue(context.Background(), AccessTokenClaims{})
	require.NoError(t, err)
	b, err := o.Issue(context.Background(), AccessTokenClaims{})
	require.NoError(t, err)
	require.NotEmpty(t, a)
	require.NotEqual(t, a, b, "opaque issuer must produce distinct random tokens")
	require.GreaterOrEqual(t, len(a), 40, "opaque token should be base64url-encoded 32 bytes")
}

func TestJWTIssuer_RFC9068ClaimShape(t *testing.T) {
	key := generateRSAKey(t)
	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "kid-1",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
	}
	require.NoError(t, cfg.Validate())

	issuer, err := newJWTIssuer(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()
	tokenString, err := issuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "user-42",
		ClientID:  "client-abc",
		Audience:  "https://api.example.com",
		Scopes:    []string{"openid", "profile"},
		Email:     "user@example.com",
		Groups:    []string{"admins", "engineering"},
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
		FamilyID:  "family-xyz",
	})
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)
	require.Equal(t, 3, strings.Count(tokenString, ".")+1, "JWT must have three segments")

	parsed, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		return key.Public(), nil
	})
	require.NoError(t, err)
	require.True(t, parsed.Valid)

	require.Equal(t, "RS256", parsed.Method.Alg())
	require.Equal(t, rfc9068TokenType, parsed.Header["typ"])
	require.Equal(t, "kid-1", parsed.Header["kid"])

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	require.Equal(t, "https://auth.example.com", claims["iss"])
	require.Equal(t, "user-42", claims["sub"])
	require.Equal(t, "client-abc", claims["client_id"])
	require.Equal(t, "https://api.example.com", claims["aud"])
	require.Equal(t, "openid profile", claims["scope"])
	require.Equal(t, "user@example.com", claims["email"])
	require.Equal(t, "family-xyz", claims["family_id"])

	groups, ok := claims["groups"].([]any)
	require.True(t, ok, "groups should serialize as JSON array")
	require.Equal(t, []any{"admins", "engineering"}, groups)

	// jti must be present and non-empty even when caller did not supply one
	require.NotEmpty(t, claims["jti"])
	// exp matches caller value
	require.InDelta(t, float64(now.Add(15*time.Minute).Unix()), claims["exp"], 1)
}

func TestJWTIssuer_RequiresExpiry(t *testing.T) {
	key := generateRSAKey(t)
	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "kid-1",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
	}
	issuer, err := newJWTIssuer(cfg)
	require.NoError(t, err)
	_, err = issuer.Issue(context.Background(), AccessTokenClaims{Subject: "u"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ExpiresAt")
}

func TestJWTIssuer_PreservesCallerJTI(t *testing.T) {
	key := generateRSAKey(t)
	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "kid-1",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
	}
	issuer, err := newJWTIssuer(cfg)
	require.NoError(t, err)
	tokenString, err := issuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "u",
		Audience:  "a",
		ExpiresAt: time.Now().Add(time.Minute),
		JTI:       "caller-supplied-jti",
	})
	require.NoError(t, err)
	parsed, err := jwt.Parse(tokenString, func(*jwt.Token) (any, error) { return key.Public(), nil })
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	require.Equal(t, "caller-supplied-jti", claims["jti"])
}

func TestPublicJWKFromConfig_OpaqueModeReturnsNil(t *testing.T) {
	jwk, err := publicJWKFromConfig(&Config{})
	require.NoError(t, err)
	require.Nil(t, jwk)
}

func TestPublicJWKFromConfig_RSAEncoding(t *testing.T) {
	key := generateRSAKey(t)
	cfg := &Config{
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "kid-rsa",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
	}
	jwk, err := publicJWKFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, jwk)
	require.Equal(t, "kid-rsa", jwk.KeyID)
	require.Equal(t, "RS256", jwk.Algorithm)
	require.Equal(t, "sig", jwk.Use)
	require.True(t, jwk.IsPublic())
	pub, ok := jwk.Key.(*rsa.PublicKey)
	require.True(t, ok)
	require.Equal(t, 0, key.N.Cmp(pub.N))
	require.Equal(t, key.E, pub.E)
}

func TestPublicJWKFromConfig_ECDSAEncoding(t *testing.T) {
	key := generateECKey(t, elliptic.P256())
	cfg := &Config{
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "kid-ec",
		AccessTokenSigningAlgorithm: SigningAlgorithmES256,
	}
	jwk, err := publicJWKFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, jwk)
	require.True(t, jwk.IsPublic())
	require.Equal(t, "kid-ec", jwk.KeyID)
	require.Equal(t, "ES256", jwk.Algorithm)
}

func TestJoinScopes(t *testing.T) {
	require.Equal(t, "", joinScopes(nil))
	require.Equal(t, "", joinScopes([]string{}))
	require.Equal(t, "openid", joinScopes([]string{"openid"}))
	require.Equal(t, "openid profile email", joinScopes([]string{"openid", "profile", "email"}))
	require.Equal(t, "openid email", joinScopes([]string{"openid", "", "email"}), "empties dropped")
}
