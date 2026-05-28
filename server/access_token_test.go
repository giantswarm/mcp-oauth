package server

import (
	"context"
	"crypto/elliptic"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
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

	parsed, err := josejwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	require.Len(t, parsed.Headers, 1)
	require.Equal(t, "RS256", parsed.Headers[0].Algorithm)
	require.Equal(t, "kid-1", parsed.Headers[0].KeyID)
	typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	require.Equal(t, rfc9068TokenType, typ)

	var standard josejwt.Claims
	var private rfc9068Claims
	require.NoError(t, parsed.Claims(key.Public(), &standard, &private))

	require.Equal(t, "https://auth.example.com", standard.Issuer)
	require.Equal(t, "user-42", standard.Subject)
	require.Equal(t, josejwt.Audience{"https://api.example.com"}, standard.Audience)
	require.NotNil(t, standard.Expiry)
	require.InDelta(t, now.Add(15*time.Minute).Unix(), int64(*standard.Expiry), 1)
	require.NotNil(t, standard.IssuedAt)
	require.NotNil(t, standard.NotBefore)
	require.Equal(t, int64(*standard.IssuedAt), int64(*standard.NotBefore))
	require.NotEmpty(t, standard.ID)

	require.Equal(t, "client-abc", private.ClientID)
	require.Equal(t, "openid profile", private.Scope)
	require.Equal(t, "user@example.com", private.Email)
	require.Equal(t, "family-xyz", private.FamilyID)
	require.Equal(t, []string{"admins", "engineering"}, private.Groups)
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
	parsed, err := josejwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	var standard josejwt.Claims
	require.NoError(t, parsed.Claims(key.Public(), &standard))
	require.Equal(t, "caller-supplied-jti", standard.ID)
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
	require.Equal(t, "", helpers.JoinScopes(nil))
	require.Equal(t, "", helpers.JoinScopes([]string{}))
	require.Equal(t, "openid", helpers.JoinScopes([]string{"openid"}))
	require.Equal(t, "openid profile email", helpers.JoinScopes([]string{"openid", "profile", "email"}))
	require.Equal(t, "openid email", helpers.JoinScopes([]string{"openid", "", "email"}), "empties dropped")
}
