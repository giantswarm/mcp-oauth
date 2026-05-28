package server

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers"
)

// signSubjectTokenWithType is signSubjectToken with a caller-controlled typ
// header so RFC 9068 typ enforcement can be exercised.
func signSubjectTokenWithType(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims josejwt.Claims) string {
	t.Helper()
	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key: jose.JSONWebKey{
			Key:       key,
			KeyID:     kid,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		},
	}
	opts := &jose.SignerOptions{}
	opts.WithType(jose.ContentType(typ))
	opts.WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(signingKey, opts)
	require.NoError(t, err)
	tokenString, err := josejwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return tokenString
}

func TestValidateToken_TrustedIssuer_Accepts(t *testing.T) {
	key := newTestECKey(t)
	const kid = "ti-kid"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	srv, _, _ := setupFlowTestServer(t)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{srv.Config.GetResourceIdentifier()},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	token := signSubjectTokenWithType(t, key, kid, rfc9068TokenType, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{srv.Config.GetResourceIdentifier()},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	userInfo, err := srv.ValidateToken(context.Background(), token)
	require.NoError(t, err)
	require.NotNil(t, userInfo)
	require.Equal(t, testSubject, userInfo.ID)
	require.Equal(t, providers.TokenSourceSSO, userInfo.TokenSource)
}

func TestValidateToken_TrustedIssuer_DefaultsAudienceToResourceIdentifier(t *testing.T) {
	key := newTestECKey(t)
	const kid = "ti-kid"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	srv, _, _ := setupFlowTestServer(t)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:  testIssuer,
		JwksURL: jwksURL,
		// AllowedAudiences omitted: ValidateToken must default to the server's
		// own resource identifier.
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	token := signSubjectTokenWithType(t, key, kid, rfc9068TokenType, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{srv.Config.GetResourceIdentifier()},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	userInfo, err := srv.ValidateToken(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, testSubject, userInfo.ID)
}

func TestValidateToken_TrustedIssuer_RejectsWrongTyp(t *testing.T) {
	key := newTestECKey(t)
	const kid = "ti-kid"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	srv, _, _ := setupFlowTestServer(t)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{srv.Config.GetResourceIdentifier()},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	token := signSubjectTokenWithType(t, key, kid, "JWT", josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{srv.Config.GetResourceIdentifier()},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	_, err = srv.ValidateToken(context.Background(), token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "RFC 9068")
}

func TestValidateToken_TrustedIssuer_RejectsWrongAudience(t *testing.T) {
	key := newTestECKey(t)
	const kid = "ti-kid"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	srv, _, _ := setupFlowTestServer(t)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{srv.Config.GetResourceIdentifier()},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	token := signSubjectTokenWithType(t, key, kid, rfc9068TokenType, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{"https://other.example.com"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	_, err = srv.ValidateToken(context.Background(), token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "trusted issuer JWT validation failed")
}

func TestValidateToken_TrustedIssuer_UnknownIssFallsThroughToOpaque(t *testing.T) {
	key := newTestECKey(t)
	const kid = "ti-kid"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	srv, _, provider := setupFlowTestServer(t)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{srv.Config.GetResourceIdentifier()},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	provider.ValidateTokenFunc = func(_ context.Context, accessToken string) (*providers.UserInfo, error) {
		if accessToken == "opaque-bearer" {
			return &providers.UserInfo{ID: "opaque-user", Email: "u@example.com"}, nil
		}
		return nil, errors.New("not configured")
	}

	userInfo, err := srv.ValidateToken(context.Background(), "opaque-bearer")
	require.NoError(t, err)
	require.Equal(t, "opaque-user", userInfo.ID)

	// A JWT carrying an iss that is not configured must also fall through,
	// not be hard-rejected as a trusted-issuer failure.
	jwtUnknownIss := signSubjectTokenWithType(t, key, kid, rfc9068TokenType, josejwt.Claims{
		Issuer:   "https://stranger.example.com",
		Subject:  "x",
		Audience: josejwt.Audience{srv.Config.GetResourceIdentifier()},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})
	provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		// Opaque path is reached but rejects the unknown bearer.
		return nil, errors.New("unknown bearer")
	}
	_, err = srv.ValidateToken(context.Background(), jwtUnknownIss)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "trusted issuer JWT")
}
