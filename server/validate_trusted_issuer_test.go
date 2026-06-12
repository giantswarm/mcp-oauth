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
	"github.com/giantswarm/mcp-oauth/providers/oidc"
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

// TestValidateToken_TrustedIssuer_IDTokenFallsThroughToForwarded covers the
// gazelle-style deployment where the server's main OIDC provider is ALSO
// configured as a trusted issuer (for RFC 8693 subject-token validation).
// A forwarded ID token (typ != at+jwt) from that issuer whose aud is in
// TrustedAudiences must not be hard-rejected by the trusted-issuer branch;
// it falls through to the forwarded-ID-token branch and is accepted there.
func TestValidateToken_TrustedIssuer_IDTokenFallsThroughToForwarded(t *testing.T) {
	h := newForwardedTokenHarness(t)

	tiJWKSClient := oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{
		HTTPClient:     h.jwksServer.Client(),
		AllowPrivateIP: true,
	})
	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           h.issuer,
		JwksURL:          h.jwksServer.URL,
		AllowedAudiences: []string{h.audience},
	}}, tiJWKSClient)
	require.NoError(t, err)
	h.srv.trustedIssuerValidator = v

	// signToken signs with typ "JWT" — an ID token, not an RFC 9068 access
	// token. aud is in TrustedAudiences, so the trusted-issuer branch must
	// defer instead of hard-rejecting on the typ check.
	tok := h.signToken(t, h.validClaims())

	userInfo, err := h.srv.ValidateToken(context.Background(), tok)
	require.NoError(t, err)
	require.NotNil(t, userInfo)
	require.Equal(t, "user-subject-123", userInfo.ID)
	require.Equal(t, providers.TokenSourceSSO, userInfo.TokenSource)
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
		if accessToken == "opaque-bearer" { //nolint:gosec // G101 false positive — test fixture label, not a credential
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

func TestValidateToken_TrustedIssuer_AcceptedTypHeaders_K8sSAToken(t *testing.T) {
	key := newTestECKey(t)
	const kid = "ti-kid"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	srv, _, _ := setupFlowTestServer(t)

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:             testIssuer,
		JwksURL:            jwksURL,
		AllowedAudiences:   []string{srv.Config.GetResourceIdentifier()},
		AcceptedTypHeaders: []string{"", "JWT"},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	claims := josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{srv.Config.GetResourceIdentifier()},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	}

	// Kubernetes SA tokens carry no typ header at all.
	noTyp := signSubjectTokenWithType(t, key, kid, "", claims)
	userInfo, err := srv.ValidateToken(context.Background(), noTyp)
	require.NoError(t, err)
	require.Equal(t, testSubject, userInfo.ID)

	plainJWT := signSubjectTokenWithType(t, key, kid, "JWT", claims)
	userInfo, err = srv.ValidateToken(context.Background(), plainJWT)
	require.NoError(t, err)
	require.Equal(t, testSubject, userInfo.ID)

	// at+jwt is no longer in the accepted set once overridden.
	atJWT := signSubjectTokenWithType(t, key, kid, rfc9068TokenType, claims)
	_, err = srv.ValidateToken(context.Background(), atJWT)
	require.Error(t, err)
}

func TestValidateToken_TrustedIssuer_DefaultTypStillRejectsMissingTyp(t *testing.T) {
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

	noTyp := signSubjectTokenWithType(t, key, kid, "", josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{srv.Config.GetResourceIdentifier()},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})
	_, err = srv.ValidateToken(context.Background(), noTyp)
	require.Error(t, err)
	require.Contains(t, err.Error(), "RFC 9068")
}
