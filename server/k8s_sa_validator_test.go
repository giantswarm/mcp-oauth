package server

import (
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

const (
	testK8sIssuer   = "https://kubernetes.default.svc.cluster.local"
	testK8sAudience = "https://mcp.example.com"
)

func TestTrustedIssuer_AllowedClaims_GlobMatch(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	subject := "system:serviceaccount:ai-platform:my-svc"
	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  subject,
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testK8sIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testK8sAudience},
		AllowedClaims:    map[string]string{"sub": "system:serviceaccount:ai-platform:*"},
	}}, jwksClient)
	require.NoError(t, err)

	identity, err := v.Validate(t.Context(), token, SubjectTokenTypeJWT)
	require.NoError(t, err)
	require.Equal(t, subject, identity.Subject)
}

func TestTrustedIssuer_AllowedClaims_BlockedNamespace(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  "system:serviceaccount:other:svc",
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testK8sIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testK8sAudience},
		AllowedClaims:    map[string]string{"sub": "system:serviceaccount:ai-platform:*"},
	}}, jwksClient)
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), token, SubjectTokenTypeJWT)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match allowed pattern")
}

func TestTrustedIssuer_AllowedClaims_ExactMatch(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	subject := "system:serviceaccount:ai-platform:my-svc"
	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  subject,
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testK8sIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testK8sAudience},
		AllowedClaims:    map[string]string{"sub": "system:serviceaccount:ai-platform:my-svc"},
	}}, jwksClient)
	require.NoError(t, err)

	identity, err := v.Validate(t.Context(), token, SubjectTokenTypeJWT)
	require.NoError(t, err)
	require.Equal(t, subject, identity.Subject)
}

func TestTrustedIssuer_AllowedClaims_BlockedByName(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  "system:serviceaccount:ai-platform:other",
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testK8sIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testK8sAudience},
		AllowedClaims:    map[string]string{"sub": "system:serviceaccount:ai-platform:allowed"},
	}}, jwksClient)
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), token, SubjectTokenTypeJWT)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match allowed pattern")
}

func TestTrustedIssuer_NoAllowedClaims_AnySubPasses(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	subject := "system:serviceaccount:any-ns:any-sa"
	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  subject,
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testK8sIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testK8sAudience},
	}}, jwksClient)
	require.NoError(t, err)

	identity, err := v.Validate(t.Context(), token, SubjectTokenTypeJWT)
	require.NoError(t, err)
	require.Equal(t, subject, identity.Subject)
}

func TestTrustedIssuer_AllowedClaims_UnsupportedTokenType(t *testing.T) {
	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:  testK8sIssuer,
		JwksURL: "https://example.com/jwks",
	}}, nil)
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), "sometoken", "urn:ietf:params:oauth:token-type:saml2")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported subject_token_type")
}
