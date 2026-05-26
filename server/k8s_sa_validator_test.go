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

func testK8sSASubject(ns, name string) string {
	return "system:serviceaccount:" + ns + ":" + name
}

func TestK8sSAValidator_ValidToken(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	subject := testK8sSASubject("test-ns", "test-sa")
	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  subject,
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newK8sSAValidatorWithClient([]KubernetesSATrust{{
		Issuer:           testK8sIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testK8sAudience},
	}}, jwksClient)
	require.NoError(t, err)

	for _, tt := range []struct{ name, tokenType string }{
		{"jwt type", SubjectTokenTypeJWT},
		{"access_token type", SubjectTokenTypeAccessToken},
	} {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := v.Validate(t.Context(), token, tt.tokenType)
			require.NoError(t, err)
			require.Equal(t, subject, identity.Subject)
			require.Equal(t, testK8sIssuer, identity.Issuer)
		})
	}
}

func TestK8sSAValidator_AllowedNamespace(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	subject := testK8sSASubject("allowed-ns", "test-sa")
	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  subject,
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newK8sSAValidatorWithClient([]KubernetesSATrust{{
		Issuer:            testK8sIssuer,
		JwksURL:           jwksURL,
		AllowedAudiences:  []string{testK8sAudience},
		AllowedNamespaces: []string{"allowed-ns"},
	}}, jwksClient)
	require.NoError(t, err)

	identity, err := v.Validate(t.Context(), token, SubjectTokenTypeJWT)
	require.NoError(t, err)
	require.Equal(t, subject, identity.Subject)
}

func TestK8sSAValidator_BlockedNamespace(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	subject := testK8sSASubject("blocked-ns", "test-sa")
	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  subject,
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newK8sSAValidatorWithClient([]KubernetesSATrust{{
		Issuer:            testK8sIssuer,
		JwksURL:           jwksURL,
		AllowedAudiences:  []string{testK8sAudience},
		AllowedNamespaces: []string{"allowed-ns"},
	}}, jwksClient)
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), token, SubjectTokenTypeJWT)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not in the allowed list")
}

func TestK8sSAValidator_AllowedServiceAccount(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	subject := testK8sSASubject("test-ns", "allowed-sa")
	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  subject,
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newK8sSAValidatorWithClient([]KubernetesSATrust{{
		Issuer:                 testK8sIssuer,
		JwksURL:                jwksURL,
		AllowedAudiences:       []string{testK8sAudience},
		AllowedServiceAccounts: []string{"test-ns/allowed-sa"},
	}}, jwksClient)
	require.NoError(t, err)

	identity, err := v.Validate(t.Context(), token, SubjectTokenTypeJWT)
	require.NoError(t, err)
	require.Equal(t, subject, identity.Subject)
}

func TestK8sSAValidator_BlockedServiceAccount(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	subject := testK8sSASubject("test-ns", "blocked-sa")
	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testK8sIssuer,
		Subject:  subject,
		Audience: josejwt.Audience{testK8sAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	v, err := newK8sSAValidatorWithClient([]KubernetesSATrust{{
		Issuer:                 testK8sIssuer,
		JwksURL:                jwksURL,
		AllowedAudiences:       []string{testK8sAudience},
		AllowedServiceAccounts: []string{"test-ns/allowed-sa"},
	}}, jwksClient)
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), token, SubjectTokenTypeJWT)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not in the allowed list")
}

func TestK8sSAValidator_UnsupportedTokenType(t *testing.T) {
	v, err := newK8sSAValidatorWithClient([]KubernetesSATrust{{
		Issuer:  testK8sIssuer,
		JwksURL: "https://example.com/jwks",
	}}, nil)
	require.NoError(t, err)

	_, err = v.Validate(t.Context(), "sometoken", SubjectTokenTypeIDToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported subject_token_type")
}

func TestNewK8sSAValidator_Errors(t *testing.T) {
	t.Run("empty trusts", func(t *testing.T) {
		_, err := NewK8sSAValidator(nil)
		require.Error(t, err)
	})
	t.Run("empty Issuer", func(t *testing.T) {
		_, err := NewK8sSAValidator([]KubernetesSATrust{{JwksURL: "https://example.com/jwks"}})
		require.Error(t, err)
	})
	t.Run("empty JwksURL", func(t *testing.T) {
		_, err := NewK8sSAValidator([]KubernetesSATrust{{Issuer: testK8sIssuer}})
		require.Error(t, err)
	})
}

func TestWithKubernetesSATrust_RegistersJWTType(t *testing.T) {
	key := newTestECKey(t)
	const kid = "k8s-test-key"
	jwksURL, _ := serveStaticJWKS(t, key, kid)

	srv, _, _ := setupFlowTestServer(t)

	WithKubernetesSATrust([]KubernetesSATrust{{
		Issuer:           testK8sIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{testK8sAudience},
	}})(srv)

	require.NotNil(t, srv.SubjectValidatorFor(SubjectTokenTypeJWT))
	require.Nil(t, srv.SubjectValidatorFor(SubjectTokenTypeAccessToken))
	require.Nil(t, srv.SubjectValidatorFor(SubjectTokenTypeIDToken))
}
