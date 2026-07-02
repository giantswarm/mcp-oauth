package server

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

// TestNewOIDCValidator_PermissiveClientTrustsExplicitCA exercises the real
// NewOIDCValidator (not the test-only client-injecting constructor) against a
// TLS JWKS endpoint whose certificate chains only to an explicitly-configured
// CA pool. An issuer with AllowPrivateIPJWKS reaches an internal endpoint that
// presents a certificate from a CA supplied via TrustedIssuer.RootCAs.
//
// Parallel-safe: CA trust is explicit config, no http.DefaultTransport swap.
func TestNewOIDCValidator_PermissiveClientTrustsExplicitCA(t *testing.T) {
	t.Parallel()
	key := newTestECKey(t)
	const kid = "ca-trust-key"

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)

	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{testAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	// Control: no RootCAs configured, so the permissive client verifies against
	// the system pool and cannot validate the self-signed JWKS endpoint.
	vUntrusted, err := NewOIDCValidator([]TrustedIssuer{{
		Issuer:             testIssuer,
		JwksURL:            srv.URL,
		AllowedAudiences:   []string{testAudience},
		AllowPrivateIPJWKS: true,
	}})
	require.NoError(t, err)
	_, err = vUntrusted.Validate(t.Context(), token, nil)
	require.Error(t, err)

	// With the server's CA supplied explicitly via TrustedIssuer.RootCAs, the
	// permissive client trusts the endpoint.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	vTrusted, err := NewOIDCValidator([]TrustedIssuer{{
		Issuer:             testIssuer,
		JwksURL:            srv.URL,
		AllowedAudiences:   []string{testAudience},
		AllowPrivateIPJWKS: true,
		RootCAs:            pool,
	}})
	require.NoError(t, err)
	identity, err := vTrusted.Validate(t.Context(), token, nil)
	require.NoError(t, err)
	require.Equal(t, testSubject, identity.Subject)
}
