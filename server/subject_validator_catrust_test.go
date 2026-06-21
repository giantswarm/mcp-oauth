package server

import (
	"crypto/tls"
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

// TestNewOIDCValidator_PermissiveClientTrustsProcessCABundle exercises the real
// NewOIDCValidator (not the test-only client-injecting constructor) against a
// TLS JWKS endpoint whose certificate is trusted only through http.DefaultTransport.
// An issuer with AllowPrivateIPJWKS must reach an internal endpoint that presents
// a CA the host process installs on http.DefaultTransport at startup.
func TestNewOIDCValidator_PermissiveClientTrustsProcessCABundle(t *testing.T) {
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

	issuers := []TrustedIssuer{{
		Issuer:             testIssuer,
		JwksURL:            srv.URL,
		AllowedAudiences:   []string{testAudience},
		AllowPrivateIPJWKS: true,
	}}
	token := signSubjectToken(t, key, kid, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{testAudience},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	// Control: the server's CA is not in the process trust store, so the
	// permissive client cannot verify the self-signed JWKS endpoint.
	vUntrusted, err := NewOIDCValidator(issuers)
	require.NoError(t, err)
	_, err = vUntrusted.Validate(t.Context(), token, nil)
	require.Error(t, err)

	// Install the server's CA on http.DefaultTransport, mirroring a host process
	// that injects an extra CA file at startup.
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	original := http.DefaultTransport
	cloned := original.(*http.Transport).Clone()
	cloned.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = cloned
	t.Cleanup(func() { http.DefaultTransport = original })

	vTrusted, err := NewOIDCValidator(issuers)
	require.NoError(t, err)
	identity, err := vTrusted.Validate(t.Context(), token, nil)
	require.NoError(t, err)
	require.Equal(t, testSubject, identity.Subject)
}
