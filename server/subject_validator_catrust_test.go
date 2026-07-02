package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
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

// newTLSServerWithFreshCert starts a TLS httptest server with its own
// self-signed certificate instead of the certificate all httptest servers
// share, so per-server CA pools are actually distinct.
func newTLSServerWithFreshCert(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fresh-test-cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestNewOIDCValidator_PerIssuerRootCAs verifies that each AllowPrivateIPJWKS
// issuer's JWKS fetch is verified against that issuer's own RootCAs pool.
// Regression test for the shared permissive client that used only the FIRST
// permissive issuer's pool, silently rejecting a second issuer whose endpoint
// chained to a different internal CA.
//
// Parallel-safe: CA trust is explicit config, no http.DefaultTransport swap.
func TestNewOIDCValidator_PerIssuerRootCAs(t *testing.T) {
	t.Parallel()
	key := newTestECKey(t)
	const kid = "per-issuer-ca-key"

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       key.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}}}
	jwksHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	// Two JWKS endpoints, each with its own self-signed CA.
	srv1 := newTLSServerWithFreshCert(t, jwksHandler)
	srv2 := newTLSServerWithFreshCert(t, jwksHandler)
	pool1 := x509.NewCertPool()
	pool1.AddCert(srv1.Certificate())
	pool2 := x509.NewCertPool()
	pool2.AddCert(srv2.Certificate())

	const issuer2 = "https://second.issuer.example.com"
	v, err := NewOIDCValidator([]TrustedIssuer{
		{
			Issuer:             testIssuer,
			JwksURL:            srv1.URL,
			AllowedAudiences:   []string{testAudience},
			AllowPrivateIPJWKS: true,
			RootCAs:            pool1,
		},
		{
			Issuer:             issuer2,
			JwksURL:            srv2.URL,
			AllowedAudiences:   []string{testAudience},
			AllowPrivateIPJWKS: true,
			RootCAs:            pool2,
		},
	})
	require.NoError(t, err)

	// Tokens from BOTH issuers must validate: each issuer's client verifies its
	// endpoint against its own pool (pool1 does not trust srv2 and vice versa).
	for _, iss := range []string{testIssuer, issuer2} {
		token := signSubjectToken(t, key, kid, josejwt.Claims{
			Issuer:   iss,
			Subject:  testSubject,
			Audience: josejwt.Audience{testAudience},
			Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		})
		identity, err := v.Validate(t.Context(), token, nil)
		require.NoError(t, err, "issuer %s must validate against its own RootCAs", iss)
		require.Equal(t, testSubject, identity.Subject)
	}
}
