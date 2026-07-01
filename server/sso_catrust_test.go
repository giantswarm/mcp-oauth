package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// TestGetJWKSClient_PermissiveClientTrustsProcessCABundle verifies that the SSO
// forwarded-ID-token JWKS client honors a CA the host process installs on
// http.DefaultTransport when AllowPrivateIPJWKS is set — the same mechanism
// NewOIDCValidator's permissive trusted-issuer client uses.
//
// Before this fix the SSO path built an SSRF-safe client that verified against the
// system pool alone, so an internal-CA Dex (the case AllowPrivateIPJWKS exists for)
// was rejected with "x509: certificate signed by unknown authority" even when the
// host process had installed that CA on http.DefaultTransport.
//
// Note: this exercises the real srv.getJWKSClient() construction, unlike
// newForwardedTokenHarness which injects a client that trusts the test server.
//
// NOT parallel-safe: it mutates the global http.DefaultTransport (restored via
// t.Cleanup). Do not add t.Parallel() to this test.
func TestGetJWKSClient_PermissiveClientTrustsProcessCABundle(t *testing.T) {
	const (
		issuer   = "https://auth.internal.example"
		audience = "forwarded-audience"
		keyID    = "ca-trust-key"
	)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       privateKey.Public(),
		KeyID:     keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}}}
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksServer.Close)

	// newServer builds a Server that uses the REAL getJWKSClient() (no injected
	// client). getJWKSClient captures the current http.DefaultTransport, so the CA
	// trust is decided at construction time.
	newServer := func() *Server {
		mockProvider := mock.NewProvider()
		mockProvider.JWKSURIFunc = func(context.Context) (string, error) { return jwksServer.URL, nil }
		mockProvider.IssuerURLFunc = func() string { return issuer }
		store := memory.New()
		t.Cleanup(func() { store.Stop() })
		return &Server{
			Config: &Config{
				Issuer:             issuer,
				TrustedAudiences:   []string{audience},
				AllowPrivateIPJWKS: true,
			},
			Logger:          slog.Default(),
			provider:        mockProvider,
			tokenStore:      store,
			Instrumentation: testInstrumentation(t),
			Auditor:         testAuditor(),
		}
	}

	token := signTestRS256Token(t, privateKey, keyID, oidc.IDTokenClaims{
		Claims: josejwt.Claims{
			Subject:  "user-subject-123",
			Issuer:   issuer,
			Audience: josejwt.Audience{audience},
			IssuedAt: josejwt.NewNumericDate(time.Now()),
			Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "user@internal.example",
	})
	ctx := context.Background()

	// Control: the JWKS server's self-signed CA is not in the process trust store,
	// so the permissive SSO JWKS client cannot verify it. The audience matches, so
	// this returns a validation error (not the benign "not an SSO token" nil, nil).
	userInfo, err := newServer().validateForwardedIDToken(ctx, token)
	require.Error(t, err)
	require.Nil(t, userInfo)

	// Install the server's CA on http.DefaultTransport, mirroring a host process
	// (e.g. mcp-kubernetes) that injects an extra CA file at startup.
	pool := x509.NewCertPool()
	pool.AddCert(jwksServer.Certificate())
	original := http.DefaultTransport
	cloned := original.(*http.Transport).Clone()
	cloned.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = cloned
	t.Cleanup(func() { http.DefaultTransport = original })

	// A server constructed after the CA is installed builds its JWKS client on the
	// updated DefaultTransport → the forwarded ID token now validates.
	userInfo, err = newServer().validateForwardedIDToken(ctx, token)
	require.NoError(t, err)
	require.NotNil(t, userInfo)
	require.Equal(t, "user-subject-123", userInfo.ID)
}
