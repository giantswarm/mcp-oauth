package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// TestGetJWKSClient_PermissiveRefusesCrossHostRedirect verifies that the SSO
// forwarded-ID-token JWKS client keeps the cross-host redirect guard even when
// AllowPrivateIPJWKS is set. The SSO path builds its client via
// NewJWKSClientWithOptions -> NewPrivateIPAllowedHTTPClient, which sets
// CheckRedirect: blockCrossHostRedirect. With AllowPrivateIPJWKS the SSRF dial
// guard is off, so this redirect guard is the remaining defense against a
// compromised internal Dex 302-ing the JWKS fetch to an arbitrary internal
// target. A raw &http.Client{Transport: http.DefaultTransport} (the earlier
// workaround) would silently follow the redirect.
//
// NOT parallel-safe: it mutates the global http.DefaultTransport (restored via
// t.Cleanup). Do not add t.Parallel() to this test.
func TestGetJWKSClient_PermissiveRefusesCrossHostRedirect(t *testing.T) {
	const (
		issuer   = "https://auth.internal.example"
		audience = "forwarded-audience"
		keyID    = "redirect-guard-key"
	)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// The final target must never be reached: the redirect to it (a different
	// host:port) must be refused before any connection is made.
	var finalReached bool
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		finalReached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(final.Close)

	// The JWKS endpoint 302-redirects to the final (cross-host) target.
	entry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/keys", http.StatusFound)
	}))
	t.Cleanup(entry.Close)

	// Trust both servers' CAs on http.DefaultTransport so the TLS handshake to
	// the entry server succeeds (and would succeed to the final one too) — this
	// isolates the assertion to the redirect guard, not a TLS trust failure.
	pool := x509.NewCertPool()
	pool.AddCert(entry.Certificate())
	pool.AddCert(final.Certificate())
	original := http.DefaultTransport
	cloned := original.(*http.Transport).Clone()
	cloned.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = cloned
	t.Cleanup(func() { http.DefaultTransport = original })

	mockProvider := mock.NewProvider()
	mockProvider.JWKSURIFunc = func(context.Context) (string, error) { return entry.URL + "/keys", nil }
	mockProvider.IssuerURLFunc = func() string { return issuer }
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	srv := &Server{
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

	// The audience matches, so the SSO path attempts the JWKS fetch. The fetch
	// hits the cross-host redirect, which must be refused -> validation errors.
	userInfo, err := srv.validateForwardedIDToken(context.Background(), token)
	require.Error(t, err)
	require.Nil(t, userInfo)
	require.Contains(t, err.Error(), "cross-host redirect")
	require.False(t, finalReached, "cross-host redirect target must never be reached")
}
