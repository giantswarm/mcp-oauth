package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

// TestGetJWKSClient_PermissiveClientTrustsExplicitCA verifies that the SSO
// forwarded-ID-token JWKS client trusts an internal-CA Dex when the CA pool is
// supplied via Config.JWKSRootCAs, and rejects it when no pool is configured
// (system pool). Exercises the real srv.getJWKSClient() construction, unlike
// newForwardedTokenHarness which injects a client that trusts the test server.
//
// Parallel-safe: CA trust is explicit config, no http.DefaultTransport swap.
func TestGetJWKSClient_PermissiveClientTrustsExplicitCA(t *testing.T) {
	t.Parallel()
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

	// newServer builds a Server that uses the REAL getJWKSClient(), verifying the
	// JWKS endpoint against the provided rootCAs pool (nil = system pool).
	newServer := func(rootCAs *x509.CertPool) *Server {
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
				JWKSRootCAs:        rootCAs,
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

	// Control: no JWKSRootCAs → system pool → the self-signed JWKS endpoint is
	// rejected. The audience matches, so this returns a validation error (not the
	// benign "not an SSO token" nil, nil).
	userInfo, err := newServer(nil).validateForwardedIDToken(ctx, token)
	require.Error(t, err)
	require.Nil(t, userInfo)

	// With the server's CA supplied via Config.JWKSRootCAs, the forwarded ID
	// token validates.
	pool := x509.NewCertPool()
	pool.AddCert(jwksServer.Certificate())
	userInfo, err = newServer(pool).validateForwardedIDToken(ctx, token)
	require.NoError(t, err)
	require.NotNil(t, userInfo)
	require.Equal(t, "user-subject-123", userInfo.ID)
}
