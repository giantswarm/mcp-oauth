package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/dex"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// newRequiredScopesDexProvider returns a Dex provider configured with
// federated:id, backed by a TLS server that serves only the discovery
// document.
func newRequiredScopesDexProvider(t *testing.T) *dex.Provider {
	t.Helper()
	dexServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		issuer := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/keys",
		})
	}))
	t.Cleanup(dexServer.Close)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(dexServer.Certificate())
	provider, err := dex.NewProvider(&dex.Config{
		IssuerURL:    dexServer.URL,
		ClientID:     "mcp",
		ClientSecret: "secret",
		RedirectURL:  "https://auth.example.com/oauth/callback",
		Scopes:       []string{"openid", "profile", "email", "groups", "offline_access", "federated:id"},
		RootCAs:      rootCAs,
	})
	require.NoError(t, err)
	return provider
}

// upstreamScope starts an authorization flow with the client scope and
// returns the scope parameter of the upstream authorization URL.
func upstreamScope(t *testing.T, required []string, clientScope string) string {
	t.Helper()
	ctx := context.Background()
	store := memory.New()
	t.Cleanup(store.Stop)

	srv, err := New(newRequiredScopesDexProvider(t), store, store, store, &Config{
		Issuer:                      "https://auth.example.com",
		RequiredUpstreamScopes:      required,
		DisableNonceEchoRequirement: true,
	}, nil)
	require.NoError(t, err)

	const redirectURI = "https://example.com/callback"
	client, _, err := srv.RegisterClient(ctx, "Test Client", ClientTypeConfidential, "",
		[]string{redirectURI}, nil, "192.168.1.100", 10)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte(testutil.GenerateRandomString(testPKCEVerifierLength)))
	authorizationURL, err := srv.StartAuthorizationFlow(ctx, client.ClientID, mustParseURL(t, redirectURI), clientScope, "",
		base64.RawURLEncoding.EncodeToString(hash[:]), PKCEMethodS256, testutil.GenerateRandomString(43), nil)
	require.NoError(t, err)
	return mustParseURL(t, authorizationURL).Query().Get("scope")
}

// TestRequiredUpstreamScopes checks that the scopes of RequiredUpstreamScopes
// reach the upstream provider when the client sends its own scope.
func TestRequiredUpstreamScopes(t *testing.T) {
	t.Run("off: a client scope drops the provider's federated:id", func(t *testing.T) {
		scopes := strings.Fields(upstreamScope(t, nil, "openid email"))
		require.NotContains(t, scopes, "federated:id")
		require.Contains(t, scopes, "offline_access")
	})

	t.Run("off: no client scope keeps the provider's federated:id", func(t *testing.T) {
		require.Contains(t, strings.Fields(upstreamScope(t, nil, "")), "federated:id")
	})

	t.Run("on: a client scope keeps federated:id", func(t *testing.T) {
		scopes := strings.Fields(upstreamScope(t, []string{"federated:id"}, "openid email"))
		require.Contains(t, scopes, "federated:id")
		require.Contains(t, scopes, "email")
	})

	t.Run("on: a client scope that already carries federated:id lists it once", func(t *testing.T) {
		scopes := strings.Fields(upstreamScope(t, []string{"federated:id"}, "openid federated:id"))
		count := 0
		for _, scope := range scopes {
			if scope == "federated:id" {
				count++
			}
		}
		require.Equal(t, 1, count, scopes)
	})

	t.Run("on: no client scope keeps federated:id", func(t *testing.T) {
		require.Contains(t, strings.Fields(upstreamScope(t, []string{"federated:id"}, "")), "federated:id")
	})
}
