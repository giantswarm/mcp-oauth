package oauthconfig_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/handler"
	"github.com/giantswarm/mcp-oauth/oauthconfig"
	"github.com/giantswarm/mcp-oauth/providers/dex"
	"github.com/giantswarm/mcp-oauth/providers/google"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

func resolvedGoogleSettings() oauthconfig.Settings {
	return oauthconfig.Settings{
		Server: &server.Config{Issuer: "https://auth.example.test", TrustedAudiences: []string{"platform"}},
		Google: &google.Config{ClientID: "client", ClientSecret: "test-secret", RedirectURL: "https://auth.example.test/oauth/callback"},
		Logger: slog.New(slog.DiscardHandler),
	}
}

func TestSetupResolvedSettingsAndRoutes(t *testing.T) {
	t.Setenv("OAUTH_ISSUER", "https://ignored.example.test")
	t.Setenv("OAUTH_PROVIDER", "invalid")
	runtime, cleanup, err := oauthconfig.Setup(resolvedGoogleSettings())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup(context.WithoutCancel(t.Context()))) })
	require.Equal(t, []string{"platform"}, runtime.Server.Config.TrustedAudiences)
	mux := http.NewServeMux()
	runtime.Handler.RegisterOAuthRoutes(mux, handler.OAuthRoutesOptions{MCPPath: "/mcp", IncludeMetadata: true})
	mux.Handle("/mcp", runtime.Handler.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	listener := httptest.NewServer(mux)
	t.Cleanup(listener.Close)
	response, err := listener.Client().Get(listener.URL + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	var metadata map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
	require.Equal(t, "https://auth.example.test", metadata["issuer"])
	require.NoError(t, response.Body.Close())
	response, err = listener.Client().Get(listener.URL + "/mcp")
	require.NoError(t, err)
	defer func() { require.NoError(t, response.Body.Close()) }()
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	require.Contains(t, response.Header.Get("WWW-Authenticate"), "resource_metadata=")
	require.NoError(t, cleanup(t.Context()))
	require.NoError(t, cleanup(t.Context()))
}

func TestSetupDexCustomTrustRoot(t *testing.T) {
	var issuer string
	identityProvider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/keys")
	}))
	t.Cleanup(identityProvider.Close)
	issuer = identityProvider.URL
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identityProvider.Certificate().Raw}), 0o600))
	settings := resolvedGoogleSettings()
	settings.Google = nil
	settings.RootCAFile = caFile
	settings.Dex = &dex.Config{IssuerURL: issuer, ClientID: "client", ClientSecret: "test-secret", RedirectURL: settings.Server.Issuer + "/oauth/callback", DiscoveryTimeout: time.Second}
	runtime, cleanup, err := oauthconfig.Setup(settings)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup(context.WithoutCancel(t.Context()))) })
	require.NotNil(t, runtime.Server.Config.JWKSRootCAs)
	require.Nil(t, settings.Server.JWKSRootCAs)
}

func TestSetupRefusesInvalidConfiguration(t *testing.T) {
	for _, name := range []string{"missing server", "missing provider", "multiple providers", "persistent without encryption", "invalid CA", "invalid server"} {
		t.Run(name, func(t *testing.T) {
			settings := resolvedGoogleSettings()
			switch name {
			case "missing server":
				settings.Server = nil
			case "missing provider":
				settings.Google = nil
			case "multiple providers":
				settings.Dex = &dex.Config{}
			case "persistent without encryption":
				settings.Valkey = &valkey.Config{Address: "127.0.0.1:1"}
			case "invalid CA":
				settings.RootCAFile = filepath.Join(t.TempDir(), "missing")
			case "invalid server":
				settings.Server.Issuer = ""
			}
			runtime, cleanup, err := oauthconfig.Setup(settings)
			require.Error(t, err)
			require.Nil(t, runtime)
			require.Nil(t, cleanup)
		})
	}
}
