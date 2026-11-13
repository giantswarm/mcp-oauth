package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func staticMetadataFixture() ClientMetadata {
	return ClientMetadata{
		ClientID:     "https://client.invalid/metadata.json",
		ClientName:   "Offline CLI",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scope:        "openid profile",
	}
}

func TestStaticClientMetadataValidation(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{"disabled CIMD", func(c *Config) { c.EnableClientIDMetadataDocuments = false }},
		{"duplicate", func(c *Config) { c.StaticClientMetadata = append(c.StaticClientMetadata, c.StaticClientMetadata[0]) }},
		{"non URL", func(c *Config) { c.StaticClientMetadata[0].ClientID = "cli" }},
		{"HTTP identifier", func(c *Config) { c.StaticClientMetadata[0].ClientID = "http://client.invalid/metadata.json" }},
		{"query identifier", func(c *Config) { c.StaticClientMetadata[0].ClientID += "?x=1" }},
		{"missing name", func(c *Config) { c.StaticClientMetadata[0].ClientName = "" }},
		{"no callbacks", func(c *Config) { c.StaticClientMetadata[0].RedirectURIs = nil }},
		{"remote HTTP callback", func(c *Config) { c.StaticClientMetadata[0].RedirectURIs = []string{"http://remote.invalid/callback"} }},
		{"confidential", func(c *Config) { c.StaticClientMetadata[0].TokenEndpointAuthMethod = "client_secret_basic" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Issuer: testAuthIssuer, EnableClientIDMetadataDocuments: true, StaticClientMetadata: []ClientMetadata{staticMetadataFixture()}}
			require.NoError(t, cfg.Validate())
			tc.change(cfg)
			require.ErrorContains(t, cfg.Validate(), "StaticClientMetadata")
			store := memory.New()
			defer store.Stop()
			_, err := NewWithCombined(mock.NewProvider(), store, cfg, nil)
			require.ErrorContains(t, err, "StaticClientMetadata")
		})
	}
}

func TestStaticClientMetadataOfflineAndImmutable(t *testing.T) {
	metadata := staticMetadataFixture()
	cfg := &Config{
		Issuer: testAuthIssuer, EnableClientIDMetadataDocuments: true,
		AllowLocalhostRedirectURIs: true, RequirePKCE: true,
		StaticClientMetadata: []ClientMetadata{metadata},
	}
	store := memory.New()
	defer store.Stop()
	srv, err := NewWithCombined(mock.NewProvider(), store, cfg, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, srv.Shutdown(context.Background())) }()

	// The reserved .invalid domain cannot supply metadata. Resolution must
	// survive cache clearing and must not read a caller-mutated config slice.
	cfg.StaticClientMetadata[0].RedirectURIs[0] = "https://attacker.invalid/callback"
	cfg.StaticClientMetadata = nil
	for range 2 {
		client, err := srv.GetClient(t.Context(), metadata.ClientID)
		require.NoError(t, err)
		require.True(t, client.IsPublic())
		require.Equal(t, "none", client.TokenEndpointAuthMethod)
		require.Equal(t, []string{"code"}, client.ResponseTypes)
		require.Equal(t, []string{"http://localhost:3000/callback"}, client.RedirectURIs)
		require.NoError(t, srv.validateRedirectURI(client, "http://localhost:54321/callback"))
		require.Error(t, srv.validateRedirectURI(client, "http://localhost:54321/other"))
		require.Error(t, srv.validateRedirectURI(client, "https://attacker.invalid/callback"))
		client.RedirectURIs[0] = "https://attacker.invalid/callback"
		client.GrantTypes[0] = "client_credentials"
		srv.metadataCache.Clear()
	}
	redirect, err := url.Parse("http://localhost:54321/callback")
	require.NoError(t, err)
	_, err = srv.StartAuthorizationFlow(t.Context(), metadata.ClientID, redirect, "openid", "", "", "", "0123456789abcdef0123456789abcdef", nil)
	require.ErrorContains(t, err, "PKCE")
	require.True(t, srv.RequiresConsent(metadata.ClientID, redirect.String()))
	_, err = srv.PrepareAuthorization(t.Context(), metadata.ClientID, redirect, "openid", "",
		"0123456789abcdef0123456789abcdef0123456789abc", "S256", "0123456789abcdef0123456789abcdef", nil)
	require.NoError(t, err)
	_, err = srv.PrepareAuthorization(t.Context(), metadata.ClientID, redirect, "admin", "",
		"0123456789abcdef0123456789abcdef0123456789abc", "S256", "0123456789abcdef0123456789abcdef", nil)
	require.Error(t, err)
}

func TestStaticClientMetadataExactMatchAndFetchFallback(t *testing.T) {
	var requests atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		metadata := staticMetadataFixture()
		metadata.ClientID = "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(metadata))
	}))
	defer endpoint.Close()
	metadata := staticMetadataFixture()
	metadata.ClientID = endpoint.URL + "/pinned.json"
	cfg := &Config{
		Issuer: testAuthIssuer, EnableClientIDMetadataDocuments: true,
		AllowPrivateIPClientMetadata: true,
		ClientMetadataRootCAs:        endpoint.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		StaticClientMetadata:         []ClientMetadata{metadata},
	}
	store := memory.New()
	defer store.Stop()
	srv, err := NewWithCombined(mock.NewProvider(), store, cfg, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, srv.Shutdown(context.Background())) }()
	_, err = srv.GetClient(t.Context(), metadata.ClientID)
	require.NoError(t, err)
	require.Zero(t, requests.Load())
	_, err = srv.GetClient(t.Context(), endpoint.URL+"/other.json")
	require.NoError(t, err)
	require.EqualValues(t, 1, requests.Load())
}
