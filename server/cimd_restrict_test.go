package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func newRestrictTestServer(t *testing.T, cfg *Config) *Server {
	t.Helper()
	store := memory.New()
	srv, err := NewWithCombined(mock.NewProvider(), store, cfg, nil)
	if err != nil {
		store.Stop()
	}
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, srv.Shutdown(context.Background())) })
	return srv
}

func TestRestrictClientMetadataValidation(t *testing.T) {
	base := func() *Config {
		return &Config{
			Issuer:                          testAuthIssuer,
			EnableClientIDMetadataDocuments: true,
			RestrictClientMetadata:          true,
			ClientMetadataHosts:             []string{"muster.example.com"},
		}
	}
	require.NoError(t, base().Validate())

	cases := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"CIMD disabled", func(c *Config) { c.EnableClientIDMetadataDocuments = false }, "RestrictClientMetadata requires EnableClientIDMetadataDocuments"},
		{"nothing allowed", func(c *Config) { c.ClientMetadataHosts = nil }, "RestrictClientMetadata needs PreRegisteredClientMetadata or ClientMetadataHosts"},
		{"hosts without restrict", func(c *Config) { c.RestrictClientMetadata = false }, "ClientMetadataHosts requires RestrictClientMetadata"},
		{"wildcard", func(c *Config) { c.ClientMetadataHosts = []string{"*.example.com"} }, "ClientMetadataHosts[0]"},
		{"IPv4 literal", func(c *Config) { c.ClientMetadataHosts = []string{"10.0.0.1"} }, "ClientMetadataHosts[0]"},
		{"IPv6 literal", func(c *Config) { c.ClientMetadataHosts = []string{"::1"} }, "ClientMetadataHosts[0]"},
		{"port", func(c *Config) { c.ClientMetadataHosts = []string{"muster.example.com:443"} }, "ClientMetadataHosts[0]"},
		{"URL", func(c *Config) { c.ClientMetadataHosts = []string{"https://muster.example.com"} }, "ClientMetadataHosts[0]"},
		{"empty", func(c *Config) { c.ClientMetadataHosts = []string{""} }, "ClientMetadataHosts[0]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.change(cfg)
			require.ErrorContains(t, cfg.Validate(), tc.want)
		})
	}

	t.Run("pins only", func(t *testing.T) {
		cfg := base()
		cfg.ClientMetadataHosts = nil
		cfg.PreRegisteredClientMetadata = []ClientMetadata{preRegisteredMetadataFixture()}
		require.NoError(t, cfg.Validate())
	})
}

func TestRestrictClientMetadataAllows(t *testing.T) {
	pinned := preRegisteredMetadataFixture()
	srv := newRestrictTestServer(t, &Config{
		Issuer:                          testAuthIssuer,
		EnableClientIDMetadataDocuments: true,
		RestrictClientMetadata:          true,
		ClientMetadataHosts:             []string{"Muster.Example.com."},
		PreRegisteredClientMetadata:     []ClientMetadata{pinned},
	})

	for _, clientID := range []string{
		"https://muster.example.com/oauth/client.json",
		"https://MUSTER.example.com./oauth/client.json",
		"https://muster.example.com:8443/oauth/client.json",
	} {
		require.NoError(t, srv.checkClientMetadataAllowed(clientID), clientID)
	}
	for _, clientID := range []string{
		"https://claude.ai/oauth/client.json",
		"https://muster.example.com.evil.test/oauth/client.json",
		"https://client.invalid/other.json",
	} {
		require.ErrorIs(t, srv.checkClientMetadataAllowed(clientID), ErrClientMetadataNotAllowed, clientID)
	}
}

func TestRestrictClientMetadataRefusesWithoutNetwork(t *testing.T) {
	var requests atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		metadata := preRegisteredMetadataFixture()
		metadata.ClientID = "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(metadata))
	}))
	defer endpoint.Close()

	pinned := preRegisteredMetadataFixture()
	srv := newRestrictTestServer(t, &Config{
		Issuer:                          testAuthIssuer,
		EnableClientIDMetadataDocuments: true,
		AllowPrivateIPClientMetadata:    true,
		ClientMetadataRootCAs:           endpoint.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		RestrictClientMetadata:          true,
		PreRegisteredClientMetadata:     []ClientMetadata{pinned},
	})

	audit := captureAudit(srv)
	_, err := srv.GetClient(t.Context(), endpoint.URL+"/unlisted.json")
	require.ErrorIs(t, err, ErrClientMetadataNotAllowed)
	require.Zero(t, requests.Load())
	require.Zero(t, srv.metadataCache.metrics.fetchFails, "a refused client ID is not a fetch")
	blocked := onlyAuditLine(t, audit, "client_metadata_fetch_blocked")
	require.Equal(t, "not_allowed", blocked.Details[logKeyReason])

	client, err := srv.GetClient(t.Context(), pinned.ClientID)
	require.NoError(t, err)
	require.Equal(t, pinned.ClientID, client.ClientID)
	require.Zero(t, requests.Load())
}

func TestRestrictClientMetadataOffKeepsFetch(t *testing.T) {
	var requests atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		metadata := preRegisteredMetadataFixture()
		metadata.ClientID = "https://" + r.Host + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(metadata))
	}))
	defer endpoint.Close()

	srv := newRestrictTestServer(t, &Config{
		Issuer:                          testAuthIssuer,
		EnableClientIDMetadataDocuments: true,
		AllowPrivateIPClientMetadata:    true,
		ClientMetadataRootCAs:           endpoint.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
	})
	_, err := srv.GetClient(t.Context(), endpoint.URL+"/any.json")
	require.NoError(t, err)
	require.EqualValues(t, 1, requests.Load())
}
