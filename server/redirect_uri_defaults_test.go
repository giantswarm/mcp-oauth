package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func newRedirectDefaultsServer(t *testing.T, config *Config) (*Server, error) {
	t.Helper()
	store := memory.New()
	t.Cleanup(store.Stop)
	config.DisableDNSValidation = true
	config.DisableDNSValidationStrict = true
	return New(mock.NewProvider(), store, store, store, config, nil)
}

func TestRedirectURIDefaults_LoopbackAllowedOnAnyPort(t *testing.T) {
	srv, err := newRedirectDefaultsServer(t, &Config{Issuer: "https://auth.example.com"})
	require.NoError(t, err)
	require.True(t, srv.Config.AllowLocalhostRedirectURIs)

	for _, redirectURI := range []string{
		"http://127.0.0.1:49152/callback",
		"http://127.0.0.1/callback",
		"http://[::1]:61000/callback",
		"http://localhost:3000/callback",
	} {
		t.Run(redirectURI, func(t *testing.T) {
			require.NoError(t, srv.ValidateRedirectURIForRegistration(t.Context(), redirectURI))
		})
	}

	client, _, err := srv.RegisterClient(t.Context(), "Native", ClientTypePublic, "",
		[]string{"http://127.0.0.1:49152/callback"}, []string{"openid"}, "192.168.1.100", 10)
	require.NoError(t, err)
	require.NoError(t, srv.validateRedirectURI(client, "http://127.0.0.1:61234/callback"))
}

func TestRedirectURIDefaults_DisableLocalhostRedirectURIs(t *testing.T) {
	srv, err := newRedirectDefaultsServer(t, &Config{
		Issuer:                       "https://auth.example.com",
		DisableLocalhostRedirectURIs: true,
	})
	require.NoError(t, err)
	require.False(t, srv.Config.AllowLocalhostRedirectURIs)
	require.Error(t, srv.ValidateRedirectURIForRegistration(t.Context(), "http://127.0.0.1:49152/callback"))
}

func TestRedirectURIDefaults_PlainHTTPOnPublicHostRefused(t *testing.T) {
	srv, err := newRedirectDefaultsServer(t, &Config{Issuer: "https://auth.example.com"})
	require.NoError(t, err)
	require.Error(t, srv.ValidateRedirectURIForRegistration(t.Context(), "http://app.example.com/callback"))
}

func TestRedirectURIDefaults_DisableProductionMode(t *testing.T) {
	tests := []struct {
		name              string
		issuer            string
		allowInsecureHTTP bool
		wantRefused       bool
	}{
		{name: "https issuer", issuer: "https://auth.example.com", wantRefused: true},
		{name: "http issuer on a public host", issuer: "http://auth.example.com", allowInsecureHTTP: true, wantRefused: true},
		{name: "localhost issuer", issuer: "http://localhost:8080"},
		{name: "IPv4 loopback issuer", issuer: "http://127.0.0.1:8080"},
		{name: "IPv6 loopback issuer", issuer: "http://[::1]:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := newRedirectDefaultsServer(t, &Config{
				Issuer:                tt.issuer,
				AllowInsecureHTTP:     tt.allowInsecureHTTP,
				DisableProductionMode: true,
			})
			if tt.wantRefused {
				require.ErrorContains(t, err, "DisableProductionMode")
				require.ErrorContains(t, err, "AllowLocalhostRedirectURIs")
				return
			}
			require.NoError(t, err)
			require.NoError(t, srv.ValidateRedirectURIForRegistration(t.Context(), "http://app.example.com/callback"))
		})
	}
}
