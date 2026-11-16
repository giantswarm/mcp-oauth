package server

import (
	"strings"
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

func TestRedirectURIDefaults_AllowLocalhostRedirectURIsFalseIsOverwritten(t *testing.T) {
	srv, err := newRedirectDefaultsServer(t, &Config{
		Issuer:                     "https://auth.example.com",
		AllowLocalhostRedirectURIs: false,
	})
	require.NoError(t, err)
	require.True(t, srv.Config.AllowLocalhostRedirectURIs)
	require.NoError(t, srv.ValidateRedirectURIForRegistration(t.Context(), "http://127.0.0.1:49152/callback"))
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
		wantDeprecation   bool
		wantAuthorization bool
	}{
		{name: "https issuer", issuer: "https://auth.example.com", wantDeprecation: true},
		{name: "http issuer on a public host", issuer: "http://auth.example.com", allowInsecureHTTP: true, wantDeprecation: true, wantAuthorization: true},
		{name: "localhost issuer", issuer: "http://localhost:8080", wantAuthorization: true},
		{name: "IPv4 loopback issuer", issuer: "http://127.0.0.1:8080", wantAuthorization: true},
		{name: "IPv6 loopback issuer", issuer: "http://[::1]:8080", wantAuthorization: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, logs := captureLogger()
			store := memory.New()
			t.Cleanup(store.Stop)
			srv, err := New(mock.NewProvider(), store, store, store, &Config{
				Issuer:                     tt.issuer,
				AllowInsecureHTTP:          tt.allowInsecureHTTP,
				DisableProductionMode:      true,
				DisableDNSValidation:       true,
				DisableDNSValidationStrict: true,
			}, logger)
			require.NoError(t, err)
			client, _, err := srv.RegisterClient(t.Context(), "Web", ClientTypePublic, "",
				[]string{"http://app.example.com/callback"}, []string{"openid"}, "192.168.1.100", 10)
			require.NoError(t, err)
			authorizationErr := srv.validateRedirectURI(client, "http://app.example.com/callback")
			if tt.wantAuthorization {
				require.NoError(t, authorizationErr)
			} else {
				require.Error(t, authorizationErr)
			}

			deprecated := strings.Contains(logs.String(), "DEPRECATED: DisableProductionMode")
			require.Equal(t, tt.wantDeprecation, deprecated, logs.String())
			if tt.wantDeprecation {
				require.Contains(t, logs.String(), "AllowLocalhostRedirectURIs")
			}
		})
	}
}
