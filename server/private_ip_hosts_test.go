package server

import (
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestBlanketPrivateIPSwitchDeprecations(t *testing.T) {
	tests := []struct {
		name       string
		config     Config
		wantLogs   []string
		absentLogs []string
	}{
		{
			name: "host lists log no deprecation",
			config: Config{
				AllowPrivateIPClientMetadataHosts: []string{"gateway.internal"},
				AllowPrivateIPRedirectURIHosts:    []string{"portal.internal"},
				AllowPrivateIPJWKSHosts:           []string{"dex.internal"},
			},
			wantLogs:   []string{"SECURITY WARNING: AllowPrivateIPJWKSHosts is set"},
			absentLogs: []string{"DEPRECATED"},
		},
		{
			name: "blanket switches name their host list",
			config: Config{
				AllowPrivateIPClientMetadata: true,
				AllowPrivateIPRedirectURIs:   true,
				AllowPrivateIPJWKS:           true,
			},
			wantLogs: []string{
				"DEPRECATED: AllowPrivateIPClientMetadata lifts the private-IP check for every host; list the hosts in AllowPrivateIPClientMetadataHosts instead",
				"DEPRECATED: AllowPrivateIPRedirectURIs lifts the private-IP check for every host; list the hosts in AllowPrivateIPRedirectURIHosts instead",
				"DEPRECATED: AllowPrivateIPJWKS lifts the private-IP check for every host; list the hosts in AllowPrivateIPJWKSHosts instead",
			},
			absentLogs: []string{"overrides"},
		},
		{
			name: "blanket switch and host list conflict",
			config: Config{
				AllowPrivateIPJWKS:      true,
				AllowPrivateIPJWKSHosts: []string{"dex.internal"},
			},
			wantLogs: []string{"AllowPrivateIPJWKS overrides AllowPrivateIPJWKSHosts: every host may resolve to a private address"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, logs := captureLogger()
			store := memory.New()
			t.Cleanup(store.Stop)
			config := tt.config
			config.Issuer = "https://auth.example.com"
			_, err := New(mock.NewProvider(), store, store, store, &config, logger)
			require.NoError(t, err)
			for _, want := range tt.wantLogs {
				require.Contains(t, logs.String(), want)
			}
			for _, absent := range tt.absentLogs {
				require.NotContains(t, logs.String(), absent)
			}
		})
	}
}

func TestTrustedIssuerBlanketPrivateIPDeprecation(t *testing.T) {
	logger, logs := captureLogger()
	logTrustedIssuerPrivateIPDeprecations([]TrustedIssuer{
		{Issuer: "https://blanket.example.com", AllowPrivateIPJWKS: true},
		{Issuer: "https://listed.example.com", AllowPrivateIPJWKSHosts: []string{"dex.internal"}},
	}, logger)

	require.Contains(t, logs.String(), "DEPRECATED: TrustedIssuer.AllowPrivateIPJWKS lifts the private-IP check for every host; list the host in AllowPrivateIPJWKSHosts instead")
	require.NotContains(t, logs.String(), "listed.example.com")
}

func TestAllowPrivateIPJWKSHosts(t *testing.T) {
	srv := newTLSServerWithFreshCert(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	serverURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	byName := "https://" + net.JoinHostPort("localhost", serverURL.Port()) + "/keys"
	byLoopbackIP := srv.URL + "/keys"

	newServer := func(t *testing.T, config Config) *Server {
		t.Helper()
		store := memory.New()
		t.Cleanup(store.Stop)
		config.Issuer = "https://auth.example.com"
		config.JWKSRootCAs = pool
		server, err := New(mock.NewProvider(), store, store, store, &config, slog.New(slog.NewTextHandler(io.Discard, nil)))
		require.NoError(t, err)
		return server
	}

	t.Run("listed host is fetched", func(t *testing.T) {
		client := newServer(t, Config{AllowPrivateIPJWKSHosts: []string{"localhost"}}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), byName)
		require.NoError(t, err)
	})

	t.Run("unlisted loopback host is refused", func(t *testing.T) {
		client := newServer(t, Config{AllowPrivateIPJWKSHosts: []string{"localhost"}}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), byLoopbackIP)
		require.ErrorContains(t, err, "loopback")
	})

	t.Run("no list refuses the listed name too", func(t *testing.T) {
		client := newServer(t, Config{}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), byName)
		require.ErrorIs(t, err, oidc.ErrRestrictedAddress)
	})
}
