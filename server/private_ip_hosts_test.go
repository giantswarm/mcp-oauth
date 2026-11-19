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

	newServer := func(t *testing.T, issuer string, config Config, opts ...Option) *Server {
		t.Helper()
		store := memory.New()
		t.Cleanup(store.Stop)
		config.Issuer = "https://auth.example.com"
		config.JWKSRootCAs = pool
		provider := mock.NewProvider()
		provider.IssuerURLFunc = func() string { return issuer }
		server, err := New(provider, store, store, store, &config, slog.New(slog.NewTextHandler(io.Discard, nil)), opts...)
		require.NoError(t, err)
		return server
	}
	const publicIssuer = "https://idp.example.com"

	t.Run("listed host resolving to loopback is refused", func(t *testing.T) {
		client := newServer(t, publicIssuer, Config{AllowPrivateIPJWKSHosts: []string{"localhost"}}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), byName)
		require.ErrorIs(t, err, oidc.ErrRestrictedAddress)
		require.ErrorContains(t, err, errListedHost)
	})

	t.Run("unlisted loopback host is refused", func(t *testing.T) {
		client := newServer(t, publicIssuer, Config{AllowPrivateIPJWKSHosts: []string{"localhost"}}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), byLoopbackIP)
		require.ErrorContains(t, err, "loopback")
	})

	t.Run("no list refuses the listed name too", func(t *testing.T) {
		client := newServer(t, publicIssuer, Config{}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), byName)
		require.ErrorIs(t, err, oidc.ErrRestrictedAddress)
		require.NotContains(t, err.Error(), errListedHost)
	})

	t.Run("issuer host gets the listed-host policy, which refuses loopback", func(t *testing.T) {
		issuer := "https://" + net.JoinHostPort("LocalHost.", serverURL.Port())
		client := newServer(t, issuer, Config{}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), byName)
		require.ErrorIs(t, err, oidc.ErrRestrictedAddress)
		require.ErrorContains(t, err, errListedHost)
	})

	t.Run("jwks_uri on another host than the issuer keeps the guard", func(t *testing.T) {
		issuer := "https://" + net.JoinHostPort("localhost", serverURL.Port())
		client := newServer(t, issuer, Config{}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), byLoopbackIP)
		require.ErrorContains(t, err, "loopback")
		require.NotContains(t, err.Error(), errListedHost)
	})

	t.Run("blanket still lifts the guard for the issuer host", func(t *testing.T) {
		issuer := "https://" + net.JoinHostPort("localhost", serverURL.Port())
		client := newServer(t, issuer, Config{AllowPrivateIPJWKS: true}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), byName)
		require.NoError(t, err)
	})

	t.Run("trusted issuer on the provider's host gets no allowance", func(t *testing.T) {
		issuer := "https://" + net.JoinHostPort("localhost", serverURL.Port())
		server := newServer(t, issuer, Config{}, WithTrustedIssuers([]TrustedIssuer{{
			Issuer:  issuer,
			JwksURL: byName,
			RootCAs: pool,
		}}))
		client := server.trustedIssuerValidator.issuerClients[issuer]
		require.NotNil(t, client)
		_, err := client.FetchJWKS(t.Context(), byName)
		require.ErrorIs(t, err, oidc.ErrRestrictedAddress)
		require.NotContains(t, err.Error(), errListedHost)
	})
}

func TestProviderJWKSPrivateIPHosts(t *testing.T) {
	withIssuer := func(issuer string) *mock.Provider {
		provider := mock.NewProvider()
		provider.IssuerURLFunc = func() string { return issuer }
		return provider
	}
	listed := make([]string, 1, 4)
	listed[0] = "keys.internal"

	require.Equal(t, []string{"keys.internal", "dex.internal"},
		providerJWKSPrivateIPHosts(withIssuer("https://dex.internal:5556/dex"), listed))
	require.Equal(t, []string{"keys.internal"}, listed[:cap(listed)][:1], "listed must not be appended to in place")
	require.Equal(t, listed, providerJWKSPrivateIPHosts(withIssuer(""), listed))
	require.Equal(t, listed, providerJWKSPrivateIPHosts(withIssuer("://bad"), listed))
	require.Equal(t, []string{"dex.internal"}, providerJWKSPrivateIPHosts(withIssuer("https://dex.internal"), nil))
}
