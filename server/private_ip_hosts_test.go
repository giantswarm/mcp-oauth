package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestPrivateIPHostDeprecations(t *testing.T) {
	tests := []struct {
		name       string
		config     Config
		wantLogs   []string
		absentLogs []string
	}{
		{
			name: "new host lists log no deprecation",
			config: Config{
				ClientMetadataPrivateIPHosts: []string{"gateway.internal"},
				RedirectURIPrivateIPHosts:    []string{"portal.internal"},
				JWKSPrivateIPHosts:           []string{"dex.internal"},
			},
			absentLogs: []string{"DEPRECATED"},
		},
		{
			name: "renamed host lists",
			config: Config{
				AllowPrivateIPClientMetadataHosts: []string{"gateway.internal"},
				AllowPrivateIPRedirectURIHosts:    []string{"portal.internal"},
			},
			wantLogs: []string{
				"DEPRECATED: AllowPrivateIPClientMetadataHosts is renamed ClientMetadataPrivateIPHosts",
				"DEPRECATED: AllowPrivateIPRedirectURIHosts is renamed RedirectURIPrivateIPHosts",
			},
		},
		{
			name: "blanket switches",
			config: Config{
				AllowPrivateIPClientMetadata: true,
				AllowPrivateIPRedirectURIs:   true,
				AllowPrivateIPJWKS:           true,
			},
			wantLogs: []string{
				"DEPRECATED: AllowPrivateIPClientMetadata lifts the private-IP check for every host; list the hosts in ClientMetadataPrivateIPHosts instead",
				"DEPRECATED: AllowPrivateIPRedirectURIs lifts the private-IP check for every host; list the hosts in RedirectURIPrivateIPHosts instead",
				"DEPRECATED: AllowPrivateIPJWKS lifts the private-IP check for every host; list the hosts in JWKSPrivateIPHosts instead",
			},
			absentLogs: []string{"overrides"},
		},
		{
			name: "blanket switch and host list conflict",
			config: Config{
				AllowPrivateIPJWKS: true,
				JWKSPrivateIPHosts: []string{"dex.internal"},
			},
			wantLogs: []string{"AllowPrivateIPJWKS overrides JWKSPrivateIPHosts: every host may resolve to a private address"},
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

func TestMergeHosts(t *testing.T) {
	require.Equal(t, []string{"a", "b", "c"}, mergeHosts([]string{"a", "b"}, []string{"b", "c"}))
	require.Equal(t, []string{"a"}, mergeHosts([]string{"a"}, nil))
	require.Equal(t, []string{"b"}, mergeHosts(nil, []string{"b"}))
}

func TestRedirectURIPrivateIPHosts(t *testing.T) {
	const privateHost = "gateway.internal.example.com"
	tests := []struct {
		name      string
		config    Config
		hostname  string
		addresses []string
		category  string
	}{
		{"listed host", Config{RedirectURIPrivateIPHosts: []string{privateHost}}, privateHost, []string{"10.0.0.1"}, ""},
		{"listed host through the renamed field", Config{AllowPrivateIPRedirectURIHosts: []string{privateHost}}, privateHost, []string{"10.0.0.1"}, ""},
		{"unlisted host", Config{RedirectURIPrivateIPHosts: []string{privateHost}}, "other.internal.example.com", []string{"10.0.0.1"}, RedirectURIErrorCategoryDNSPrivateIP},
		{"listed host resolving link-local", Config{RedirectURIPrivateIPHosts: []string{privateHost}}, privateHost, []string{"169.254.169.254"}, RedirectURIErrorCategoryDNSLinkLocal},
		{"blanket switch overrides the list", Config{RedirectURIPrivateIPHosts: []string{privateHost}, AllowPrivateIPRedirectURIs: true}, "other.internal.example.com", []string{"10.0.0.1"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newMockDNSResolver()
			addresses := make([]net.IP, 0, len(tt.addresses))
			for _, address := range tt.addresses {
				addresses = append(addresses, net.ParseIP(address))
			}
			resolver.setResult(tt.hostname, addresses...)
			config := tt.config
			config.Issuer = testAuthIssuer
			config.DNSResolver = resolver.resolver()
			server, err := newTestServerSetup(true).createServer(&config)
			require.NoError(t, err)
			t.Cleanup(server.stopMetadataCacheCleanup)

			err = server.ValidateRedirectURIForRegistration(t.Context(), "https://"+tt.hostname+"/callback")
			if tt.category == "" {
				require.NoError(t, err)
				return
			}
			require.Equal(t, tt.category, GetRedirectURIErrorCategory(err))
		})
	}
}

func TestClientMetadataPrivateIPHosts(t *testing.T) {
	srv := newTLSServerWithFreshCert(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ClientMetadata{
			ClientID:                "https://" + r.Host + r.URL.Path,
			ClientName:              "Private Host Client",
			RedirectURIs:            []string{"https://app.example.com/callback"},
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		})
	}))
	serverURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	byName := "https://" + net.JoinHostPort("localhost", serverURL.Port()) + "/client.json"
	byLoopbackIP := srv.URL + "/client.json"
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	fetch := func(t *testing.T, clientID string, config Config) (*ClientMetadata, error) {
		t.Helper()
		config.EnableClientIDMetadataDocuments = true
		config.ClientMetadataRootCAs = pool
		server := &Server{
			Config:          &config,
			Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
			Instrumentation: testInstrumentation(t),
			Auditor:         testAuditor(),
		}
		metadata, _, err := server.fetchClientMetadata(context.Background(), clientID)
		return metadata, err
	}

	t.Run("listed host is fetched", func(t *testing.T) {
		metadata, err := fetch(t, byName, Config{ClientMetadataPrivateIPHosts: []string{"localhost"}})
		require.NoError(t, err)
		require.Equal(t, "Private Host Client", metadata.ClientName)
	})

	t.Run("renamed field still lists the host", func(t *testing.T) {
		_, err := fetch(t, byName, Config{AllowPrivateIPClientMetadataHosts: []string{"localhost"}})
		require.NoError(t, err)
	})

	t.Run("unlisted loopback host is refused", func(t *testing.T) {
		_, err := fetch(t, byLoopbackIP, Config{ClientMetadataPrivateIPHosts: []string{"localhost"}})
		require.ErrorContains(t, err, errPrivateIP)
	})

	t.Run("unlisted link-local host is refused", func(t *testing.T) {
		_, err := validateAndSanitizeMetadataURL("https://169.254.169.254/client.json", false, []string{"localhost"})
		require.ErrorContains(t, err, errPrivateIP)
	})

	t.Run("a literal IP is not matched by a listed hostname", func(t *testing.T) {
		transport := createSSRFProtectedTransport(false, []string{"localhost"}, nil)
		_, err := transport.DialContext(t.Context(), "tcp", net.JoinHostPort("127.0.0.1", serverURL.Port()))
		require.ErrorContains(t, err, errPrivateIP)
	})
}

func TestJWKSPrivateIPHosts(t *testing.T) {
	srv := newTLSServerWithFreshCert(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	serverURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

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
		client := newServer(t, Config{JWKSPrivateIPHosts: []string{"localhost"}}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), "https://"+net.JoinHostPort("localhost", serverURL.Port())+"/keys")
		require.NoError(t, err)
	})

	t.Run("unlisted loopback host is refused", func(t *testing.T) {
		client := newServer(t, Config{JWKSPrivateIPHosts: []string{"localhost"}}).getJWKSClient()
		_, err := client.FetchJWKS(t.Context(), srv.URL+"/keys")
		require.Error(t, err)
		require.Contains(t, err.Error(), "loopback")
	})

	t.Run("trusted issuer host list creates its own client", func(t *testing.T) {
		validator, err := NewOIDCValidator([]TrustedIssuer{{
			Issuer:             testIssuer,
			JwksURL:            "https://example.com/jwks",
			JWKSPrivateIPHosts: []string{"muster.agent-platform.svc.cluster.local"},
		}})
		require.NoError(t, err)
		require.NotNil(t, validator.issuerClients[testIssuer])
	})
}

func TestTrustedIssuerPrivateIPDeprecations(t *testing.T) {
	logger, logs := captureLogger()
	logTrustedIssuerPrivateIPDeprecations([]TrustedIssuer{
		{Issuer: "https://renamed.example.com", AllowPrivateIPJWKSHosts: []string{"dex.internal"}},
		{Issuer: "https://blanket.example.com", AllowPrivateIPJWKS: true},
		{Issuer: "https://current.example.com", JWKSPrivateIPHosts: []string{"dex.internal"}},
	}, logger)

	require.Contains(t, logs.String(), "DEPRECATED: TrustedIssuer.AllowPrivateIPJWKSHosts is renamed JWKSPrivateIPHosts")
	require.Contains(t, logs.String(), "DEPRECATED: TrustedIssuer.AllowPrivateIPJWKS lifts the private-IP check for every host")
	require.NotContains(t, logs.String(), "current.example.com")
}
