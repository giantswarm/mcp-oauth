package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const errPrivateIP = "private/internal IP"

// TestValidateAndSanitizeMetadataURL_AllowedPrivateHosts covers the listed /
// unlisted / global-bool combinations of the CIMD private-IP allowance. Both
// "localhost" and "127.0.0.1" resolve to loopback without a DNS server.
func TestValidateAndSanitizeMetadataURL_AllowedPrivateHosts(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		allowPrivateIP bool
		allowedHosts   []string
		wantErr        bool
	}{
		{"listed private host is accepted", "https://localhost/client.json", false, []string{"localhost"}, false},
		{"unlisted private host is refused", "https://127.0.0.1/client.json", false, []string{"localhost"}, true},
		{"no allowance refuses the listed host", "https://localhost/client.json", false, nil, true},
		{"global bool accepts every private host", "https://127.0.0.1/client.json", true, nil, false},
		{"global bool and list accept an unlisted host", "https://127.0.0.1/client.json", true, []string{"localhost"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAndSanitizeMetadataURL(tt.url, tt.allowPrivateIP, tt.allowedHosts)
			if tt.wantErr {
				require.ErrorContains(t, err, errPrivateIP)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.url, got)
		})
	}
}

// TestSSRFProtectedTransport_AllowedPrivateHosts pins the connection-time
// guard: the dialer lets a listed host reach a private address and still
// refuses an unlisted one, so DNS rebinding of an unlisted host stays covered.
func TestSSRFProtectedTransport_AllowedPrivateHosts(t *testing.T) {
	srv := newTLSServerWithFreshCert(t, http.NotFoundHandler())
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	transport := createSSRFProtectedTransport(false, []string{"localhost"}, nil)

	conn, err := transport.DialContext(t.Context(), "tcp", net.JoinHostPort("localhost", port))
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	_, err = transport.DialContext(t.Context(), "tcp", net.JoinHostPort("127.0.0.1", port))
	require.ErrorContains(t, err, errPrivateIP)
}

// TestFetchClientMetadata_AllowedPrivateHostsAndRootCAs fetches a CIMD
// document from a loopback server whose certificate chains to its own CA: the
// fetch succeeds only for a listed host and only with that CA configured.
func TestFetchClientMetadata_AllowedPrivateHostsAndRootCAs(t *testing.T) {
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
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	byName := "https://" + net.JoinHostPort("localhost", u.Port()) + "/client.json"
	byIP := srv.URL + "/client.json"

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	fetch := func(t *testing.T, clientID string, cfg Config) (*ClientMetadata, error) {
		t.Helper()
		cfg.EnableClientIDMetadataDocuments = true
		s := &Server{
			Config:          &cfg,
			Logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError})),
			Instrumentation: testInstrumentation(t),
			Auditor:         testAuditor(),
		}
		md, _, err := s.fetchClientMetadata(context.Background(), clientID)
		return md, err
	}

	t.Run("listed host with the configured pool is fetched", func(t *testing.T) {
		md, err := fetch(t, byName, Config{
			AllowPrivateIPClientMetadataHosts: []string{"localhost"},
			ClientMetadataRootCAs:             pool,
		})
		require.NoError(t, err)
		require.Equal(t, "Private Host Client", md.ClientName)
	})

	t.Run("listed host without the pool fails certificate verification", func(t *testing.T) {
		_, err := fetch(t, byName, Config{AllowPrivateIPClientMetadataHosts: []string{"localhost"}})
		require.ErrorContains(t, err, "certificate")
		require.NotContains(t, err.Error(), errPrivateIP)
	})

	t.Run("another private host is refused", func(t *testing.T) {
		_, err := fetch(t, byIP, Config{
			AllowPrivateIPClientMetadataHosts: []string{"localhost"},
			ClientMetadataRootCAs:             pool,
		})
		require.ErrorContains(t, err, errPrivateIP)
	})

	t.Run("global bool with the configured pool fetches any private host", func(t *testing.T) {
		md, err := fetch(t, byIP, Config{
			AllowPrivateIPClientMetadata: true,
			ClientMetadataRootCAs:        pool,
		})
		require.NoError(t, err)
		require.Equal(t, "Private Host Client", md.ClientName)
	})
}
