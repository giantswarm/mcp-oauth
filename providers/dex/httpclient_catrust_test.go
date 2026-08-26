package dex

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestResolveHTTPClient_RootCAs verifies that an explicit CA pool reaches the
// Dex client on both dial postures. A Dex on a public address can present an
// internal-CA certificate, so trust must not require AllowPrivateIP.
func TestResolveHTTPClient_RootCAs(t *testing.T) {
	t.Parallel()
	pool := x509.NewCertPool()

	for _, allowPrivateIP := range []bool{false, true} {
		name := "without AllowPrivateIP"
		if allowPrivateIP {
			name = "with AllowPrivateIP"
		}
		t.Run(name, func(t *testing.T) {
			client := resolveHTTPClient(nil, allowPrivateIP, pool, 5*time.Second)
			transport, ok := client.Transport.(*http.Transport)
			require.True(t, ok, "expected *http.Transport, got %T", client.Transport)
			require.NotNil(t, transport.TLSClientConfig)
			require.Same(t, pool, transport.TLSClientConfig.RootCAs)
			require.GreaterOrEqual(t, transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))
			require.False(t, transport.TLSClientConfig.InsecureSkipVerify)
		})
	}

	t.Run("nil pool keeps system-pool verification on a tuned transport", func(t *testing.T) {
		client := resolveHTTPClient(nil, false, nil, 5*time.Second)
		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok, "expected *http.Transport, got %T", client.Transport)
		require.Nil(t, transport.TLSClientConfig, "a nil pool must not pin a CA")
		require.True(t, transport.ForceAttemptHTTP2)
		require.NotZero(t, transport.IdleConnTimeout)
	})
}
