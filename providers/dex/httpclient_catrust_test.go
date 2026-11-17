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
// Dex client, so an internal-CA Dex is trusted without replacing the client.
func TestResolveHTTPClient_RootCAs(t *testing.T) {
	t.Parallel()
	pool := x509.NewCertPool()

	t.Run("pool is pinned", func(t *testing.T) {
		client := resolveHTTPClient(nil, pool, 5*time.Second)
		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok, "expected *http.Transport, got %T", client.Transport)
		require.NotNil(t, transport.TLSClientConfig)
		require.Same(t, pool, transport.TLSClientConfig.RootCAs)
		require.GreaterOrEqual(t, transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))
		require.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	})

	t.Run("nil pool keeps system-pool verification", func(t *testing.T) {
		client := resolveHTTPClient(nil, nil, 5*time.Second)
		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok, "expected *http.Transport, got %T", client.Transport)
		require.Nil(t, transport.TLSClientConfig, "a nil pool must not pin a CA")
	})
}
