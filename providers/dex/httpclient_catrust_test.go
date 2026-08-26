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

	t.Run("without AllowPrivateIP", func(t *testing.T) {
		client := resolveHTTPClient(nil, false, pool, 5*time.Second)
		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok, "expected *http.Transport, got %T", client.Transport)
		require.NotNil(t, transport.TLSClientConfig)
		require.Same(t, pool, transport.TLSClientConfig.RootCAs)
		require.GreaterOrEqual(t, transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))
		require.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	})

	t.Run("with AllowPrivateIP", func(t *testing.T) {
		client := resolveHTTPClient(nil, true, pool, 5*time.Second)
		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok, "expected *http.Transport, got %T", client.Transport)
		require.NotNil(t, transport.TLSClientConfig)
		require.Same(t, pool, transport.TLSClientConfig.RootCAs)
	})

	t.Run("nil pool keeps the default transport", func(t *testing.T) {
		client := resolveHTTPClient(nil, false, nil, 5*time.Second)
		require.Nil(t, client.Transport, "a nil pool must not pin a transport")
	})

	t.Run("explicit client wins", func(t *testing.T) {
		explicit := &http.Client{}
		require.Same(t, explicit, resolveHTTPClient(explicit, false, pool, 5*time.Second))
	})
}
