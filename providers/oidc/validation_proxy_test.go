package oidc

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/proxytunnel"
	"github.com/giantswarm/mcp-oauth/internal/proxytunnel/proxytunneltest"
)

func proxyAlways(proxyURL *url.URL) proxytunnel.Selector {
	return func(string, string) (*url.URL, error) { return proxyURL, nil }
}

// TestHostScopedDialTunnelsTheCheckedIP pins that a proxied guarded dial asks
// the proxy for the validated IP, never for the hostname.
func TestHostScopedDialTunnelsTheCheckedIP(t *testing.T) {
	// The dialer connects to the first address localhost resolves to, so the
	// backend listens there.
	ips, err := net.DefaultResolver.LookupIP(t.Context(), "ip", "localhost")
	require.NoError(t, err)
	listener, err := net.Listen("tcp", net.JoinHostPort(ips[0].String(), "0"))
	require.NoError(t, err)
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("keys"))
	}))
	backend.Listener = listener
	backend.Start()
	t.Cleanup(backend.Close)
	_, port, err := net.SplitHostPort(backend.Listener.Addr().String())
	require.NoError(t, err)
	proxy := proxytunneltest.New(t, http.StatusOK)

	dial := hostScopedPrivateIPDialContext(&net.Dialer{}, []string{"localhost"}, proxyAlways(proxy.URL()))
	client := &http.Client{Transport: &http.Transport{DialContext: dial}}
	resp, err := client.Get("http://" + net.JoinHostPort("localhost", port) + "/keys")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "keys", string(body))

	requests := proxy.Requests()
	require.Len(t, requests, 1)
	host, _, err := net.SplitHostPort(requests[0].Host)
	require.NoError(t, err)
	require.True(t, net.ParseIP(host).IsLoopback(), "CONNECT target %q must be the checked IP", requests[0].Host)
}

// TestSSRFSafeDialRefusesPrivateTargetBeforeTheProxy pins that the guard runs
// before any proxy is contacted.
func TestSSRFSafeDialRefusesPrivateTargetBeforeTheProxy(t *testing.T) {
	proxy := proxytunneltest.New(t, http.StatusOK)

	dial := ssrfSafeDialContext(&net.Dialer{}, proxyAlways(proxy.URL()))
	_, err := dial(t.Context(), "tcp", net.JoinHostPort("localhost", "443"))
	require.ErrorIs(t, err, ErrRestrictedAddress)
	require.Empty(t, proxy.Requests())
}
