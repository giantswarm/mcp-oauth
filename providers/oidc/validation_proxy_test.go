package oidc

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/privateaddr/privateaddrtest"
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

	dial := hostScopedPrivateIPDialContext(&net.Dialer{}, []string{"localhost"}, proxyAlways(proxy.URL()), privateaddrtest.LoopbackAsPrivate(isPrivateOrRestrictedIP))
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

// TestGuardedDialTriesEachValidatedAddress listens on the last address
// localhost resolves to, so the dial only succeeds if it moves past the
// earlier ones, directly and through the proxy.
func TestGuardedDialTriesEachValidatedAddress(t *testing.T) {
	ips, err := net.DefaultResolver.LookupIP(t.Context(), "ip", "localhost")
	require.NoError(t, err)
	if len(ips) < 2 {
		t.Skip("localhost resolves to a single address here")
	}
	last := ips[len(ips)-1]
	listener, err := net.Listen("tcp", net.JoinHostPort(last.String(), "0"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	addr := net.JoinHostPort("localhost", port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	t.Run("direct", func(t *testing.T) {
		dial := hostScopedPrivateIPDialContext(dialer, []string{"localhost"}, proxyAlways(nil), privateaddrtest.LoopbackAsPrivate(isPrivateOrRestrictedIP))
		conn, err := dial(t.Context(), "tcp", addr)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	})

	t.Run("through the proxy", func(t *testing.T) {
		proxy := proxytunneltest.New(t, http.StatusOK)
		dial := hostScopedPrivateIPDialContext(dialer, []string{"localhost"}, proxyAlways(proxy.URL()), privateaddrtest.LoopbackAsPrivate(isPrivateOrRestrictedIP))
		conn, err := dial(t.Context(), "tcp", addr)
		require.NoError(t, err)
		require.NoError(t, conn.Close())

		requests := proxy.Requests()
		require.Len(t, requests, len(ips))
		require.Equal(t, net.JoinHostPort(last.String(), port), requests[len(requests)-1].Host)
	})
}

// TestDefaultDialClientNamesAProxyRefusal pins that a client on the proxy
// environment reports a refused CONNECT as the proxy's refusal, not as the
// bare status text net/http returns, and that discovery says how to fix it.
func TestDefaultDialClientNamesAProxyRefusal(t *testing.T) {
	proxy := proxytunneltest.New(t, http.StatusForbidden)
	client := NewDefaultDialHTTPClient(5*time.Second, nil)
	client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy.URL())

	_, err := client.Get("https://dex.example.test/dex/.well-known/openid-configuration")
	var refused *proxytunnel.ConnectRefusedError
	require.ErrorAs(t, err, &refused)
	require.Equal(t, http.StatusForbidden, refused.StatusCode)
	require.Equal(t, "dex.example.test:443", refused.Target)
	require.ErrorContains(t, err, "proxy refused CONNECT dex.example.test:443")

	_, err = NewDiscoveryClient(client, time.Minute, nil).Discover(t.Context(), "https://dex.example.test/dex")
	require.ErrorAs(t, err, &refused)
	require.ErrorContains(t, err, "add the issuer host to NO_PROXY")
}

// TestDefaultDialClientPassesAnAcceptedConnect pins that the refusal hook
// leaves a 200 CONNECT alone.
func TestDefaultDialClientPassesAnAcceptedConnect(t *testing.T) {
	require.NoError(t, refuseNonOKConnect(t.Context(), nil, &http.Request{Host: "dex.example.test:443"}, &http.Response{StatusCode: http.StatusOK}))
}
