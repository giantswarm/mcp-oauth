package proxytunnel_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/proxytunnel"
	"github.com/giantswarm/mcp-oauth/internal/proxytunnel/proxytunneltest"
)

func echoServer(t *testing.T) (net.IP, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)
	return addr.IP, strconv.Itoa(addr.Port)
}

func TestDialTunnelsToTheCheckedIP(t *testing.T) {
	proxy := proxytunneltest.New(t, http.StatusOK)
	ip, port := echoServer(t)
	proxyURL := proxy.URL()
	proxyURL.User = url.UserPassword("egress", "s3cret")

	conn, err := proxytunnel.Dial(t.Context(), &net.Dialer{}, "tcp", proxyURL, ip, port)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "ping", string(reply))

	requests := proxy.Requests()
	require.Len(t, requests, 1)
	require.Equal(t, http.MethodConnect, requests[0].Method)
	require.Equal(t, net.JoinHostPort(ip.String(), port), requests[0].Host)
	require.Equal(t, "Basic ZWdyZXNzOnMzY3JldA==", requests[0].Header.Get("Proxy-Authorization"))
}

func TestDialWithoutProxyConnectsDirectly(t *testing.T) {
	ip, port := echoServer(t)

	conn, err := proxytunnel.Dial(t.Context(), &net.Dialer{}, "tcp", nil, ip, port)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

func TestDialReportsARefusedConnect(t *testing.T) {
	proxy := proxytunneltest.New(t, http.StatusForbidden)
	ip, port := echoServer(t)

	conn, err := proxytunnel.Dial(t.Context(), &net.Dialer{}, "tcp", proxy.URL(), ip, port)
	require.ErrorContains(t, err, "proxy refused CONNECT")
	require.ErrorContains(t, err, "403")
	require.Nil(t, conn)
}

func TestDialRefusesUnsupportedProxyScheme(t *testing.T) {
	ip, port := echoServer(t)

	conn, err := proxytunnel.Dial(t.Context(), &net.Dialer{}, "tcp", &url.URL{Scheme: "socks5", Host: "127.0.0.1:1080"}, ip, port)
	require.ErrorContains(t, err, `unsupported proxy scheme "socks5"`)
	require.Nil(t, conn)
}

func TestDialStopsWhenTheContextEnds(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = conn.Close() })
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	silentProxy := &url.URL{Scheme: "http", Host: listener.Addr().String()}

	conn, err := proxytunnel.Dial(ctx, &net.Dialer{}, "tcp", silentProxy, net.IPv4(127, 0, 0, 1), "443")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, conn)
}

func TestFromEnvironmentHonorsNoProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.internal:3128")
	t.Setenv("NO_PROXY", ".svc,dex.example.org")

	selector := proxytunnel.FromEnvironment()

	proxyURL, err := selector("client.example.com", "443")
	require.NoError(t, err)
	require.Equal(t, "http://proxy.internal:3128", proxyURL.String())

	proxyURL, err = selector("dex.example.org", "443")
	require.NoError(t, err)
	require.Nil(t, proxyURL)

	proxyURL, err = selector("keys.cluster.svc", "443")
	require.NoError(t, err)
	require.Nil(t, proxyURL)
}
