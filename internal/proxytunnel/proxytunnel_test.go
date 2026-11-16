package proxytunnel_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
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

// scriptedProxy answers the first CONNECT with answer verbatim and, when relay
// is set, then relays bytes to the requested target.
func scriptedProxy(t *testing.T, answer string, relay bool) *url.URL {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		if !relay {
			_, _ = io.WriteString(conn, answer)
			return
		}
		upstream, err := net.Dial("tcp", request.Host)
		if err != nil {
			return
		}
		defer func() { _ = upstream.Close() }()
		_, _ = io.WriteString(conn, answer)
		go func() { _, _ = io.Copy(upstream, conn) }()
		_, _ = io.Copy(conn, upstream)
	}()
	return &url.URL{Scheme: "http", Host: listener.Addr().String()}
}

func TestDialBracketsAnIPv6Target(t *testing.T) {
	proxy := proxytunneltest.New(t, http.StatusForbidden)

	_, err := proxytunnel.Dial(t.Context(), &net.Dialer{}, "tcp", proxy.URL(), net.ParseIP("2001:db8::1"), "443")
	require.ErrorContains(t, err, "proxy refused CONNECT [2001:db8::1]:443")

	requests := proxy.Requests()
	require.Len(t, requests, 1)
	require.Equal(t, "[2001:db8::1]:443", requests[0].Host)
	require.Equal(t, "[2001:db8::1]:443", requests[0].RequestURI)
}

// TestDialIgnoresContentLengthOnASuccessfulConnect pins RFC 9110 section
// 9.3.6: the bytes after a 200 answer belong to the tunnel even when the
// proxy declares a body.
func TestDialIgnoresContentLengthOnASuccessfulConnect(t *testing.T) {
	ip, port := echoServer(t)
	proxyURL := scriptedProxy(t, "HTTP/1.1 200 Connection established\r\nContent-Length: 4\r\n\r\n", true)

	conn, err := proxytunnel.Dial(t.Context(), &net.Dialer{Timeout: 5 * time.Second}, "tcp", proxyURL, ip, port)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "ping", string(reply))
}

func TestDialRefusesDataBufferedAfterTheAnswer(t *testing.T) {
	proxyURL := scriptedProxy(t, "HTTP/1.1 200 Connection established\r\n\r\nearly", false)

	conn, err := proxytunnel.Dial(t.Context(), &net.Dialer{Timeout: 5 * time.Second}, "tcp", proxyURL, net.IPv4(127, 0, 0, 1), "443")
	require.ErrorContains(t, err, "proxy sent data after its answer")
	require.Nil(t, conn)
}

// TestDialBoundsTheTunnelByTheDialerTimeout pins that a proxy which never
// answers cannot hold the dial open when the context has no deadline, as with
// the dial context net/http passes.
func TestDialBoundsTheTunnelByTheDialerTimeout(t *testing.T) {
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
	silentProxy := &url.URL{Scheme: "http", Host: listener.Addr().String()}

	conn, err := proxytunnel.Dial(context.WithoutCancel(t.Context()), &net.Dialer{Timeout: 100 * time.Millisecond}, "tcp", silentProxy, net.IPv4(127, 0, 0, 1), "443")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Nil(t, conn)
}

// TestDialVerifiesAnHTTPSProxy pins that an https:// proxy is reached over TLS
// with its hostname as the server name, and that its certificate is verified.
func TestDialVerifiesAnHTTPSProxy(t *testing.T) {
	serverNames := make(chan string, 1)
	proxy := httptest.NewUnstartedServer(http.NotFoundHandler())
	proxy.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverNames <- hello.ServerName
			return nil, nil
		},
	}
	proxy.Config.ErrorLog = log.New(io.Discard, "", 0)
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	_, port, err := net.SplitHostPort(proxy.Listener.Addr().String())
	require.NoError(t, err)
	proxyURL := &url.URL{Scheme: "https", Host: net.JoinHostPort("localhost", port)}

	conn, err := proxytunnel.Dial(t.Context(), &net.Dialer{Timeout: 5 * time.Second}, "tcp4", proxyURL, net.IPv4(127, 0, 0, 1), "443")
	var verificationErr *tls.CertificateVerificationError
	require.ErrorAs(t, err, &verificationErr)
	require.Nil(t, conn)
	require.Equal(t, "localhost", <-serverNames)
}
