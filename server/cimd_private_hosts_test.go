package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/privateaddr/privateaddrtest"
	"github.com/giantswarm/mcp-oauth/internal/proxytunnel"
	"github.com/giantswarm/mcp-oauth/internal/proxytunnel/proxytunneltest"
)

const (
	errPrivateIP  = "private/internal IP"
	errListedHost = "a private-IP host list does not allow"
)

// TestValidateAndSanitizeMetadataURL_AllowedPrivateHosts covers the listed /
// unlisted / global-bool combinations of the CIMD private-IP allowance. Both
// "localhost" and "127.0.0.1" resolve to loopback without a DNS server;
// LoopbackAsPrivate lets loopback stand in for a private address.
func TestValidateAndSanitizeMetadataURL_AllowedPrivateHosts(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		allowPrivateIP bool
		allowedHosts   []string
		checkListed    listedHostCheck
		wantErr        string
	}{
		{"listed private host is accepted", "https://localhost/client.json", false, []string{"localhost"}, privateaddrtest.LoopbackAsPrivate(isPrivateIP), ""},
		{"listed host matches case-insensitively with a trailing dot", "https://LocalHost./client.json", false, []string{"localhost"}, privateaddrtest.LoopbackAsPrivate(isPrivateIP), ""},
		{"listed host resolving to loopback is refused", "https://localhost/client.json", false, []string{"localhost"}, checkListedMetadataHost, errListedHost},
		{"unlisted private host is refused", "https://127.0.0.1/client.json", false, []string{"localhost"}, privateaddrtest.LoopbackAsPrivate(isPrivateIP), errPrivateIP},
		{"no allowance refuses the listed host", "https://localhost/client.json", false, nil, privateaddrtest.LoopbackAsPrivate(isPrivateIP), errPrivateIP},
		{"global bool accepts every private host", "https://127.0.0.1/client.json", true, nil, checkListedMetadataHost, ""},
		{"global bool and list accept an unlisted host", "https://127.0.0.1/client.json", true, []string{"localhost"}, checkListedMetadataHost, ""},
		{"global bool overrides the listed-host policy", "https://localhost/client.json", true, []string{"localhost"}, checkListedMetadataHost, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAndSanitizeMetadataURL(tt.url, tt.allowPrivateIP, tt.allowedHosts, tt.checkListed)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
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
// With the production policy a listed host that resolves to loopback is
// refused too.
func TestSSRFProtectedTransport_AllowedPrivateHosts(t *testing.T) {
	srv := newTLSServerWithFreshCert(t, http.NotFoundHandler())
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	transport := createSSRFProtectedTransport(false, []string{"localhost"}, nil, noProxy, privateaddrtest.LoopbackAsPrivate(isPrivateIP))

	conn, err := transport.DialContext(t.Context(), "tcp", net.JoinHostPort("localhost", port))
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	_, err = transport.DialContext(t.Context(), "tcp", net.JoinHostPort("127.0.0.1", port))
	require.ErrorContains(t, err, errPrivateIP)

	production := createSSRFProtectedTransport(false, []string{"localhost"}, nil, noProxy, checkListedMetadataHost)
	_, err = production.DialContext(t.Context(), "tcp", net.JoinHostPort("localhost", port))
	require.ErrorContains(t, err, errListedHost)
}

// TestFetchClientMetadata_AllowedPrivateHostsAndRootCAs fetches a CIMD
// document from a loopback server whose certificate chains to its own CA: a
// listed host does not lift loopback, and the blanket fetch succeeds only with
// that CA configured.
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

	t.Run("listed host resolving to loopback is refused", func(t *testing.T) {
		_, err := fetch(t, byName, Config{
			AllowPrivateIPClientMetadataHosts: []string{"localhost"},
			ClientMetadataRootCAs:             pool,
		})
		require.ErrorContains(t, err, errListedHost)
	})

	t.Run("blanket without the pool fails certificate verification", func(t *testing.T) {
		_, err := fetch(t, byName, Config{AllowPrivateIPClientMetadata: true})
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

func noProxy(string, string) (*url.URL, error) { return nil, nil }

func proxyAlways(proxyURL *url.URL) proxytunnel.Selector {
	return func(string, string) (*url.URL, error) { return proxyURL, nil }
}

// TestSSRFProtectedTransport_TunnelsTheCheckedIPThroughTheProxy fetches over
// HTTPS through a CONNECT proxy: the proxy is asked for the validated IP, not
// the hostname, and TLS still verifies the hostname.
func TestSSRFProtectedTransport_TunnelsTheCheckedIPThroughTheProxy(t *testing.T) {
	srv := newTLSServerWithFreshCert(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("metadata"))
	}))
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	proxy := proxytunneltest.New(t, http.StatusOK)

	client := &http.Client{Transport: createSSRFProtectedTransport(false, []string{"localhost"}, pool, proxyAlways(proxy.URL()), privateaddrtest.LoopbackAsPrivate(isPrivateIP))}
	resp, err := client.Get("https://" + net.JoinHostPort("localhost", port) + "/client.json")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "metadata", string(body))

	// localhost may resolve to ::1 and 127.0.0.1; each checked address the
	// dialer tries is its own CONNECT, and none names the host.
	requests := proxy.Requests()
	require.NotEmpty(t, requests)
	for _, request := range requests {
		host, _, err := net.SplitHostPort(request.Host)
		require.NoError(t, err)
		require.True(t, net.ParseIP(host).IsLoopback(), "CONNECT target %q must be a checked IP", request.Host)
	}
}

// TestSSRFProtectedTransport_RefusesPrivateTargetBeforeTheProxy pins that the
// guard runs before any proxy is contacted.
func TestSSRFProtectedTransport_RefusesPrivateTargetBeforeTheProxy(t *testing.T) {
	proxy := proxytunneltest.New(t, http.StatusOK)
	transport := createSSRFProtectedTransport(false, nil, nil, proxyAlways(proxy.URL()), checkListedMetadataHost)

	_, err := transport.DialContext(t.Context(), "tcp", net.JoinHostPort("localhost", "443"))
	require.ErrorContains(t, err, errPrivateIP)
	require.Empty(t, proxy.Requests())
}

func TestDialFirstReachable_FallsBackFromARefusedAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
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
	ips := []net.IPAddr{{IP: net.IPv4(127, 0, 0, 2)}, {IP: net.IPv4(127, 0, 0, 1)}}
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	t.Run("direct", func(t *testing.T) {
		conn, err := dialFirstReachable(t.Context(), dialer, "tcp", "metadata.example", port, ips, nil)
		require.NoError(t, err)
		require.Equal(t, listener.Addr().String(), conn.RemoteAddr().String())
		require.NoError(t, conn.Close())
	})

	t.Run("through the proxy", func(t *testing.T) {
		proxy := proxytunneltest.New(t, http.StatusOK)
		conn, err := dialFirstReachable(t.Context(), dialer, "tcp", "metadata.example", port, ips, proxy.URL())
		require.NoError(t, err)
		require.NoError(t, conn.Close())

		requests := proxy.Requests()
		require.Len(t, requests, 2)
		require.Equal(t, net.JoinHostPort("127.0.0.2", port), requests[0].Host)
		require.Equal(t, net.JoinHostPort("127.0.0.1", port), requests[1].Host)
	})
}

// TestFetchClientMetadata_NeverFetchesJWKSURI pins that a jwks_uri inside a
// metadata document is not fetched, so an allowed metadata host cannot be
// used to reach another private host. The blanket allowance is used because
// it is the widest: what it does not fetch, a host list does not either.
func TestFetchClientMetadata_NeverFetchesJWKSURI(t *testing.T) {
	var jwksHits atomic.Int32
	jwks := newTLSServerWithFreshCert(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwksHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	jwksURL, err := url.Parse(jwks.URL)
	require.NoError(t, err)

	for _, authMethod := range []string{"none", "private_key_jwt"} {
		t.Run(authMethod, func(t *testing.T) {
			srv := newTLSServerWithFreshCert(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"client_id":                  "https://" + r.Host + r.URL.Path,
					"client_name":                "Client With Keys",
					"redirect_uris":              []string{"https://app.example.com/callback"},
					"token_endpoint_auth_method": authMethod,
					"jwks_uri":                   "https://" + net.JoinHostPort("localhost", jwksURL.Port()) + "/keys",
				})
			}))
			u, err := url.Parse(srv.URL)
			require.NoError(t, err)
			pool := x509.NewCertPool()
			pool.AddCert(srv.Certificate())
			pool.AddCert(jwks.Certificate())

			s := &Server{
				Config: &Config{
					EnableClientIDMetadataDocuments:   true,
					AllowPrivateIPClientMetadata:      true,
					AllowPrivateIPClientMetadataHosts: []string{"localhost"},
					ClientMetadataRootCAs:             pool,
				},
				Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
				Instrumentation: testInstrumentation(t),
				Auditor:         testAuditor(),
			}
			md, _, err := s.fetchClientMetadata(t.Context(), "https://"+net.JoinHostPort("localhost", u.Port())+"/client.json")
			if authMethod == "none" {
				require.NoError(t, err)
				require.Equal(t, "Client With Keys", md.ClientName)
			} else {
				require.ErrorContains(t, err, "token_endpoint_auth_method")
			}
			require.Zero(t, jwksHits.Load())
		})
	}
}

// TestCheckListedMetadataHost pins that a listed metadata host reaches every
// address an unlisted one may, plus RFC 1918 and RFC 4193, and nothing else.
func TestCheckListedMetadataHost(t *testing.T) {
	for _, tt := range []struct {
		addr     string
		unlisted bool
		listed   bool
	}{
		{"8.8.8.8", true, true},
		{"10.0.0.1", false, true},
		{"fd00::1", false, true},
		{"100.64.0.1", false, false},
		{"127.0.0.1", false, false},
		{"169.254.169.254", false, false},
		{"fe80::1", false, false},
	} {
		t.Run(tt.addr, func(t *testing.T) {
			ip := net.ParseIP(tt.addr)
			require.Equal(t, tt.unlisted, !isPrivateIP(ip))
			require.Equal(t, tt.listed, checkListedMetadataHost("gateway.internal", []net.IP{ip}) == nil)
		})
	}
}

// TestMetadataFetchError_NamesPinningOnARefusedConnect pins the hint an
// operator gets when a proxy that allows by domain refuses the CONNECT to the
// checked IP.
func TestMetadataFetchError_NamesPinningOnARefusedConnect(t *testing.T) {
	proxy := proxytunneltest.New(t, http.StatusForbidden)
	client := &http.Client{Transport: createSSRFProtectedTransport(false, []string{"localhost"}, nil, proxyAlways(proxy.URL()), privateaddrtest.LoopbackAsPrivate(isPrivateIP))}
	_, err := client.Get("https://localhost:443/client.json")
	require.Error(t, err)

	fetchErr := metadataFetchError("https://localhost/client.json", err)
	require.ErrorContains(t, fetchErr, "proxy refused CONNECT")
	require.ErrorContains(t, fetchErr, "PreRegisteredClientMetadata")
	var refused *proxytunnel.ConnectRefusedError
	require.ErrorAs(t, fetchErr, &refused)

	plain := metadataFetchError("https://localhost/client.json", errors.New("connection reset"))
	require.NotContains(t, plain.Error(), "PreRegisteredClientMetadata")

	authRequired := metadataFetchError("https://localhost/client.json", &proxytunnel.ConnectRefusedError{
		Target: "127.0.0.1:443", StatusCode: http.StatusProxyAuthRequired, Status: "407 Proxy Authentication Required",
	})
	require.NotContains(t, authRequired.Error(), "PreRegisteredClientMetadata")
}
