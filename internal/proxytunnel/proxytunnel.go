// Package proxytunnel connects to addresses the caller has already validated,
// through the HTTP proxy the environment names for their host.
//
// A guarded dialer resolves a hostname, checks every address, and must then
// reach exactly the address it checked. Handing the hostname to a proxy would
// let the proxy resolve it again, so the check would no longer cover the
// connection. Dial instead asks the proxy for a CONNECT tunnel to the checked
// IP; TLS on top of the tunnel still verifies the original hostname.
package proxytunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http/httpproxy"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"

	// defaultTunnelTimeout bounds a tunnel set-up when the dialer has no
	// Timeout, the same bound net/http puts on its own CONNECT exchange.
	defaultTunnelTimeout = time.Minute
)

// Selector returns the proxy for a connection to host and port, or nil to
// connect directly.
type Selector func(host, port string) (*url.URL, error)

// FromEnvironment reads HTTPS_PROXY and NO_PROXY (and their lowercase forms)
// once and returns the Selector they describe. The target is treated as an
// HTTPS URL: the guarded clients fetch HTTPS endpoints, and a CONNECT tunnel
// is what HTTPS_PROXY means for them. NO_PROXY is matched against the
// hostname, as net/http does.
func FromEnvironment() Selector {
	proxyFunc := httpproxy.FromEnvironment().ProxyFunc()
	return func(host, port string) (*url.URL, error) {
		return proxyFunc(&url.URL{Scheme: schemeHTTPS, Host: net.JoinHostPort(host, port)})
	}
}

// Dial connects to ip:port: directly when proxyURL is nil, otherwise through a
// CONNECT tunnel opened on the proxy. The proxy address itself is operator
// configuration and is dialed without any address check.
//
// Reaching the proxy and the CONNECT exchange together are bounded by
// dialer.Timeout (one minute when it is zero), because net/http dials with a
// context that neither the request's cancellation nor its deadline ends.
func Dial(ctx context.Context, dialer *net.Dialer, network string, proxyURL *url.URL, ip net.IP, port string) (net.Conn, error) {
	target := net.JoinHostPort(ip.String(), port)
	if proxyURL == nil {
		return dialer.DialContext(ctx, network, target)
	}

	timeout := dialer.Timeout
	if timeout <= 0 {
		timeout = defaultTunnelTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialProxy(ctx, dialer, network, proxyURL)
	if err != nil {
		return nil, err
	}
	if err := connect(ctx, conn, proxyURL, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// DialEach dials ips in order with Dial, one attempt (and through a proxy one
// CONNECT) per address, and returns the first connection. The dial budget is
// the earliest of dialer.Timeout, dialer.Deadline and the context deadline;
// like net.Dialer, each attempt gets the time left divided by the addresses
// left, with a two-second floor, so an address that drops packets cannot use
// up the whole budget.
func DialEach(ctx context.Context, dialer *net.Dialer, network string, proxyURL *url.URL, ips []net.IP, port string) (net.Conn, error) {
	return dialInTurn(ctx, dialBudget(ctx, dialer, time.Now()), len(ips), func(ctx context.Context, i int) (net.Conn, error) {
		return Dial(ctx, dialer, network, proxyURL, ips[i], port)
	})
}

// dialBudget is the deadline net.Dialer derives for a dial started at now:
// the earliest non-zero of now+Timeout, Deadline and the context deadline.
func dialBudget(ctx context.Context, dialer *net.Dialer, now time.Time) time.Time {
	var deadline time.Time
	earliest := func(candidate time.Time) {
		if !candidate.IsZero() && (deadline.IsZero() || candidate.Before(deadline)) {
			deadline = candidate
		}
	}
	if dialer.Timeout > 0 {
		earliest(now.Add(dialer.Timeout))
	}
	earliest(dialer.Deadline)
	if ctxDeadline, ok := ctx.Deadline(); ok {
		earliest(ctxDeadline)
	}
	return deadline
}

// dialInTurn runs attempt for 0..n-1 until one succeeds, giving each the
// share of deadline partialDeadline assigns. A zero deadline leaves the
// attempts unbounded here.
func dialInTurn(ctx context.Context, deadline time.Time, n int, attempt func(ctx context.Context, i int) (net.Conn, error)) (net.Conn, error) {
	if n == 0 {
		return nil, errors.New("no address to dial")
	}
	errs := make([]error, 0, n)
	for i := range n {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(append(errs, err)...)
		}
		attemptCtx := ctx
		if !deadline.IsZero() {
			attemptDeadline, ok := partialDeadline(time.Now(), deadline, n-i)
			if !ok {
				return nil, errors.Join(append(errs, context.DeadlineExceeded)...)
			}
			var cancel context.CancelFunc
			attemptCtx, cancel = context.WithDeadline(ctx, attemptDeadline)
			defer cancel()
		}
		conn, err := attempt(attemptCtx, i)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// partialDeadline is net.Dialer's split of a dial deadline across the
// addresses left: an equal share each, but at least two seconds while that
// much time remains. ok is false once the deadline has passed.
func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, bool) {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return time.Time{}, false
	}
	const minimum = 2 * time.Second
	share := remaining / time.Duration(addrsRemaining)
	if share < minimum {
		share = min(minimum, remaining)
	}
	return now.Add(share), true
}

func dialProxy(ctx context.Context, dialer *net.Dialer, network string, proxyURL *url.URL) (net.Conn, error) {
	addr := proxyURL.Host
	if proxyURL.Port() == "" {
		port := "80"
		if proxyURL.Scheme == schemeHTTPS {
			port = "443"
		}
		addr = net.JoinHostPort(proxyURL.Hostname(), port)
	}

	switch proxyURL.Scheme {
	case schemeHTTP:
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to proxy %s: %w", addr, err)
		}
		return conn, nil
	case schemeHTTPS:
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{ServerName: proxyURL.Hostname(), MinVersion: tls.VersionTLS12},
		}
		conn, err := tlsDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to proxy %s: %w", addr, err)
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q: only http and https proxies can open a CONNECT tunnel", proxyURL.Scheme)
	}
}

// connect sends CONNECT target on conn and reads the proxy's answer. The
// connection is closed if ctx ends first, which unblocks the read.
//
// A 200 answer carries no body: RFC 9110 section 9.3.6 has the client ignore
// Content-Length and Transfer-Encoding on it, so every byte after the header
// belongs to the tunnel and the body is never read. The header is capped at
// http.DefaultMaxHeaderBytes.
func connect(ctx context.Context, conn net.Conn, proxyURL *url.URL, target string) (err error) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		if !stop() && err == nil {
			err = ctx.Err()
		}
	}()

	header := make(http.Header)
	if user := proxyURL.User; user != nil {
		password, _ := user.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: header,
	}
	if err := request.Write(conn); err != nil {
		return errors.Join(fmt.Errorf("failed to send CONNECT %s to proxy", target), err, ctx.Err())
	}

	reader := bufio.NewReader(&io.LimitedReader{R: conn, N: http.DefaultMaxHeaderBytes})
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return errors.Join(fmt.Errorf("failed to read the proxy's answer to CONNECT %s", target), err, ctx.Err())
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy refused CONNECT %s: %s", target, response.Status)
	}
	if reader.Buffered() > 0 {
		return fmt.Errorf("proxy sent data after its answer to CONNECT %s", target)
	}
	return nil
}
