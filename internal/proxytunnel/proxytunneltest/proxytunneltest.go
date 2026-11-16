// Package proxytunneltest provides a CONNECT proxy for tests.
package proxytunneltest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

// Proxy is a minimal HTTP proxy that answers CONNECT with a fixed status and,
// on 200, relays bytes to the requested target.
type Proxy struct {
	listener net.Listener
	status   int

	mu       sync.Mutex
	requests []*http.Request
}

// New starts a proxy that answers every CONNECT with status, and stops it when
// the test ends.
func New(t *testing.T, status int) *Proxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxy := &Proxy{listener: listener, status: status}
	t.Cleanup(func() { _ = listener.Close() })
	go proxy.serve()
	return proxy
}

// URL is the proxy's address as an http:// proxy URL.
func (p *Proxy) URL() *url.URL {
	return &url.URL{Scheme: "http", Host: p.listener.Addr().String()}
}

// Requests returns the CONNECT requests received so far.
func (p *Proxy) Requests() []*http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*http.Request(nil), p.requests...)
}

func (p *Proxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *Proxy) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	request, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}
	p.mu.Lock()
	p.requests = append(p.requests, request)
	p.mu.Unlock()

	if p.status != http.StatusOK {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n\r\n", p.status, http.StatusText(p.status))
		return
	}
	upstream, err := net.Dial("tcp", request.Host)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer func() { _ = upstream.Close() }()
	_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { _, _ = io.Copy(upstream, conn) }()
	_, _ = io.Copy(conn, upstream)
}
