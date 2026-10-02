package dex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// flakyDiscoveryServer wraps a mock Dex server so that its first failures
// discovery requests answer status instead of the document.
func flakyDiscoveryServer(t *testing.T, failures int64, status int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	dex := setupMockDexServer(t)
	t.Cleanup(dex.Close)

	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" && calls.Add(1) <= failures {
			w.WriteHeader(status)
			return
		}
		dex.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &calls
}

func TestNewProvider_DiscoveryRetriesUntilDexAnswers(t *testing.T) {
	server, calls := flakyDiscoveryServer(t, 3, http.StatusServiceUnavailable)
	var logs bytes.Buffer

	provider, err := NewProvider(testConfig(server, func(c *Config) {
		c.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	}))
	if err != nil {
		t.Fatalf("NewProvider() error = %v, want success after Dex recovers", err)
	}
	if provider.Endpoint.TokenURL == "" {
		t.Error("TokenURL is empty after a retried discovery")
	}
	if got := calls.Load(); got != 4 {
		t.Errorf("discovery requests = %d, want 4 (3 failures, 1 success)", got)
	}
	if got := strings.Count(logs.String(), "retrying"); got != 3 {
		t.Errorf("retry log lines = %d, want 3:\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "attempts=4") {
		t.Errorf("success log does not name the attempts:\n%s", logs.String())
	}
}

func TestNewProvider_DiscoveryPermanentFailureReturnsAtOnce(t *testing.T) {
	server, calls := flakyDiscoveryServer(t, 1000, http.StatusNotFound)

	start := time.Now()
	_, err := NewProvider(testConfig(server))
	if err == nil {
		t.Fatal("NewProvider() succeeded, want error for a 404 discovery answer")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("discovery requests = %d, want 1 (no retry on 404)", got)
	}
	if elapsed := time.Since(start); elapsed > discoveryBackoffInitial {
		t.Errorf("NewProvider() took %v, want an immediate failure", elapsed)
	}
	var statusErr *oidc.DiscoveryStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusNotFound {
		t.Errorf("error = %v, want a DiscoveryStatusError with status 404", err)
	}
}

func TestNewProvider_DiscoveryTimeoutNamesLastFailureAndAttempts(t *testing.T) {
	server, calls := flakyDiscoveryServer(t, 1000, http.StatusBadGateway)

	_, err := NewProvider(testConfig(server, func(c *Config) {
		c.DiscoveryTimeout = 600 * time.Millisecond
	}))
	if err == nil {
		t.Fatal("NewProvider() succeeded, want error after the discovery timeout")
	}
	attempts := calls.Load()
	if attempts < 2 {
		t.Errorf("discovery requests = %d, want retries before giving up", attempts)
	}
	for _, want := range []string{"status 502", fmt.Sprintf("(%d attempts)", attempts), "discovery timeout of 600ms"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

func TestNewProvider_NegativeDiscoveryTimeout(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	_, err := NewProvider(testConfig(server, func(c *Config) { c.DiscoveryTimeout = -time.Second }))
	if err == nil || !strings.Contains(err.Error(), "discovery timeout") {
		t.Errorf("NewProvider() error = %v, want a negative discovery timeout error", err)
	}
}

func TestIsDiscoveryRetryable(t *testing.T) {
	wrapURL := func(err error) error {
		return fmt.Errorf("failed to fetch OIDC discovery document: %w",
			&url.Error{Op: "Get", URL: "https://dex.example.com/.well-known/openid-configuration", Err: err})
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"503", &oidc.DiscoveryStatusError{StatusCode: http.StatusServiceUnavailable}, true},
		{"500", &oidc.DiscoveryStatusError{StatusCode: http.StatusInternalServerError}, true},
		{"429", &oidc.DiscoveryStatusError{StatusCode: http.StatusTooManyRequests}, true},
		{"404", &oidc.DiscoveryStatusError{StatusCode: http.StatusNotFound}, false},
		{"401", &oidc.DiscoveryStatusError{StatusCode: http.StatusUnauthorized}, false},
		{"connection refused", wrapURL(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}), true},
		{"connection reset", wrapURL(&net.OpError{Op: "read", Err: syscall.ECONNRESET}), true},
		{"DNS timeout", wrapURL(fmt.Errorf("DNS resolution failed: %w", &net.DNSError{Err: "i/o timeout", Name: "dex.example.com", IsTimeout: true})), true},
		{"DNS temporary", wrapURL(fmt.Errorf("DNS resolution failed: %w", &net.DNSError{Err: "server misbehaving", Name: "dex.example.com", IsTemporary: true})), true},
		{"NXDOMAIN", wrapURL(fmt.Errorf("DNS resolution failed: %w", &net.DNSError{Err: "no such host", Name: "dex.example.com", IsNotFound: true})), false},
		{"attempt deadline", context.DeadlineExceeded, true},
		{"client timeout", wrapURL(&net.OpError{Op: "dial", Err: timeoutError{}}), true},
		{"SSRF refusal", wrapURL(errors.New(`DNS rebinding attack detected: "dex.example.com" resolved to restricted IP 10.0.0.1`)), false},
		{"invalid document", errors.New("invalid discovery document: token_endpoint must use HTTPS"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDiscoveryRetryable(tt.err); got != tt.want {
				t.Errorf("isDiscoveryRetryable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
