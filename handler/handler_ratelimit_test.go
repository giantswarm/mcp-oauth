package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// testStateMinLen is a state value at MinStateLength so the authorize handler
// passes input validation and reaches the rate-limit gate.
const testStateMinLen = "abcdefghijklmnopqrstuvwx" // 24 chars, == MinStateLength

// newOAuthTestServer returns a baseline test server with default config.
// The caller wires whatever rate limiter the test needs (or leaves them
// nil). Stop hooks are registered via t.Cleanup.
func newOAuthTestServer(t *testing.T) *server.Server {
	t.Helper()

	store := memory.New()
	t.Cleanup(store.Stop)

	srv, err := server.New(mock.NewProvider(), store, store, store, &server.Config{Issuer: testIssuer}, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}
	return srv
}

// rate=0 with burst=N yields a no-refill bucket: exactly N requests pass, the
// (N+1)-th is rejected for the rest of the test.
func setupTestHandlerWithRateLimit(t *testing.T, burst int) *Handler {
	t.Helper()

	srv := newOAuthTestServer(t)
	srv.RateLimiter = security.NewRateLimiter(0, burst, nil)
	t.Cleanup(srv.RateLimiter.Stop)

	return New(srv, nil)
}

// endpointCase is a shared request/response fixture for the four OAuth
// flow endpoints exercised by the rate-limit tests. Each case builds a
// fresh *http.Request with the given RemoteAddr and dispatches it through
// the matching handler. Kept generic so other cross-endpoint properties
// can reuse the table.
type endpointCase struct {
	name    string
	request func(remoteAddr string) *http.Request
	serve   func(h *Handler, w http.ResponseWriter, r *http.Request)
}

// oauthEndpointCases returns one case per CWE-307 endpoint:
// /authorize, /token, /revoke, /introspect.
func oauthEndpointCases() []endpointCase {
	return []endpointCase{
		{
			name: "ServeAuthorization",
			request: func(remoteAddr string) *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=x&state="+testStateMinLen, nil)
				req.RemoteAddr = remoteAddr
				return req
			},
			serve: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeAuthorization(w, r) },
		},
		{
			name: "ServeToken",
			request: func(remoteAddr string) *http.Request {
				body := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}.Encode()
				req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = remoteAddr
				return req
			},
			serve: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeToken(w, r) },
		},
		{
			name: "ServeTokenRevocation",
			request: func(remoteAddr string) *http.Request {
				body := url.Values{"token": {"x"}}.Encode()
				req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = remoteAddr
				return req
			},
			serve: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeTokenRevocation(w, r) },
		},
		{
			name: "ServeTokenIntrospection",
			request: func(remoteAddr string) *http.Request {
				// No Basic Auth on purpose: the rate-limit gate sits before
				// client authentication, and bcrypt'd Basic Auth here would
				// dominate test wall time for the no-limiter case below.
				body := url.Values{"token": {"x"}}.Encode()
				req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = remoteAddr
				return req
			},
			serve: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeTokenIntrospection(w, r) },
		},
	}
}

func TestHandler_OAuthEndpoints_IPRateLimit(t *testing.T) {
	const burst = 2

	for _, tc := range oauthEndpointCases() {
		t.Run(tc.name, func(t *testing.T) {
			handler := setupTestHandlerWithRateLimit(t, burst)

			for i := 0; i < burst; i++ {
				w := httptest.NewRecorder()
				tc.serve(handler, w, tc.request(testClientRemoteAddr))
				if w.Code == http.StatusTooManyRequests {
					t.Fatalf("burst request %d already 429; expected within-burst pass-through", i+1)
				}
			}

			w := httptest.NewRecorder()
			tc.serve(handler, w, tc.request(testClientRemoteAddr))

			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusTooManyRequests)
			}
			if got := w.Header().Get("Retry-After"); got == "" {
				t.Error("Retry-After header missing on 429")
			}

			var body map[string]string
			if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body["error"] != oauth.ErrorCodeRateLimitExceeded {
				t.Errorf("error = %q, want %q", body["error"], oauth.ErrorCodeRateLimitExceeded)
			}
		})
	}
}

func TestHandler_OAuthEndpoints_IPRateLimit_PerIP(t *testing.T) {
	for _, tc := range oauthEndpointCases() {
		t.Run(tc.name, func(t *testing.T) {
			handler := setupTestHandlerWithRateLimit(t, 1)

			send := func(remoteAddr string) int {
				w := httptest.NewRecorder()
				tc.serve(handler, w, tc.request(remoteAddr))
				return w.Code
			}

			if code := send("10.0.0.1:1111"); code == http.StatusTooManyRequests {
				t.Fatalf("first request from IP A returned 429: %d", code)
			}
			if code := send("10.0.0.1:2222"); code != http.StatusTooManyRequests {
				t.Fatalf("second request from IP A: status = %d, want 429", code)
			}
			if code := send("10.0.0.2:1111"); code == http.StatusTooManyRequests {
				t.Fatalf("first request from IP B returned 429 (cross-IP leakage): %d", code)
			}
		})
	}
}

// TestHandler_OAuthEndpoints_NoRateLimiter pins the no-op contract: when no
// limiter is wired, 429 is never returned even under sustained traffic.
func TestHandler_OAuthEndpoints_NoRateLimiter(t *testing.T) {
	for _, tc := range oauthEndpointCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newOAuthTestServer(t)
			// srv.RateLimiter intentionally left nil
			handler := New(srv, nil)

			for i := 0; i < 50; i++ {
				w := httptest.NewRecorder()
				tc.serve(handler, w, tc.request(testClientRemoteAddr))
				if w.Code == http.StatusTooManyRequests {
					t.Fatalf("request %d returned 429 with no rate limiter configured", i+1)
				}
			}
		})
	}
}

// TestHandler_IPRateLimit_IPv6BucketedBy64 confirms the CWE-307 closure isn't
// bypassable by walking a /64: two distinct IPv6 /128s within the same /64
// share a bucket; a /128 in a different /64 does not.
func TestHandler_IPRateLimit_IPv6BucketedBy64(t *testing.T) {
	handler := setupTestHandlerWithRateLimit(t, 1)

	send := func(remoteAddr string) int {
		body := url.Values{"grant_type": {"x"}}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		handler.ServeToken(w, req)
		return w.Code
	}

	if code := send("[2001:db8::1]:1111"); code == http.StatusTooManyRequests {
		t.Fatalf("first request from 2001:db8::1 returned 429: %d", code)
	}
	if code := send("[2001:db8::2]:1111"); code != http.StatusTooManyRequests {
		t.Fatalf("second /64-sibling 2001:db8::2 should hit shared bucket: status = %d, want 429", code)
	}
	if code := send("[2001:db8:1::1]:1111"); code == http.StatusTooManyRequests {
		t.Fatalf("different /64 (2001:db8:1::/64) should not be rate-limited: %d", code)
	}
}

// TestHandler_TokenEndpoint_PostAuthUserRateLimit confirms the issue's
// optional second pass: a successfully-authenticated client is also bounded
// by the user rate limiter (keyed by client_id), so authenticated abusers
// can't enumerate tokens at unbounded rate.
func TestHandler_TokenEndpoint_PostAuthUserRateLimit(t *testing.T) {
	srv := newOAuthTestServer(t)
	srv.UserRateLimiter = security.NewRateLimiter(0, 1, nil) // 1 token, no refill
	t.Cleanup(srv.UserRateLimiter.Stop)
	handler := New(srv, nil)

	client, secret, err := handler.server.RegisterClient(
		context.Background(),
		"Test Client",
		"confidential",
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	send := func() *httptest.ResponseRecorder {
		body := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {"invalid-code-causes-exchange-failure"},
			"redirect_uri": {"https://example.com/callback"},
		}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(client.ClientID, secret)
		req.RemoteAddr = testClientRemoteAddr
		w := httptest.NewRecorder()
		handler.ServeToken(w, req)
		return w
	}

	first := send()
	if first.Code == http.StatusTooManyRequests {
		t.Fatalf("first authenticated request returned 429: %d", first.Code)
	}

	second := send()
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second authenticated request: status = %d, want 429", second.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(second.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != oauth.ErrorCodeRateLimitExceeded {
		t.Errorf("error = %q, want %q", body["error"], oauth.ErrorCodeRateLimitExceeded)
	}
}

// TestHandler_TokenEndpoint_PublicClientSkipsUserRateLimit pins the
// confidential-only contract: a public PKCE client must not be bounded by
// the user rate limiter (its client_id is attacker-controllable; the IP
// limit is the only meaningful bound for public clients).
func TestHandler_TokenEndpoint_PublicClientSkipsUserRateLimit(t *testing.T) {
	srv := newOAuthTestServer(t)
	srv.UserRateLimiter = security.NewRateLimiter(0, 1, nil)
	t.Cleanup(srv.UserRateLimiter.Stop)
	handler := New(srv, nil)

	client, _, err := handler.server.RegisterClient(
		context.Background(),
		"Public Test Client",
		"public",
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	send := func() int {
		body := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"invalid-code-causes-exchange-failure"},
			"redirect_uri":  {"https://example.com/callback"},
			"client_id":     {client.ClientID},
			"code_verifier": {"verifier-not-validated-here"},
		}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = testClientRemoteAddr
		w := httptest.NewRecorder()
		handler.ServeToken(w, req)
		return w.Code
	}

	// Burst of requests well past the user limiter's burst=1 — none must 429
	// since the user limit is gated on confidential-client status.
	for i := 0; i < 5; i++ {
		if code := send(); code == http.StatusTooManyRequests {
			t.Fatalf("public-client request %d returned 429 — user limiter applied incorrectly", i+1)
		}
	}
}

// TestHandler_IPRateLimit_RetryAfterDerivedFromRate confirms that the
// Retry-After hint reflects the limiter's configured rate rather than a
// fixed constant.
func TestHandler_IPRateLimit_RetryAfterDerivedFromRate(t *testing.T) {
	tests := []struct {
		name string
		rate int
		want string
	}{
		{"rate 10 rps → 1s (ceil)", 10, "1"},
		{"rate 1 rps → 1s", 1, "1"},
		{"rate 0 (no refill) → 60s fallback", 0, "60"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newOAuthTestServer(t)
			srv.RateLimiter = security.NewRateLimiter(tt.rate, 1, nil)
			t.Cleanup(srv.RateLimiter.Stop)
			handler := New(srv, nil)

			body := url.Values{"grant_type": {"x"}}.Encode()
			send := func() *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = testClientRemoteAddr
				w := httptest.NewRecorder()
				handler.ServeToken(w, req)
				return w
			}
			send() // consume the single bucket token
			w := send()

			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusTooManyRequests)
			}
			if got := w.Header().Get("Retry-After"); got != tt.want {
				t.Errorf("Retry-After = %q, want %q", got, tt.want)
			}
		})
	}
}
