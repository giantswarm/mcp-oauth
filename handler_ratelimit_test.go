package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// testStateMinLen is a state value at MinStateLength so the authorize handler
// passes input validation and reaches the rate-limit gate.
const testStateMinLen = "abcdefghijklmnopqrstuvwx" // 24 chars, == MinStateLength

// newTestServerForRateLimit returns a server with default body-size config and
// a deterministic teardown. The caller assigns RateLimiter (or leaves it nil).
func newTestServerForRateLimit(t *testing.T) *server.Server {
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

	srv := newTestServerForRateLimit(t)
	srv.RateLimiter = security.NewRateLimiter(0, burst, nil)
	t.Cleanup(srv.RateLimiter.Stop)

	return NewHandler(srv, nil)
}

type endpointCase struct {
	name    string
	request func(remoteAddr string) *http.Request
	serve   func(h *Handler, w http.ResponseWriter, r *http.Request)
}

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
			if body["error"] != ErrorCodeRateLimitExceeded {
				t.Errorf("error = %q, want %q", body["error"], ErrorCodeRateLimitExceeded)
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
			srv := newTestServerForRateLimit(t)
			// srv.RateLimiter intentionally left nil
			handler := NewHandler(srv, nil)

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
