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

// setupTestHandlerWithRateLimit returns a handler whose server has an IP rate
// limiter sized to allow `burst` requests before returning 429. Refill rate is
// 0/s so the (burst+1)-th request inside the window is reliably rejected.
func setupTestHandlerWithRateLimit(t *testing.T, burst int) (*Handler, *memory.Store) {
	t.Helper()

	store := memory.New()
	provider := mock.NewProvider()

	config := &server.Config{
		Issuer:             testIssuer,
		MaxRequestBodySize: 1 << 16,
	}

	srv, err := server.New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("server.New() error = %v", err)
	}
	srv.RateLimiter = security.NewRateLimiter(0, burst, nil)
	t.Cleanup(func() { srv.RateLimiter.Stop() })

	return NewHandler(srv, nil), store
}

// TestHandler_OAuthEndpoints_IPRateLimit covers CWE-307: the OAuth flow
// endpoints must reject the (burst+1)-th request from the same IP with 429.
func TestHandler_OAuthEndpoints_IPRateLimit(t *testing.T) {
	const burst = 2

	tests := []struct {
		name    string
		request func() *http.Request
		serve   func(h *Handler, w http.ResponseWriter, r *http.Request)
	}{
		{
			name: "ServeAuthorization",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=x&state=abcdefghij", nil)
				req.RemoteAddr = testClientRemoteAddr
				return req
			},
			serve: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeAuthorization(w, r) },
		},
		{
			name: "ServeToken",
			request: func() *http.Request {
				body := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}.Encode()
				req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = testClientRemoteAddr
				return req
			},
			serve: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeToken(w, r) },
		},
		{
			name: "ServeTokenRevocation",
			request: func() *http.Request {
				body := url.Values{"token": {"x"}}.Encode()
				req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.RemoteAddr = testClientRemoteAddr
				return req
			},
			serve: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeTokenRevocation(w, r) },
		},
		{
			name: "ServeTokenIntrospection",
			request: func() *http.Request {
				body := url.Values{"token": {"x"}}.Encode()
				req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth("client-x", "secret")
				req.RemoteAddr = testClientRemoteAddr
				return req
			},
			serve: func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeTokenIntrospection(w, r) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler, store := setupTestHandlerWithRateLimit(t, burst)
			defer store.Stop()

			for i := 0; i < burst; i++ {
				w := httptest.NewRecorder()
				tc.serve(handler, w, tc.request())
				if w.Code == http.StatusTooManyRequests {
					t.Fatalf("burst request %d already 429; expected within-burst pass-through", i+1)
				}
			}

			w := httptest.NewRecorder()
			tc.serve(handler, w, tc.request())

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

// TestHandler_OAuthEndpoints_IPRateLimit_PerIP confirms the limiter keys on
// client IP — exhausting one IP must not affect a different IP.
func TestHandler_OAuthEndpoints_IPRateLimit_PerIP(t *testing.T) {
	handler, store := setupTestHandlerWithRateLimit(t, 1)
	defer store.Stop()

	exhaust := func(remoteAddr string) int {
		body := url.Values{"grant_type": {"x"}}.Encode()
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		handler.ServeToken(w, req)
		return w.Code
	}

	if code := exhaust("10.0.0.1:1111"); code == http.StatusTooManyRequests {
		t.Fatalf("first request from IP A returned 429: %d", code)
	}
	if code := exhaust("10.0.0.1:2222"); code != http.StatusTooManyRequests {
		t.Fatalf("second request from IP A: status = %d, want 429", code)
	}
	if code := exhaust("10.0.0.2:1111"); code == http.StatusTooManyRequests {
		t.Fatalf("first request from IP B returned 429 (cross-IP leakage): %d", code)
	}
}
