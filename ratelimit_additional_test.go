package oauth

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGetClientIP_WithProxyHeaders_TrustProxy(t *testing.T) {
	tests := []struct {
		name          string
		xForwardedFor string
		xRealIP       string
		remoteAddr    string
		trustProxy    bool
		expectedIP    string
	}{
		{
			name:          "trust proxy with X-Forwarded-For (uses LAST IP from trusted proxy)",
			xForwardedFor: "192.168.1.1, 10.0.0.1",
			remoteAddr:    "127.0.0.1:1234",
			trustProxy:    true,
			expectedIP:    "10.0.0.1", // Security: Use LAST IP (from trusted proxy) to prevent client spoofing
		},
		{
			name:       "trust proxy with X-Real-IP",
			xRealIP:    "192.168.1.1",
			remoteAddr: "127.0.0.1:1234",
			trustProxy: true,
			expectedIP: "192.168.1.1",
		},
		{
			name:          "don't trust proxy with X-Forwarded-For",
			xForwardedFor: "192.168.1.1",
			remoteAddr:    "127.0.0.1:1234",
			trustProxy:    false,
			expectedIP:    "127.0.0.1",
		},
		{
			name:       "no proxy headers",
			remoteAddr: "192.168.1.1:5678",
			trustProxy: true,
			expectedIP: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := getClientIP(req, tt.trustProxy)
			if ip != tt.expectedIP {
				t.Errorf("getClientIP() = %s, want %s", ip, tt.expectedIP)
			}
		})
	}
}

func TestRateLimiter_CleanupInactiveLimiters(t *testing.T) {
	rl := NewRateLimiter(10, 20, false, 100*time.Millisecond, slog.Default())

	// Create a limiter by making a request
	ip := "192.168.1.1"
	if !rl.Allow(ip) {
		t.Error("First request should be allowed")
	}

	// Verify limiter exists
	rl.mu.RLock()
	_, exists := rl.limiters[ip]
	rl.mu.RUnlock()
	if !exists {
		t.Error("Limiter should exist after first request")
	}

	// Wait for cleanup (it should NOT remove the limiter since it was just used)
	time.Sleep(150 * time.Millisecond)

	// Limiter should still exist (not inactive yet)
	rl.mu.RLock()
	_, exists = rl.limiters[ip]
	rl.mu.RUnlock()
	if !exists {
		t.Error("Recently used limiter should not be cleaned up")
	}
}

func TestHandler_RateLimitMiddleware_NoRateLimiter(t *testing.T) {
	// Create handler without rate limiting
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
		// No RateLimitRate set
	})

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.RateLimitMiddleware(next).ServeHTTP(w, req)

	if !nextCalled {
		t.Error("Next handler should be called when no rate limiter is configured")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Response code = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRateLimiter_BurstAllowance(t *testing.T) {
	// Create rate limiter with rate=1/sec, burst=5
	rl := NewRateLimiter(1, 5, false, 1*time.Minute, slog.Default())

	ip := "192.168.1.1"

	// Should allow burst of 5 requests immediately
	for i := 0; i < 5; i++ {
		if !rl.Allow(ip) {
			t.Errorf("Request %d should be allowed (within burst limit)", i+1)
		}
	}

	// 6th request should be denied (burst exhausted, no time to replenish)
	if rl.Allow(ip) {
		t.Error("Request should be denied after burst exhausted")
	}
}
