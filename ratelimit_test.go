package oauth

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(10, 20, false, 5*time.Minute, slog.Default())
	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}
	if rl.rate != 10 {
		t.Errorf("Expected rate 10, got %d", rl.rate)
	}
	if rl.burst != 20 {
		t.Errorf("Expected burst 20, got %d", rl.burst)
	}
	if rl.trustProxy != false {
		t.Errorf("Expected trustProxy false, got %v", rl.trustProxy)
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	rl := NewRateLimiter(10, 10, false, 5*time.Minute, slog.Default()) // 10 requests per second, burst of 10

	// First 10 requests should be allowed (burst)
	for i := 0; i < 10; i++ {
		if !rl.Allow("192.168.1.1") {
			t.Errorf("Request %d should be allowed (within burst)", i+1)
		}
	}

	// 11th request should be denied (burst exhausted)
	if rl.Allow("192.168.1.1") {
		t.Error("Request 11 should be denied (burst exhausted)")
	}

	// Wait for token to replenish
	time.Sleep(150 * time.Millisecond)

	// Should allow 1-2 more requests after waiting
	if !rl.Allow("192.168.1.1") {
		t.Error("Request should be allowed after waiting")
	}
}

func TestRateLimiter_MultipleIPs(t *testing.T) {
	rl := NewRateLimiter(10, 5, false, 5*time.Minute, slog.Default()) // 10 requests per second, burst of 5

	// Exhaust burst for first IP
	for i := 0; i < 5; i++ {
		if !rl.Allow("192.168.1.1") {
			t.Errorf("Request %d for IP1 should be allowed", i+1)
		}
	}

	// First IP should be denied
	if rl.Allow("192.168.1.1") {
		t.Error("IP1 should be rate limited")
	}

	// Second IP should still have full burst available
	for i := 0; i < 5; i++ {
		if !rl.Allow("192.168.1.2") {
			t.Errorf("Request %d for IP2 should be allowed", i+1)
		}
	}

	// Second IP should now be denied
	if rl.Allow("192.168.1.2") {
		t.Error("IP2 should be rate limited")
	}
}

func TestRateLimiter_TokenReplenishment(t *testing.T) {
	rl := NewRateLimiter(100, 2, false, 5*time.Minute, slog.Default()) // 100 requests per second, burst of 2

	// Use up burst
	if !rl.Allow("192.168.1.1") {
		t.Error("First request should be allowed")
	}
	if !rl.Allow("192.168.1.1") {
		t.Error("Second request should be allowed")
	}

	// Should be denied
	if rl.Allow("192.168.1.1") {
		t.Error("Third request should be denied")
	}

	// Wait for token replenishment (100/sec = 10ms per token)
	time.Sleep(15 * time.Millisecond)

	// Should be allowed again
	if !rl.Allow("192.168.1.1") {
		t.Error("Request should be allowed after replenishment")
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	config := &Config{
		Resource: "https://test.example.com",
		RateLimit: RateLimitConfig{
			Rate:  2, // 2 requests per second
			Burst: 2, // burst of 2
		},
		CleanupInterval: 10 * time.Minute,
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Create a test handler that always succeeds
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Wrap with rate limit middleware
	rateLimitedHandler := handler.RateLimitMiddleware(testHandler)

	// First 2 requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		rateLimitedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: expected status 200, got %d", i+1, w.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	w := httptest.NewRecorder()
	rateLimitedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w.Code)
	}

	// Check Retry-After header
	if w.Header().Get("Retry-After") != "1" {
		t.Errorf("Expected Retry-After header, got %s", w.Header().Get("Retry-After"))
	}
}

func TestRateLimitMiddleware_NoRateLimiter(t *testing.T) {
	config := &Config{
		Resource: "https://test.example.com",
		RateLimit: RateLimitConfig{
			Rate: 0, // No rate limiting
		},
		CleanupInterval: 10 * time.Minute,
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitedHandler := handler.RateLimitMiddleware(testHandler)

	// Should allow unlimited requests
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		rateLimitedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d should succeed without rate limiting", i+1)
		}
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddr    string
		xForwardedFor string
		xRealIP       string
		trustProxy    bool
		expectedIP    string
	}{
		{
			name:       "RemoteAddr only - no proxy trust",
			remoteAddr: "192.168.1.1:1234",
			trustProxy: false,
			expectedIP: "192.168.1.1",
		},
		{
			name:          "X-Forwarded-For with trust proxy",
			remoteAddr:    "10.0.0.1:1234",
			xForwardedFor: "203.0.113.1",
			trustProxy:    true,
			expectedIP:    "203.0.113.1",
		},
		{
			name:          "X-Forwarded-For without trust proxy (should ignore)",
			remoteAddr:    "10.0.0.1:1234",
			xForwardedFor: "203.0.113.1",
			trustProxy:    false,
			expectedIP:    "10.0.0.1",
		},
		{
			name:          "X-Forwarded-For multiple IPs with trust (takes LAST IP from trusted proxy)",
			remoteAddr:    "10.0.0.1:1234",
			xForwardedFor: "203.0.113.1, 198.51.100.1, 10.0.0.1",
			trustProxy:    true,
			expectedIP:    "10.0.0.1", // Security: Use LAST IP (from trusted proxy) to prevent spoofing
		},
		{
			name:       "X-Real-IP with trust proxy",
			remoteAddr: "10.0.0.1:1234",
			xRealIP:    "203.0.113.1",
			trustProxy: true,
			expectedIP: "203.0.113.1",
		},
		{
			name:       "X-Real-IP without trust proxy (should ignore)",
			remoteAddr: "10.0.0.1:1234",
			xRealIP:    "203.0.113.1",
			trustProxy: false,
			expectedIP: "10.0.0.1",
		},
		{
			name:          "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr:    "10.0.0.1:1234",
			xForwardedFor: "203.0.113.1",
			xRealIP:       "198.51.100.1",
			trustProxy:    true,
			expectedIP:    "203.0.113.1",
		},
		{
			name:       "IPv6 address",
			remoteAddr: "[::1]:1234",
			trustProxy: false,
			expectedIP: "[",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := getClientIP(req, tt.trustProxy)
			if ip != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestExtractIPFromAddr(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{
			name:     "IPv4 with port",
			addr:     "192.168.1.1:1234",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv4 without port",
			addr:     "192.168.1.1",
			expected: "192.168.1.1",
		},
		{
			name:     "IPv6 with port",
			addr:     "[::1]:8080",
			expected: "[",
		},
		{
			name:     "Empty string",
			addr:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractIPFromAddr(tt.addr)
			if result != tt.expected {
				t.Errorf("extractIPFromAddr(%q) = %q, want %q", tt.addr, result, tt.expected)
			}
		})
	}
}
