package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name              string
		remoteAddr        string
		xForwardedFor     string
		xRealIP           string
		trustProxy        bool
		trustedProxyCount int
		want              string
	}{
		{
			name:       "direct connection",
			remoteAddr: "192.168.1.100:12345",
			trustProxy: false,
			want:       "192.168.1.100",
		},
		{
			name:          "X-Forwarded-For with trust",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "203.0.113.1, 10.0.0.2",
			trustProxy:    true,
			want:          "203.0.113.1",
		},
		{
			name:          "X-Forwarded-For without trust",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "203.0.113.1",
			trustProxy:    false,
			want:          "10.0.0.1",
		},
		{
			name:       "X-Real-IP with trust",
			remoteAddr: "10.0.0.1:12345",
			xRealIP:    "203.0.113.1",
			trustProxy: true,
			want:       "203.0.113.1",
		},
		{
			name:       "X-Real-IP without trust",
			remoteAddr: "10.0.0.1:12345",
			xRealIP:    "203.0.113.1",
			trustProxy: false,
			want:       "10.0.0.1",
		},
		{
			name:              "X-Forwarded-For with multiple proxies",
			remoteAddr:        "10.0.0.1:12345",
			xForwardedFor:     "203.0.113.1, 10.0.0.2, 10.0.0.3",
			trustProxy:        true,
			trustedProxyCount: 2,
			want:              "203.0.113.1",
		},
		{
			name:          "X-Forwarded-For with whitespace",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: " 203.0.113.1 , 10.0.0.2 ",
			trustProxy:    true,
			want:          "203.0.113.1",
		},
		{
			name:          "X-Forwarded-For with single IP",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "203.0.113.1",
			trustProxy:    true,
			want:          "203.0.113.1",
		},
		{
			name:          "X-Forwarded-For with invalid IP",
			remoteAddr:    "10.0.0.1:12345",
			xForwardedFor: "not-an-ip",
			trustProxy:    true,
			want:          "10.0.0.1",
		},
		{
			name:       "IPv6 remote address",
			remoteAddr: "[::1]:12345",
			trustProxy: false,
			want:       "::1",
		},
		{
			name:       "malformed remote address",
			remoteAddr: "malformed",
			trustProxy: false,
			want:       "malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr

			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}

			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := GetClientIP(req, tt.trustProxy, tt.trustedProxyCount)
			if got != tt.want {
				t.Errorf("GetClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetClientIP_PreferenceOrder(t *testing.T) {
	// When trust proxy is enabled, X-Forwarded-For should be preferred over X-Real-IP
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	req.Header.Set("X-Real-IP", "203.0.113.2")

	got := GetClientIP(req, true, 0)
	if got != "203.0.113.1" {
		t.Errorf("GetClientIP() should prefer X-Forwarded-For, got %q", got)
	}
}

func TestGetClientIP_TrustedProxyCount(t *testing.T) {
	tests := []struct {
		name              string
		xForwardedFor     string
		trustedProxyCount int
		want              string
	}{
		{
			name:              "no trusted proxies specified (default 1)",
			xForwardedFor:     "203.0.113.1, 10.0.0.2",
			trustedProxyCount: 0,
			want:              "203.0.113.1",
		},
		{
			name:              "1 trusted proxy",
			xForwardedFor:     "203.0.113.1, 10.0.0.2",
			trustedProxyCount: 1,
			want:              "203.0.113.1",
		},
		{
			name:              "2 trusted proxies",
			xForwardedFor:     "203.0.113.1, 10.0.0.2, 10.0.0.3",
			trustedProxyCount: 2,
			want:              "203.0.113.1",
		},
		{
			name:              "more trusted proxies than IPs",
			xForwardedFor:     "203.0.113.1",
			trustedProxyCount: 5,
			want:              "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "10.0.0.1:12345"
			req.Header.Set("X-Forwarded-For", tt.xForwardedFor)

			got := GetClientIP(req, true, tt.trustedProxyCount)
			if got != tt.want {
				t.Errorf("GetClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
