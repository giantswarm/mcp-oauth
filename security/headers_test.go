package security

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetSecurityHeaders(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		wantHSTS  bool
	}{
		{
			name:      "HTTPS server",
			serverURL: "https://example.com",
			wantHSTS:  true,
		},
		{
			name:      "HTTP server",
			serverURL: "http://example.com",
			wantHSTS:  false,
		},
		{
			name:      "invalid URL",
			serverURL: "://invalid",
			wantHSTS:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			SetSecurityHeaders(w, tt.serverURL)

			// Verify X-Frame-Options
			if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want %q", got, "DENY")
			}

			// Verify X-Content-Type-Options
			if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
			}

			// Verify X-XSS-Protection
			if got := w.Header().Get("X-XSS-Protection"); got != "1; mode=block" {
				t.Errorf("X-XSS-Protection = %q, want %q", got, "1; mode=block")
			}

			// Verify Content-Security-Policy
			if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'none'; frame-ancestors 'none'" {
				t.Errorf("Content-Security-Policy = %q, want %q", got, "default-src 'none'; frame-ancestors 'none'")
			}

			// Verify Referrer-Policy
			if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy = %q, want %q", got, "no-referrer")
			}

			// Verify Cache-Control
			if got := w.Header().Get("Cache-Control"); got != "no-store, no-cache, must-revalidate, private" {
				t.Errorf("Cache-Control = %q, want %q", got, "no-store, no-cache, must-revalidate, private")
			}

			// Verify Pragma
			if got := w.Header().Get("Pragma"); got != "no-cache" {
				t.Errorf("Pragma = %q, want %q", got, "no-cache")
			}

			// Verify HSTS header
			hstsHeader := w.Header().Get("Strict-Transport-Security")
			if tt.wantHSTS {
				if hstsHeader != "max-age=31536000; includeSubDomains" {
					t.Errorf("Strict-Transport-Security = %q, want %q", hstsHeader, "max-age=31536000; includeSubDomains")
				}
			} else {
				if hstsHeader != "" {
					t.Errorf("Strict-Transport-Security should not be set for HTTP, got %q", hstsHeader)
				}
			}
		})
	}
}

func TestSetSecurityHeaders_AllHeadersPresent(t *testing.T) {
	w := httptest.NewRecorder()
	SetSecurityHeaders(w, "https://example.com")

	requiredHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Cache-Control",
		"Pragma",
		"Strict-Transport-Security",
	}

	for _, header := range requiredHeaders {
		if w.Header().Get(header) == "" {
			t.Errorf("Header %q should be set", header)
		}
	}
}

func TestSetSecurityHeaders_HTTPNoHSTS(t *testing.T) {
	w := httptest.NewRecorder()
	SetSecurityHeaders(w, "http://example.com")

	requiredHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Referrer-Policy",
		"Cache-Control",
		"Pragma",
	}

	for _, header := range requiredHeaders {
		if w.Header().Get(header) == "" {
			t.Errorf("Header %q should be set", header)
		}
	}

	// HSTS should NOT be set for HTTP
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("Strict-Transport-Security should not be set for HTTP")
	}
}

func TestSetInterstitialSecurityHeaders(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		wantHSTS  bool
	}{
		{
			name:      "HTTPS server",
			serverURL: "https://example.com",
			wantHSTS:  true,
		},
		{
			name:      "HTTP server",
			serverURL: "http://example.com",
			wantHSTS:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			SetInterstitialSecurityHeaders(w, tt.serverURL)

			// Verify X-Frame-Options
			if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options = %q, want %q", got, "DENY")
			}

			// Verify X-Content-Type-Options
			if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
			}

			// Verify X-XSS-Protection
			if got := w.Header().Get("X-XSS-Protection"); got != "1; mode=block" {
				t.Errorf("X-XSS-Protection = %q, want %q", got, "1; mode=block")
			}

			// Verify Referrer-Policy
			if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Errorf("Referrer-Policy = %q, want %q", got, "no-referrer")
			}

			// Verify Cache-Control
			if got := w.Header().Get("Cache-Control"); got != "no-store, no-cache, must-revalidate, private" {
				t.Errorf("Cache-Control = %q, want %q", got, "no-store, no-cache, must-revalidate, private")
			}

			// Verify Pragma
			if got := w.Header().Get("Pragma"); got != "no-cache" {
				t.Errorf("Pragma = %q, want %q", got, "no-cache")
			}

			// Verify HSTS header
			hstsHeader := w.Header().Get("Strict-Transport-Security")
			if tt.wantHSTS {
				if hstsHeader != "max-age=31536000; includeSubDomains" {
					t.Errorf("Strict-Transport-Security = %q, want %q", hstsHeader, "max-age=31536000; includeSubDomains")
				}
			} else {
				if hstsHeader != "" {
					t.Errorf("Strict-Transport-Security should not be set for HTTP, got %q", hstsHeader)
				}
			}
		})
	}
}

func TestSetInterstitialSecurityHeaders_CSPContainsScriptHash(t *testing.T) {
	w := httptest.NewRecorder()
	SetInterstitialSecurityHeaders(w, "https://example.com")

	csp := w.Header().Get("Content-Security-Policy")

	// Verify CSP contains the script hash
	if csp == "" {
		t.Fatal("Content-Security-Policy header should be set")
	}

	// Check that CSP contains the expected directives
	expectedParts := []string{
		"default-src 'none'",
		"script-src '" + InterstitialScriptHash + "'",
		"style-src 'unsafe-inline'",
		"frame-ancestors 'none'",
	}

	for _, part := range expectedParts {
		if !strings.Contains(csp, part) {
			t.Errorf("CSP should contain %q, got: %s", part, csp)
		}
	}

	// Verify CSP does NOT allow unsafe-inline for scripts
	if strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Error("CSP should NOT contain 'unsafe-inline' for scripts")
	}
}

func TestInterstitialScriptHash_Format(t *testing.T) {
	// Verify the hash has the correct format
	if !strings.Contains(InterstitialScriptHash, "sha256-") {
		t.Errorf("InterstitialScriptHash should start with 'sha256-', got: %s", InterstitialScriptHash)
	}

	// SHA-256 base64 encoded is 44 characters (32 bytes = 256 bits, base64 encoded)
	// Plus "sha256-" prefix = 51 characters total
	expectedLen := len("sha256-") + 44
	if len(InterstitialScriptHash) != expectedLen {
		t.Errorf("InterstitialScriptHash length = %d, want %d", len(InterstitialScriptHash), expectedLen)
	}
}
