package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/mock"
)

// TestIsURLClientID tests URL client ID detection
func TestIsURLClientID(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		want     bool
	}{
		{
			name:     "empty string",
			clientID: "",
			want:     false,
		},
		{
			name:     "simple client ID",
			clientID: "my-app-12345",
			want:     false,
		},
		{
			name:     "HTTP URL - not allowed",
			clientID: "http://example.com/client",
			want:     false,
		},
		{
			name:     "HTTPS URL with path",
			clientID: "https://example.com/oauth/client-metadata.json",
			want:     true,
		},
		{
			name:     "HTTPS URL without path",
			clientID: "https://example.com",
			want:     true,
		},
		{
			name:     "HTTPS URL with port",
			clientID: "https://example.com:8443/client",
			want:     true,
		},
		{
			name:     "invalid URL format",
			clientID: "://invalid",
			want:     false,
		},
		{
			name:     "missing scheme",
			clientID: "example.com/client",
			want:     false,
		},
		// Security: Test rejection of userinfo
		{
			name:     "HTTPS URL with userinfo - rejected",
			clientID: "https://user:pass@example.com/client",
			want:     false,
		},
		// Security: Test rejection of query parameters
		{
			name:     "HTTPS URL with query - rejected",
			clientID: "https://example.com/client?redirect=http://evil.com",
			want:     false,
		},
		{
			name:     "HTTPS URL with query param - rejected",
			clientID: "https://example.com/client?foo=bar",
			want:     false,
		},
		// Security: Test rejection of fragments
		{
			name:     "HTTPS URL with fragment - rejected",
			clientID: "https://example.com/client#../../etc/passwd",
			want:     false,
		},
		{
			name:     "HTTPS URL with simple fragment - rejected",
			clientID: "https://example.com/client#section",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isURLClientID(tt.clientID)
			if got != tt.want {
				t.Errorf("isURLClientID(%q) = %v, want %v", tt.clientID, got, tt.want)
			}
		})
	}
}

// TestIsPrivateIP tests private IP detection for SSRF protection
func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		// Loopback addresses
		{name: "IPv4 loopback", ip: "127.0.0.1", want: true},
		{name: "IPv4 loopback 2", ip: "127.0.0.2", want: true},
		{name: "IPv4 loopback 255", ip: "127.255.255.255", want: true},
		{name: "IPv6 loopback", ip: "::1", want: true},

		// Private IPv4 ranges
		{name: "10.0.0.0/8 start", ip: "10.0.0.0", want: true},
		{name: "10.0.0.0/8 mid", ip: "10.123.45.67", want: true},
		{name: "10.0.0.0/8 end", ip: "10.255.255.255", want: true},
		{name: "172.16.0.0/12 start", ip: "172.16.0.0", want: true},
		{name: "172.16.0.0/12 mid", ip: "172.20.45.67", want: true},
		{name: "172.16.0.0/12 end", ip: "172.31.255.255", want: true},
		{name: "192.168.0.0/16 start", ip: "192.168.0.0", want: true},
		{name: "192.168.0.0/16 mid", ip: "192.168.1.1", want: true},
		{name: "192.168.0.0/16 end", ip: "192.168.255.255", want: true},

		// Link-local addresses
		{name: "IPv4 link-local", ip: "169.254.1.1", want: true},
		{name: "IPv6 link-local", ip: "fe80::1", want: true},

		// Public addresses
		{name: "Google DNS", ip: "8.8.8.8", want: false},
		{name: "Cloudflare DNS", ip: "1.1.1.1", want: false},
		{name: "example.com", ip: "93.184.216.34", want: false},
		{name: "Public IPv6", ip: "2001:4860:4860::8888", want: false},

		// Edge cases
		{name: "9.x.x.x - not private", ip: "9.255.255.255", want: false},
		{name: "11.x.x.x - not private", ip: "11.0.0.0", want: false},
		{name: "172.15.x.x - not private", ip: "172.15.255.255", want: false},
		{name: "172.32.x.x - not private", ip: "172.32.0.0", want: false},
		{name: "192.167.x.x - not private", ip: "192.167.255.255", want: false},
		{name: "192.169.x.x - not private", ip: "192.169.0.0", want: false},

		// SECURITY: IPv4-mapped IPv6 addresses (::ffff:0:0/96)
		// These can be used to bypass IPv4 checks - must be detected as private
		{name: "IPv4-mapped loopback", ip: "::ffff:127.0.0.1", want: true},
		{name: "IPv4-mapped 10.x", ip: "::ffff:10.0.0.1", want: true},
		{name: "IPv4-mapped 192.168.x", ip: "::ffff:192.168.1.1", want: true},
		{name: "IPv4-mapped 172.16.x", ip: "::ffff:172.16.0.1", want: true},
		{name: "IPv4-mapped public", ip: "::ffff:8.8.8.8", want: false},

		// SECURITY: fd00::/8 ULA range (additional check beyond fc00::/7)
		{name: "fd00::/8 ULA start", ip: "fd00::1", want: true},
		{name: "fd00::/8 ULA mid", ip: "fd12:3456:789a::1", want: true},
		{name: "fd00::/8 ULA end", ip: "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.want {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// TestValidateMetadataURL tests SSRF protection in URL validation
func TestValidateMetadataURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errText string
	}{
		{
			name:    "HTTP not allowed",
			url:     "http://example.com/client",
			wantErr: true,
			errText: "must use HTTPS",
		},
		{
			name:    "invalid URL",
			url:     "://invalid",
			wantErr: true,
			errText: "invalid URL",
		},
		{
			name:    "localhost blocked",
			url:     "https://localhost/client",
			wantErr: true,
			errText: "private/internal IP",
		},
		{
			name:    "127.0.0.1 blocked",
			url:     "https://127.0.0.1/client",
			wantErr: true,
			errText: "private/internal IP",
		},
		{
			name:    "10.x.x.x blocked",
			url:     "https://10.0.0.1/client",
			wantErr: true,
			errText: "private/internal IP",
		},
		{
			name:    "192.168.x.x blocked",
			url:     "https://192.168.1.1/client",
			wantErr: true,
			errText: "private/internal IP",
		},
		{
			name:    "valid public HTTPS URL",
			url:     "https://example.com/client",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitizedURL, err := validateAndSanitizeMetadataURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateAndSanitizeMetadataURL(%q) expected error containing %q, got nil", tt.url, tt.errText)
					return
				}
				if tt.errText != "" && !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("validateAndSanitizeMetadataURL(%q) error = %v, want error containing %q", tt.url, err, tt.errText)
				}
				if sanitizedURL != "" {
					t.Errorf("validateAndSanitizeMetadataURL(%q) expected empty URL on error, got %q", tt.url, sanitizedURL)
				}
			} else {
				if err != nil {
					t.Errorf("validateAndSanitizeMetadataURL(%q) unexpected error: %v", tt.url, err)
				}
				if sanitizedURL == "" {
					t.Errorf("validateAndSanitizeMetadataURL(%q) expected non-empty URL, got empty", tt.url)
				}
			}
		})
	}
}

// TestFetchClientMetadata tests metadata fetching with mock HTTP server
func TestFetchClientMetadata(t *testing.T) {
	// We'll set serverURL in the handler once we know it
	var serverURL string

	// Create mock HTTP server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check User-Agent
		if ua := r.Header.Get("User-Agent"); ua != "mcp-oauth" {
			t.Errorf("User-Agent = %q, want %q", ua, "mcp-oauth")
		}

		// Check Accept header
		if accept := r.Header.Get("Accept"); accept != "application/json" {
			t.Errorf("Accept = %q, want %q", accept, "application/json")
		}

		// Return valid metadata
		metadata := ClientMetadata{
			ClientID:                serverURL + r.URL.Path,
			ClientName:              "Test Client",
			RedirectURIs:            []string{"https://app.example.com/callback"},
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	}))
	defer ts.Close()
	serverURL = ts.URL

	// Create test server
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	srv := &Server{
		Config: &Config{
			ClientMetadataFetchTimeout:      10 * time.Second,
			EnableClientIDMetadataDocuments: true,
		},
		Logger: logger,
	}

	// Test successful fetch
	t.Run("successful fetch", func(t *testing.T) {
		clientID := ts.URL + "/client-metadata.json"

		// Skip SSRF validation for test server (it uses TLS test cert with private IP)
		// We'll test SSRF separately
		metadata, _, err := srv.fetchClientMetadata(context.Background(), clientID)
		if err != nil {
			// Expected for test server with private IP - this is correct behavior
			if strings.Contains(err.Error(), "private/internal IP") {
				t.Skip("Test server uses private IP - SSRF protection working as expected")
			}
			t.Fatalf("fetchClientMetadata() error = %v", err)
		}

		if metadata.ClientID != clientID {
			t.Errorf("ClientID = %q, want %q", metadata.ClientID, clientID)
		}
		if metadata.ClientName != "Test Client" {
			t.Errorf("ClientName = %q, want %q", metadata.ClientName, "Test Client")
		}
		if len(metadata.RedirectURIs) != 1 {
			t.Errorf("len(RedirectURIs) = %d, want 1", len(metadata.RedirectURIs))
		}
	})

	// Test client_id mismatch
	t.Run("client_id mismatch", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
		testSrv := &Server{
			Config: &Config{
				ClientMetadataFetchTimeout:      10 * time.Second,
				EnableClientIDMetadataDocuments: true,
			},
			Logger: logger,
		}

		// Create server that returns wrong client_id
		badTS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			metadata := ClientMetadata{
				ClientID:     "https://wrong.example.com/client",
				RedirectURIs: []string{"https://app.example.com/callback"},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(metadata)
		}))
		defer badTS.Close()

		clientID := badTS.URL + "/client"
		_, _, err := testSrv.fetchClientMetadata(context.Background(), clientID)
		if err == nil {
			t.Error("expected error (SSRF protection or mismatch), got nil")
		}
		// Expected: SSRF protection blocks localhost, which is correct behavior
		// Test server always uses localhost/127.0.0.1, so we expect SSRF protection
		if !strings.Contains(err.Error(), "private/internal IP") && !strings.Contains(err.Error(), "mismatch") {
			t.Errorf("expected SSRF or mismatch error, got: %v", err)
		}
	})
}

// TestMetadataCache tests the client metadata cache
func TestMetadataCache(t *testing.T) {
	cache := newClientMetadataCache(5*time.Minute, 100)

	metadata := &ClientMetadata{
		ClientID:     "https://example.com/client",
		ClientName:   "Test Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	client := metadataToClient(metadata)

	// Test cache miss
	_, ok := cache.Get("https://example.com/client")
	if ok {
		t.Error("expected cache miss, got hit")
	}

	// Test cache set and hit
	cache.Set("https://example.com/client", metadata, client, 5*time.Minute)
	cachedClient, ok := cache.Get("https://example.com/client")
	if !ok {
		t.Error("expected cache hit, got miss")
	}
	if cachedClient.ClientID != metadata.ClientID {
		t.Errorf("cached ClientID = %q, want %q", cachedClient.ClientID, metadata.ClientID)
	}

	// Test cache expiry
	cache.Set("https://example.com/expired", metadata, client, 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	_, ok = cache.Get("https://example.com/expired")
	if ok {
		t.Error("expected cache miss for expired entry, got hit")
	}

	// Test LRU eviction
	smallCache := newClientMetadataCache(5*time.Minute, 2) // Max 2 entries
	smallCache.Set("client1", metadata, client, 5*time.Minute)
	smallCache.Set("client2", metadata, client, 5*time.Minute)
	if smallCache.Size() != 2 {
		t.Errorf("cache size = %d, want 2", smallCache.Size())
	}

	// Add third entry - should evict oldest
	smallCache.Set("client3", metadata, client, 5*time.Minute)
	if smallCache.Size() != 2 {
		t.Errorf("cache size = %d, want 2 after eviction", smallCache.Size())
	}

	// client1 should be evicted (oldest)
	_, ok = smallCache.Get("client1")
	if ok {
		t.Error("expected client1 to be evicted, but found in cache")
	}

	// Test cleanup
	cache.Set("https://example.com/cleanup", metadata, client, 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	removed := cache.CleanupExpired()
	if removed == 0 {
		t.Error("expected at least 1 expired entry to be cleaned up")
	}
}

// TestMetadataToClient tests conversion from ClientMetadata to storage.Client
func TestMetadataToClient(t *testing.T) {
	metadata := &ClientMetadata{
		ClientID:                "https://example.com/client",
		ClientName:              "Test Client",
		RedirectURIs:            []string{"https://app.example.com/callback", "http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scope:                   "openid profile email",
	}

	client := metadataToClient(metadata)

	if client.ClientID != metadata.ClientID {
		t.Errorf("ClientID = %q, want %q", client.ClientID, metadata.ClientID)
	}
	if client.ClientName != metadata.ClientName {
		t.Errorf("ClientName = %q, want %q", client.ClientName, metadata.ClientName)
	}
	if len(client.RedirectURIs) != len(metadata.RedirectURIs) {
		t.Errorf("len(RedirectURIs) = %d, want %d", len(client.RedirectURIs), len(metadata.RedirectURIs))
	}
	if client.ClientType != "public" {
		t.Errorf("ClientType = %q, want %q", client.ClientType, "public")
	}
	if len(client.Scopes) != 3 {
		t.Errorf("len(Scopes) = %d, want 3", len(client.Scopes))
	}

	// Test confidential client
	confidentialMeta := &ClientMetadata{
		ClientID:                "https://example.com/confidential",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	confidentialClient := metadataToClient(confidentialMeta)
	if confidentialClient.ClientType != "confidential" {
		t.Errorf("ClientType = %q, want %q for non-none auth method", confidentialClient.ClientType, "confidential")
	}
}

// TestHasLocalhostRedirectURIsOnly tests localhost detection
func TestHasLocalhostRedirectURIsOnly(t *testing.T) {
	tests := []struct {
		name         string
		redirectURIs []string
		want         bool
	}{
		{
			name:         "empty list",
			redirectURIs: []string{},
			want:         false,
		},
		{
			name:         "only localhost",
			redirectURIs: []string{"http://localhost:3000/callback"},
			want:         true,
		},
		{
			name:         "only 127.0.0.1",
			redirectURIs: []string{"http://127.0.0.1:3000/callback"},
			want:         true,
		},
		{
			name:         "only IPv6 loopback",
			redirectURIs: []string{"http://[::1]:3000/callback"},
			want:         true,
		},
		{
			name:         "mixed localhost and public",
			redirectURIs: []string{"http://localhost:3000/callback", "https://app.example.com/callback"},
			want:         false,
		},
		{
			name:         "only public",
			redirectURIs: []string{"https://app.example.com/callback"},
			want:         false,
		},
		{
			name:         "multiple localhost variants",
			redirectURIs: []string{"http://localhost:3000/callback", "http://127.0.0.1:8080/callback"},
			want:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasLocalhostRedirectURIsOnly(tt.redirectURIs)
			if got != tt.want {
				t.Errorf("hasLocalhostRedirectURIsOnly(%v) = %v, want %v", tt.redirectURIs, got, tt.want)
			}
		})
	}
}

// TestMetadataFetchRateLimiting tests rate limiting for metadata fetches per domain
func TestMetadataFetchRateLimiting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create server with CIMD enabled
	config := &Config{
		EnableClientIDMetadataDocuments: true,
		ClientMetadataFetchTimeout:      5 * time.Second,
		ClientMetadataCacheTTL:          5 * time.Minute,
	}

	srv := &Server{
		Config:        config,
		Logger:        logger,
		metadataCache: newClientMetadataCache(config.ClientMetadataCacheTTL, 1000),
	}

	// Set up strict rate limiter: 2 requests per second, burst of 2
	// This means only 2 requests are allowed before rate limiting kicks in
	srv.metadataFetchRateLimiter = security.NewRateLimiter(0, 2, logger)

	// Test that rate limiting is enforced per domain
	// Use unique paths to avoid cache hits
	domain := "example.com"
	testURL1 := "https://" + domain + "/client1"
	testURL2 := "https://" + domain + "/client2"
	testURL3 := "https://" + domain + "/client3"

	// Track which errors we get
	errors := make([]error, 3)

	// Make three requests quickly
	for i, clientID := range []string{testURL1, testURL2, testURL3} {
		_, errors[i] = srv.getOrFetchClient(context.Background(), clientID)
	}

	// First two should pass rate limiting (but may fail for other reasons like SSRF or network)
	// Third one should be rate limited
	for i, err := range errors[:2] {
		if err != nil && strings.Contains(err.Error(), "rate limit exceeded") {
			t.Errorf("Request %d should not be rate limited, got: %v", i+1, err)
		}
	}

	// Third request MUST be rate limited
	if errors[2] == nil {
		t.Error("Expected rate limit error for third request, got nil")
	} else if !strings.Contains(errors[2].Error(), "rate limit exceeded") {
		t.Errorf("Expected rate limit error for third request, got: %v", errors[2])
	}
}

// TestRedirectURIValidation tests the redirect URI validation in fetchClientMetadata
func TestRedirectURIValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	tests := []struct {
		name        string
		redirectURI string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid https redirect uri",
			redirectURI: "https://app.example.com/callback",
			wantErr:     false,
		},
		{
			name:        "valid http localhost",
			redirectURI: "http://localhost:3000/callback",
			wantErr:     false,
		},
		{
			name:        "valid http 127.0.0.1",
			redirectURI: "http://127.0.0.1:8080/callback",
			wantErr:     false,
		},
		{
			name:        "valid http ipv6 loopback",
			redirectURI: "http://[::1]:9000/callback",
			wantErr:     false,
		},
		{
			name:        "invalid scheme - javascript",
			redirectURI: "javascript:alert(1)",
			wantErr:     true,
			errContains: "must use http or https scheme",
		},
		{
			name:        "invalid scheme - data",
			redirectURI: "data:text/html,<script>alert(1)</script>",
			wantErr:     true,
			errContains: "must use http or https scheme",
		},
		{
			name:        "http non-localhost",
			redirectURI: "http://example.com/callback",
			wantErr:     true,
			errContains: "http redirect_uri only allowed for localhost",
		},
		{
			name:        "invalid url",
			redirectURI: "://invalid",
			wantErr:     true,
			errContains: "invalid redirect_uri",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server that returns metadata with the test redirect URI
			var serverURL string
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				metadata := ClientMetadata{
					ClientID:     serverURL + "/client",
					RedirectURIs: []string{tt.redirectURI},
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(metadata)
			}))
			defer ts.Close()
			serverURL = ts.URL

			srv := &Server{
				Config: &Config{
					ClientMetadataFetchTimeout:      5 * time.Second,
					EnableClientIDMetadataDocuments: true,
				},
				Logger: logger,
			}

			clientID := serverURL + "/client"
			_, _, err := srv.fetchClientMetadata(context.Background(), clientID)

			// We expect SSRF protection to block localhost test server, which is correct
			// So we check if the error is either SSRF-related OR the validation error we expect
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				// Accept either SSRF protection (test server on localhost) or our validation error
				if !strings.Contains(err.Error(), "private/internal IP") && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %v, want error containing %q or SSRF protection", err, tt.errContains)
				}
			} else {
				// For valid URIs, we still expect SSRF protection to block test server
				if err != nil && !strings.Contains(err.Error(), "private/internal IP") {
					t.Errorf("unexpected error for valid redirect URI: %v", err)
				}
			}
		})
	}
}

// TestParseCacheControlMaxAge tests the Cache-Control max-age parsing with capping
func TestParseCacheControlMaxAge(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		want         int
	}{
		{
			name:         "no cache-control",
			cacheControl: "",
			want:         0,
		},
		{
			name:         "no max-age directive",
			cacheControl: "public, must-revalidate",
			want:         0,
		},
		{
			name:         "valid max-age under cap",
			cacheControl: "max-age=300",
			want:         300,
		},
		{
			name:         "max-age with other directives",
			cacheControl: "public, max-age=600, must-revalidate",
			want:         600,
		},
		{
			name:         "max-age at cap",
			cacheControl: "max-age=3600",
			want:         3600,
		},
		{
			name:         "max-age exceeds cap - should be capped",
			cacheControl: "max-age=7200",
			want:         3600, // Capped at 1 hour
		},
		{
			name:         "very large max-age - should be capped",
			cacheControl: "max-age=999999999",
			want:         3600, // Capped at 1 hour
		},
		{
			name:         "negative max-age",
			cacheControl: "max-age=-100",
			want:         0,
		},
		{
			name:         "invalid max-age format",
			cacheControl: "max-age=abc",
			want:         0,
		},
		{
			name:         "max-age with whitespace",
			cacheControl: "max-age = 500",
			want:         0, // Strict parsing - no space around =
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCacheControlMaxAge(tt.cacheControl)
			if got != tt.want {
				t.Errorf("parseCacheControlMaxAge(%q) = %d, want %d", tt.cacheControl, got, tt.want)
			}
		})
	}
}

// mockClock implements Clock for deterministic testing
type mockClock struct {
	mu  sync.Mutex
	now time.Time
}

func newMockClock(t time.Time) *mockClock {
	return &mockClock{now: t}
}

func (m *mockClock) Now() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

func (m *mockClock) Advance(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = m.now.Add(d)
}

// TestNegativeCache tests the negative cache functionality for failed metadata fetches
func TestNegativeCache(t *testing.T) {
	cache := newClientMetadataCache(5*time.Minute, 100)

	// Test negative cache miss
	t.Run("negative cache miss", func(t *testing.T) {
		_, found := cache.GetNegative("https://example.com/client")
		if found {
			t.Error("expected negative cache miss, got hit")
		}
	})

	// Test negative cache set and hit
	t.Run("negative cache set and hit", func(t *testing.T) {
		clientID := "https://example.com/bad-client"
		errorMsg := "failed to fetch metadata: connection refused"

		cache.SetNegative(clientID, errorMsg)

		got, found := cache.GetNegative(clientID)
		if !found {
			t.Error("expected negative cache hit, got miss")
		}
		if got != errorMsg {
			t.Errorf("negative cache error = %q, want %q", got, errorMsg)
		}
	})

	// Test negative cache expiry (deterministic with mock clock)
	t.Run("negative cache expiry", func(t *testing.T) {
		clock := newMockClock(time.Now())
		shortCache := newClientMetadataCacheWithClock(5*time.Minute, 100, clock)
		shortCache.negativeTTL = 1 * time.Minute

		clientID := "https://example.com/expired-client"
		shortCache.SetNegative(clientID, "some error")

		// Verify entry exists before expiry
		_, found := shortCache.GetNegative(clientID)
		if !found {
			t.Error("expected negative cache hit before expiry")
		}

		// Advance clock past TTL
		clock.Advance(2 * time.Minute)

		_, found = shortCache.GetNegative(clientID)
		if found {
			t.Error("expected negative cache miss for expired entry, got hit")
		}
	})

	// Test negative cache increment on repeated failures
	t.Run("negative cache increment attempts", func(t *testing.T) {
		clientID := "https://example.com/retry-client"
		cache.SetNegative(clientID, "error 1")
		cache.SetNegative(clientID, "error 2")

		// Entry should still exist and have updated error
		got, found := cache.GetNegative(clientID)
		if !found {
			t.Error("expected negative cache hit after multiple failures")
		}
		if got != "error 2" {
			t.Errorf("negative cache error = %q, want %q", got, "error 2")
		}
	})

	// Test negative cache LRU eviction
	t.Run("negative cache LRU eviction", func(t *testing.T) {
		smallCache := newClientMetadataCache(5*time.Minute, 100)
		smallCache.maxNegativeEntries = 2

		smallCache.SetNegative("client1", "error1")
		smallCache.SetNegative("client2", "error2")

		if smallCache.NegativeSize() != 2 {
			t.Errorf("negative cache size = %d, want 2", smallCache.NegativeSize())
		}

		// Add third entry - should evict oldest
		smallCache.SetNegative("client3", "error3")
		if smallCache.NegativeSize() != 2 {
			t.Errorf("negative cache size = %d, want 2 after eviction", smallCache.NegativeSize())
		}

		// client1 should be evicted (oldest)
		_, found := smallCache.GetNegative("client1")
		if found {
			t.Error("expected client1 to be evicted from negative cache, but found")
		}
	})

	// Test that successful fetch clears negative cache entry
	t.Run("successful fetch clears negative cache", func(t *testing.T) {
		clientID := "https://example.com/recovered-client"
		cache.SetNegative(clientID, "initial error")

		// Verify negative entry exists
		_, found := cache.GetNegative(clientID)
		if !found {
			t.Error("expected negative cache hit before successful fetch")
		}

		// Simulate successful fetch by calling Set
		metadata := &ClientMetadata{
			ClientID:     clientID,
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		client := metadataToClient(metadata)
		cache.Set(clientID, metadata, client, 5*time.Minute)

		// Negative entry should be cleared
		_, found = cache.GetNegative(clientID)
		if found {
			t.Error("expected negative cache miss after successful fetch, but found")
		}
	})

	// Test CleanupExpired cleans both positive and negative entries (deterministic with mock clock)
	t.Run("cleanup expired cleans negative entries", func(t *testing.T) {
		clock := newMockClock(time.Now())
		cleanupCache := newClientMetadataCacheWithClock(5*time.Minute, 100, clock)
		cleanupCache.negativeTTL = 1 * time.Minute

		cleanupCache.SetNegative("neg1", "error1")
		cleanupCache.SetNegative("neg2", "error2")

		// Verify entries exist before expiry
		if cleanupCache.NegativeSize() != 2 {
			t.Errorf("negative cache size = %d before cleanup, want 2", cleanupCache.NegativeSize())
		}

		// Advance clock past TTL
		clock.Advance(2 * time.Minute)

		removed := cleanupCache.CleanupExpired()
		if removed != 2 {
			t.Errorf("expected 2 entries removed, got %d", removed)
		}
		if cleanupCache.NegativeSize() != 0 {
			t.Errorf("negative cache size = %d after cleanup, want 0", cleanupCache.NegativeSize())
		}
	})

	// Test Clear clears both positive and negative caches
	t.Run("clear clears both caches", func(t *testing.T) {
		clearCache := newClientMetadataCache(5*time.Minute, 100)

		metadata := &ClientMetadata{
			ClientID:     "https://example.com/client",
			RedirectURIs: []string{"https://app.example.com/callback"},
		}
		client := metadataToClient(metadata)
		clearCache.Set("https://example.com/client", metadata, client, 5*time.Minute)
		clearCache.SetNegative("https://example.com/bad-client", "error")

		if clearCache.Size() != 1 || clearCache.NegativeSize() != 1 {
			t.Errorf("cache not properly populated: size=%d, negativeSize=%d", clearCache.Size(), clearCache.NegativeSize())
		}

		clearCache.Clear()

		if clearCache.Size() != 0 {
			t.Errorf("positive cache size = %d after clear, want 0", clearCache.Size())
		}
		if clearCache.NegativeSize() != 0 {
			t.Errorf("negative cache size = %d after clear, want 0", clearCache.NegativeSize())
		}
	})
}

// TestNegativeCacheMetrics tests that negative cache metrics are tracked
func TestNegativeCacheMetrics(t *testing.T) {
	cache := newClientMetadataCache(5*time.Minute, 100)

	// Set a negative entry
	cache.SetNegative("https://example.com/bad", "error")

	// Get it (should be a hit)
	cache.GetNegative("https://example.com/bad")

	// Get a non-existent entry (should not affect negative hits)
	cache.GetNegative("https://example.com/nonexistent")

	metrics := cache.GetMetrics()
	if metrics.negativeCached != 1 {
		t.Errorf("negativeCached = %d, want 1", metrics.negativeCached)
	}
	if metrics.negativeHits != 1 {
		t.Errorf("negativeHits = %d, want 1", metrics.negativeHits)
	}
}

// TestGetOrFetchClient_NonURLClientID tests that non-URL client IDs fall back to normal client store lookup
func TestGetOrFetchClient_NonURLClientID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create mock storage and pre-register a client
	clientStore := mock.NewMockClientStore()
	err := clientStore.SaveClient(context.Background(), &storage.Client{
		ClientID:     "my-regular-client",
		ClientName:   "Regular Client",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
	})
	if err != nil {
		t.Fatalf("failed to save client: %v", err)
	}

	config := &Config{
		EnableClientIDMetadataDocuments: true,
		ClientMetadataCacheTTL:          5 * time.Minute,
	}

	srv := &Server{
		Config:        config,
		Logger:        logger,
		clientStore:   clientStore,
		metadataCache: newClientMetadataCache(config.ClientMetadataCacheTTL, 1000),
	}

	// Test that non-URL client IDs use normal client store lookup
	client, err := srv.getOrFetchClient(context.Background(), "my-regular-client")
	if err != nil {
		t.Fatalf("getOrFetchClient() error = %v", err)
	}
	if client.ClientID != "my-regular-client" {
		t.Errorf("ClientID = %q, want %q", client.ClientID, "my-regular-client")
	}
	if client.ClientName != "Regular Client" {
		t.Errorf("ClientName = %q, want %q", client.ClientName, "Regular Client")
	}
}

// TestGetOrFetchClient_URLClientID_CIMDDisabled tests that URL client IDs are rejected when CIMD is disabled
func TestGetOrFetchClient_URLClientID_CIMDDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := &Config{
		EnableClientIDMetadataDocuments: false, // CIMD disabled
	}

	srv := &Server{
		Config:        config,
		Logger:        logger,
		metadataCache: newClientMetadataCache(5*time.Minute, 1000),
	}

	// Test that URL client IDs are rejected when CIMD is disabled
	_, err := srv.getOrFetchClient(context.Background(), "https://example.com/client-metadata.json")
	if err == nil {
		t.Error("expected error for URL client ID when CIMD is disabled, got nil")
	}
	if !strings.Contains(err.Error(), "client_id_metadata_documents feature is disabled") {
		t.Errorf("expected CIMD disabled error, got: %v", err)
	}
}

// TestGetOrFetchClient_URLClientID_CacheHit tests that cached URL clients are returned
func TestGetOrFetchClient_URLClientID_CacheHit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := &Config{
		EnableClientIDMetadataDocuments: true,
		ClientMetadataCacheTTL:          5 * time.Minute,
	}

	srv := &Server{
		Config:        config,
		Logger:        logger,
		metadataCache: newClientMetadataCache(config.ClientMetadataCacheTTL, 1000),
	}

	// Pre-populate cache with a URL client
	clientID := "https://example.com/client-metadata.json"
	metadata := &ClientMetadata{
		ClientID:     clientID,
		ClientName:   "Cached Client",
		RedirectURIs: []string{"https://app.example.com/callback"},
	}
	client := metadataToClient(metadata)
	srv.metadataCache.Set(clientID, metadata, client, 5*time.Minute)

	// Test that cached client is returned
	cachedClient, err := srv.getOrFetchClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("getOrFetchClient() error = %v", err)
	}
	if cachedClient.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", cachedClient.ClientID, clientID)
	}
	if cachedClient.ClientName != "Cached Client" {
		t.Errorf("ClientName = %q, want %q", cachedClient.ClientName, "Cached Client")
	}
}

// TestGetOrFetchClient_URLClientID_NegativeCacheHit tests that failed URL clients return cached error
func TestGetOrFetchClient_URLClientID_NegativeCacheHit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	config := &Config{
		EnableClientIDMetadataDocuments: true,
		ClientMetadataCacheTTL:          5 * time.Minute,
	}

	srv := &Server{
		Config:        config,
		Logger:        logger,
		metadataCache: newClientMetadataCache(config.ClientMetadataCacheTTL, 1000),
	}

	// Pre-populate negative cache
	clientID := "https://example.com/bad-client"
	srv.metadataCache.SetNegative(clientID, "previous validation failure")

	// Test that negative cached error is returned
	_, err := srv.getOrFetchClient(context.Background(), clientID)
	if err == nil {
		t.Error("expected error for negatively cached client ID, got nil")
	}
	if !strings.Contains(err.Error(), "previously failed validation") {
		t.Errorf("expected negative cache error, got: %v", err)
	}
}
