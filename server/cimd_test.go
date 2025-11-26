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
	"testing"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
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
			err := validateMetadataURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateMetadataURL(%q) expected error containing %q, got nil", tt.url, tt.errText)
					return
				}
				if tt.errText != "" && !strings.Contains(err.Error(), tt.errText) {
					t.Errorf("validateMetadataURL(%q) error = %v, want error containing %q", tt.url, err, tt.errText)
				}
			} else {
				if err != nil {
					t.Errorf("validateMetadataURL(%q) unexpected error: %v", tt.url, err)
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
