package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockTime implements timeProvider for deterministic testing.
type mockTime struct {
	now time.Time
}

func (m *mockTime) Now() time.Time                  { return m.now }
func (m *mockTime) Since(t time.Time) time.Duration { return m.now.Sub(t) }

// newTestClient creates a discovery client with validation disabled for testing.
// This allows tests to use httptest servers (which use loopback addresses)
// without triggering SSRF protection.
func newTestClient(httpClient *http.Client, ttl time.Duration) *DiscoveryClient {
	client := NewDiscoveryClient(httpClient, ttl, slog.Default())
	client.skipValidation = true // Bypass SSRF validation for test servers
	return client
}

func TestNewDiscoveryClient(t *testing.T) {
	t.Run("with default values", func(t *testing.T) {
		client := NewDiscoveryClient(nil, 0, nil)
		if client == nil {
			t.Fatal("NewDiscoveryClient() returned nil")
		}
		if client.httpClient == nil {
			t.Error("httpClient should be initialized with default")
		}
		if client.cacheTTL != 1*time.Hour {
			t.Errorf("cacheTTL = %v, want %v", client.cacheTTL, 1*time.Hour)
		}
		if client.logger == nil {
			t.Error("logger should be initialized with default")
		}
	})

	t.Run("with custom values", func(t *testing.T) {
		customClient := &http.Client{Timeout: 5 * time.Second}
		customLogger := slog.Default()
		customTTL := 30 * time.Minute

		client := NewDiscoveryClient(customClient, customTTL, customLogger)
		if client.httpClient != customClient {
			t.Error("httpClient should use custom value")
		}
		if client.cacheTTL != customTTL {
			t.Errorf("cacheTTL = %v, want %v", client.cacheTTL, customTTL)
		}
		if client.logger != customLogger {
			t.Error("logger should use custom value")
		}
	})
}

func TestDiscoveryClient_Discover(t *testing.T) {
	validDoc := DiscoveryDocument{
		Issuer:                 "https://dex.example.com",
		AuthorizationEndpoint:  "https://dex.example.com/auth",
		TokenEndpoint:          "https://dex.example.com/token",
		UserInfoEndpoint:       "https://dex.example.com/userinfo",
		JWKSUri:                "https://dex.example.com/keys",
		ScopesSupported:        []string{"openid", "profile", "email", "groups"},
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
	}

	t.Run("successful discovery", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				t.Errorf("unexpected path: %s", r.URL.Path)
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(validDoc); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
		}))
		defer server.Close()

		client := newTestClient(server.Client(), 1*time.Hour)
		doc, err := client.Discover(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("Discover() error = %v", err)
		}

		if doc.Issuer != validDoc.Issuer {
			t.Errorf("Issuer = %v, want %v", doc.Issuer, validDoc.Issuer)
		}
		if doc.AuthorizationEndpoint != validDoc.AuthorizationEndpoint {
			t.Errorf("AuthorizationEndpoint = %v, want %v", doc.AuthorizationEndpoint, validDoc.AuthorizationEndpoint)
		}
	})

	t.Run("SECURITY: reject HTTP issuer URL", func(t *testing.T) {
		client := NewDiscoveryClient(nil, 1*time.Hour, slog.Default())
		_, err := client.Discover(context.Background(), "http://dex.example.com")
		if err == nil {
			t.Error("Discover() should reject HTTP issuer URL")
		}
		if !strings.Contains(err.Error(), "must use HTTPS") {
			t.Errorf("error should mention HTTPS requirement, got: %v", err)
		}
	})

	t.Run("SECURITY: reject private IP", func(t *testing.T) {
		client := NewDiscoveryClient(nil, 1*time.Hour, slog.Default())
		_, err := client.Discover(context.Background(), "https://10.0.0.1")
		if err == nil {
			t.Error("Discover() should reject private IP")
		}
		if !strings.Contains(err.Error(), "private IP") {
			t.Errorf("error should mention private IP, got: %v", err)
		}
	})

	t.Run("SECURITY: reject localhost", func(t *testing.T) {
		client := NewDiscoveryClient(nil, 1*time.Hour, slog.Default())
		_, err := client.Discover(context.Background(), "https://127.0.0.1")
		if err == nil {
			t.Error("Discover() should reject loopback address")
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("error should mention loopback, got: %v", err)
		}
	})

	t.Run("SECURITY: reject HTTP endpoints in discovery", func(t *testing.T) {
		httpDoc := validDoc
		httpDoc.AuthorizationEndpoint = "http://dex.example.com/auth" // HTTP instead of HTTPS

		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(httpDoc)
		}))
		defer server.Close()

		client := newTestClient(server.Client(), 1*time.Hour)
		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Error("Discover() should reject HTTP endpoints")
		}
		if !strings.Contains(err.Error(), "must use HTTPS") {
			t.Errorf("error should mention HTTPS requirement, got: %v", err)
		}
	})

	t.Run("cache hit", func(t *testing.T) {
		callCount := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(validDoc)
		}))
		defer server.Close()

		client := newTestClient(server.Client(), 1*time.Hour)

		// First call - should hit server
		_, err := client.Discover(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("first Discover() error = %v", err)
		}

		// Second call - should use cache
		_, err = client.Discover(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("second Discover() error = %v", err)
		}

		if callCount != 1 {
			t.Errorf("expected 1 HTTP call (cache hit), got %d", callCount)
		}
	})

	t.Run("cache expiry", func(t *testing.T) {
		callCount := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			callCount++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(validDoc)
		}))
		defer server.Close()

		// Short TTL for testing
		client := newTestClient(server.Client(), 100*time.Millisecond)

		// Use mock time for deterministic testing
		mockTime := &mockTime{now: time.Now()}
		client.timeProvider = mockTime

		// First call
		_, err := client.Discover(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("first Discover() error = %v", err)
		}

		// Advance mock time to expire cache
		mockTime.now = mockTime.now.Add(150 * time.Millisecond)

		// Second call - should hit server again
		_, err = client.Discover(context.Background(), server.URL)
		if err != nil {
			t.Fatalf("second Discover() error = %v", err)
		}

		if callCount != 2 {
			t.Errorf("expected 2 HTTP calls (cache expired), got %d", callCount)
		}
	})

	t.Run("404 not found", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer server.Close()

		client := newTestClient(server.Client(), 1*time.Hour)
		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Error("Discover() should return error for 404")
		}
		if !strings.Contains(err.Error(), "status 404") {
			t.Errorf("error should mention status code, got: %v", err)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not json"))
		}))
		defer server.Close()

		client := newTestClient(server.Client(), 1*time.Hour)
		_, err := client.Discover(context.Background(), server.URL)
		if err == nil {
			t.Error("Discover() should return error for malformed JSON")
		}
		if !strings.Contains(err.Error(), "decode") {
			t.Errorf("error should mention decode failure, got: %v", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(1 * time.Second) // Simulate slow response
			_ = json.NewEncoder(w).Encode(validDoc)
		}))
		defer server.Close()

		client := newTestClient(server.Client(), 1*time.Hour)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := client.Discover(ctx, server.URL)
		if err == nil {
			t.Error("Discover() should return error when context is cancelled")
		}
	})
}

func TestDiscoveryClient_validateDocument(t *testing.T) {
	client := NewDiscoveryClient(nil, 1*time.Hour, slog.Default())

	tests := []struct {
		name    string
		doc     *DiscoveryDocument
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid document",
			doc: &DiscoveryDocument{
				Issuer:                "https://dex.example.com",
				AuthorizationEndpoint: "https://dex.example.com/auth",
				TokenEndpoint:         "https://dex.example.com/token",
				JWKSUri:               "https://dex.example.com/keys",
			},
			wantErr: false,
		},
		{
			name: "missing issuer",
			doc: &DiscoveryDocument{
				AuthorizationEndpoint: "https://dex.example.com/auth",
				TokenEndpoint:         "https://dex.example.com/token",
				JWKSUri:               "https://dex.example.com/keys",
			},
			wantErr: true,
			errMsg:  "issuer is required",
		},
		{
			name: "HTTP issuer",
			doc: &DiscoveryDocument{
				Issuer:                "http://dex.example.com",
				AuthorizationEndpoint: "https://dex.example.com/auth",
				TokenEndpoint:         "https://dex.example.com/token",
				JWKSUri:               "https://dex.example.com/keys",
			},
			wantErr: true,
			errMsg:  "must use HTTPS",
		},
		{
			name: "HTTP authorization endpoint",
			doc: &DiscoveryDocument{
				Issuer:                "https://dex.example.com",
				AuthorizationEndpoint: "http://dex.example.com/auth",
				TokenEndpoint:         "https://dex.example.com/token",
				JWKSUri:               "https://dex.example.com/keys",
			},
			wantErr: true,
			errMsg:  "must use HTTPS",
		},
		{
			name: "optional userinfo endpoint can be HTTPS",
			doc: &DiscoveryDocument{
				Issuer:                "https://dex.example.com",
				AuthorizationEndpoint: "https://dex.example.com/auth",
				TokenEndpoint:         "https://dex.example.com/token",
				UserInfoEndpoint:      "https://dex.example.com/userinfo",
				JWKSUri:               "https://dex.example.com/keys",
			},
			wantErr: false,
		},
		{
			name: "optional userinfo endpoint must be HTTPS if present",
			doc: &DiscoveryDocument{
				Issuer:                "https://dex.example.com",
				AuthorizationEndpoint: "https://dex.example.com/auth",
				TokenEndpoint:         "https://dex.example.com/token",
				UserInfoEndpoint:      "http://dex.example.com/userinfo",
				JWKSUri:               "https://dex.example.com/keys",
			},
			wantErr: true,
			errMsg:  "must use HTTPS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.validateDocument(tt.doc)
			if tt.wantErr {
				if err == nil {
					t.Error("validateDocument() expected error, got nil")
					return
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateDocument() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("validateDocument() unexpected error = %v", err)
			}
		})
	}
}

func TestDiscoveryClient_ClearCache(t *testing.T) {
	validDoc := DiscoveryDocument{
		Issuer:                "https://dex.example.com",
		AuthorizationEndpoint: "https://dex.example.com/auth",
		TokenEndpoint:         "https://dex.example.com/token",
		JWKSUri:               "https://dex.example.com/keys",
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(validDoc)
	}))
	defer server.Close()

	client := newTestClient(server.Client(), 1*time.Hour)

	// Populate cache
	_, err := client.Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	// Verify cache is populated (check will return immediately)
	_, ok := client.cache.Load(server.URL)
	if !ok {
		t.Error("cache should be populated")
	}

	// Clear cache
	client.ClearCache()

	// Verify cache is empty
	_, ok = client.cache.Load(server.URL)
	if ok {
		t.Error("cache should be empty after ClearCache()")
	}
}
