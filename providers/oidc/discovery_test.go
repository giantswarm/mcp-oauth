package oidc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
	return NewDiscoveryClientWithOptions(httpClient, ttl, slog.Default(), WithSkipValidation())
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

// TestDiscoveryClient_Discover_SingleflightCoalescesColdMisses confirms that
// N concurrent cold-cache callers for the same issuer fire a single HTTP
// fetch. Eliminates fleet-bounce stampede against the IdP.
func TestDiscoveryClient_Discover_SingleflightCoalescesColdMisses(t *testing.T) {
	const concurrency = 32

	validDoc := DiscoveryDocument{
		Issuer:                 "https://dex.example.com",
		AuthorizationEndpoint:  "https://dex.example.com/auth",
		TokenEndpoint:          "https://dex.example.com/token",
		UserInfoEndpoint:       "https://dex.example.com/userinfo",
		JWKSUri:                "https://dex.example.com/keys",
		ResponseTypesSupported: []string{"code"},
	}

	var (
		fetches int64
		release = make(chan struct{})
	)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		atomic.AddInt64(&fetches, 1)
		<-release // hold the in-flight request until all callers are queued
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(validDoc)
	}))
	defer server.Close()

	client := newTestClient(server.Client(), 1*time.Hour)

	var (
		ready sync.WaitGroup
		wg    sync.WaitGroup
	)
	ready.Add(concurrency)
	docs := make([]*DiscoveryDocument, concurrency)
	errs := make([]error, concurrency)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ready.Done()
			docs[idx], errs[idx] = client.Discover(context.Background(), server.URL)
		}(i)
	}

	// Wait for every goroutine to start before unblocking the upstream so
	// the singleflight join window is as wide as possible.
	ready.Wait()
	close(release)
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "caller %d", i)
		require.NotNil(t, docs[i])
		require.Equal(t, validDoc.Issuer, docs[i].Issuer)
	}
	require.EqualValues(t, 1, atomic.LoadInt64(&fetches),
		"cold-cache callers must coalesce into a single upstream fetch (got %d)", atomic.LoadInt64(&fetches))
}

// TestDiscoveryClient_Discover_CallerCancelDoesNotPoisonOthers verifies that
// when one coalesced caller cancels its context the others still receive the
// shared fetch result (the leader's ctx is detached from the fetch).
func TestDiscoveryClient_Discover_CallerCancelDoesNotPoisonOthers(t *testing.T) {
	validDoc := DiscoveryDocument{
		Issuer:                 "https://dex.example.com",
		AuthorizationEndpoint:  "https://dex.example.com/auth",
		TokenEndpoint:          "https://dex.example.com/token",
		JWKSUri:                "https://dex.example.com/keys",
		ResponseTypesSupported: []string{"code"},
	}

	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(validDoc)
	}))
	defer server.Close()

	client := newTestClient(server.Client(), 1*time.Hour)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()

	type result struct {
		doc *DiscoveryDocument
		err error
	}
	leaderResult := make(chan result, 1)
	joinerResult := make(chan result, 1)

	var ready sync.WaitGroup
	ready.Add(2)
	go func() {
		ready.Done()
		doc, err := client.Discover(leaderCtx, server.URL)
		leaderResult <- result{doc: doc, err: err}
	}()
	go func() {
		ready.Done()
		doc, err := client.Discover(context.Background(), server.URL)
		joinerResult <- result{doc: doc, err: err}
	}()

	ready.Wait()
	cancelLeader()

	select {
	case r := <-leaderResult:
		require.ErrorIs(t, r.err, context.Canceled, "leader must observe its own cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not return within 2s of cancel")
	}

	close(release)

	select {
	case r := <-joinerResult:
		require.NoError(t, r.err, "joiner must receive the shared fetch result, not the leader's cancellation")
		require.NotNil(t, r.doc)
		require.Equal(t, validDoc.Issuer, r.doc.Issuer)
	case <-time.After(2 * time.Second):
		t.Fatal("joiner did not return within 2s of upstream release")
	}
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
