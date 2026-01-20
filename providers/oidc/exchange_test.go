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

func TestNewTokenExchangeClient(t *testing.T) {
	t.Run("with default values", func(t *testing.T) {
		client := NewTokenExchangeClient(nil)
		if client == nil {
			t.Fatal("NewTokenExchangeClient() returned nil")
		}
		if client.httpClient == nil {
			t.Error("httpClient should be initialized with default")
		}
		if client.logger == nil {
			t.Error("logger should be initialized with default")
		}
		if client.allowPrivateIP {
			t.Error("allowPrivateIP should be false by default")
		}
	})

	t.Run("with custom logger", func(t *testing.T) {
		customLogger := slog.Default()
		client := NewTokenExchangeClient(customLogger)
		if client.logger != customLogger {
			t.Error("logger should use custom value")
		}
	})
}

func TestNewTokenExchangeClientWithOptions(t *testing.T) {
	t.Run("with AllowPrivateIP enabled", func(t *testing.T) {
		client := NewTokenExchangeClientWithOptions(TokenExchangeClientOptions{
			AllowPrivateIP: true,
			Logger:         slog.Default(),
		})
		if !client.allowPrivateIP {
			t.Error("allowPrivateIP should be true")
		}
	})

	t.Run("with custom HTTP client", func(t *testing.T) {
		customHTTPClient := &http.Client{Timeout: 5 * time.Second}
		client := NewTokenExchangeClientWithOptions(TokenExchangeClientOptions{
			HTTPClient: customHTTPClient,
		})
		if client.httpClient != customHTTPClient {
			t.Error("httpClient should use custom value")
		}
	})
}

// newTestTokenExchangeClient creates a token exchange client for testing.
// It uses the provided HTTP client and skips SSRF validation for test servers.
func newTestTokenExchangeClient(httpClient *http.Client) *TokenExchangeClient {
	return &TokenExchangeClient{
		httpClient:     httpClient,
		logger:         slog.Default(),
		allowPrivateIP: true, // Allow localhost for tests
	}
}

func TestTokenExchangeClient_Exchange(t *testing.T) {
	validResponse := TokenExchangeResponse{
		AccessToken:     "new-access-token",
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       3600,
		Scope:           "openid profile email",
	}

	t.Run("successful exchange", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request method and content type
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
				t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %s", ct)
			}

			// Parse and verify form data
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
			}

			if grantType := r.FormValue("grant_type"); grantType != GrantTypeTokenExchange {
				t.Errorf("expected grant_type %s, got %s", GrantTypeTokenExchange, grantType)
			}
			if subjectToken := r.FormValue("subject_token"); subjectToken != "test-subject-token" {
				t.Errorf("expected subject_token test-subject-token, got %s", subjectToken)
			}
			if connectorID := r.FormValue("connector_id"); connectorID != "source-cluster" {
				t.Errorf("expected connector_id source-cluster, got %s", connectorID)
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(validResponse); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())
		resp, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint:    server.URL,
			SubjectToken:     "test-subject-token",
			SubjectTokenType: TokenTypeIDToken,
			ConnectorID:      "source-cluster",
		})
		if err != nil {
			t.Fatalf("Exchange() error = %v", err)
		}
		if resp.AccessToken != validResponse.AccessToken {
			t.Errorf("AccessToken = %v, want %v", resp.AccessToken, validResponse.AccessToken)
		}
		if resp.ExpiresIn != validResponse.ExpiresIn {
			t.Errorf("ExpiresIn = %v, want %v", resp.ExpiresIn, validResponse.ExpiresIn)
		}
	})

	t.Run("with client authentication", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify Basic auth
			username, password, ok := r.BasicAuth()
			if !ok {
				t.Error("expected Basic authentication")
			}
			if username != "client-id" {
				t.Errorf("expected client-id, got %s", username)
			}
			if password != "client-secret" {
				t.Errorf("expected client-secret, got %s", password)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(validResponse)
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())
		resp, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: server.URL,
			SubjectToken:  "test-subject-token",
			ConnectorID:   "source-cluster",
			ClientID:      "client-id",
			ClientSecret:  "client-secret",
		})
		if err != nil {
			t.Fatalf("Exchange() error = %v", err)
		}
		if resp.AccessToken != validResponse.AccessToken {
			t.Errorf("AccessToken = %v, want %v", resp.AccessToken, validResponse.AccessToken)
		}
	})

	t.Run("with optional parameters", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
			}

			// Verify optional parameters
			if scope := r.FormValue("scope"); scope != "openid profile" {
				t.Errorf("expected scope 'openid profile', got %s", scope)
			}
			if audience := r.FormValue("audience"); audience != "https://api.cluster-b.example.com" {
				t.Errorf("expected audience, got %s", audience)
			}
			if requestedType := r.FormValue("requested_token_type"); requestedType != TokenTypeAccessToken {
				t.Errorf("expected requested_token_type, got %s", requestedType)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(validResponse)
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint:      server.URL,
			SubjectToken:       "test-subject-token",
			ConnectorID:        "source-cluster",
			Scope:              "openid profile",
			Audience:           "https://api.cluster-b.example.com",
			RequestedTokenType: TokenTypeAccessToken,
		})
		if err != nil {
			t.Fatalf("Exchange() error = %v", err)
		}
	})

	t.Run("default subject token type", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
			}

			// Should default to ID token type
			if tokenType := r.FormValue("subject_token_type"); tokenType != TokenTypeIDToken {
				t.Errorf("expected default subject_token_type %s, got %s", TokenTypeIDToken, tokenType)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(validResponse)
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: server.URL,
			SubjectToken:  "test-subject-token",
			ConnectorID:   "source-cluster",
			// SubjectTokenType not specified - should default to TokenTypeIDToken
		})
		if err != nil {
			t.Fatalf("Exchange() error = %v", err)
		}
	})

	t.Run("missing token endpoint", func(t *testing.T) {
		client := NewTokenExchangeClient(nil)
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			SubjectToken: "test-token",
			ConnectorID:  "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should return error for missing token endpoint")
		}
		if !strings.Contains(err.Error(), "token endpoint is required") {
			t.Errorf("error should mention token endpoint, got: %v", err)
		}
	})

	t.Run("missing subject token", func(t *testing.T) {
		client := NewTokenExchangeClient(nil)
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: "https://example.com/token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should return error for missing subject token")
		}
		if !strings.Contains(err.Error(), "subject token is required") {
			t.Errorf("error should mention subject token, got: %v", err)
		}
	})

	t.Run("missing connector ID", func(t *testing.T) {
		client := NewTokenExchangeClient(nil)
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: "https://example.com/token",
			SubjectToken:  "test-token",
		})

		if err == nil {
			t.Error("Exchange() should return error for missing connector ID")
		}
		if !strings.Contains(err.Error(), "connector ID is required") {
			t.Errorf("error should mention connector ID, got: %v", err)
		}
	})

	t.Run("invalid connector ID", func(t *testing.T) {
		client := NewTokenExchangeClient(nil)
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: "https://example.com/token",
			SubjectToken:  "test-token",
			ConnectorID:   "invalid connector!@#",
		})

		if err == nil {
			t.Error("Exchange() should return error for invalid connector ID")
		}
		if !strings.Contains(err.Error(), "invalid connector ID") {
			t.Errorf("error should mention invalid connector ID, got: %v", err)
		}
	})

	t.Run("SECURITY: reject HTTP token endpoint", func(t *testing.T) {
		client := NewTokenExchangeClient(nil)
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: "http://example.com/token",
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should reject HTTP token endpoint")
		}
		if !strings.Contains(err.Error(), "HTTPS") {
			t.Errorf("error should mention HTTPS, got: %v", err)
		}
	})

	t.Run("SECURITY: reject private IP by default", func(t *testing.T) {
		client := NewTokenExchangeClient(nil)
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: "https://10.0.0.1/token",
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should reject private IP")
		}
		if !strings.Contains(err.Error(), "private IP") {
			t.Errorf("error should mention private IP, got: %v", err)
		}
	})

	t.Run("SECURITY: reject localhost by default", func(t *testing.T) {
		client := NewTokenExchangeClient(nil)
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: "https://127.0.0.1/token",
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should reject loopback address")
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("error should mention loopback, got: %v", err)
		}
	})

	t.Run("OAuth error response", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(TokenExchangeErrorResponse{
				Error:            "invalid_grant",
				ErrorDescription: "The subject token is expired",
			})
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: server.URL,
			SubjectToken:  "expired-token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should return error for OAuth error response")
		}
		if !strings.Contains(err.Error(), "invalid_grant") {
			t.Errorf("error should contain error code, got: %v", err)
		}
		if !strings.Contains(err.Error(), "subject token is expired") {
			t.Errorf("error should contain error description, got: %v", err)
		}
	})

	t.Run("OAuth error response without description", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(TokenExchangeErrorResponse{
				Error: "invalid_request",
			})
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: server.URL,
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should return error")
		}
		if !strings.Contains(err.Error(), "invalid_request") {
			t.Errorf("error should contain error code, got: %v", err)
		}
	})

	t.Run("non-JSON error response", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Internal Server Error"))
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: server.URL,
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should return error")
		}
		if !strings.Contains(err.Error(), "status 500") {
			t.Errorf("error should contain status code, got: %v", err)
		}
	})

	t.Run("response missing access token", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(TokenExchangeResponse{
				// AccessToken is empty
				TokenType: "Bearer",
			})
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: server.URL,
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should return error for missing access token")
		}
		if !strings.Contains(err.Error(), "missing access_token") {
			t.Errorf("error should mention missing access_token, got: %v", err)
		}
	})

	t.Run("malformed JSON response", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not json"))
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: server.URL,
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should return error for malformed JSON")
		}
		if !strings.Contains(err.Error(), "parse") {
			t.Errorf("error should mention parse failure, got: %v", err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(1 * time.Second)
			_ = json.NewEncoder(w).Encode(validResponse)
		}))
		defer server.Close()

		client := newTestTokenExchangeClient(server.Client())

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := client.Exchange(ctx, TokenExchangeRequest{
			TokenEndpoint: server.URL,
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should return error when context is cancelled")
		}
	})
}

func TestTokenExchangeCache(t *testing.T) {
	t.Run("basic get and set", func(t *testing.T) {
		cache := NewTokenExchangeCache()

		key := GenerateCacheKey("https://dex.cluster-b.example.com/token", "cluster-a", "user-123")
		cache.Set(key, "test-token", TokenTypeAccessToken, 3600)

		cached := cache.Get(key)
		if cached == nil {
			t.Fatal("Get() returned nil for existing key")
		}
		if cached.AccessToken != "test-token" {
			t.Errorf("AccessToken = %v, want test-token", cached.AccessToken)
		}
		if cached.IssuedTokenType != TokenTypeAccessToken {
			t.Errorf("IssuedTokenType = %v, want %v", cached.IssuedTokenType, TokenTypeAccessToken)
		}
	})

	t.Run("get non-existent key", func(t *testing.T) {
		cache := NewTokenExchangeCache()

		cached := cache.Get("non-existent")
		if cached != nil {
			t.Error("Get() should return nil for non-existent key")
		}
	})

	t.Run("expired token returns nil", func(t *testing.T) {
		cache := NewTokenExchangeCache()

		key := "expired-key"
		// Set with 0 seconds (will be immediately expired due to buffer)
		cache.Set(key, "expired-token", TokenTypeAccessToken, 0)

		cached := cache.Get(key)
		if cached != nil {
			t.Error("Get() should return nil for expired token")
		}
	})

	t.Run("delete", func(t *testing.T) {
		cache := NewTokenExchangeCache()

		key := "delete-key"
		cache.Set(key, "token", TokenTypeAccessToken, 3600)

		// Verify it exists
		if cache.Get(key) == nil {
			t.Fatal("token should exist before delete")
		}

		cache.Delete(key)

		if cache.Get(key) != nil {
			t.Error("token should not exist after delete")
		}
	})

	t.Run("clear", func(t *testing.T) {
		cache := NewTokenExchangeCache()

		cache.Set("key1", "token1", TokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", TokenTypeAccessToken, 3600)

		if cache.Size() != 2 {
			t.Errorf("Size() = %d, want 2", cache.Size())
		}

		cache.Clear()

		if cache.Size() != 0 {
			t.Errorf("Size() = %d, want 0 after clear", cache.Size())
		}
	})

	t.Run("size", func(t *testing.T) {
		cache := NewTokenExchangeCache()

		if cache.Size() != 0 {
			t.Errorf("Size() = %d, want 0 for empty cache", cache.Size())
		}

		cache.Set("key1", "token1", TokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", TokenTypeAccessToken, 3600)
		cache.Set("key3", "token3", TokenTypeAccessToken, 3600)

		if cache.Size() != 3 {
			t.Errorf("Size() = %d, want 3", cache.Size())
		}
	})

	t.Run("cleanup removes expired tokens", func(t *testing.T) {
		cache := NewTokenExchangeCache()

		// Add some valid tokens
		cache.Set("valid1", "token1", TokenTypeAccessToken, 3600)
		cache.Set("valid2", "token2", TokenTypeAccessToken, 3600)

		// Add expired tokens (0 seconds means immediately expired due to buffer)
		cache.Set("expired1", "token3", TokenTypeAccessToken, 0)
		cache.Set("expired2", "token4", TokenTypeAccessToken, 0)

		// Cache should have all 4 entries
		if cache.Size() != 4 {
			t.Errorf("Size() = %d, want 4 before cleanup", cache.Size())
		}

		removed := cache.Cleanup()
		if removed != 2 {
			t.Errorf("Cleanup() removed %d, want 2", removed)
		}

		// Cache should have only valid entries now
		if cache.Size() != 2 {
			t.Errorf("Size() = %d, want 2 after cleanup", cache.Size())
		}

		// Verify correct tokens remain
		if cache.Get("valid1") == nil {
			t.Error("valid1 should still exist")
		}
		if cache.Get("valid2") == nil {
			t.Error("valid2 should still exist")
		}
	})

	t.Run("concurrent access", func(t *testing.T) {
		cache := NewTokenExchangeCache()
		done := make(chan bool)

		// Writer goroutine
		go func() {
			for i := 0; i < 100; i++ {
				key := GenerateCacheKey("endpoint", "connector", string(rune('a'+i%26)))
				cache.Set(key, "token", TokenTypeAccessToken, 3600)
			}
			done <- true
		}()

		// Reader goroutine
		go func() {
			for i := 0; i < 100; i++ {
				key := GenerateCacheKey("endpoint", "connector", string(rune('a'+i%26)))
				_ = cache.Get(key)
			}
			done <- true
		}()

		// Cleanup goroutine
		go func() {
			for i := 0; i < 10; i++ {
				cache.Cleanup()
			}
			done <- true
		}()

		// Wait for all goroutines
		<-done
		<-done
		<-done
	})
}

func TestGenerateCacheKey(t *testing.T) {
	t.Run("generates consistent hash", func(t *testing.T) {
		key1 := GenerateCacheKey("https://dex.example.com/token", "source-cluster", "user-123")
		key2 := GenerateCacheKey("https://dex.example.com/token", "source-cluster", "user-123")
		if key1 != key2 {
			t.Errorf("GenerateCacheKey() should be deterministic, got %v and %v", key1, key2)
		}
		// Key should be base64url encoded SHA-256 (43 chars without padding)
		if len(key1) != 43 {
			t.Errorf("GenerateCacheKey() length = %d, want 43 (base64url SHA-256)", len(key1))
		}
	})

	t.Run("different inputs produce different keys", func(t *testing.T) {
		key1 := GenerateCacheKey("https://dex.example.com/token", "cluster-a", "user-1")
		key2 := GenerateCacheKey("https://dex.example.com/token", "cluster-b", "user-1")
		key3 := GenerateCacheKey("https://dex.example.com/token", "cluster-a", "user-2")
		if key1 == key2 {
			t.Error("Different connector IDs should produce different keys")
		}
		if key1 == key3 {
			t.Error("Different user IDs should produce different keys")
		}
	})

	t.Run("prevents collision with delimiter characters", func(t *testing.T) {
		// These would collide with simple ":" delimiter
		key1 := GenerateCacheKey("https://a:b", "c", "d")
		key2 := GenerateCacheKey("https://a", "b:c", "d")
		if key1 == key2 {
			t.Error("Keys with delimiter characters in values should not collide")
		}
	})
}

func TestTokenExchangeConstants(t *testing.T) {
	// Verify constants are defined correctly per RFC 8693
	// These are RFC-defined URN identifiers, not credentials (gosec false positive)
	expectedGrantType := "urn:ietf:params:oauth:grant-type:token-exchange"   // #nosec G101
	expectedIDToken := "urn:ietf:params:oauth:token-type:id_token"           // #nosec G101
	expectedAccessToken := "urn:ietf:params:oauth:token-type:access_token"   // #nosec G101
	expectedRefreshToken := "urn:ietf:params:oauth:token-type:refresh_token" // #nosec G101
	expectedJWT := "urn:ietf:params:oauth:token-type:jwt"                    // #nosec G101

	if GrantTypeTokenExchange != expectedGrantType {
		t.Errorf("GrantTypeTokenExchange = %v, want %v", GrantTypeTokenExchange, expectedGrantType)
	}
	if TokenTypeIDToken != expectedIDToken {
		t.Errorf("TokenTypeIDToken = %v, want %v", TokenTypeIDToken, expectedIDToken)
	}
	if TokenTypeAccessToken != expectedAccessToken {
		t.Errorf("TokenTypeAccessToken = %v, want %v", TokenTypeAccessToken, expectedAccessToken)
	}
	if TokenTypeRefreshToken != expectedRefreshToken {
		t.Errorf("TokenTypeRefreshToken = %v, want %v", TokenTypeRefreshToken, expectedRefreshToken)
	}
	if TokenTypeJWT != expectedJWT {
		t.Errorf("TokenTypeJWT = %v, want %v", TokenTypeJWT, expectedJWT)
	}
}

func TestTokenExchangeCache_LRUEviction(t *testing.T) {
	t.Run("evicts least recently used when at capacity", func(t *testing.T) {
		// Create cache with max 3 entries
		cache := NewTokenExchangeCacheWithMaxEntries(3)

		// Add 3 entries
		cache.Set("key1", "token1", TokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", TokenTypeAccessToken, 3600)
		cache.Set("key3", "token3", TokenTypeAccessToken, 3600)

		if cache.Size() != 3 {
			t.Fatalf("Size() = %d, want 3", cache.Size())
		}

		// Add 4th entry, should evict key1 (least recently used)
		cache.Set("key4", "token4", TokenTypeAccessToken, 3600)

		if cache.Size() != 3 {
			t.Errorf("Size() = %d, want 3 after eviction", cache.Size())
		}

		// key1 should be evicted
		if cache.Get("key1") != nil {
			t.Error("key1 should have been evicted")
		}

		// key2, key3, key4 should still exist
		if cache.Get("key2") == nil {
			t.Error("key2 should still exist")
		}
		if cache.Get("key3") == nil {
			t.Error("key3 should still exist")
		}
		if cache.Get("key4") == nil {
			t.Error("key4 should still exist")
		}
	})

	t.Run("accessing entry prevents eviction", func(t *testing.T) {
		cache := NewTokenExchangeCacheWithMaxEntries(3)

		// Add 3 entries
		cache.Set("key1", "token1", TokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", TokenTypeAccessToken, 3600)
		cache.Set("key3", "token3", TokenTypeAccessToken, 3600)

		// Access key1 to move it to front
		_ = cache.Get("key1")

		// Add 4th entry, should evict key2 (now least recently used)
		cache.Set("key4", "token4", TokenTypeAccessToken, 3600)

		// key1 should still exist (was accessed)
		if cache.Get("key1") == nil {
			t.Error("key1 should still exist after access")
		}

		// key2 should be evicted
		if cache.Get("key2") != nil {
			t.Error("key2 should have been evicted")
		}
	})

	t.Run("updating entry moves it to front", func(t *testing.T) {
		cache := NewTokenExchangeCacheWithMaxEntries(3)

		cache.Set("key1", "token1", TokenTypeAccessToken, 3600)
		cache.Set("key2", "token2", TokenTypeAccessToken, 3600)
		cache.Set("key3", "token3", TokenTypeAccessToken, 3600)

		// Update key1
		cache.Set("key1", "token1-updated", TokenTypeAccessToken, 3600)

		// Add 4th entry, should evict key2 (now least recently used)
		cache.Set("key4", "token4", TokenTypeAccessToken, 3600)

		if cache.Get("key1") == nil {
			t.Error("key1 should still exist after update")
		}
		if cache.Get("key1").AccessToken != "token1-updated" {
			t.Error("key1 should have updated value")
		}
		if cache.Get("key2") != nil {
			t.Error("key2 should have been evicted")
		}
	})
}

func TestTokenExchangeCache_GetStats(t *testing.T) {
	cache := NewTokenExchangeCacheWithMaxEntries(100)

	// Initial stats
	stats := cache.GetStats()
	if stats.CurrentEntries != 0 {
		t.Errorf("CurrentEntries = %d, want 0", stats.CurrentEntries)
	}
	if stats.MaxEntries != 100 {
		t.Errorf("MaxEntries = %d, want 100", stats.MaxEntries)
	}
	if stats.TotalEvictions != 0 {
		t.Errorf("TotalEvictions = %d, want 0", stats.TotalEvictions)
	}

	// Add some entries
	cache.Set("key1", "token1", TokenTypeAccessToken, 3600)
	cache.Set("key2", "token2", TokenTypeAccessToken, 3600)

	stats = cache.GetStats()
	if stats.CurrentEntries != 2 {
		t.Errorf("CurrentEntries = %d, want 2", stats.CurrentEntries)
	}
	if stats.MemoryPressure != 2.0 {
		t.Errorf("MemoryPressure = %f, want 2.0", stats.MemoryPressure)
	}
}

func TestTokenExchangeCache_UnlimitedMode(t *testing.T) {
	// maxEntries=0 means unlimited
	cache := NewTokenExchangeCacheWithMaxEntries(0)

	// Add many entries
	for i := 0; i < 100; i++ {
		cache.Set(GenerateCacheKey("endpoint", "connector", string(rune('a'+i%26))), "token", TokenTypeAccessToken, 3600)
	}

	// No evictions should occur
	stats := cache.GetStats()
	if stats.TotalEvictions != 0 {
		t.Errorf("TotalEvictions = %d, want 0 in unlimited mode", stats.TotalEvictions)
	}
}

func TestValidateResourceParameter(t *testing.T) {
	client := NewTokenExchangeClient(nil)

	t.Run("valid HTTPS resource", func(t *testing.T) {
		_, err := client.Exchange(t.Context(), TokenExchangeRequest{
			TokenEndpoint: "https://dex.example.com/token",
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
			Resource:      "https://api.example.com/v1",
		})
		// Will fail due to network, but should not fail on resource validation
		if err != nil && strings.Contains(err.Error(), "resource") {
			t.Errorf("Valid HTTPS resource should not fail validation: %v", err)
		}
	})

	t.Run("valid HTTP resource", func(t *testing.T) {
		_, err := client.Exchange(t.Context(), TokenExchangeRequest{
			TokenEndpoint: "https://dex.example.com/token",
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
			Resource:      "http://localhost:8080/api",
		})
		// Will fail due to network, but should not fail on resource validation
		if err != nil && strings.Contains(err.Error(), "resource") {
			t.Errorf("Valid HTTP resource should not fail validation: %v", err)
		}
	})

	t.Run("reject relative URI", func(t *testing.T) {
		_, err := client.Exchange(t.Context(), TokenExchangeRequest{
			TokenEndpoint: "https://dex.example.com/token",
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
			Resource:      "/api/v1",
		})
		if err == nil || !strings.Contains(err.Error(), "absolute URI") {
			t.Errorf("Relative URI should be rejected, got: %v", err)
		}
	})

	t.Run("reject non-http scheme", func(t *testing.T) {
		_, err := client.Exchange(t.Context(), TokenExchangeRequest{
			TokenEndpoint: "https://dex.example.com/token",
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
			Resource:      "ftp://files.example.com",
		})
		if err == nil || !strings.Contains(err.Error(), "HTTP or HTTPS") {
			t.Errorf("Non-HTTP scheme should be rejected, got: %v", err)
		}
	})

	t.Run("reject excessively long resource", func(t *testing.T) {
		longResource := "https://example.com/" + strings.Repeat("a", 2100)
		_, err := client.Exchange(t.Context(), TokenExchangeRequest{
			TokenEndpoint: "https://dex.example.com/token",
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
			Resource:      longResource,
		})
		if err == nil || !strings.Contains(err.Error(), "maximum length") {
			t.Errorf("Excessively long resource should be rejected, got: %v", err)
		}
	})

	t.Run("empty resource is allowed", func(t *testing.T) {
		_, err := client.Exchange(t.Context(), TokenExchangeRequest{
			TokenEndpoint: "https://dex.example.com/token",
			SubjectToken:  "test-token",
			ConnectorID:   "source-cluster",
			Resource:      "", // Empty is OK (optional field)
		})
		// Will fail due to network, but should not fail on resource validation
		if err != nil && strings.Contains(err.Error(), "resource") {
			t.Errorf("Empty resource should be allowed: %v", err)
		}
	})
}
