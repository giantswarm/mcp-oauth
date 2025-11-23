package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestHandler_ValidateGoogleToken_MissingHeader(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	wrappedHandler := handler.ValidateGoogleToken(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("ValidateGoogleToken() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	// Check WWW-Authenticate header
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("ValidateGoogleToken() should set WWW-Authenticate header")
	}
}

func TestHandler_ValidateGoogleToken_InvalidFormat(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	wrappedHandler := handler.ValidateGoogleToken(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("ValidateGoogleToken() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}

	// Check WWW-Authenticate header
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Error("ValidateGoogleToken() should set WWW-Authenticate header")
	}
}

func TestHandler_ValidateGoogleToken_InvalidToken(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	wrappedHandler := handler.ValidateGoogleToken(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("ValidateGoogleToken() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandler_OptionalGoogleToken_NoToken(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := handler.OptionalGoogleToken(testHandler)

	// Test without token (should succeed)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("OptionalGoogleToken() without token status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandler_ValidateGoogleTokenFunc(t *testing.T) {
	handler, _ := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called without valid token")
	})

	wrappedHandler := handler.ValidateGoogleTokenFunc(testHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	wrappedHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("ValidateGoogleTokenFunc() status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestGetUserFromContext(t *testing.T) {
	// Test with empty context (should not panic)
	ctx := context.Background()
	user, ok := GetUserFromContext(ctx)
	if ok {
		t.Error("GetUserFromContext() should return false for empty context")
	}
	if user != nil {
		t.Error("GetUserFromContext() should return nil user for empty context")
	}
}

func TestGetGoogleTokenFromContext(t *testing.T) {
	// Test with empty context (should not panic)
	ctx := context.Background()
	token, ok := GetGoogleTokenFromContext(ctx)
	if ok {
		t.Error("GetGoogleTokenFromContext() should return false for empty context")
	}
	if token != nil {
		t.Error("GetGoogleTokenFromContext() should return nil token for empty context")
	}
}

func TestHandler_CacheGoogleToken(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	token := &oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	// Cache a token
	if err := handler.CacheGoogleToken("user@example.com", token); err != nil {
		t.Fatalf("CacheGoogleToken() error = %v", err)
	}

	// Verify it can be retrieved
	retrieved, err := handler.GetCachedGoogleToken("user@example.com")
	if err != nil {
		t.Fatalf("GetCachedGoogleToken() error = %v", err)
	}

	if retrieved.AccessToken != token.AccessToken {
		t.Errorf("GetCachedGoogleToken() AccessToken = %s, want %s", retrieved.AccessToken, token.AccessToken)
	}
}

func TestHandler_GetCachedGoogleToken_NotFound(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	_, err = handler.GetCachedGoogleToken("nonexistent@example.com")
	if err == nil {
		t.Error("GetCachedGoogleToken() for non-existent user should return error")
	}
}

func TestHandler_OptionalGoogleToken_InvalidToken(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called with invalid token")
	})

	wrappedHandler := handler.OptionalGoogleToken(testHandler)

	// Test with invalid token (should fail)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("OptionalGoogleToken() with invalid token status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandler_OptionalGoogleToken_InvalidFormat(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called with invalid format")
	})

	wrappedHandler := handler.OptionalGoogleToken(testHandler)

	// Test with invalid format
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("OptionalGoogleToken() with invalid format status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
