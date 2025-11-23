package oauth

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestNewHandler_WithGoogleCredentials(t *testing.T) {
	config := &Config{
		Resource: "https://mcp.example.com",
		GoogleAuth: GoogleAuthConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
		SupportedScopes: []string{
			"https://www.googleapis.com/auth/gmail.readonly",
		},
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	if !handler.CanRefreshTokens() {
		t.Error("Expected handler to support token refresh with Google credentials")
	}
}

func TestNewHandler_WithoutGoogleCredentials(t *testing.T) {
	config := &Config{
		Resource: "https://mcp.example.com",
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	if handler.CanRefreshTokens() {
		t.Error("Expected handler to not support token refresh without Google credentials")
	}
}

func TestNewHandler_WithRateLimiting(t *testing.T) {
	config := &Config{
		Resource: "https://mcp.example.com",
		RateLimit: RateLimitConfig{
			Rate:            10,
			Burst:           20,
			CleanupInterval: 5 * time.Minute,
			TrustProxy:      false,
		},
		GoogleAuth: GoogleAuthConfig{
			ClientID:     "test-id",
			ClientSecret: "test-secret",
		},
		CleanupInterval: 1 * time.Minute,
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	if handler.rateLimiter == nil {
		t.Error("Expected rate limiter to be initialized")
	}
}

func TestNewHandler_DefaultScopes(t *testing.T) {
	config := &Config{
		Resource: "https://mcp.example.com",
		// No scopes provided
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	cfg := handler.GetConfig()
	if len(cfg.SupportedScopes) == 0 {
		t.Error("Expected default scopes to be set")
	}

	// Check for some expected default scopes
	hasOpenID := false
	hasEmail := false
	for _, scope := range cfg.SupportedScopes {
		if scope == "openid" {
			hasOpenID = true
		}
		if scope == "email" {
			hasEmail = true
		}
	}

	if !hasOpenID {
		t.Error("Expected default scopes to include openid")
	}
	if !hasEmail {
		t.Error("Expected default scopes to include email")
	}
}

func TestNewHandler_CustomLogger(t *testing.T) {
	// Create a custom logger
	var buf bytes.Buffer
	customLogger := slog.New(slog.NewTextHandler(&buf, nil))

	config := &Config{
		Resource: "https://mcp.example.com",
		Logger:   customLogger,
	}

	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	if handler.logger != customLogger {
		t.Error("Expected handler to use custom logger")
	}
}

func TestHandler_RevokeToken(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// Add a token
	store := handler.GetStore()
	err = store.SaveGoogleToken("test@example.com", &oauth2.Token{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Revoke the token
	err = handler.RevokeToken("test@example.com")
	if err != nil {
		t.Errorf("RevokeToken() error = %v", err)
	}

	// Verify token is gone
	_, err = store.GetGoogleToken("test@example.com")
	if err == nil {
		t.Error("Expected error when getting revoked token")
	}
}

func TestHandler_ServeRevoke(t *testing.T) {
	handler, err := NewHandler(&Config{
		Resource: "https://mcp.example.com",
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// Add a token to revoke
	store := handler.GetStore()
	err = store.SaveGoogleToken("test@example.com", &oauth2.Token{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Test successful revocation
	t.Run("successful revocation", func(t *testing.T) {
		reqBody := map[string]string{"email": "test@example.com"}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.ServeRevoke(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("ServeRevoke() status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	// Test method not allowed
	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/revoke", nil)
		w := httptest.NewRecorder()

		handler.ServeRevoke(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("ServeRevoke() status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})

	// Test invalid request body
	t.Run("invalid request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", bytes.NewReader([]byte("invalid json")))
		w := httptest.NewRecorder()

		handler.ServeRevoke(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("ServeRevoke() status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	// Test missing email
	t.Run("missing email", func(t *testing.T) {
		reqBody := map[string]string{"email": ""}
		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.ServeRevoke(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("ServeRevoke() status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

func TestHandler_CanRefreshTokens(t *testing.T) {
	t.Run("with credentials", func(t *testing.T) {
		handler, _ := NewHandler(&Config{
			Resource: "https://mcp.example.com",
			GoogleAuth: GoogleAuthConfig{
				ClientID:     "test-id",
				ClientSecret: "test-secret",
			},
		})

		if !handler.CanRefreshTokens() {
			t.Error("Expected CanRefreshTokens() = true with credentials")
		}
	})

	t.Run("without credentials", func(t *testing.T) {
		handler, _ := NewHandler(&Config{
			Resource: "https://mcp.example.com",
		})

		if handler.CanRefreshTokens() {
			t.Error("Expected CanRefreshTokens() = false without credentials")
		}
	})

	t.Run("with partial credentials", func(t *testing.T) {
		handler, _ := NewHandler(&Config{
			Resource: "https://mcp.example.com",
			GoogleAuth: GoogleAuthConfig{
				ClientID: "test-id",
				// Missing ClientSecret
			},
		})

		if handler.CanRefreshTokens() {
			t.Error("Expected CanRefreshTokens() = false with partial credentials")
		}
	})
}
