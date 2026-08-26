package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	// A token endpoint on a public address can present an internal-CA
	// certificate, so RootCAs must reach the transport on both dial postures.
	t.Run("RootCAs on every dial posture", func(t *testing.T) {
		pool := x509.NewCertPool()

		for _, allowPrivateIP := range []bool{false, true} {
			client := NewTokenExchangeClientWithOptions(TokenExchangeClientOptions{
				AllowPrivateIP: allowPrivateIP,
				RootCAs:        pool,
			})
			transport, ok := client.httpClient.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("expected *http.Transport, got %T", client.httpClient.Transport)
			}
			if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs != pool {
				t.Errorf("AllowPrivateIP=%v: expected the transport to verify against the supplied pool", allowPrivateIP)
			}
			if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
				t.Errorf("AllowPrivateIP=%v: InsecureSkipVerify must never be set", allowPrivateIP)
			}
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

	t.Run("client secret with special characters is RFC 6749 encoded", func(t *testing.T) {
		// Synthetic value containing the characters that x-www-form-urlencoded
		// mangles: "+" decodes to a space, "/" and "=" are otherwise
		// significant. This mirrors the shape of real base64-std client secrets
		// (e.g. Dex static clients) without embedding one.
		const wantClientValue = "aA0+bB1/cC2+dD3=="
		const wantClientID = "downstream-token-exchange-client"

		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate an RFC 6749 §2.3.1 compliant server (like Dex): the Basic
			// credential components are form-urlencoded, so the server must
			// url-unescape them before comparison.
			rawUser, rawPass, ok := r.BasicAuth()
			if !ok {
				t.Fatal("expected Basic authentication")
			}
			gotUser, err := url.QueryUnescape(rawUser)
			if err != nil {
				t.Fatalf("client id not url-decodable: %v", err)
			}
			gotPass, err := url.QueryUnescape(rawPass)
			if err != nil {
				t.Fatalf("client secret not url-decodable: %v", err)
			}
			if gotUser != wantClientID {
				t.Errorf("client id = %q, want %q", gotUser, wantClientID)
			}
			if gotPass != wantClientValue {
				t.Errorf("client secret = %q, want %q (mangled credential would fail client auth)", gotPass, wantClientValue)
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
			ClientID:      wantClientID,
			ClientSecret:  wantClientValue,
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

	t.Run("SECURITY: reject excessively long subject token", func(t *testing.T) {
		client := NewTokenExchangeClient(nil)
		// Create a subject token that exceeds the 64KB limit
		longToken := strings.Repeat("a", 65*1024) // 65KB
		_, err := client.Exchange(context.Background(), TokenExchangeRequest{
			TokenEndpoint: "https://example.com/token",
			SubjectToken:  longToken,
			ConnectorID:   "source-cluster",
		})

		if err == nil {
			t.Error("Exchange() should reject excessively long subject token")
		}
		if !strings.Contains(err.Error(), "maximum length") {
			t.Errorf("error should mention maximum length, got: %v", err)
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
