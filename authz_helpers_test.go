package oauth

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// testLogger creates a logger for testing
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Quiet during tests
	}))
}

func TestParseAuthCodeRequest(t *testing.T) {
	tests := []struct {
		name        string
		formValues  map[string]string
		wantErr     bool
		wantErrCode string
	}{
		{
			name: "valid request",
			formValues: map[string]string{
				"code":          "test-code",
				"redirect_uri":  "https://example.com/callback",
				"client_id":     "test-client",
				"code_verifier": "test-verifier",
			},
			wantErr: false,
		},
		{
			name: "missing code",
			formValues: map[string]string{
				"redirect_uri": "https://example.com/callback",
			},
			wantErr:     true,
			wantErrCode: "invalid_request",
		},
		{
			name: "optional parameters missing",
			formValues: map[string]string{
				"code": "test-code",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token", nil)
			req.Form = make(map[string][]string)
			for k, v := range tt.formValues {
				req.Form.Set(k, v)
			}

			h := &Handler{}
			params, err := h.parseAuthCodeRequest(req)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if err.Code != tt.wantErrCode {
					t.Errorf("error code = %v, want %v", err.Code, tt.wantErrCode)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if params.Code != tt.formValues["code"] {
					t.Errorf("code = %v, want %v", params.Code, tt.formValues["code"])
				}
			}
		})
	}
}

func TestValidateAndRetrieveAuthCode(t *testing.T) {
	logger := testLogger()
	flowStore := NewFlowStore(logger)

	// Create a test authorization code
	authCode := &AuthorizationCode{
		Code:        "test-code",
		ClientID:    "test-client",
		RedirectURI: "https://example.com/callback",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
	}
	flowStore.SaveAuthorizationCode(authCode)

	h := &Handler{
		flowStore: flowStore,
		logger:    logger,
	}

	tests := []struct {
		name        string
		params      *authCodeRequest
		wantErr     bool
		wantErrCode string
	}{
		{
			name: "valid auth code",
			params: &authCodeRequest{
				Code:        "test-code",
				RedirectURI: "https://example.com/callback",
				ClientID:    "test-client",
			},
			wantErr: false,
		},
		{
			name: "invalid code",
			params: &authCodeRequest{
				Code:        "invalid-code",
				RedirectURI: "https://example.com/callback",
				ClientID:    "test-client",
			},
			wantErr:     true,
			wantErrCode: "invalid_grant",
		},
		{
			name: "redirect uri mismatch",
			params: &authCodeRequest{
				Code:        "test-code-2",
				RedirectURI: "https://wrong.com/callback",
				ClientID:    "test-client",
			},
			wantErr:     true,
			wantErrCode: "invalid_grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Re-save for each test since GetAuthorizationCode deletes it
			if tt.params.Code == "test-code" {
				authCode.Code = "test-code"
				flowStore.SaveAuthorizationCode(authCode)
			} else if tt.params.Code == "test-code-2" {
				authCode2 := &AuthorizationCode{
					Code:        "test-code-2",
					ClientID:    "test-client",
					RedirectURI: "https://example.com/callback",
					Scope:       "openid",
					ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
				}
				flowStore.SaveAuthorizationCode(authCode2)
			}

			_, err := h.validateAndRetrieveAuthCode(tt.params)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if err.Code != tt.wantErrCode {
					t.Errorf("error code = %v, want %v", err.Code, tt.wantErrCode)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidatePKCE(t *testing.T) {
	logger := testLogger()
	h := &Handler{logger: logger}

	tests := []struct {
		name         string
		authCode     *AuthorizationCode
		codeVerifier string
		clientID     string
		wantErr      bool
		wantErrCode  string
	}{
		{
			name: "valid S256 PKCE",
			authCode: &AuthorizationCode{
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", // SHA256 of "test-verifier"
				CodeChallengeMethod: "S256",
			},
			codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", // 43 chars
			clientID:     "test-client",
			wantErr:      false,
		},
		{
			name: "no PKCE required",
			authCode: &AuthorizationCode{
				CodeChallenge: "",
			},
			codeVerifier: "",
			clientID:     "test-client",
			wantErr:      false,
		},
		{
			name: "missing code verifier",
			authCode: &AuthorizationCode{
				CodeChallenge:       "test-challenge",
				CodeChallengeMethod: "S256",
			},
			codeVerifier: "",
			clientID:     "test-client",
			wantErr:      true,
			wantErrCode:  "invalid_request",
		},
		{
			name: "verifier too short",
			authCode: &AuthorizationCode{
				CodeChallenge:       "test-challenge",
				CodeChallengeMethod: "S256",
			},
			codeVerifier: "short",
			clientID:     "test-client",
			wantErr:      true,
			wantErrCode:  "invalid_request",
		},
		{
			name: "invalid characters in verifier",
			authCode: &AuthorizationCode{
				CodeChallenge:       "test-challenge",
				CodeChallengeMethod: "S256",
			},
			codeVerifier: "invalid!@#$%^&*()characters-that-are-super-long-enough",
			clientID:     "test-client",
			wantErr:      true,
			wantErrCode:  "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.validatePKCE(tt.authCode, tt.codeVerifier, tt.clientID)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if err.Code != tt.wantErrCode {
					t.Errorf("error code = %v, want %v", err.Code, tt.wantErrCode)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAuthenticateClient(t *testing.T) {
	logger := testLogger()
	clientStore := NewClientStore(logger)

	// Register test clients
	confidentialClient, _ := clientStore.RegisterClient(&ClientRegistrationRequest{
		ClientName:              "Confidential Client",
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ClientType:              "confidential",
	}, "127.0.0.1")

	publicClient, _ := clientStore.RegisterClient(&ClientRegistrationRequest{
		ClientName:              "Public Client",
		RedirectURIs:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "none",
		ClientType:              "public",
	}, "127.0.0.1")

	h := &Handler{
		clientStore: clientStore,
		logger:      logger,
	}

	tests := []struct {
		name        string
		req         *http.Request
		clientID    string
		wantErr     bool
		wantErrCode string
	}{
		{
			name: "public client - no auth required",
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/token", nil)
				return req
			}(),
			clientID: publicClient.ClientID,
			wantErr:  false,
		},
		{
			name: "confidential client - valid basic auth",
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/token", nil)
				req.SetBasicAuth(confidentialClient.ClientID, confidentialClient.ClientSecret)
				return req
			}(),
			clientID: confidentialClient.ClientID,
			wantErr:  false,
		},
		{
			name: "confidential client - invalid secret",
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/token", nil)
				req.SetBasicAuth(confidentialClient.ClientID, "wrong-secret")
				return req
			}(),
			clientID:    confidentialClient.ClientID,
			wantErr:     true,
			wantErrCode: "invalid_client",
		},
		{
			name: "invalid client id",
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/token", nil)
				return req
			}(),
			clientID:    "invalid-client",
			wantErr:     true,
			wantErrCode: "invalid_client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.authenticateClient(tt.req, tt.clientID)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if err.Code != tt.wantErrCode {
					t.Errorf("error code = %v, want %v", err.Code, tt.wantErrCode)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestEnsureFreshGoogleToken(t *testing.T) {
	logger := testLogger()
	h := &Handler{
		logger: logger,
	}

	tests := []struct {
		name        string
		authCode    *AuthorizationCode
		wantErr     bool
		wantErrCode string
	}{
		{
			name: "token not expired",
			authCode: &AuthorizationCode{
				GoogleAccessToken:  "valid-token",
				GoogleRefreshToken: "refresh-token",
				GoogleTokenExpiry:  time.Now().Add(1 * time.Hour).Unix(),
				UserEmail:          "test@example.com",
			},
			wantErr: false,
		},
		{
			name: "token expired without refresh",
			authCode: &AuthorizationCode{
				GoogleAccessToken:  "expired-token",
				GoogleRefreshToken: "",
				GoogleTokenExpiry:  time.Now().Add(-1 * time.Hour).Unix(),
				UserEmail:          "test@example.com",
			},
			wantErr:     true,
			wantErrCode: "invalid_grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := h.ensureFreshGoogleToken(context.Background(), tt.authCode)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if err.Code != tt.wantErrCode {
					t.Errorf("error code = %v, want %v", err.Code, tt.wantErrCode)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if token == nil {
					t.Fatal("expected token but got nil")
				}
			}
		})
	}
}

func TestStoreTokens(t *testing.T) {
	logger := testLogger()
	store := NewStore()
	store.SetLogger(logger)

	h := &Handler{
		store:  store,
		logger: logger,
	}

	authCode := &AuthorizationCode{
		UserEmail: "test@example.com",
	}

	googleToken := &oauth2.Token{
		AccessToken:  "google-access-token",
		RefreshToken: "google-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	accessToken := "access-token"

	oauthErr := h.storeTokens(authCode, googleToken, accessToken)
	if oauthErr != nil {
		t.Fatalf("unexpected error: %v", oauthErr)
	}

	// Verify token was stored by email
	storedToken, err := store.GetGoogleToken(authCode.UserEmail)
	if err != nil {
		t.Fatalf("failed to retrieve token by email: %v", err)
	}
	if storedToken.AccessToken != googleToken.AccessToken {
		t.Errorf("stored token access token = %v, want %v", storedToken.AccessToken, googleToken.AccessToken)
	}

	// Verify token was stored by access token
	storedToken2, err := store.GetGoogleToken(accessToken)
	if err != nil {
		t.Fatalf("failed to retrieve token by access token: %v", err)
	}
	if storedToken2.AccessToken != googleToken.AccessToken {
		t.Errorf("stored token2 access token = %v, want %v", storedToken2.AccessToken, googleToken.AccessToken)
	}
}

func TestIssueRefreshToken(t *testing.T) {
	logger := testLogger()
	store := NewStore()
	store.SetLogger(logger)

	h := &Handler{
		store:  store,
		logger: logger,
		config: &Config{
			Security: SecurityConfig{
				RefreshTokenTTL: 90 * 24 * time.Hour,
			},
		},
	}

	tests := []struct {
		name     string
		authCode *AuthorizationCode
		wantNil  bool
	}{
		{
			name: "with Google refresh token",
			authCode: &AuthorizationCode{
				GoogleRefreshToken: "google-refresh-token",
				UserEmail:          "test@example.com",
			},
			wantNil: false,
		},
		{
			name: "without Google refresh token",
			authCode: &AuthorizationCode{
				GoogleRefreshToken: "",
				UserEmail:          "test@example.com",
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refreshToken, err := h.issueRefreshToken(tt.authCode)

			if tt.wantNil {
				if refreshToken != "" {
					t.Errorf("expected empty refresh token but got %v", refreshToken)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if refreshToken == "" {
					t.Fatal("expected refresh token but got empty string")
				}

				// Verify token was stored
				email, err := store.GetRefreshToken(refreshToken)
				if err != nil {
					t.Fatalf("failed to retrieve refresh token: %v", err)
				}
				if email != tt.authCode.UserEmail {
					t.Errorf("stored email = %v, want %v", email, tt.authCode.UserEmail)
				}
			}
		})
	}
}
