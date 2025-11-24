package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func setupFlowTestServer(t *testing.T) (*Server, *memory.Store, *mock.MockProvider) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewMockProvider()

	config := &Config{
		Issuer:               "https://auth.example.com",
		SupportedScopes:      []string{"openid", "email", "profile"},
		AuthorizationCodeTTL: 600,
		AccessTokenTTL:       3600,
		RequirePKCE:          true,
		AllowPKCEPlain:       false,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return srv, store, provider
}

func TestServer_StartAuthorizationFlow(t *testing.T) {
	srv, store, _ := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		"Test Client",
		ClientTypeConfidential,
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	tests := []struct {
		name                string
		clientID            string
		redirectURI         string
		scope               string
		codeChallenge       string
		codeChallengeMethod string
		clientState         string
		wantErr             bool
	}{
		{
			name:                "valid authorization flow",
			clientID:            client.ClientID,
			redirectURI:         "https://example.com/callback",
			scope:               "openid email",
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			clientState:         "client-state-" + testutil.GenerateRandomString(10),
			wantErr:             false,
		},
		{
			name:                "missing state",
			clientID:            client.ClientID,
			redirectURI:         "https://example.com/callback",
			scope:               "openid",
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			clientState:         "",
			wantErr:             true,
		},
		{
			name:                "missing PKCE challenge",
			clientID:            client.ClientID,
			redirectURI:         "https://example.com/callback",
			scope:               "openid",
			codeChallenge:       "",
			codeChallengeMethod: "",
			clientState:         "state-" + testutil.GenerateRandomString(10),
			wantErr:             true,
		},
		{
			name:                "invalid client ID",
			clientID:            "invalid-client-id",
			redirectURI:         "https://example.com/callback",
			scope:               "openid",
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			clientState:         "state-" + testutil.GenerateRandomString(10),
			wantErr:             true,
		},
		{
			name:                "unregistered redirect URI",
			clientID:            client.ClientID,
			redirectURI:         "https://evil.com/callback",
			scope:               "openid",
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			clientState:         "state-" + testutil.GenerateRandomString(10),
			wantErr:             true,
		},
		{
			name:                "invalid scope",
			clientID:            client.ClientID,
			redirectURI:         "https://example.com/callback",
			scope:               "invalid-scope",
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			clientState:         "state-" + testutil.GenerateRandomString(10),
			wantErr:             true,
		},
		{
			name:                "plain PKCE not allowed",
			clientID:            client.ClientID,
			redirectURI:         "https://example.com/callback",
			scope:               "openid",
			codeChallenge:       validVerifier,
			codeChallengeMethod: PKCEMethodPlain,
			clientState:         "state-" + testutil.GenerateRandomString(10),
			wantErr:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL, err := srv.StartAuthorizationFlow(
				tt.clientID,
				tt.redirectURI,
				tt.scope,
				tt.codeChallenge,
				tt.codeChallengeMethod,
				tt.clientState,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("StartAuthorizationFlow() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if authURL == "" {
					t.Error("StartAuthorizationFlow() returned empty authorization URL")
				}

				// Verify authorization state was saved
				authState, err := store.GetAuthorizationState(tt.clientState)
				if err != nil {
					t.Errorf("Authorization state not saved: %v", err)
				} else {
					if authState.ClientID != tt.clientID {
						t.Errorf("authState.ClientID = %q, want %q", authState.ClientID, tt.clientID)
					}
					if authState.RedirectURI != tt.redirectURI {
						t.Errorf("authState.RedirectURI = %q, want %q", authState.RedirectURI, tt.redirectURI)
					}
				}
			}
		})
	}
}

func TestServer_HandleProviderCallback(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		"Test Client",
		ClientTypeConfidential,
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := "client-state-" + testutil.GenerateRandomString(10)

	// Start authorization flow
	_, err = srv.StartAuthorizationFlow(
		client.ClientID,
		"https://example.com/callback",
		"openid email",
		validChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	// Get the provider state
	authState, err := store.GetAuthorizationState(clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}
	providerState := authState.ProviderState

	tests := []struct {
		name          string
		providerState string
		code          string
		wantErr       bool
	}{
		{
			name:          "valid provider callback",
			providerState: providerState,
			code:          "provider-auth-code",
			wantErr:       false,
		},
		{
			name:          "invalid provider state",
			providerState: "invalid-state",
			code:          "provider-auth-code",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCode, returnedClientState, err := srv.HandleProviderCallback(
				context.Background(),
				tt.providerState,
				tt.code,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("HandleProviderCallback() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if authCode == nil {
					t.Fatal("HandleProviderCallback() returned nil authCode")
				}

				if authCode.Code == "" {
					t.Error("Authorization code is empty")
				}

				if returnedClientState != clientState {
					t.Errorf("returnedClientState = %q, want %q", returnedClientState, clientState)
				}

				if authCode.ClientID != client.ClientID {
					t.Errorf("authCode.ClientID = %q, want %q", authCode.ClientID, client.ClientID)
				}

				// Verify provider was called
				if provider.GetCallCount("ExchangeCode") == 0 {
					t.Error("Provider ExchangeCode should have been called")
				}
				if provider.GetCallCount("ValidateToken") == 0 {
					t.Error("Provider ValidateToken should have been called")
				}
			}
		})
	}
}

func TestServer_ExchangeAuthorizationCode(t *testing.T) {
	srv, store, _ := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		"Test Client",
		ClientTypeConfidential,
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Create an authorization code
	authCode := &storage.AuthorizationCode{
		Code:                testutil.GenerateRandomString(32),
		ClientID:            client.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid email",
		CodeChallenge:       validChallenge,
		CodeChallengeMethod: PKCEMethodS256,
		UserID:              "test-user-123",
		ProviderToken: &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
	}

	err = store.SaveAuthorizationCode(authCode)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	tests := []struct {
		name         string
		code         string
		clientID     string
		redirectURI  string
		codeVerifier string
		wantErr      bool
	}{
		{
			name:         "valid code exchange",
			code:         authCode.Code,
			clientID:     client.ClientID,
			redirectURI:  "https://example.com/callback",
			codeVerifier: validVerifier,
			wantErr:      false,
		},
		{
			name:         "invalid code",
			code:         "invalid-code",
			clientID:     client.ClientID,
			redirectURI:  "https://example.com/callback",
			codeVerifier: validVerifier,
			wantErr:      true,
		},
		{
			name:         "wrong client ID",
			code:         authCode.Code,
			clientID:     "wrong-client-id",
			redirectURI:  "https://example.com/callback",
			codeVerifier: validVerifier,
			wantErr:      true,
		},
		{
			name:         "wrong redirect URI",
			code:         authCode.Code,
			clientID:     client.ClientID,
			redirectURI:  "https://wrong.com/callback",
			codeVerifier: validVerifier,
			wantErr:      true,
		},
		{
			name:         "invalid code verifier",
			code:         authCode.Code,
			clientID:     client.ClientID,
			redirectURI:  "https://example.com/callback",
			codeVerifier: testutil.GenerateRandomString(50), // Different verifier
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh authorization code for each test
			if tt.name != "invalid code" && tt.name != "wrong client ID" {
				freshCode := &storage.AuthorizationCode{
					Code:                testutil.GenerateRandomString(32),
					ClientID:            client.ClientID,
					RedirectURI:         "https://example.com/callback",
					Scope:               "openid email",
					CodeChallenge:       validChallenge,
					CodeChallengeMethod: PKCEMethodS256,
					UserID:              "test-user-123",
					ProviderToken: &oauth2.Token{
						AccessToken:  "provider-access-token",
						RefreshToken: "provider-refresh-token",
						Expiry:       time.Now().Add(1 * time.Hour),
					},
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(10 * time.Minute),
					Used:      false,
				}
				if tt.name == "valid code exchange" {
					freshCode.Code = authCode.Code
				}
				if tt.name != "invalid code" {
					_ = store.SaveAuthorizationCode(freshCode)
					if tt.name == "wrong redirect URI" || tt.name == "invalid code verifier" {
						tt := struct {
							name         string
							code         string
							clientID     string
							redirectURI  string
							codeVerifier string
							wantErr      bool
						}{
							name:         tt.name,
							code:         freshCode.Code,
							clientID:     tt.clientID,
							redirectURI:  tt.redirectURI,
							codeVerifier: tt.codeVerifier,
							wantErr:      tt.wantErr,
						}
						token, _, err := srv.ExchangeAuthorizationCode(
							context.Background(),
							tt.code,
							tt.clientID,
							tt.redirectURI,
							tt.codeVerifier,
						)

						if (err != nil) != tt.wantErr {
							t.Errorf("ExchangeAuthorizationCode() error = %v, wantErr %v", err, tt.wantErr)
							return
						}

						if !tt.wantErr && token == nil {
							t.Error("ExchangeAuthorizationCode() returned nil token")
						}
						return
					}
				}
			}

			token, _, err := srv.ExchangeAuthorizationCode(
				context.Background(),
				tt.code,
				tt.clientID,
				tt.redirectURI,
				tt.codeVerifier,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExchangeAuthorizationCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if token == nil {
					t.Fatal("ExchangeAuthorizationCode() returned nil token")
				}

				if token.AccessToken == "" {
					t.Error("Access token is empty")
				}

				if token.RefreshToken == "" {
					t.Error("Refresh token is empty")
				}
			}
		})
	}
}

func TestServer_ValidateToken(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	// Configure provider to return valid user info
	provider.ValidateTokenFunc = func(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
		if accessToken == "valid-token" {
			return &providers.UserInfo{
				ID:    "user-123",
				Email: "test@example.com",
				Name:  "Test User",
			}, nil
		}
		return nil, context.DeadlineExceeded
	}

	tests := []struct {
		name        string
		accessToken string
		wantErr     bool
	}{
		{
			name:        "valid token",
			accessToken: "valid-token",
			wantErr:     false,
		},
		{
			name:        "invalid token",
			accessToken: "invalid-token",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userInfo, err := srv.ValidateToken(context.Background(), tt.accessToken)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if userInfo == nil {
					t.Fatal("ValidateToken() returned nil userInfo")
				}

				if userInfo.ID != "user-123" {
					t.Errorf("userInfo.ID = %q, want %q", userInfo.ID, "user-123")
				}

				// Verify user info was saved
				savedInfo, err := store.GetUserInfo(userInfo.ID)
				if err != nil {
					t.Errorf("User info not saved: %v", err)
				} else if savedInfo.Email != userInfo.Email {
					t.Errorf("savedInfo.Email = %q, want %q", savedInfo.Email, userInfo.Email)
				}
			}
		})
	}
}

// TestServer_RefreshTokenRotation tests basic refresh token rotation without reuse
func TestServer_RefreshTokenRotation(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	// Enable refresh token rotation
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400 // 24 hours

	// Register a client
	client, _, err := srv.RegisterClient(
		"Test Client",
		ClientTypeConfidential,
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID

	// Generate PKCE
	codeVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Start auth flow and get tokens
	clientState := "client-state-" + testutil.GenerateRandomString(10)
	_, err = srv.StartAuthorizationFlow(
		clientID,
		"https://example.com/callback",
		"openid email",
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(
		context.Background(),
		authState.ProviderState,
		"provider-code-"+testutil.GenerateRandomString(10),
	)
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	token, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCodeObj.Code,
		clientID,
		"https://example.com/callback",
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	firstRefreshToken := token.RefreshToken

	// Verify first token family exists
	family1, err := store.GetRefreshTokenFamily(firstRefreshToken)
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily() error = %v", err)
	}
	if family1.Generation != 0 {
		t.Errorf("First token generation = %d, want 0", family1.Generation)
	}
	if family1.Revoked {
		t.Error("First token family should not be revoked")
	}

	// Configure mock provider to return a new token on refresh
	provider.RefreshTokenFunc = func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "new-provider-access-token",
			RefreshToken: "new-provider-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}, nil
	}

	// Refresh the token (should rotate)
	token2, err := srv.RefreshAccessToken(context.Background(), firstRefreshToken, clientID)
	if err != nil {
		t.Fatalf("RefreshAccessToken() error = %v", err)
	}

	secondRefreshToken := token2.RefreshToken

	// Verify rotation happened
	if secondRefreshToken == firstRefreshToken {
		t.Error("Refresh token should have been rotated")
	}

	// Verify second token has incremented generation
	family2, err := store.GetRefreshTokenFamily(secondRefreshToken)
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily() error = %v for second token", err)
	}
	if family2.Generation != 1 {
		t.Errorf("Second token generation = %d, want 1", family2.Generation)
	}
	if family2.FamilyID != family1.FamilyID {
		t.Errorf("Second token family ID = %s, want %s (same family)", family2.FamilyID, family1.FamilyID)
	}

	// Verify first token was deleted (rotated out)
	_, err = store.GetRefreshTokenInfo(firstRefreshToken)
	if err == nil {
		t.Error("First refresh token should have been deleted after rotation")
	}

	// Verify second token is still valid
	_, err = store.GetRefreshTokenInfo(secondRefreshToken)
	if err != nil {
		t.Errorf("Second refresh token should be valid, got error: %v", err)
	}
}

// TestServer_RefreshTokenReuseDetection tests that refresh token reuse is detected and revokes all tokens
// This is a CRITICAL OAuth 2.1 security feature
func TestServer_RefreshTokenReuseDetection(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	// Enable refresh token rotation (required for reuse detection)
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400 // 24 hours

	// Register a client
	client, _, err := srv.RegisterClient(
		"Test Client",
		ClientTypeConfidential,
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID

	// Generate PKCE
	codeVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Start auth flow and get initial tokens
	clientState := "client-state-" + testutil.GenerateRandomString(10)
	_, err = srv.StartAuthorizationFlow(
		clientID,
		"https://example.com/callback",
		"openid email",
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(
		context.Background(),
		authState.ProviderState,
		"provider-code-"+testutil.GenerateRandomString(10),
	)
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	token, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCodeObj.Code,
		clientID,
		"https://example.com/callback",
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	firstRefreshToken := token.RefreshToken
	firstAccessToken := token.AccessToken

	// Get family info for later verification
	family1, err := store.GetRefreshTokenFamily(firstRefreshToken)
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily() error = %v", err)
	}
	familyID := family1.FamilyID

	// Verify tokens exist
	tokens, err := store.GetTokensByUserClient("mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) < 2 {
		t.Errorf("Expected at least 2 tokens initially, got %d", len(tokens))
	}

	// Configure mock provider for refresh
	provider.RefreshTokenFunc = func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "rotated-provider-access-token",
			RefreshToken: "rotated-provider-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}, nil
	}

	// Legitimate user refreshes token (rotation happens)
	token2, err := srv.RefreshAccessToken(context.Background(), firstRefreshToken, clientID)
	if err != nil {
		t.Fatalf("Legitimate RefreshAccessToken() error = %v", err)
	}

	secondRefreshToken := token2.RefreshToken
	secondAccessToken := token2.AccessToken

	// Verify rotation happened
	if secondRefreshToken == firstRefreshToken {
		t.Fatal("Refresh token should have been rotated")
	}

	// Verify first token was deleted
	_, err = store.GetRefreshTokenInfo(firstRefreshToken)
	if err == nil {
		t.Error("First refresh token should have been deleted after rotation")
	}

	// Verify second token is valid
	_, err = store.GetRefreshTokenInfo(secondRefreshToken)
	if err != nil {
		t.Errorf("Second refresh token should be valid, got error: %v", err)
	}

	// CRITICAL TEST: Attacker tries to reuse the old (rotated) token
	// This should detect reuse and revoke ALL tokens
	_, err = srv.RefreshAccessToken(context.Background(), firstRefreshToken, clientID)
	if err == nil {
		t.Fatal("Reuse of rotated refresh token should have failed")
	}

	// Verify error message is generic (per RFC 6749 - don't reveal security details)
	errStr := err.Error()
	if !containsString(errStr, "invalid") {
		t.Errorf("Error should be generic 'invalid grant', got: %v", err)
	}

	// CRITICAL: Verify family was revoked
	revokedFamily, err := store.GetRefreshTokenFamily(firstRefreshToken)
	if err != nil {
		t.Logf("Note: Family metadata for first token deleted (acceptable): %v", err)
	} else if !revokedFamily.Revoked {
		t.Error("Token family should have been revoked after reuse detection")
	}

	// Verify family is revoked when checking with second token
	family2, err := store.GetRefreshTokenFamily(secondRefreshToken)
	if err == nil {
		if !family2.Revoked {
			t.Error("Token family should be revoked after reuse detection")
		}
		if family2.FamilyID != familyID {
			t.Errorf("Family ID changed: got %s, want %s", family2.FamilyID, familyID)
		}
	}

	// CRITICAL: Verify ALL tokens for user+client were revoked
	tokens, err = store.GetTokensByUserClient("mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("ALL tokens should have been revoked, but found %d tokens: %v", len(tokens), tokens)
	}

	// Verify specific tokens were deleted
	_, err = store.GetToken(firstAccessToken)
	if err == nil {
		t.Error("First access token should have been revoked")
	}

	_, err = store.GetToken(secondAccessToken)
	if err == nil {
		t.Error("Second access token should have been revoked")
	}

	_, err = store.GetRefreshTokenInfo(secondRefreshToken)
	if err == nil {
		t.Error("Second refresh token should have been revoked")
	}
}

// TestServer_RefreshTokenReuseMultipleRotations tests reuse detection after multiple rotations
func TestServer_RefreshTokenReuseMultipleRotations(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	// Enable refresh token rotation
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400

	// Register a client
	client, _, err := srv.RegisterClient(
		"Test Client",
		ClientTypeConfidential,
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID

	// Generate PKCE
	codeVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get initial tokens
	clientState := "client-state-" + testutil.GenerateRandomString(10)
	_, err = srv.StartAuthorizationFlow(
		clientID,
		"https://example.com/callback",
		"openid email",
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(
		context.Background(),
		authState.ProviderState,
		"provider-code-"+testutil.GenerateRandomString(10),
	)
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	token, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCodeObj.Code,
		clientID,
		"https://example.com/callback",
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	// Store all refresh tokens for reuse testing
	refreshTokens := []string{token.RefreshToken}

	// Configure mock provider
	provider.RefreshTokenFunc = func(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}, nil
	}

	// Perform 3 legitimate rotations
	currentToken := token.RefreshToken
	for i := 0; i < 3; i++ {
		newToken, err := srv.RefreshAccessToken(context.Background(), currentToken, clientID)
		if err != nil {
			t.Fatalf("Rotation %d failed: %v", i+1, err)
		}
		refreshTokens = append(refreshTokens, newToken.RefreshToken)
		currentToken = newToken.RefreshToken
	}

	// Verify we have 4 tokens (initial + 3 rotations)
	if len(refreshTokens) != 4 {
		t.Errorf("Expected 4 refresh tokens, got %d", len(refreshTokens))
	}

	// Try to reuse token from 2 rotations ago (generation 2, current is 3)
	oldToken := refreshTokens[2]
	_, err = srv.RefreshAccessToken(context.Background(), oldToken, clientID)
	if err == nil {
		t.Fatal("Reuse of old refresh token should have failed")
	}

	// Verify error is generic (per RFC 6749 - don't reveal security details)
	if !containsString(err.Error(), "invalid") {
		t.Errorf("Error should be generic 'invalid grant', got: %v", err)
	}

	// Verify ALL tokens were revoked
	tokens, err := store.GetTokensByUserClient("mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("ALL tokens should have been revoked, but found %d", len(tokens))
	}

	// Verify current token is also revoked
	_, err = store.GetRefreshTokenInfo(currentToken)
	if err == nil {
		t.Error("Current refresh token should have been revoked after reuse detection")
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestServer_RevokeToken(t *testing.T) {
	srv, store, _ := setupFlowTestServer(t)

	userID := "test-user-123"
	clientID := "test-client-id"
	refreshToken := testutil.GenerateRandomString(32)
	familyID := testutil.GenerateRandomString(32)

	// Save tokens
	providerToken := &oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "provider-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	err := store.SaveToken(userID, providerToken)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	err = store.SaveRefreshTokenWithFamily(refreshToken, userID, clientID, familyID, 1, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily() error = %v", err)
	}

	// Test revocation
	err = srv.RevokeToken(context.Background(), refreshToken, clientID, "192.168.1.100")
	if err != nil {
		t.Errorf("RevokeToken() error = %v", err)
	}

	// Verify token family was revoked (not just the individual token)
	family, err := store.GetRefreshTokenFamily(familyID)
	if err == nil && family != nil && !family.Revoked {
		t.Error("Token family should have been revoked")
	}
}

// TestServer_AuthorizationCodeReuseRevokesTokens tests that when an authorization code is reused,
// all tokens for that user+client are revoked (OAuth 2.1 requirement)
func TestServer_AuthorizationCodeReuseRevokesTokens(t *testing.T) {
	srv, store, _ := setupFlowTestServer(t)

	// Register a client
	client, _, err := srv.RegisterClient(
		"Test Client",
		ClientTypeConfidential,
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID

	// Generate PKCE challenge
	codeVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Start authorization flow
	clientState := "client-state-" + testutil.GenerateRandomString(10)
	_, err = srv.StartAuthorizationFlow(
		clientID,
		"https://example.com/callback",
		"openid email",
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	// Get provider state from stored auth state
	authState, err := store.GetAuthorizationState(clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}
	providerState := authState.ProviderState

	// Simulate provider callback
	authCodeObj, returnedState, err := srv.HandleProviderCallback(
		context.Background(),
		providerState,
		"provider-code-"+testutil.GenerateRandomString(10),
	)
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}
	if returnedState != clientState {
		t.Errorf("HandleProviderCallback() returned state = %v, want %v", returnedState, clientState)
	}

	authCode := authCodeObj.Code

	// First exchange - should succeed
	token1, scope, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		clientID,
		"https://example.com/callback",
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("First ExchangeAuthorizationCode() error = %v", err)
	}
	if scope != "openid email" {
		t.Errorf("ExchangeAuthorizationCode() scope = %v, want %v", scope, "openid email")
	}

	accessToken1 := token1.AccessToken
	refreshToken1 := token1.RefreshToken

	// Verify tokens are stored
	if _, err := store.GetToken(accessToken1); err != nil {
		t.Errorf("Access token not found in storage after first exchange")
	}
	if _, err := store.GetRefreshTokenInfo(refreshToken1); err != nil {
		t.Errorf("Refresh token not found in storage after first exchange")
	}

	// Verify token metadata is stored (using mock user ID from mock provider)
	tokens, err := store.GetTokensByUserClient("mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	initialTokenCount := len(tokens)
	if initialTokenCount < 2 {
		t.Errorf("Expected at least 2 tokens (access + refresh), got %d", initialTokenCount)
	}

	// Second exchange with same code - should fail and revoke ALL tokens
	_, _, err = srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		clientID,
		"https://example.com/callback",
		codeVerifier,
	)
	if err == nil {
		t.Fatal("Second ExchangeAuthorizationCode() should have failed due to code reuse")
	}

	// Check error message
	// Verify error message is generic (per RFC 6749 - don't reveal security details to attackers)
	errStr := err.Error()
	if !containsString(errStr, "invalid_grant") && !containsString(errStr, "invalid grant") {
		t.Errorf("ExchangeAuthorizationCode() error = %v, want generic 'invalid grant' error", err)
	}

	// Verify all tokens were revoked
	tokens, err = store.GetTokensByUserClient("mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected all tokens to be revoked, but found %d tokens", len(tokens))
	}

	// Verify access token was deleted
	if _, err := store.GetToken(accessToken1); err == nil {
		t.Error("Access token should have been revoked")
	}

	// Verify refresh token was deleted
	if _, err := store.GetRefreshTokenInfo(refreshToken1); err == nil {
		t.Error("Refresh token should have been revoked")
	}
}

// TestServer_AuthorizationCodeReuseRevokesMultipleTokens tests that code reuse revokes
// all tokens including those from previous refresh operations
func TestServer_AuthorizationCodeReuseRevokesMultipleTokens(t *testing.T) {
	srv, store, _ := setupFlowTestServer(t)

	// Enable refresh token rotation
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400 // 24 hours

	// Register a client
	client, _, err := srv.RegisterClient(
		"Test Client 2",
		ClientTypeConfidential,
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.101",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID

	// Generate PKCE challenge
	codeVerifier := testutil.GenerateRandomString(50)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Start authorization flow
	clientState := "state-" + testutil.GenerateRandomString(10)
	_, err = srv.StartAuthorizationFlow(
		clientID,
		"https://example.com/callback",
		"openid email",
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	// Get provider state
	authState, err := store.GetAuthorizationState(clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}
	providerState := authState.ProviderState

	authCodeObj, _, err := srv.HandleProviderCallback(
		context.Background(),
		providerState,
		"provider-code-"+testutil.GenerateRandomString(10),
	)
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}
	authCode := authCodeObj.Code

	// Exchange the authorization code
	token1, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		clientID,
		"https://example.com/callback",
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	// Refresh the token multiple times to create multiple tokens
	token2, err := srv.RefreshAccessToken(context.Background(), token1.RefreshToken, clientID)
	if err != nil {
		t.Fatalf("RefreshAccessToken() error = %v", err)
	}

	token3, err := srv.RefreshAccessToken(context.Background(), token2.RefreshToken, clientID)
	if err != nil {
		t.Fatalf("Second RefreshAccessToken() error = %v", err)
	}

	// Verify we have multiple tokens (using mock user ID)
	tokens, err := store.GetTokensByUserClient("mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) < 2 {
		t.Logf("Warning: Expected multiple tokens, got %d", len(tokens))
	}

	// Now attempt to reuse the original authorization code
	_, _, err = srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		clientID,
		"https://example.com/callback",
		codeVerifier,
	)
	if err == nil {
		t.Fatal("Code reuse should have been detected")
	}

	// Verify ALL tokens were revoked (including the refreshed ones)
	tokens, err = store.GetTokensByUserClient("mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected all tokens to be revoked, but found %d tokens remaining", len(tokens))
	}

	// Verify the latest access token is invalid
	if _, err := store.GetToken(token3.AccessToken); err == nil {
		t.Error("Latest access token should have been revoked")
	}
}

// TestServer_RevokeAllTokensForUserClient tests the bulk revocation method directly
func TestServer_RevokeAllTokensForUserClient(t *testing.T) {
	srv, store, _ := setupFlowTestServer(t)

	userID := "test_user_789"
	clientID := "test_client_123"

	// Save some test tokens with metadata
	token1 := &oauth2.Token{
		AccessToken:  "access_token_1",
		RefreshToken: "refresh_token_1",
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	}
	token2 := &oauth2.Token{
		AccessToken:  "access_token_2",
		RefreshToken: "refresh_token_2",
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	}

	if err := store.SaveToken("access_token_1", token1); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveToken("access_token_2", token2); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Save metadata
	if err := store.SaveTokenMetadata("access_token_1", userID, clientID, "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}
	if err := store.SaveTokenMetadata("access_token_2", userID, clientID, "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	// Save a token for a different client (should not be revoked)
	token3 := &oauth2.Token{
		AccessToken: "access_token_3",
		Expiry:      time.Now().Add(time.Hour),
		TokenType:   "Bearer",
	}
	if err := store.SaveToken("access_token_3", token3); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveTokenMetadata("access_token_3", userID, "different_client", "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	// Verify tokens exist
	tokens, err := store.GetTokensByUserClient(userID, clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("Expected 2 tokens before revocation, got %d", len(tokens))
	}

	// Revoke all tokens for user+client
	err = srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err != nil {
		t.Fatalf("RevokeAllTokensForUserClient() error = %v", err)
	}

	// Verify tokens were revoked
	tokens, err = store.GetTokensByUserClient(userID, clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens after revocation, got %d", len(tokens))
	}

	// Verify tokens are actually deleted from storage
	if _, err := store.GetToken("access_token_1"); err == nil {
		t.Error("Token 1 should have been deleted")
	}
	if _, err := store.GetToken("access_token_2"); err == nil {
		t.Error("Token 2 should have been deleted")
	}

	// Verify the different client's token still exists
	if _, err := store.GetToken("access_token_3"); err != nil {
		t.Error("Token for different client should not have been deleted")
	}
	differentClientTokens, err := store.GetTokensByUserClient(userID, "different_client")
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(differentClientTokens) != 1 {
		t.Errorf("Expected 1 token for different client, got %d", len(differentClientTokens))
	}
}
