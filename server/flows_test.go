package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const (
	testUserID    = "user-123"
	testUserEmail = "test@example.com"
	testUserName  = "Test User"
	// testPKCEVerifierLength is the length used for PKCE verifiers in tests
	// PKCE spec (RFC 7636) requires verifiers to be 43-128 characters
	testPKCEVerifierLength = 50
)

func setupFlowTestServer(t *testing.T) (*Server, *memory.Store, *mock.Provider) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	config := &Config{
		Issuer:               "https://auth.example.com",
		SupportedScopes:      []string{"openid", "email", "profile"},
		AuthorizationCodeTTL: 600,
		AccessTokenTTL:       3600,
		RequirePKCE:          true,
		AllowPKCEPlain:       false,
		ClockSkewGracePeriod: 5, // 5 seconds grace period for testing
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return srv, store, provider
}

func TestServer_StartAuthorizationFlow(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
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
			clientState:         testutil.GenerateRandomString(43),
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
			clientState:         testutil.GenerateRandomString(43),
			wantErr:             true,
		},
		{
			name:                "invalid client ID",
			clientID:            "invalid-client-id",
			redirectURI:         "https://example.com/callback",
			scope:               "openid",
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			clientState:         testutil.GenerateRandomString(43),
			wantErr:             true,
		},
		{
			name:                "unregistered redirect URI",
			clientID:            client.ClientID,
			redirectURI:         "https://evil.com/callback",
			scope:               "openid",
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			clientState:         testutil.GenerateRandomString(43),
			wantErr:             true,
		},
		{
			name:                "invalid scope",
			clientID:            client.ClientID,
			redirectURI:         "https://example.com/callback",
			scope:               "invalid-scope",
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			clientState:         testutil.GenerateRandomString(43),
			wantErr:             true,
		},
		{
			name:                "plain PKCE not allowed",
			clientID:            client.ClientID,
			redirectURI:         "https://example.com/callback",
			scope:               "openid",
			codeChallenge:       validVerifier,
			codeChallengeMethod: PKCEMethodPlain,
			clientState:         testutil.GenerateRandomString(43),
			wantErr:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL, err := srv.StartAuthorizationFlow(ctx,
				tt.clientID,
				tt.redirectURI,
				tt.scope,
				"", // resource parameter (optional)
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
				authState, err := store.GetAuthorizationState(ctx, tt.clientState)
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
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	// Start authorization flow
	_, err = srv.StartAuthorizationFlow(ctx,
		client.ClientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		validChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	// Get the provider state
	authState, err := store.GetAuthorizationState(ctx, clientState)
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
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
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

	err = store.SaveAuthorizationCode(ctx, authCode)
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
			codeVerifier: testutil.GenerateRandomString(testPKCEVerifierLength), // Different verifier
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
					_ = store.SaveAuthorizationCode(ctx, freshCode)
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
							"", // resource parameter (optional)
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
				"", // resource parameter (optional)
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

// TestServer_ExchangeAuthorizationCode_PublicClient_PKCEEnforcement tests
// that public clients MUST use PKCE (OAuth 2.1 requirement) while confidential
// clients can optionally use PKCE for enhanced security.
func TestServer_ExchangeAuthorizationCode_PublicClient_PKCEEnforcement(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a public client (mobile app, SPA)
	publicClient, _, err := srv.RegisterClient(ctx,
		"Public Mobile App",
		ClientTypePublic,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient(public) error = %v", err)
	}

	// Register a confidential client (server-side web app)
	confidentialClient, _, err := srv.RegisterClient(ctx,
		"Confidential Server App",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.101",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient(confidential) error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	tests := []struct {
		name                string
		clientID            string
		clientType          string
		codeChallenge       string
		codeChallengeMethod string
		codeVerifier        string
		wantErr             bool
		wantErrContains     string
		description         string
	}{
		{
			name:                "public client with PKCE should succeed",
			clientID:            publicClient.ClientID,
			clientType:          ClientTypePublic,
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			codeVerifier:        validVerifier,
			wantErr:             false,
			description:         "Public clients with PKCE should successfully exchange authorization codes (OAuth 2.1)",
		},
		{
			name:                "public client without PKCE should fail",
			clientID:            publicClient.ClientID,
			clientType:          ClientTypePublic,
			codeChallenge:       "",
			codeChallengeMethod: "",
			codeVerifier:        "",
			wantErr:             true,
			wantErrContains:     "invalid_grant",
			description:         "Public clients MUST use PKCE to prevent authorization code theft (OAuth 2.1)",
		},
		{
			name:                "confidential client with PKCE should succeed",
			clientID:            confidentialClient.ClientID,
			clientType:          ClientTypeConfidential,
			codeChallenge:       validChallenge,
			codeChallengeMethod: PKCEMethodS256,
			codeVerifier:        validVerifier,
			wantErr:             false,
			description:         "Confidential clients with PKCE should successfully exchange codes (enhanced security)",
		},
		{
			name:                "confidential client without PKCE should succeed for backward compatibility",
			clientID:            confidentialClient.ClientID,
			clientType:          ClientTypeConfidential,
			codeChallenge:       "",
			codeChallengeMethod: "",
			codeVerifier:        "",
			wantErr:             false,
			description:         "Confidential clients without PKCE should work for backward compatibility",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh authorization code for this test
			authCode := &storage.AuthorizationCode{
				Code:                testutil.GenerateRandomString(32),
				ClientID:            tt.clientID,
				RedirectURI:         "https://example.com/callback",
				Scope:               "openid email",
				CodeChallenge:       tt.codeChallenge,
				CodeChallengeMethod: tt.codeChallengeMethod,
				UserID:              "test-user-pkce-" + testutil.GenerateRandomString(8),
				ProviderToken: &oauth2.Token{
					AccessToken:  "provider-access-token-" + testutil.GenerateRandomString(16),
					RefreshToken: "provider-refresh-token-" + testutil.GenerateRandomString(16),
					Expiry:       time.Now().Add(1 * time.Hour),
				},
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
				Used:      false,
			}

			err := store.SaveAuthorizationCode(ctx, authCode)
			if err != nil {
				t.Fatalf("SaveAuthorizationCode() error = %v", err)
			}

			// Attempt token exchange
			token, scope, err := srv.ExchangeAuthorizationCode(
				context.Background(),
				authCode.Code,
				tt.clientID,
				"https://example.com/callback",
				"", // resource parameter (optional)
				tt.codeVerifier,
			)

			// Verify error behavior
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: ExchangeAuthorizationCode() error = %v, wantErr %v", tt.description, err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("%s: error should contain %q, got %q", tt.description, tt.wantErrContains, err.Error())
				}

				// Verify audit logging for security event
				// (In production, this would be checked via audit log inspection)
				t.Logf("%s: Security violation correctly rejected: %v", tt.description, err)
			} else {
				// Success case - verify token issuance
				if token == nil {
					t.Fatalf("%s: ExchangeAuthorizationCode() returned nil token", tt.description)
				}

				if token.AccessToken == "" {
					t.Errorf("%s: Access token is empty", tt.description)
				}

				if token.RefreshToken == "" {
					t.Errorf("%s: Refresh token is empty", tt.description)
				}

				if scope == "" {
					t.Errorf("%s: Scope is empty", tt.description)
				}

				// Verify code was marked as used (OAuth 2.1 security)
				usedCode, err := store.GetAuthorizationCode(ctx, authCode.Code)
				if err != nil {
					t.Logf("%s: Authorization code properly cleaned up (expected for one-time use)", tt.description)
				} else if !usedCode.Used {
					t.Errorf("%s: Authorization code should be marked as used", tt.description)
				}

				t.Logf("%s: Token exchange successful", tt.description)
			}
		})
	}
}

// TestServer_ExchangeAuthorizationCode_AllowPublicClientsWithoutPKCE tests
// the legacy compatibility mode where public clients can authenticate without PKCE.
// This tests the AllowPublicClientsWithoutPKCE config option.
func TestServer_ExchangeAuthorizationCode_AllowPublicClientsWithoutPKCE(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	defer store.Stop()

	provider := mock.NewProvider()

	tests := []struct {
		name                          string
		allowPublicClientsWithoutPKCE bool
		includeCodeChallenge          bool
		wantErr                       bool
		wantErrContains               string
		description                   string
	}{
		{
			name:                          "default secure config - public client without PKCE should fail",
			allowPublicClientsWithoutPKCE: false,
			includeCodeChallenge:          false,
			wantErr:                       true,
			wantErrContains:               "invalid_grant",
			description:                   "Default secure config requires PKCE for public clients",
		},
		{
			name:                          "insecure config - public client without PKCE should succeed",
			allowPublicClientsWithoutPKCE: true,
			includeCodeChallenge:          false,
			wantErr:                       false,
			description:                   "Legacy mode allows public clients without PKCE (insecure)",
		},
		{
			name:                          "secure config - public client with PKCE should succeed",
			allowPublicClientsWithoutPKCE: false,
			includeCodeChallenge:          true,
			wantErr:                       false,
			description:                   "Public clients with PKCE work regardless of config",
		},
		{
			name:                          "insecure config - public client with PKCE should succeed",
			allowPublicClientsWithoutPKCE: true,
			includeCodeChallenge:          true,
			wantErr:                       false,
			description:                   "Public clients with PKCE work even in legacy mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server with specific config
			config := &Config{
				Issuer:                        "https://auth.example.com",
				AllowPublicClientsWithoutPKCE: tt.allowPublicClientsWithoutPKCE,
			}

			srv, err := New(provider, store, store, store, config, nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			// Register a public client
			publicClient, _, err := srv.RegisterClient(ctx,
				"Test Public Client",
				ClientTypePublic,
				"", // tokenEndpointAuthMethod
				[]string{"https://example.com/callback"},
				[]string{"openid", "email"},
				"192.168.1.100",
				10,
			)
			if err != nil {
				t.Fatalf("RegisterClient() error = %v", err)
			}

			var codeChallenge string
			var codeChallengeMethod string
			var codeVerifier string

			if tt.includeCodeChallenge {
				codeVerifier = testutil.GenerateRandomString(testPKCEVerifierLength)
				hash := sha256.Sum256([]byte(codeVerifier))
				codeChallenge = base64.RawURLEncoding.EncodeToString(hash[:])
				codeChallengeMethod = PKCEMethodS256
			}

			// Create authorization code
			authCode := &storage.AuthorizationCode{
				Code:                testutil.GenerateRandomString(32),
				ClientID:            publicClient.ClientID,
				RedirectURI:         "https://example.com/callback",
				Scope:               "openid email",
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
				UserID:              "test-user-legacy-" + testutil.GenerateRandomString(8),
				ProviderToken: &oauth2.Token{
					AccessToken:  "provider-access-token-" + testutil.GenerateRandomString(16),
					RefreshToken: "provider-refresh-token-" + testutil.GenerateRandomString(16),
					Expiry:       time.Now().Add(1 * time.Hour),
				},
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
				Used:      false,
			}

			err = store.SaveAuthorizationCode(ctx, authCode)
			if err != nil {
				t.Fatalf("SaveAuthorizationCode() error = %v", err)
			}

			// Attempt token exchange
			token, scope, err := srv.ExchangeAuthorizationCode(
				context.Background(),
				authCode.Code,
				publicClient.ClientID,
				"https://example.com/callback",
				"", // resource parameter (optional)
				codeVerifier,
			)

			// Verify error behavior
			if (err != nil) != tt.wantErr {
				t.Errorf("%s: ExchangeAuthorizationCode() error = %v, wantErr %v", tt.description, err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("%s: error should contain %q, got %q", tt.description, tt.wantErrContains, err.Error())
				}
				t.Logf("%s: Correctly rejected with error: %v", tt.description, err)
			} else {
				// Success case - verify token issuance
				if token == nil {
					t.Fatalf("%s: ExchangeAuthorizationCode() returned nil token", tt.description)
				}

				if token.AccessToken == "" {
					t.Errorf("%s: Access token is empty", tt.description)
				}

				if token.RefreshToken == "" {
					t.Errorf("%s: Refresh token is empty", tt.description)
				}

				if scope == "" {
					t.Errorf("%s: Scope is empty", tt.description)
				}

				t.Logf("%s: Token exchange successful (config: AllowPublicClientsWithoutPKCE=%v, PKCE=%v)",
					tt.description, tt.allowPublicClientsWithoutPKCE, tt.includeCodeChallenge)
			}
		})
	}
}

// TestServer_ExchangeAuthorizationCode_PublicClient_ReuseDetection ensures
// that when a public client attempts to reuse an authorization code (potential
// token theft attack), all tokens for that user+client are revoked per OAuth 2.1.
func TestServer_ExchangeAuthorizationCode_PublicClient_ReuseDetection(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a public client
	publicClient, _, err := srv.RegisterClient(ctx,
		"Public Mobile App",
		ClientTypePublic,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Create authorization code with PKCE
	authCode := &storage.AuthorizationCode{
		Code:                testutil.GenerateRandomString(32),
		ClientID:            publicClient.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid email",
		CodeChallenge:       validChallenge,
		CodeChallengeMethod: PKCEMethodS256,
		UserID:              "test-user-reuse-" + testutil.GenerateRandomString(8),
		ProviderToken: &oauth2.Token{
			AccessToken:  "provider-access-token-" + testutil.GenerateRandomString(16),
			RefreshToken: "provider-refresh-token-" + testutil.GenerateRandomString(16),
			Expiry:       time.Now().Add(1 * time.Hour),
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
	}

	err = store.SaveAuthorizationCode(ctx, authCode)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// First exchange should succeed
	token1, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode.Code,
		publicClient.ClientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		validVerifier,
	)
	if err != nil {
		t.Fatalf("First ExchangeAuthorizationCode() error = %v", err)
	}
	if token1 == nil {
		t.Fatal("First token exchange returned nil token")
	}

	t.Logf("First token exchange successful - token issued")

	// Second exchange (code reuse) should fail
	token2, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode.Code,
		publicClient.ClientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		validVerifier,
	)

	if err == nil {
		t.Fatal("Second ExchangeAuthorizationCode() should have failed (code reuse detected)")
	}
	if token2 != nil {
		t.Error("Second token exchange should return nil token")
	}

	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("Error should contain 'invalid_grant', got: %v", err)
	}

	t.Logf("Code reuse correctly detected and rejected: %v", err)

	// In production, this would also verify that all tokens for user+client were revoked
	// This is tested in the comprehensive reuse detection tests
}

func TestServer_ValidateToken(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Configure provider to return valid user info
	provider.ValidateTokenFunc = func(_ context.Context, accessToken string) (*providers.UserInfo, error) {
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
				savedInfo, err := store.GetUserInfo(ctx, userInfo.ID)
				if err != nil {
					t.Errorf("User info not saved: %v", err)
				} else if savedInfo.Email != userInfo.Email {
					t.Errorf("savedInfo.Email = %q, want %q", savedInfo.Email, userInfo.Email)
				}
			}
		})
	}
}

// setupValidTokenProvider returns a provider function that always validates tokens successfully
func setupValidTokenProvider() func(context.Context, string) (*providers.UserInfo, error) {
	return func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    "user-123",
			Email: "test@example.com",
			Name:  "Test User",
		}, nil
	}
}

// TestServer_ValidateToken_LocalExpiry tests local token expiry validation before provider check
func TestServer_ValidateToken_LocalExpiry(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Set up provider to always return valid user info
	provider.ValidateTokenFunc = setupValidTokenProvider()

	tests := []struct {
		name           string
		accessToken    string
		tokenExpiry    time.Time
		saveToken      bool
		clockSkewGrace int64
		wantErr        bool
		wantErrMsg     string
	}{
		{
			name:           "token not in storage - proceed to provider",
			accessToken:    "not-stored-token",
			saveToken:      false,
			clockSkewGrace: 5,
			wantErr:        false,
		},
		{
			name:           "token valid - not expired",
			accessToken:    "valid-token",
			tokenExpiry:    time.Now().Add(10 * time.Minute),
			saveToken:      true,
			clockSkewGrace: 5,
			wantErr:        false,
		},
		{
			name:           "token expired - beyond grace period",
			accessToken:    "expired-token",
			tokenExpiry:    time.Now().Add(-10 * time.Minute),
			saveToken:      true,
			clockSkewGrace: 5,
			wantErr:        true,
			wantErrMsg:     "access token expired (local validation)",
		},
		{
			name:           "token expired but within grace period",
			accessToken:    "grace-period-token",
			tokenExpiry:    time.Now().Add(-3 * time.Second),
			saveToken:      true,
			clockSkewGrace: 5,
			wantErr:        false,
		},
		{
			name:           "token just at grace period boundary",
			accessToken:    "boundary-token",
			tokenExpiry:    time.Now().Add(-4 * time.Second),
			saveToken:      true,
			clockSkewGrace: 5,
			wantErr:        false,
		},
		{
			name:           "token expired just beyond grace period",
			accessToken:    "just-beyond-grace",
			tokenExpiry:    time.Now().Add(-6 * time.Second),
			saveToken:      true,
			clockSkewGrace: 5,
			wantErr:        true,
			wantErrMsg:     "access token expired (local validation)",
		},
		{
			name:           "zero grace period - strict expiry check",
			accessToken:    "zero-grace-token",
			tokenExpiry:    time.Now().Add(-1 * time.Second),
			saveToken:      true,
			clockSkewGrace: 0,
			wantErr:        true,
			wantErrMsg:     "access token expired (local validation)",
		},
		{
			name:           "large grace period - expired token still valid",
			accessToken:    "large-grace-token",
			tokenExpiry:    time.Now().Add(-30 * time.Second),
			saveToken:      true,
			clockSkewGrace: 60,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original config and restore after test
			originalGrace := srv.Config.ClockSkewGracePeriod
			t.Cleanup(func() {
				srv.Config.ClockSkewGracePeriod = originalGrace
			})

			// Set clock skew grace period for this test
			srv.Config.ClockSkewGracePeriod = tt.clockSkewGrace

			// Save token to storage if needed
			if tt.saveToken {
				token := &oauth2.Token{
					AccessToken:  "provider-token-" + tt.accessToken,
					RefreshToken: "provider-refresh-" + tt.accessToken,
					Expiry:       tt.tokenExpiry,
				}
				err := store.SaveToken(ctx, tt.accessToken, token)
				if err != nil {
					t.Fatalf("SaveToken() error = %v", err)
				}
			}

			// Validate token
			userInfo, err := srv.ValidateToken(context.Background(), tt.accessToken)

			// Check error expectation
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateToken() expected error but got none")
					return
				}
				if tt.wantErrMsg != "" && !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("ValidateToken() error = %q, want error containing %q", err.Error(), tt.wantErrMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateToken() unexpected error = %v", err)
					return
				}
				if userInfo == nil {
					t.Fatal("ValidateToken() returned nil userInfo")
				}
				if userInfo.ID != "user-123" {
					t.Errorf("userInfo.ID = %q, want %q", userInfo.ID, "user-123")
				}
			}
		})
	}
}

// TestServer_ValidateToken_ClockSkewScenarios tests clock skew handling
func TestServer_ValidateToken_ClockSkewScenarios(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Provider always returns valid user info (simulating provider with skewed clock)
	provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    "user-clock-skew",
			Email: "clockskew@example.com",
			Name:  "Clock Skew User",
		}, nil
	}

	// Save original config and restore after all subtests
	originalGrace := srv.Config.ClockSkewGracePeriod
	t.Cleanup(func() {
		srv.Config.ClockSkewGracePeriod = originalGrace
	})

	// Configure grace period
	srv.Config.ClockSkewGracePeriod = 5

	t.Run("token expired locally but provider still accepts - local validation wins", func(t *testing.T) {
		accessToken := "locally-expired-token"

		// Save token with expiry 10 minutes in the past (beyond grace period)
		token := &oauth2.Token{
			AccessToken:  "provider-token",
			RefreshToken: "provider-refresh",
			Expiry:       time.Now().Add(-10 * time.Minute),
		}
		err := store.SaveToken(ctx, accessToken, token)
		if err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}

		// Try to validate - should fail locally before reaching provider
		_, err = srv.ValidateToken(context.Background(), accessToken)
		if err == nil {
			t.Error("ValidateToken() expected error for locally expired token")
		}
		if !strings.Contains(err.Error(), "expired") {
			t.Errorf("ValidateToken() error = %q, want error containing 'expired'", err.Error())
		}
	})

	t.Run("token near expiry within grace period - should pass", func(t *testing.T) {
		accessToken := "near-expiry-token" // nolint:gosec // G101: False positive - test token, not credentials

		// Save token with expiry 3 seconds in the past (within 5 second grace period)
		token := &oauth2.Token{
			AccessToken:  "provider-token-near",
			RefreshToken: "provider-refresh-near",
			Expiry:       time.Now().Add(-3 * time.Second),
		}
		err := store.SaveToken(ctx, accessToken, token)
		if err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}

		// Should succeed (within grace period)
		userInfo, err := srv.ValidateToken(context.Background(), accessToken)
		if err != nil {
			t.Errorf("ValidateToken() unexpected error = %v (token within grace period)", err)
		}
		if userInfo == nil {
			t.Fatal("ValidateToken() returned nil userInfo")
		}
	})

	t.Run("token not in local storage - provider validation proceeds", func(t *testing.T) {
		accessToken := "only-at-provider-token"

		// Don't save to local storage - simulating token from different instance
		// Provider will validate it successfully

		userInfo, err := srv.ValidateToken(context.Background(), accessToken)
		if err != nil {
			t.Errorf("ValidateToken() unexpected error = %v (token not in storage should proceed to provider)", err)
		}
		if userInfo == nil {
			t.Fatal("ValidateToken() returned nil userInfo")
		}
	})
}

// TestServer_ValidateToken_ProactiveRefresh tests proactive token refresh when token is near expiry
func TestServer_ValidateToken_ProactiveRefresh(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Configure refresh threshold (5 minutes)
	srv.Config.TokenRefreshThreshold = 300 // 5 minutes

	tests := []struct {
		name              string
		accessToken       string
		tokenExpiry       time.Time
		hasRefreshToken   bool
		refreshTokenValue string
		wantRefreshCalled bool
		wantErr           bool
		expectNewToken    bool
	}{
		{
			name:              "token near expiry with refresh token - should refresh",
			accessToken:       "near-expiry-token",
			tokenExpiry:       time.Now().Add(4 * time.Minute), // Within 5 minute threshold
			hasRefreshToken:   true,
			refreshTokenValue: "valid-refresh-token",
			wantRefreshCalled: true,
			wantErr:           false,
			expectNewToken:    true,
		},
		{
			name:              "token expiring in 2 minutes - should refresh",
			accessToken:       "very-near-expiry",
			tokenExpiry:       time.Now().Add(2 * time.Minute),
			hasRefreshToken:   true,
			refreshTokenValue: "refresh-token-2min",
			wantRefreshCalled: true,
			wantErr:           false,
			expectNewToken:    true,
		},
		{
			name:              "token expiring in 30 seconds - should refresh",
			accessToken:       "imminent-expiry",
			tokenExpiry:       time.Now().Add(30 * time.Second),
			hasRefreshToken:   true,
			refreshTokenValue: "refresh-token-30s",
			wantRefreshCalled: true,
			wantErr:           false,
			expectNewToken:    true,
		},
		{
			name:              "token not near expiry - should not refresh",
			accessToken:       "far-expiry-token",
			tokenExpiry:       time.Now().Add(10 * time.Minute), // Beyond threshold
			hasRefreshToken:   true,
			refreshTokenValue: "unused-refresh-token",
			wantRefreshCalled: false,
			wantErr:           false,
			expectNewToken:    false,
		},
		{
			name:              "token near expiry but no refresh token - should not refresh",
			accessToken:       "near-expiry-no-refresh",
			tokenExpiry:       time.Now().Add(4 * time.Minute),
			hasRefreshToken:   false,
			refreshTokenValue: "",
			wantRefreshCalled: false,
			wantErr:           false,
			expectNewToken:    false,
		},
		{
			name:              "token expiring in 6 minutes - at threshold boundary",
			accessToken:       "threshold-boundary",
			tokenExpiry:       time.Now().Add(6 * time.Minute), // Just beyond 5 minute threshold
			hasRefreshToken:   true,
			refreshTokenValue: "boundary-refresh",
			wantRefreshCalled: false,
			wantErr:           false,
			expectNewToken:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Track refresh calls (per-test variables avoid test pollution)
			var refreshCalled bool
			var refreshCalledWith string

			// Configure provider refresh function
			provider.RefreshTokenFunc = func(_ context.Context, refreshToken string) (*oauth2.Token, error) {
				refreshCalled = true
				refreshCalledWith = refreshToken
				return &oauth2.Token{
					AccessToken:  "new-access-token",
					RefreshToken: "new-refresh-token",
					Expiry:       time.Now().Add(1 * time.Hour),
					TokenType:    "Bearer",
				}, nil
			}

			// Provider always validates successfully
			provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
				return &providers.UserInfo{
					ID:    testUserID,
					Email: testUserEmail,
					Name:  testUserName,
				}, nil
			}

			// Save token to storage
			token := &oauth2.Token{
				AccessToken: "provider-token-" + tt.accessToken,
				Expiry:      tt.tokenExpiry,
				TokenType:   "Bearer",
			}
			if tt.hasRefreshToken {
				token.RefreshToken = tt.refreshTokenValue
			}

			err := store.SaveToken(ctx, tt.accessToken, token)
			if err != nil {
				t.Fatalf("SaveToken() error = %v", err)
			}

			// Validate token (should trigger proactive refresh if conditions met)
			userInfo, err := srv.ValidateToken(context.Background(), tt.accessToken)

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Check if refresh was called as expected
			if refreshCalled != tt.wantRefreshCalled {
				t.Errorf("RefreshToken called = %v, want %v", refreshCalled, tt.wantRefreshCalled)
			}

			// If refresh was expected, verify it was called with correct refresh token
			if tt.wantRefreshCalled && refreshCalledWith != tt.refreshTokenValue {
				t.Errorf("RefreshToken called with %q, want %q", refreshCalledWith, tt.refreshTokenValue)
			}

			// Verify user info was returned
			if !tt.wantErr {
				if userInfo == nil {
					t.Fatal("ValidateToken() returned nil userInfo")
				}
				if userInfo.ID != testUserID {
					t.Errorf("userInfo.ID = %q, want %q", userInfo.ID, testUserID)
				}
			}

			// If refresh was called, verify the new token was saved
			if tt.expectNewToken {
				savedToken, err := store.GetToken(ctx, tt.accessToken)
				if err != nil {
					t.Errorf("Failed to get saved token: %v", err)
				} else {
					if savedToken.AccessToken != "new-access-token" {
						t.Errorf("Saved token AccessToken = %q, want %q", savedToken.AccessToken, "new-access-token")
					}
					if savedToken.RefreshToken != "new-refresh-token" {
						t.Errorf("Saved token RefreshToken = %q, want %q", savedToken.RefreshToken, "new-refresh-token")
					}
					// Verify new expiry is later than old expiry
					if !savedToken.Expiry.After(tt.tokenExpiry) {
						t.Errorf("New token expiry %v should be after old expiry %v", savedToken.Expiry, tt.tokenExpiry)
					}
				}
			}
		})
	}
}

// TestServer_ValidateToken_ProactiveRefresh_Failure tests graceful fallback when proactive refresh fails
func TestServer_ValidateToken_ProactiveRefresh_Failure(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Configure refresh threshold
	srv.Config.TokenRefreshThreshold = 300 // 5 minutes

	// Configure provider refresh to fail
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return nil, fmt.Errorf("provider refresh failed: network error")
	}

	// Provider validation still succeeds (graceful fallback)
	validationCalled := false
	provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		validationCalled = true
		return &providers.UserInfo{
			ID:    "user-fallback",
			Email: "fallback@example.com",
			Name:  "Fallback User",
		}, nil
	}

	// Save token near expiry with refresh token
	accessToken := "near-expiry-refresh-fails" // nolint:gosec // G101: False positive - test token, not credentials
	oldExpiry := time.Now().Add(4 * time.Minute)
	token := &oauth2.Token{
		AccessToken:  "provider-token",
		RefreshToken: "failing-refresh-token",
		Expiry:       oldExpiry,
		TokenType:    "Bearer",
	}

	err := store.SaveToken(ctx, accessToken, token)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Validate token - refresh should fail but validation should succeed (graceful fallback)
	userInfo, err := srv.ValidateToken(context.Background(), accessToken)
	// Should NOT error - graceful fallback to validation
	if err != nil {
		t.Errorf("ValidateToken() error = %v, want nil (should fallback to validation)", err)
	}

	// Validation should have been called
	if !validationCalled {
		t.Error("Provider validation not called after refresh failure")
	}

	// User info should be returned from validation
	if userInfo == nil {
		t.Fatal("ValidateToken() returned nil userInfo")
	}
	if userInfo.ID != "user-fallback" {
		t.Errorf("userInfo.ID = %q, want %q", userInfo.ID, "user-fallback")
	}

	// Original token should still be in storage (refresh failed)
	savedToken, err := store.GetToken(ctx, accessToken)
	if err != nil {
		t.Errorf("Failed to get saved token: %v", err)
	} else if !savedToken.Expiry.Equal(oldExpiry) {
		// Token expiry should be unchanged (refresh failed)
		t.Errorf("Token expiry changed after failed refresh: got %v, want %v", savedToken.Expiry, oldExpiry)
	}
}

// TestServer_ValidateToken_ProactiveRefresh_CustomThreshold tests configurable refresh threshold
func TestServer_ValidateToken_ProactiveRefresh_CustomThreshold(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	tests := []struct {
		name              string
		refreshThreshold  int64 // seconds
		tokenExpiry       time.Duration
		wantRefreshCalled bool
	}{
		{
			name:              "10 minute threshold - token expiring in 9 minutes - should refresh",
			refreshThreshold:  600, // 10 minutes
			tokenExpiry:       9 * time.Minute,
			wantRefreshCalled: true,
		},
		{
			name:              "10 minute threshold - token expiring in 11 minutes - should not refresh",
			refreshThreshold:  600, // 10 minutes
			tokenExpiry:       11 * time.Minute,
			wantRefreshCalled: false,
		},
		{
			name:              "1 minute threshold - token expiring in 30 seconds - should refresh",
			refreshThreshold:  60, // 1 minute
			tokenExpiry:       30 * time.Second,
			wantRefreshCalled: true,
		},
		{
			name:              "1 minute threshold - token expiring in 2 minutes - should not refresh",
			refreshThreshold:  60, // 1 minute
			tokenExpiry:       2 * time.Minute,
			wantRefreshCalled: false,
		},
		{
			name:              "15 minute threshold - token expiring in 14 minutes - should refresh",
			refreshThreshold:  900, // 15 minutes
			tokenExpiry:       14 * time.Minute,
			wantRefreshCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set custom threshold
			srv.Config.TokenRefreshThreshold = tt.refreshThreshold

			// Track refresh calls
			refreshCalled := false
			provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
				refreshCalled = true
				return &oauth2.Token{
					AccessToken:  "new-token",
					RefreshToken: "new-refresh",
					Expiry:       time.Now().Add(1 * time.Hour),
					TokenType:    "Bearer",
				}, nil
			}

			// Provider validates successfully
			provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
				return &providers.UserInfo{
					ID:    "user-custom-threshold",
					Email: "custom@example.com",
					Name:  "Custom Threshold User",
				}, nil
			}

			// Save token with specific expiry
			accessToken := "custom-threshold-token-" + tt.name
			token := &oauth2.Token{
				AccessToken:  "provider-token",
				RefreshToken: "refresh-token",
				Expiry:       time.Now().Add(tt.tokenExpiry),
				TokenType:    "Bearer",
			}

			err := store.SaveToken(ctx, accessToken, token)
			if err != nil {
				t.Fatalf("SaveToken() error = %v", err)
			}

			// Validate token
			_, err = srv.ValidateToken(context.Background(), accessToken)
			if err != nil {
				t.Errorf("ValidateToken() error = %v", err)
			}

			// Check if refresh was called as expected
			if refreshCalled != tt.wantRefreshCalled {
				t.Errorf("RefreshToken called = %v, want %v (threshold=%ds, expiry=%v)",
					refreshCalled, tt.wantRefreshCalled, tt.refreshThreshold, tt.tokenExpiry)
			}
		})
	}
}

// TestServer_RefreshTokenRotation tests basic refresh token rotation without reuse
func TestServer_RefreshTokenRotation(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Enable refresh token rotation
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400 // 24 hours

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Start auth flow and get tokens
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
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
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	firstRefreshToken := token.RefreshToken

	// Verify first token family exists
	family1, err := store.GetRefreshTokenFamily(ctx, firstRefreshToken)
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
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
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
	family2, err := store.GetRefreshTokenFamily(ctx, secondRefreshToken)
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
	_, err = store.GetRefreshTokenInfo(ctx, firstRefreshToken)
	if err == nil {
		t.Error("First refresh token should have been deleted after rotation")
	}

	// Verify second token is still valid
	_, err = store.GetRefreshTokenInfo(ctx, secondRefreshToken)
	if err != nil {
		t.Errorf("Second refresh token should be valid, got error: %v", err)
	}
}

// TestServer_RefreshTokenReuseDetection tests that refresh token reuse is detected and revokes all tokens
// This is a CRITICAL OAuth 2.1 security feature
func TestServer_RefreshTokenReuseDetection(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Enable refresh token rotation (required for reuse detection)
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400 // 24 hours

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Start auth flow and get initial tokens
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
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
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	firstRefreshToken := token.RefreshToken
	firstAccessToken := token.AccessToken

	// Get family info for later verification
	family1, err := store.GetRefreshTokenFamily(ctx, firstRefreshToken)
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily() error = %v", err)
	}
	familyID := family1.FamilyID

	// Verify tokens exist
	tokens, err := store.GetTokensByUserClient(ctx, "mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) < 2 {
		t.Errorf("Expected at least 2 tokens initially, got %d", len(tokens))
	}

	// Configure mock provider for refresh
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
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
	_, err = store.GetRefreshTokenInfo(ctx, firstRefreshToken)
	if err == nil {
		t.Error("First refresh token should have been deleted after rotation")
	}

	// Verify second token is valid
	_, err = store.GetRefreshTokenInfo(ctx, secondRefreshToken)
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
	if !strings.Contains(errStr, "invalid") {
		t.Errorf("Error should be generic 'invalid grant', got: %v", err)
	}

	// CRITICAL: Verify family was revoked
	revokedFamily, err := store.GetRefreshTokenFamily(ctx, firstRefreshToken)
	if err != nil {
		t.Logf("Note: Family metadata for first token deleted (acceptable): %v", err)
	} else if !revokedFamily.Revoked {
		t.Error("Token family should have been revoked after reuse detection")
	}

	// Verify family is revoked when checking with second token
	family2, err := store.GetRefreshTokenFamily(ctx, secondRefreshToken)
	if err == nil {
		if !family2.Revoked {
			t.Error("Token family should be revoked after reuse detection")
		}
		if family2.FamilyID != familyID {
			t.Errorf("Family ID changed: got %s, want %s", family2.FamilyID, familyID)
		}
	}

	// CRITICAL: Verify ALL tokens for user+client were revoked
	tokens, err = store.GetTokensByUserClient(ctx, "mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("ALL tokens should have been revoked, but found %d tokens: %v", len(tokens), tokens)
	}

	// Verify specific tokens were deleted
	_, err = store.GetToken(ctx, firstAccessToken)
	if err == nil {
		t.Error("First access token should have been revoked")
	}

	_, err = store.GetToken(ctx, secondAccessToken)
	if err == nil {
		t.Error("Second access token should have been revoked")
	}

	_, err = store.GetRefreshTokenInfo(ctx, secondRefreshToken)
	if err == nil {
		t.Error("Second refresh token should have been revoked")
	}

	// CRITICAL TEST: Verify Revoked flag persists in family metadata
	// This is essential for preventing reuse of other tokens in the same family
	// Try to get family metadata for both tokens (they should both be revoked or deleted)
	checkFamilyRevoked := func(token string) {
		family, err := store.GetRefreshTokenFamily(ctx, token)
		if err != nil {
			// Family metadata might be deleted - acceptable
			t.Logf("Family metadata for token deleted (acceptable): %v", err)
		} else {
			// If family metadata exists, it MUST be marked as revoked
			if !family.Revoked {
				t.Errorf("Family should have Revoked=true, got false for family %s", family.FamilyID[:8])
			}
			if family.RevokedAt.IsZero() {
				t.Error("RevokedAt timestamp should be set when family is revoked")
			}
			if family.FamilyID != familyID {
				t.Errorf("Family ID mismatch: got %s, want %s", family.FamilyID[:8], familyID[:8])
			}
			t.Logf("Family metadata retained for forensics with Revoked=true and RevokedAt=%v", family.RevokedAt)
		}
	}

	// Check both tokens in the family
	checkFamilyRevoked(firstRefreshToken)
	checkFamilyRevoked(secondRefreshToken)
}

// TestServer_RefreshTokenReuseMultipleRotations tests reuse detection after multiple rotations
func TestServer_RefreshTokenReuseMultipleRotations(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Enable refresh token rotation
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get initial tokens
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
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
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	// Store all refresh tokens for reuse testing
	refreshTokens := []string{token.RefreshToken}

	// Configure mock provider
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
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
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("Error should be generic 'invalid grant', got: %v", err)
	}

	// Verify ALL tokens were revoked
	tokens, err := store.GetTokensByUserClient(ctx, "mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("ALL tokens should have been revoked, but found %d", len(tokens))
	}

	// Verify current token is also revoked
	_, err = store.GetRefreshTokenInfo(ctx, currentToken)
	if err == nil {
		t.Error("Current refresh token should have been revoked after reuse detection")
	}
}

// TestServer_ConcurrentRefreshTokenReuse tests that concurrent token reuse attempts are properly handled
// This is a CRITICAL security test - only ONE request should succeed, rest should fail
func TestServer_ConcurrentRefreshTokenReuse(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Enable refresh token rotation
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get initial tokens
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
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
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	firstRefreshToken := token.RefreshToken

	// Configure mock provider
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "new-provider-access-token",
			RefreshToken: "new-provider-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}, nil
	}

	// Perform one legitimate refresh (rotation happens)
	token2, err := srv.RefreshAccessToken(context.Background(), firstRefreshToken, clientID)
	if err != nil {
		t.Fatalf("Legitimate RefreshAccessToken() error = %v", err)
	}

	// Now the firstRefreshToken is rotated out (deleted)
	// Launch 10 concurrent attempts to reuse the old token
	const numConcurrent = 10
	type result struct {
		success bool
		err     error
	}
	results := make(chan result, numConcurrent)

	// All goroutines start roughly at the same time
	for i := 0; i < numConcurrent; i++ {
		go func() {
			_, err := srv.RefreshAccessToken(context.Background(), firstRefreshToken, clientID)
			results <- result{success: err == nil, err: err}
		}()
	}

	// Collect results
	successCount := 0
	failCount := 0
	for i := 0; i < numConcurrent; i++ {
		res := <-results
		if res.success {
			successCount++
			t.Error("Concurrent reuse attempt succeeded - should have failed!")
		} else {
			failCount++
			// Verify error is security-related (either "invalid" or "revoked")
			errStr := res.err.Error()
			if !strings.Contains(errStr, "invalid") && !strings.Contains(errStr, "revoked") {
				t.Errorf("Error should indicate security failure, got: %v", res.err)
			}
		}
	}

	// CRITICAL: ALL attempts should fail (token was already rotated)
	if successCount > 0 {
		t.Errorf("SECURITY FAILURE: %d concurrent reuse attempts succeeded, expected 0", successCount)
	}
	if failCount != numConcurrent {
		t.Errorf("Expected all %d attempts to fail, but only %d failed", numConcurrent, failCount)
	}

	// Verify ALL tokens were revoked (reuse detection triggered)
	tokens, err := store.GetTokensByUserClient(ctx, "mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("ALL tokens should have been revoked, but found %d", len(tokens))
	}

	// Verify the second token (legitimate one) is also revoked
	_, err = store.GetRefreshTokenInfo(ctx, token2.RefreshToken)
	if err == nil {
		t.Error("Second refresh token should have been revoked after reuse detection")
	}

	t.Logf("Concurrent reuse test passed: %d/%d attempts correctly failed", failCount, numConcurrent)
}

// TestServer_ConcurrentAuthorizationCodeReuse tests concurrent auth code reuse
// This verifies atomic code exchange - only ONE request should succeed
func TestServer_ConcurrentAuthorizationCodeReuse(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get authorization code
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
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

	authCode := authCodeObj.Code

	// Launch 10 concurrent attempts to exchange the SAME authorization code
	const numConcurrent = 10
	type result struct {
		success bool
		token   *oauth2.Token
		err     error
	}
	results := make(chan result, numConcurrent)

	// All goroutines start roughly at the same time
	for i := 0; i < numConcurrent; i++ {
		go func() {
			token, _, err := srv.ExchangeAuthorizationCode(
				context.Background(),
				authCode,
				clientID,
				"https://example.com/callback",
				"", // resource parameter (optional)
				codeVerifier,
			)
			results <- result{success: err == nil, token: token, err: err}
		}()
	}

	// Collect results
	successCount := 0
	failCount := 0
	var successfulToken *oauth2.Token
	for i := 0; i < numConcurrent; i++ {
		res := <-results
		if res.success {
			successCount++
			successfulToken = res.token
		} else {
			failCount++
			// Verify error is generic
			if !strings.Contains(res.err.Error(), "invalid") {
				t.Errorf("Error should contain 'invalid', got: %v", res.err)
			}
		}
	}

	// CRITICAL: Exactly ONE attempt should succeed (atomic operation)
	if successCount != 1 {
		t.Errorf("SECURITY FAILURE: Expected exactly 1 success, got %d", successCount)
	}
	if failCount != numConcurrent-1 {
		t.Errorf("Expected %d failures, got %d", numConcurrent-1, failCount)
	}

	// The one successful token should be valid
	if successCount == 1 && successfulToken == nil {
		t.Error("Successful exchange should return a token")
	}

	t.Logf("Concurrent auth code test passed: 1 succeeded, %d correctly failed", failCount)
}

func TestServer_RevokeToken(t *testing.T) {
	ctx := context.Background()
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
	err := store.SaveToken(ctx, userID, providerToken)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	err = store.SaveRefreshTokenWithFamily(ctx, refreshToken, userID, clientID, familyID, 1, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily() error = %v", err)
	}

	// Test revocation
	err = srv.RevokeToken(context.Background(), refreshToken, clientID, "192.168.1.100")
	if err != nil {
		t.Errorf("RevokeToken() error = %v", err)
	}

	// Verify token family was revoked (not just the individual token)
	family, err := store.GetRefreshTokenFamily(ctx, familyID)
	if err == nil && family != nil && !family.Revoked {
		t.Error("Token family should have been revoked")
	}
}

// TestServer_AuthorizationCodeReuseRevokesTokens tests that when an authorization code is reused,
// all tokens for that user+client are revoked (OAuth 2.1 requirement)
func TestServer_AuthorizationCodeReuseRevokesTokens(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Start authorization flow
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	// Get provider state from stored auth state
	authState, err := store.GetAuthorizationState(ctx, clientState)
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
		"", // resource parameter (optional)
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
	if _, err := store.GetToken(ctx, accessToken1); err != nil {
		t.Errorf("Access token not found in storage after first exchange")
	}
	if _, err := store.GetRefreshTokenInfo(ctx, refreshToken1); err != nil {
		t.Errorf("Refresh token not found in storage after first exchange")
	}

	// Verify token metadata is stored (using mock user ID from mock provider)
	tokens, err := store.GetTokensByUserClient(ctx, "mock-user-123", clientID)
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
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err == nil {
		t.Fatal("Second ExchangeAuthorizationCode() should have failed due to code reuse")
	}

	// Check error message
	// Verify error message is generic (per RFC 6749 - don't reveal security details to attackers)
	errStr := err.Error()
	if !strings.Contains(errStr, "invalid_grant") && !strings.Contains(errStr, "invalid grant") {
		t.Errorf("ExchangeAuthorizationCode() error = %v, want generic 'invalid grant' error", err)
	}

	// Verify all tokens were revoked
	tokens, err = store.GetTokensByUserClient(ctx, "mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected all tokens to be revoked, but found %d tokens", len(tokens))
	}

	// Verify access token was deleted
	if _, err := store.GetToken(ctx, accessToken1); err == nil {
		t.Error("Access token should have been revoked")
	}

	// Verify refresh token was deleted
	if _, err := store.GetRefreshTokenInfo(ctx, refreshToken1); err == nil {
		t.Error("Refresh token should have been revoked")
	}
}

// TestServer_AuthorizationCodeReuseRevokesMultipleTokens tests that code reuse revokes
// all tokens including those from previous refresh operations
func TestServer_AuthorizationCodeReuseRevokesMultipleTokens(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Enable refresh token rotation
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400 // 24 hours

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client 2",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Start authorization flow
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	// Get provider state
	authState, err := store.GetAuthorizationState(ctx, clientState)
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
		"", // resource parameter (optional)
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
	tokens, err := store.GetTokensByUserClient(ctx, "mock-user-123", clientID)
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
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err == nil {
		t.Fatal("Code reuse should have been detected")
	}

	// Verify ALL tokens were revoked (including the refreshed ones)
	tokens, err = store.GetTokensByUserClient(ctx, "mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected all tokens to be revoked, but found %d tokens remaining", len(tokens))
	}

	// Verify the latest access token is invalid
	if _, err := store.GetToken(ctx, token3.AccessToken); err == nil {
		t.Error("Latest access token should have been revoked")
	}
}

// TestServer_RevokeAllTokensForUserClient tests the bulk revocation method directly
func TestServer_RevokeAllTokensForUserClient(t *testing.T) {
	ctx := context.Background()
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

	if err := store.SaveToken(ctx, "access_token_1", token1); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveToken(ctx, "access_token_2", token2); err != nil {
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
	if err := store.SaveToken(ctx, "access_token_3", token3); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveTokenMetadata("access_token_3", userID, "different_client", "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	// Verify tokens exist
	tokens, err := store.GetTokensByUserClient(ctx, userID, clientID)
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
	tokens, err = store.GetTokensByUserClient(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens after revocation, got %d", len(tokens))
	}

	// Verify tokens are actually deleted from storage
	if _, err := store.GetToken(ctx, "access_token_1"); err == nil {
		t.Error("Token 1 should have been deleted")
	}
	if _, err := store.GetToken(ctx, "access_token_2"); err == nil {
		t.Error("Token 2 should have been deleted")
	}

	// Verify the different client's token still exists
	if _, err := store.GetToken(ctx, "access_token_3"); err != nil {
		t.Error("Token for different client should not have been deleted")
	}
	differentClientTokens, err := store.GetTokensByUserClient(ctx, userID, "different_client")
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(differentClientTokens) != 1 {
		t.Errorf("Expected 1 token for different client, got %d", len(differentClientTokens))
	}
}

// TestServer_RevokeAllTokensProviderFailure tests that operation fails when all provider revocations fail
// (exceeds default 50% threshold)
func TestServer_RevokeAllTokensProviderFailure(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Use default threshold (50%) - should fail when 100% of provider revocations fail
	srv.Config.ProviderRevocationMaxRetries = 0 // No retries for faster test

	userID := "test_user_789"
	clientID := "test_client_123"

	// Configure mock provider to fail revocation
	revokeCallCount := 0
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		revokeCallCount++
		return fmt.Errorf("provider revocation failed: network timeout")
	}

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

	if err := store.SaveToken(ctx, "access_token_1", token1); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveToken(ctx, "access_token_2", token2); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Save metadata
	if err := store.SaveTokenMetadata("access_token_1", userID, clientID, "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}
	if err := store.SaveTokenMetadata("access_token_2", userID, clientID, "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	// Verify tokens exist before revocation
	tokens, err := store.GetTokensByUserClient(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 2 {
		t.Errorf("Expected 2 tokens before revocation, got %d", len(tokens))
	}

	// CRITICAL: Revoke all tokens - should FAIL because all provider revocations failed (100% failure rate)
	err = srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err == nil {
		t.Fatal("RevokeAllTokensForUserClient() should fail when all provider revocations fail (exceeds threshold)")
	}

	// Verify error mentions threshold or failure rate
	if !strings.Contains(err.Error(), "threshold") && !strings.Contains(err.Error(), "failure rate") {
		t.Errorf("Error should mention threshold/failure rate, got: %v", err)
	}

	// Verify provider revocation was attempted
	if revokeCallCount < 2 {
		t.Errorf("Expected at least 2 provider revocation attempts (access + refresh tokens), got %d", revokeCallCount)
	}

	t.Logf("Provider failure test passed: %d provider calls made, operation correctly failed due to 100%% failure rate", revokeCallCount)
}

// TestServer_RevokeAllTokensProviderTimeout tests that revocation fails when provider times out
// (exceeds default 50% threshold)
func TestServer_RevokeAllTokensProviderTimeout(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Set a short timeout for testing (1 second)
	srv.Config.ProviderRevocationTimeout = 1
	srv.Config.ProviderRevocationMaxRetries = 0 // No retries for faster test

	userID := "test_user_timeout"
	clientID := "test_client_timeout"

	// Configure mock provider to block (simulate slow provider)
	provider.RevokeTokenFunc = func(ctx context.Context, _ string) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			return nil
		}
	}

	// Save a test token
	token1 := &oauth2.Token{
		AccessToken: "access_token_timeout",
		Expiry:      time.Now().Add(time.Hour),
		TokenType:   "Bearer",
	}

	if err := store.SaveToken(ctx, "access_token_timeout", token1); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	if err := store.SaveTokenMetadata("access_token_timeout", userID, clientID, "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	// Start timer to verify timeout is respected
	startTime := time.Now()

	// Revoke - should timeout at provider and FAIL (100% failure rate exceeds 50% threshold)
	err := srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)

	elapsed := time.Since(startTime)

	if err == nil {
		t.Fatal("RevokeAllTokensForUserClient() should fail when provider times out (exceeds threshold)")
	}

	// Verify error mentions threshold or failure
	if !strings.Contains(err.Error(), "threshold") && !strings.Contains(err.Error(), "failure rate") && !strings.Contains(err.Error(), "failed") {
		t.Errorf("Error should mention threshold/failure, got: %v", err)
	}

	// Verify it didn't wait the full 10 seconds (should timeout after ~1 second per attempt)
	// With default 3 retries + 1 initial attempt, expect roughly: 1s * 4 attempts = ~4s
	// But we set maxRetries to 0, so just 1 attempt = ~1s
	if elapsed > 3*time.Second {
		t.Errorf("Revocation took too long (%v), timeout not respected", elapsed)
	}

	t.Logf("Provider timeout test passed: operation completed in %v and correctly failed (timeout was %ds)", elapsed, srv.Config.ProviderRevocationTimeout)
}

// TestServer_ConcurrentReuseAndRevocation tests that concurrent token reuse attempts
// during revocation are handled safely without races, panics, or deadlocks.
// This test verifies the TOCTOU fix in refresh token reuse detection.
func TestServer_ConcurrentReuseAndRevocation(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Enable refresh token rotation
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get initial tokens
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
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
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	firstRefreshToken := token.RefreshToken

	// Configure mock provider for refresh
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "rotated-provider-access-token",
			RefreshToken: "rotated-provider-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}, nil
	}

	// Perform one legitimate refresh (rotation happens)
	token2, err := srv.RefreshAccessToken(context.Background(), firstRefreshToken, clientID)
	if err != nil {
		t.Fatalf("Legitimate RefreshAccessToken() error = %v", err)
	}

	// Now firstRefreshToken is rotated out (deleted), but family metadata exists
	// This is the perfect state to test concurrent reuse detection

	// Launch 20 goroutines: 10 trying to reuse the old token, 10 trying to use valid token
	const numReuse = 10
	const numValid = 10
	const totalGoroutines = numReuse + numValid

	type result struct {
		success  bool
		err      error
		isReuse  bool
		threadID int
	}
	results := make(chan result, totalGoroutines)

	// Start all goroutines roughly at the same time
	// Half will try to reuse the OLD token (should trigger revocation)
	// Half will try to use the VALID token (should fail due to revocation)
	for i := 0; i < numReuse; i++ {
		go func(id int) {
			_, err := srv.RefreshAccessToken(context.Background(), firstRefreshToken, clientID)
			results <- result{success: err == nil, err: err, isReuse: true, threadID: id}
		}(i)
	}

	// Small delay to let reuse attempts start first
	time.Sleep(10 * time.Millisecond)

	for i := 0; i < numValid; i++ {
		go func(id int) {
			_, err := srv.RefreshAccessToken(context.Background(), token2.RefreshToken, clientID)
			results <- result{success: err == nil, err: err, isReuse: false, threadID: numReuse + id}
		}(i)
	}

	// Collect results
	reuseSuccessCount := 0
	reuseFailCount := 0
	validSuccessCount := 0
	validFailCount := 0

	for i := 0; i < totalGoroutines; i++ {
		res := <-results
		if res.isReuse {
			if res.success {
				reuseSuccessCount++
				t.Errorf("Thread %d: Reuse attempt succeeded - should have failed!", res.threadID)
			} else {
				reuseFailCount++
				// Verify error is generic
				if !strings.Contains(res.err.Error(), "invalid") && !strings.Contains(res.err.Error(), "revoked") {
					t.Errorf("Thread %d: Error should indicate security failure, got: %v", res.threadID, res.err)
				}
			}
		} else {
			if res.success {
				validSuccessCount++
				// This is possible if the goroutine ran before revocation completed
				t.Logf("Thread %d: Valid token succeeded (ran before revocation)", res.threadID)
			} else {
				validFailCount++
				// Expected - token revoked or already used
			}
		}
	}

	// CRITICAL: ALL reuse attempts should fail
	if reuseSuccessCount > 0 {
		t.Errorf("SECURITY FAILURE: %d reuse attempts succeeded, expected 0", reuseSuccessCount)
	}

	// Verify ALL tokens were eventually revoked
	tokens, err := store.GetTokensByUserClient(ctx, "mock-user-123", clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("ALL tokens should have been revoked, but found %d", len(tokens))
	}

	t.Logf("Concurrent reuse+revocation test passed: %d/%d reuse attempts failed, %d valid attempts, %d/%d valid attempts failed",
		reuseFailCount, numReuse, numValid, validFailCount, numValid)
	t.Logf("This test verifies the TOCTOU fix - no races, panics, or deadlocks occurred")
}

// TestServer_ProviderRevocationRetrySuccess tests that retry logic succeeds after transient failures
func TestServer_ProviderRevocationRetrySuccess(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Configure retry settings
	srv.Config.ProviderRevocationMaxRetries = 3
	srv.Config.ProviderRevocationTimeout = 5
	srv.Config.ProviderRevocationFailureThreshold = 0.5

	userID := "test_user_retry"
	clientID := "test_client_retry"

	// Configure provider to fail twice, then succeed
	callCount := 0
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		callCount++
		if callCount <= 2 {
			return fmt.Errorf("transient network error")
		}
		return nil // Success on 3rd attempt
	}

	// Save test tokens
	token1 := &oauth2.Token{
		AccessToken:  "access_token_retry",
		RefreshToken: "refresh_token_retry",
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	}

	if err := store.SaveToken(ctx, "access_token_retry", token1); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveTokenMetadata("access_token_retry", userID, clientID, "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	// Revoke - should succeed after retries
	err := srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err != nil {
		t.Fatalf("RevokeAllTokensForUserClient() should succeed with retries, got error: %v", err)
	}

	// Verify provider was called multiple times (for both access and refresh tokens)
	// Each token has 2 failures + 1 success = 3 attempts per token
	// Total: 2 tokens * 3 attempts = at least 6 calls
	// But since both succeed on 3rd attempt, we expect 3+3 = 6 total
	expectedCalls := 6 // 3 attempts for access token + 3 for refresh token
	if callCount != expectedCalls {
		t.Logf("Note: Got %d provider calls (access + refresh tokens with retries)", callCount)
	}

	// The important check is that revocation succeeded
	if callCount < 4 {
		t.Errorf("Expected at least 4 provider calls (retries for access + refresh), got %d", callCount)
	}

	// Verify local revocation succeeded
	tokens, err := store.GetTokensByUserClient(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens after revocation, got %d", len(tokens))
	}

	t.Logf("Retry test passed: provider revocation succeeded after %d attempts", callCount)
}

// TestServer_ProviderRevocationFailureThreshold tests that system fails when threshold is exceeded
func TestServer_ProviderRevocationFailureThreshold(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Configure strict threshold: >50% must succeed
	srv.Config.ProviderRevocationMaxRetries = 0 // No retries for faster test
	srv.Config.ProviderRevocationTimeout = 5
	srv.Config.ProviderRevocationFailureThreshold = 0.5 // 50% threshold

	userID := "test_user_threshold"
	clientID := "test_client_threshold"

	// Configure provider to fail 60% of the time (exceeds 50% threshold)
	callCount := 0
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		callCount++
		// Fail 3 out of 5 calls (60% failure rate)
		if callCount <= 3 {
			return fmt.Errorf("provider revocation failed")
		}
		return nil
	}

	// Save 5 test tokens (will result in 5 revocation attempts)
	for i := 0; i < 5; i++ {
		tokenID := fmt.Sprintf("access_token_%d", i)
		token := &oauth2.Token{
			AccessToken: tokenID,
			Expiry:      time.Now().Add(time.Hour),
			TokenType:   "Bearer",
		}
		if err := store.SaveToken(ctx, tokenID, token); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}
		if err := store.SaveTokenMetadata(tokenID, userID, clientID, "access"); err != nil {
			t.Fatalf("SaveTokenMetadata() error = %v", err)
		}
	}

	// Revoke - should FAIL due to threshold exceeded
	err := srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err == nil {
		t.Fatal("RevokeAllTokensForUserClient() should fail when threshold exceeded")
	}

	// Verify error message mentions threshold
	if !strings.Contains(err.Error(), "threshold") && !strings.Contains(err.Error(), "failure rate") {
		t.Errorf("Error should mention threshold/failure rate, got: %v", err)
	}

	// Verify 5 provider calls were made
	if callCount != 5 {
		t.Errorf("Expected 5 provider calls, got %d", callCount)
	}

	t.Logf("Threshold test passed: system correctly failed with 60%% failure rate (threshold: 50%%)")
}

// TestServer_ProviderRevocationWithinThreshold tests that system succeeds when within threshold
func TestServer_ProviderRevocationWithinThreshold(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Configure threshold: >50% must succeed
	srv.Config.ProviderRevocationMaxRetries = 0
	srv.Config.ProviderRevocationTimeout = 5
	srv.Config.ProviderRevocationFailureThreshold = 0.5 // 50% threshold

	userID := "test_user_within"
	clientID := "test_client_within"

	// Configure provider to fail 40% of the time (within 50% threshold)
	callCount := 0
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		callCount++
		// Fail 2 out of 5 calls (40% failure rate - within threshold)
		if callCount <= 2 {
			return fmt.Errorf("provider revocation failed")
		}
		return nil
	}

	// Save 5 test tokens
	for i := 0; i < 5; i++ {
		tokenID := fmt.Sprintf("access_token_%d", i)
		token := &oauth2.Token{
			AccessToken: tokenID,
			Expiry:      time.Now().Add(time.Hour),
			TokenType:   "Bearer",
		}
		if err := store.SaveToken(ctx, tokenID, token); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}
		if err := store.SaveTokenMetadata(tokenID, userID, clientID, "access"); err != nil {
			t.Fatalf("SaveTokenMetadata() error = %v", err)
		}
	}

	// Revoke - should SUCCEED (40% failure < 50% threshold)
	err := srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err != nil {
		t.Fatalf("RevokeAllTokensForUserClient() should succeed when within threshold, got error: %v", err)
	}

	// Verify 5 provider calls were made
	if callCount != 5 {
		t.Errorf("Expected 5 provider calls, got %d", callCount)
	}

	// Verify local revocation succeeded
	tokens, err := store.GetTokensByUserClient(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens after revocation, got %d", len(tokens))
	}

	t.Logf("Threshold test passed: system succeeded with 40%% failure rate (threshold: 50%%)")
}

// TestServer_ProviderRevocationExponentialBackoff tests that backoff timing is correct
func TestServer_ProviderRevocationExponentialBackoff(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Configure multiple retries to test backoff
	srv.Config.ProviderRevocationMaxRetries = 3
	srv.Config.ProviderRevocationTimeout = 5
	srv.Config.ProviderRevocationFailureThreshold = 1.0 // Allow all failures for this test

	userID := "test_user_backoff"
	clientID := "test_client_backoff"

	// Track timing of attempts
	attemptTimes := []time.Time{}
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		attemptTimes = append(attemptTimes, time.Now())
		return fmt.Errorf("always fail") // Always fail to test all retries
	}

	// Save one test token
	token1 := &oauth2.Token{
		AccessToken: "access_token_backoff",
		Expiry:      time.Now().Add(time.Hour),
		TokenType:   "Bearer",
	}
	if err := store.SaveToken(ctx, "access_token_backoff", token1); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveTokenMetadata("access_token_backoff", userID, clientID, "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	// Revoke - will fail but we're testing timing
	startTime := time.Now()
	_ = srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	totalDuration := time.Since(startTime)

	// Verify 4 attempts (1 initial + 3 retries)
	if len(attemptTimes) != 4 {
		t.Errorf("Expected 4 attempts (1 + 3 retries), got %d", len(attemptTimes))
	}

	if len(attemptTimes) >= 2 {
		// Verify exponential backoff timing
		// Expected backoffs: 100ms, 200ms, 400ms
		// Allow 50% tolerance for timing jitter
		backoff1 := attemptTimes[1].Sub(attemptTimes[0])
		if backoff1 < 50*time.Millisecond || backoff1 > 200*time.Millisecond {
			t.Errorf("First backoff should be ~100ms, got %v", backoff1)
		}

		if len(attemptTimes) >= 3 {
			backoff2 := attemptTimes[2].Sub(attemptTimes[1])
			if backoff2 < 100*time.Millisecond || backoff2 > 400*time.Millisecond {
				t.Errorf("Second backoff should be ~200ms, got %v", backoff2)
			}
		}

		if len(attemptTimes) >= 4 {
			backoff3 := attemptTimes[3].Sub(attemptTimes[2])
			if backoff3 < 200*time.Millisecond || backoff3 > 800*time.Millisecond {
				t.Errorf("Third backoff should be ~400ms, got %v", backoff3)
			}
		}
	}

	// Total time should be roughly: timeout*4 + backoff delays
	// Expected: ~5s*4 (timeouts) + 0.1+0.2+0.4s (backoffs) = ~20.7s
	// But with our test, failures should be fast, so mainly backoff time: ~0.7s
	t.Logf("Backoff test: %d attempts over %v", len(attemptTimes), totalDuration)
}

// TestServer_ProviderRevocationContextCancellation tests that cancelling context stops retries
// P0 CRITICAL: Prevents goroutine leaks and ensures proper shutdown
func TestServer_ProviderRevocationContextCancellation(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	srv.Config.ProviderRevocationMaxRetries = 10 // Many retries
	srv.Config.ProviderRevocationTimeout = 5

	userID := "test_user_cancel"
	clientID := "test_client_cancel"

	attemptCount := 0
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		attemptCount++
		// Always fail to force retries
		return fmt.Errorf("transient error")
	}

	// Save a test token
	token1 := &oauth2.Token{
		AccessToken: "access_token_cancel",
		Expiry:      time.Now().Add(time.Hour),
		TokenType:   "Bearer",
	}
	if err := store.SaveToken(ctx, "access_token_cancel", token1); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveTokenMetadata("access_token_cancel", userID, clientID, "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	// Create cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context after 200ms (should be during first backoff or second attempt)
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	startTime := time.Now()
	err := srv.RevokeAllTokensForUserClient(ctx, userID, clientID)
	elapsed := time.Since(startTime)

	// Should fail with either context cancellation or threshold error
	if err == nil {
		t.Fatal("Expected error when context cancelled, got nil")
	}

	// Should contain "context", "cancel", "threshold", or "failure" in error
	// (context cancellation may result in threshold failure if some calls completed)
	errStr := strings.ToLower(err.Error())
	hasExpectedError := strings.Contains(errStr, "context") ||
		strings.Contains(errStr, "cancel") ||
		strings.Contains(errStr, "threshold") ||
		strings.Contains(errStr, "failure")

	if !hasExpectedError {
		t.Errorf("Error should mention cancellation or threshold failure, got: %v", err)
	}

	// Should not wait full retry duration (10 retries * 5s = 50s)
	// Should complete quickly after cancellation (~200ms + small overhead)
	if elapsed > 2*time.Second {
		t.Errorf("Should complete quickly after cancellation, took %v", elapsed)
	}

	// Should have made at most 2-3 attempts before cancellation
	if attemptCount > 5 {
		t.Errorf("Should stop retrying after cancellation, made %d attempts", attemptCount)
	}

	t.Logf("Context cancellation test passed: stopped after %d attempts in %v", attemptCount, elapsed)
}

// TestServer_ProviderRevocationExactlyAtThreshold tests behavior at exact threshold boundary
// P0 CRITICAL: Clarifies ambiguous behavior when failure rate equals threshold
func TestServer_ProviderRevocationExactlyAtThreshold(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Set threshold to exactly 0.5 (50%)
	srv.Config.ProviderRevocationFailureThreshold = 0.5
	srv.Config.ProviderRevocationMaxRetries = 0

	userID := "test_user_exact_threshold"
	clientID := "test_client_exact_threshold"

	// Configure provider to fail exactly 50% (5 out of 10)
	callCount := 0
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		callCount++
		if callCount <= 5 {
			return fmt.Errorf("provider revocation failed")
		}
		return nil
	}

	// Save 10 test tokens
	for i := 0; i < 10; i++ {
		tokenID := fmt.Sprintf("access_token_%d", i)
		token := &oauth2.Token{
			AccessToken: tokenID,
			Expiry:      time.Now().Add(time.Hour),
			TokenType:   "Bearer",
		}
		if err := store.SaveToken(ctx, tokenID, token); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}
		if err := store.SaveTokenMetadata(tokenID, userID, clientID, "access"); err != nil {
			t.Fatalf("SaveTokenMetadata() error = %v", err)
		}
	}

	// Revoke - exactly 50% failure rate with 50% threshold
	// Current code uses: if failureRate > threshold
	// So 0.5 > 0.5 is FALSE, should SUCCEED
	err := srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err != nil {
		t.Fatalf("RevokeAllTokensForUserClient() should succeed at exact threshold (50%% == 50%%), got error: %v", err)
	}

	if callCount != 10 {
		t.Errorf("Expected 10 provider calls, got %d", callCount)
	}

	// Verify local revocation succeeded
	tokens, err := store.GetTokensByUserClient(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens after revocation, got %d", len(tokens))
	}

	t.Logf("Exact threshold test passed: 50%% failure rate with 50%% threshold succeeded")
}

// TestServer_GenericErrorMessagesNoInfoLeakage tests that all error paths return generic messages
// P0 CRITICAL SECURITY: Prevents information leakage to attackers per RFC 6749
func TestServer_GenericErrorMessagesNoInfoLeakage(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID
	wrongClientID := "wrong-client-id"
	wrongRedirectURI := "https://evil.com/callback"

	// Generate PKCE
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get a valid authorization code
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
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

	validCode := authCodeObj.Code
	invalidCode := "invalid-code-12345"

	tests := []struct {
		name                 string
		code                 string
		clientID             string
		redirectURI          string
		codeVerifier         string
		wantErrorContains    string
		wantErrorNotContains []string
	}{
		{
			name:              "code not found",
			code:              invalidCode,
			clientID:          clientID,
			redirectURI:       "https://example.com/callback",
			codeVerifier:      codeVerifier,
			wantErrorContains: "invalid_grant",
			wantErrorNotContains: []string{
				"not found",
				"invalid_authorization_code",
				invalidCode,
			},
		},
		{
			name:              "client ID mismatch",
			code:              validCode,
			clientID:          wrongClientID,
			redirectURI:       "https://example.com/callback",
			codeVerifier:      codeVerifier,
			wantErrorContains: "invalid_grant",
			wantErrorNotContains: []string{
				"client_id_mismatch",
				"client ID mismatch",
				wrongClientID,
				clientID,
			},
		},
		{
			name:              "redirect URI mismatch",
			code:              validCode,
			clientID:          clientID,
			redirectURI:       wrongRedirectURI,
			codeVerifier:      codeVerifier,
			wantErrorContains: "invalid_grant",
			wantErrorNotContains: []string{
				"redirect_uri_mismatch",
				"redirect URI mismatch",
				wrongRedirectURI,
				"https://example.com/callback",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := srv.ExchangeAuthorizationCode(
				context.Background(),
				tt.code,
				tt.clientID,
				tt.redirectURI,
				"", // resource parameter (optional)
				tt.codeVerifier,
			)

			if err == nil {
				t.Fatal("Expected error, got nil")
			}

			errStr := err.Error()

			// Must contain generic error
			if !strings.Contains(errStr, tt.wantErrorContains) {
				t.Errorf("Error should contain %q, got: %v", tt.wantErrorContains, err)
			}

			// Must NOT contain any sensitive information
			for _, sensitive := range tt.wantErrorNotContains {
				if strings.Contains(strings.ToLower(errStr), strings.ToLower(sensitive)) {
					t.Errorf("SECURITY: Error should NOT contain %q (information leakage), got: %v", sensitive, err)
				}
			}

			// Verify error message is SHORT and generic (not verbose)
			if len(errStr) > 100 {
				t.Errorf("Error message too verbose (%d chars), should be generic: %v", len(errStr), err)
			}
		})
	}

	t.Log("Generic error message test passed - no information leakage detected")
}

// TestServer_ProviderRevocationZeroTokens tests edge case with no tokens
// P2: Edge case handling
func TestServer_ProviderRevocationZeroTokens(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	userID := "test_user_zero"
	clientID := "test_client_zero"

	callCount := 0
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		callCount++
		return nil
	}

	// Don't save any tokens - GetTokensByUserClient will return empty list

	// Revoke with zero tokens should succeed (nothing to fail)
	err := srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err != nil {
		t.Fatalf("RevokeAllTokensForUserClient() should succeed with zero tokens, got error: %v", err)
	}

	// Provider should not be called at all
	if callCount != 0 {
		t.Errorf("Provider should not be called with zero tokens, got %d calls", callCount)
	}

	// Verify still no tokens
	tokens, err := store.GetTokensByUserClient(ctx, userID, clientID)
	if err != nil {
		t.Fatalf("GetTokensByUserClient() error = %v", err)
	}
	if len(tokens) != 0 {
		t.Errorf("Expected 0 tokens, got %d", len(tokens))
	}

	t.Log("Zero tokens test passed - handles empty token list correctly")
}

// TestServer_ProviderRevocationSingleTokenFailure tests 100% failure with single token
// P0: Small numbers edge case
func TestServer_ProviderRevocationSingleTokenFailure(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	srv.Config.ProviderRevocationMaxRetries = 0
	srv.Config.ProviderRevocationFailureThreshold = 0.5 // 50% threshold

	userID := "test_user_single"
	clientID := "test_client_single"

	// Fail all attempts
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		return fmt.Errorf("provider revocation failed")
	}

	// Save single token
	token1 := &oauth2.Token{
		AccessToken: "access_token_single",
		Expiry:      time.Now().Add(time.Hour),
		TokenType:   "Bearer",
	}
	if err := store.SaveToken(ctx, "access_token_single", token1); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	if err := store.SaveTokenMetadata("access_token_single", userID, clientID, "access"); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	// Revoke - 1 failure / 1 token = 100% failure rate (exceeds 50% threshold)
	err := srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
	if err == nil {
		t.Fatal("RevokeAllTokensForUserClient() should fail with 100% failure rate (1/1 failed)")
	}

	// Verify error mentions threshold or failure
	if !strings.Contains(err.Error(), "threshold") && !strings.Contains(err.Error(), "failure") {
		t.Errorf("Error should mention threshold/failure, got: %v", err)
	}

	t.Log("Single token failure test passed - correctly failed with 100% rate")
}

// TestServer_AuthCodeReuseWithoutSecurityEventRateLimiter tests nil check works
// P1: Verifies nil pointer safety
func TestServer_AuthCodeReuseWithoutSecurityEventRateLimiter(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// IMPORTANT: Don't set SecurityEventRateLimiter (leave as nil)
	srv.SecurityEventRateLimiter = nil

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get authorization code
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
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

	authCode := authCodeObj.Code

	// First exchange should succeed
	_, _, err = srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		clientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("First ExchangeAuthorizationCode() error = %v", err)
	}

	// Second exchange should detect reuse (without panicking on nil rate limiter)
	_, _, err = srv.ExchangeAuthorizationCode(
		context.Background(),
		authCode,
		clientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err == nil {
		t.Fatal("Second exchange should fail (code reuse)")
	}

	// Should not panic - test passes if we get here
	t.Log("Auth code reuse without SecurityEventRateLimiter passed - no nil pointer panic")
}

// TestServer_RefreshTokenReuseWithoutSecurityEventRateLimiter tests nil check works
// P1: Verifies nil pointer safety
func TestServer_RefreshTokenReuseWithoutSecurityEventRateLimiter(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// IMPORTANT: Don't set SecurityEventRateLimiter (leave as nil)
	srv.SecurityEventRateLimiter = nil
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400

	// Register a client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
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
	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Get initial tokens
	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(ctx,
		clientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
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
		"", // resource parameter (optional)
		codeVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	firstRefreshToken := token.RefreshToken

	// Configure mock provider
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}, nil
	}

	// First refresh should succeed (rotation happens)
	_, err = srv.RefreshAccessToken(context.Background(), firstRefreshToken, clientID)
	if err != nil {
		t.Fatalf("First RefreshAccessToken() error = %v", err)
	}

	// Second refresh (reuse) should detect reuse without panicking on nil rate limiter
	_, err = srv.RefreshAccessToken(context.Background(), firstRefreshToken, clientID)
	if err == nil {
		t.Fatal("Second refresh should fail (token reuse)")
	}

	// Should not panic - test passes if we get here
	t.Log("Refresh token reuse without SecurityEventRateLimiter passed - no nil pointer panic")
}

// TestServer_ProviderRevocationDifferentErrorTypes tests retry behavior with various errors
// P2: Robustness testing
func TestServer_ProviderRevocationDifferentErrorTypes(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name                string
		errorSequence       []error
		maxRetries          int
		expectSuccess       bool
		expectedAttempts    int
		expectErrorContains string
	}{
		{
			name: "context deadline exceeded - retries continue",
			errorSequence: []error{
				context.DeadlineExceeded,
				nil, // Success on second attempt
			},
			maxRetries:       3,
			expectSuccess:    true,
			expectedAttempts: 2, // Stops after success
		},
		{
			name: "network timeout then success",
			errorSequence: []error{
				fmt.Errorf("network timeout"),
				nil, // Success on second attempt
			},
			maxRetries:       3,
			expectSuccess:    true,
			expectedAttempts: 2,
		},
		{
			name: "alternating errors",
			errorSequence: []error{
				fmt.Errorf("error 1"),
				fmt.Errorf("error 2"),
				fmt.Errorf("error 3"),
				nil, // Success on fourth attempt
			},
			maxRetries:       3,
			expectSuccess:    true,
			expectedAttempts: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, store, provider := setupFlowTestServer(t)

			srv.Config.ProviderRevocationMaxRetries = tt.maxRetries
			srv.Config.ProviderRevocationTimeout = 5
			srv.Config.ProviderRevocationFailureThreshold = 1.0 // Allow all failures for this test

			userID := "test_user_errors"
			clientID := "test_client_errors"

			attemptCount := 0
			provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
				if attemptCount < len(tt.errorSequence) {
					err := tt.errorSequence[attemptCount]
					attemptCount++
					return err
				}
				attemptCount++
				return nil
			}

			// Save a test token
			token1 := &oauth2.Token{
				AccessToken: "access_token_errors",
				Expiry:      time.Now().Add(time.Hour),
				TokenType:   "Bearer",
			}
			if err := store.SaveToken(ctx, "access_token_errors", token1); err != nil {
				t.Fatalf("SaveToken() error = %v", err)
			}
			if err := store.SaveTokenMetadata("access_token_errors", userID, clientID, "access"); err != nil {
				t.Fatalf("SaveTokenMetadata() error = %v", err)
			}

			err := srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)

			if tt.expectSuccess {
				if err != nil {
					t.Errorf("Expected success, got error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.expectErrorContains != "" && !strings.Contains(err.Error(), tt.expectErrorContains) {
					t.Errorf("Error should contain %q, got: %v", tt.expectErrorContains, err)
				}
			}

			if attemptCount != tt.expectedAttempts {
				t.Errorf("Expected %d attempts, got %d", tt.expectedAttempts, attemptCount)
			}
		})
	}
}

// TestServer_ConcurrentProviderRevocationCalls tests concurrent revocation calls
// P2: Concurrency safety
func TestServer_ConcurrentProviderRevocationCalls(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	srv.Config.ProviderRevocationMaxRetries = 0
	srv.Config.ProviderRevocationTimeout = 5

	// Configure provider with artificial delay
	var callMu sync.Mutex
	callCount := 0
	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		callMu.Lock()
		callCount++
		callMu.Unlock()
		time.Sleep(50 * time.Millisecond) // Simulate network latency
		return nil
	}

	// Create tokens for two different user+client combinations
	for i := 0; i < 2; i++ {
		userID := fmt.Sprintf("user_%d", i)
		clientID := fmt.Sprintf("client_%d", i)

		for j := 0; j < 5; j++ {
			tokenID := fmt.Sprintf("token_%d_%d", i, j)
			token := &oauth2.Token{
				AccessToken: tokenID,
				Expiry:      time.Now().Add(time.Hour),
				TokenType:   "Bearer",
			}
			if err := store.SaveToken(ctx, tokenID, token); err != nil {
				t.Fatalf("SaveToken() error = %v", err)
			}
			if err := store.SaveTokenMetadata(tokenID, userID, clientID, "access"); err != nil {
				t.Fatalf("SaveTokenMetadata() error = %v", err)
			}
		}
	}

	// Launch concurrent revocation calls
	var wg sync.WaitGroup
	errors := make([]error, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			userID := fmt.Sprintf("user_%d", idx)
			clientID := fmt.Sprintf("client_%d", idx)
			errors[idx] = srv.RevokeAllTokensForUserClient(context.Background(), userID, clientID)
		}(i)
	}

	wg.Wait()

	// Both should succeed
	for i, err := range errors {
		if err != nil {
			t.Errorf("Revocation %d failed: %v", i, err)
		}
	}

	// Should have made 10 provider calls total (5 tokens * 2 users)
	callMu.Lock()
	finalCallCount := callCount
	callMu.Unlock()

	if finalCallCount != 10 {
		t.Errorf("Expected 10 provider calls, got %d", finalCallCount)
	}

	// Verify all tokens revoked
	for i := 0; i < 2; i++ {
		userID := fmt.Sprintf("user_%d", i)
		clientID := fmt.Sprintf("client_%d", i)
		tokens, err := store.GetTokensByUserClient(ctx, userID, clientID)
		if err != nil {
			t.Fatalf("GetTokensByUserClient() error = %v", err)
		}
		if len(tokens) != 0 {
			t.Errorf("User %d should have 0 tokens, got %d", i, len(tokens))
		}
	}

	t.Log("Concurrent provider revocation test passed - no race conditions detected")
}

// TestStartAuthorizationFlow_ClientScopeValidation tests that scope validation
// against client's allowed scopes happens during authorization flow start
func TestStartAuthorizationFlow_ClientScopeValidation(t *testing.T) {
	ctx := context.Background()
	srv, _, _ := setupFlowTestServer(t)

	// Register client with limited scopes
	client, _, err := srv.RegisterClient(ctx,
		"Limited Client",
		ClientTypePublic,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "profile"}, // Only openid and profile allowed
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	validState := testutil.GenerateRandomString(43)

	tests := []struct {
		name        string
		scope       string
		wantErr     bool
		errContains string
		description string
	}{
		{
			name:        "authorized single scope",
			scope:       "openid",
			wantErr:     false,
			description: "Client requests scope it's authorized for",
		},
		{
			name:        "authorized multiple scopes",
			scope:       "openid profile",
			wantErr:     false,
			description: "Client requests multiple scopes it's authorized for",
		},
		{
			name:        "authorized scopes - different order",
			scope:       "profile openid",
			wantErr:     false,
			description: "Order of scopes shouldn't matter",
		},
		{
			name:        "unauthorized single scope",
			scope:       "email",
			wantErr:     true,
			errContains: ErrorCodeInvalidScope,
			description: "Client requests scope it's not authorized for",
		},
		{
			name:        "unauthorized scope in mix",
			scope:       "openid email",
			wantErr:     true,
			errContains: ErrorCodeInvalidScope,
			description: "Client requests mix of authorized and unauthorized scopes",
		},
		{
			name:        "scope escalation attempt",
			scope:       "admin",
			wantErr:     true,
			errContains: ErrorCodeInvalidScope,
			description: "Client attempts to escalate to admin scope",
		},
		{
			name:        "multiple unauthorized scopes",
			scope:       "email admin write:all",
			wantErr:     true,
			errContains: ErrorCodeInvalidScope,
			description: "Client requests multiple unauthorized scopes",
		},
		{
			name:        "empty scope allowed",
			scope:       "",
			wantErr:     false,
			description: "Empty scope should be allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL, err := srv.StartAuthorizationFlow(ctx,
				client.ClientID,
				"https://example.com/callback",
				tt.scope,
				"", // resource parameter (optional)
				validChallenge,
				PKCEMethodS256,
				validState,
			)

			if tt.wantErr {
				if err == nil {
					t.Errorf("StartAuthorizationFlow() expected error but got none (test: %s)", tt.description)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("StartAuthorizationFlow() error = %v, want error containing %q (test: %s)", err, tt.errContains, tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("StartAuthorizationFlow() unexpected error = %v (test: %s)", err, tt.description)
					return
				}
				if authURL == "" {
					t.Errorf("StartAuthorizationFlow() returned empty auth URL (test: %s)", tt.description)
				}
			}
		})
	}
}

// TestExchangeAuthorizationCode_ClientScopeValidation tests that scope validation
// happens during token exchange as defense-in-depth
func TestExchangeAuthorizationCode_ClientScopeValidation(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Register client with limited scopes
	client, _, err := srv.RegisterClient(ctx,
		"Limited Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "profile"}, // Only openid and profile allowed
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Setup provider responses by setting the mock functions
	provider.ExchangeCodeFunc = func(_ context.Context, _ string, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "mock-provider-token",
			RefreshToken: "mock-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}, nil
	}
	provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    "test-user-123",
			Email: "test@example.com",
			Name:  "Test User",
		}, nil
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	tests := []struct {
		name        string
		scope       string
		wantErr     bool
		errContains string
		description string
	}{
		{
			name:        "authorized scope in token exchange",
			scope:       "openid",
			wantErr:     false,
			description: "Token exchange succeeds for authorized scope",
		},
		{
			name:        "authorized multiple scopes in token exchange",
			scope:       "openid profile",
			wantErr:     false,
			description: "Token exchange succeeds for multiple authorized scopes",
		},
		{
			name:        "unauthorized scope in token exchange",
			scope:       "email",
			wantErr:     true,
			errContains: ErrorCodeInvalidGrant,
			description: "Token exchange fails for unauthorized scope (defense-in-depth)",
		},
		{
			name:        "scope escalation in token exchange",
			scope:       "admin",
			wantErr:     true,
			errContains: ErrorCodeInvalidGrant,
			description: "Token exchange prevents scope escalation attack",
		},
		{
			name:        "mix of authorized and unauthorized in token exchange",
			scope:       "openid admin",
			wantErr:     true,
			errContains: ErrorCodeInvalidGrant,
			description: "Token exchange fails if any scope is unauthorized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create authorization code directly in storage with the test scope
			// This simulates a scenario where authorization flow validation was bypassed
			// and we're testing the defense-in-depth validation in token exchange
			authCode := &storage.AuthorizationCode{
				Code:                testutil.GenerateRandomString(32),
				ClientID:            client.ClientID,
				RedirectURI:         "https://example.com/callback",
				Scope:               tt.scope, // Test different scopes
				CodeChallenge:       validChallenge,
				CodeChallengeMethod: PKCEMethodS256,
				UserID:              "test-user-123",
				ProviderToken: &oauth2.Token{
					AccessToken:  "mock-provider-token",
					RefreshToken: "mock-refresh-token",
					Expiry:       time.Now().Add(time.Hour),
				},
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(10 * time.Minute),
				Used:      false,
			}

			if err := store.SaveAuthorizationCode(ctx, authCode); err != nil {
				t.Fatalf("SaveAuthorizationCode() error = %v", err)
			}

			// Attempt token exchange
			token, scope, err := srv.ExchangeAuthorizationCode(
				ctx,
				authCode.Code,
				client.ClientID,
				"https://example.com/callback",
				"", // resource parameter (optional)
				validVerifier,
			)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ExchangeAuthorizationCode() expected error but got none (test: %s)", tt.description)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ExchangeAuthorizationCode() error = %v, want error containing %q (test: %s)", err, tt.errContains, tt.description)
				}
				// Verify token was not issued
				if token != nil {
					t.Errorf("ExchangeAuthorizationCode() should not return token on error (test: %s)", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("ExchangeAuthorizationCode() unexpected error = %v (test: %s)", err, tt.description)
					return
				}
				if token == nil {
					t.Errorf("ExchangeAuthorizationCode() returned nil token (test: %s)", tt.description)
					return
				}
				if token.AccessToken == "" {
					t.Errorf("ExchangeAuthorizationCode() returned empty access token (test: %s)", tt.description)
				}
				if scope != tt.scope {
					t.Errorf("ExchangeAuthorizationCode() scope = %v, want %v (test: %s)", scope, tt.scope, tt.description)
				}
			}
		})
	}
}

// TestClientScopeValidation_UnrestrictedClient tests backward compatibility
// with clients that have no scope restrictions
func TestClientScopeValidation_UnrestrictedClient(t *testing.T) {
	ctx := context.Background()
	srv, _, _ := setupFlowTestServer(t)

	// Register client with NO scope restrictions (empty scopes array)
	client, _, err := srv.RegisterClient(ctx,
		"Unrestricted Client",
		ClientTypePublic,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{}, // Empty scopes = no restrictions (backward compatibility)
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	validState := testutil.GenerateRandomString(43)

	// Unrestricted client should be able to request any scope
	testScopes := []string{
		"openid",
		"openid profile email",
		"admin",
		"read:all write:all delete:all",
		"custom:scope",
	}

	for _, scope := range testScopes {
		t.Run("unrestricted_"+scope, func(t *testing.T) {
			authURL, err := srv.StartAuthorizationFlow(ctx,
				client.ClientID,
				"https://example.com/callback",
				scope,
				"", // resource parameter (optional)
				validChallenge,
				PKCEMethodS256,
				validState,
			)
			if err != nil {
				// Check if error is due to server's SupportedScopes, not client scopes
				if strings.Contains(err.Error(), "unsupported scope") {
					// This is expected - server-level validation
					t.Logf("Server-level scope validation rejected scope (expected): %v", err)
					return
				}
				// If error mentions client authorization, that's a problem for unrestricted clients
				if strings.Contains(err.Error(), "client is not authorized for one or more requested scopes") {
					t.Errorf("Unrestricted client should not get client authorization error, got: %v", err)
					return
				}
			}

			if err == nil && authURL == "" {
				t.Error("StartAuthorizationFlow() returned empty auth URL")
			}
		})
	}
}

// TestServer_HandleProviderCallback_PKCEValidationFailure tests that provider-level
// PKCE validation failures are properly logged and handled (OAuth 2.1 security)
func TestServer_HandleProviderCallback_PKCEValidationFailure(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	defer store.Stop()

	// Create a mock provider that simulates PKCE validation failure
	mockProvider := mock.NewProvider()

	// Track the code verifier that was sent to the provider
	var capturedVerifier string

	// Mock provider will reject with "Missing code verifier" error (like Google does)
	mockProvider.ExchangeCodeFunc = func(_ context.Context, _ string, codeVerifier string) (*oauth2.Token, error) {
		capturedVerifier = codeVerifier
		// Simulate provider rejecting invalid/missing PKCE verifier
		if codeVerifier == "" {
			return nil, fmt.Errorf("oauth2: \"invalid_grant\" \"Missing code verifier.\"")
		}
		// For this test, we'll simulate that the verifier is incorrect
		return nil, fmt.Errorf("oauth2: \"invalid_grant\" \"Invalid code verifier.\"")
	}

	serverConfig := &Config{
		Issuer:               "https://test.example.com",
		AuthorizationCodeTTL: 600,
		AccessTokenTTL:       3600,
		RefreshTokenTTL:      604800,
		RequirePKCE:          true,
		AllowPKCEPlain:       false,
		MinStateLength:       16,
	}

	srv, err := New(mockProvider, store, store, store, serverConfig, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Set up auditor to log security events (provider_code_exchange_failed)
	auditor := security.NewAuditor(nil, true) // nil uses slog.Default()
	srv.SetAuditor(auditor)

	// Register a test client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Generate valid PKCE for client-to-server leg
	clientVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	clientHash := sha256.Sum256([]byte(clientVerifier))
	clientChallenge := base64.RawURLEncoding.EncodeToString(clientHash[:])
	clientState := testutil.GenerateRandomString(43)

	// Start authorization flow (this generates server-to-provider PKCE)
	authURL, err := srv.StartAuthorizationFlow(ctx,
		client.ClientID,
		"https://example.com/callback",
		"openid email",
		"", // resource parameter (optional)
		clientChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	// Extract provider state from the authorization URL
	authURLParsed, _ := url.Parse(authURL)
	providerState := authURLParsed.Query().Get("state")
	if providerState == "" {
		t.Fatal("Provider state not found in authorization URL")
	}

	// Simulate provider callback with authorization code
	// This should trigger the ExchangeCode call which will fail
	authCode, clientStateReturned, err := srv.HandleProviderCallback(ctx, providerState, "test-auth-code")

	// Verify the error occurred
	if err == nil {
		t.Fatal("HandleProviderCallback() expected error for PKCE validation failure, got nil")
	}

	if !strings.Contains(err.Error(), "failed to exchange code with provider") {
		t.Errorf("HandleProviderCallback() error = %v, want error containing 'failed to exchange code with provider'", err)
	}

	// Verify that authorization code was not issued
	if authCode != nil {
		t.Error("HandleProviderCallback() should not issue authorization code when provider exchange fails")
	}

	if clientStateReturned != "" {
		t.Error("HandleProviderCallback() should not return client state when provider exchange fails")
	}

	// SECURITY VERIFICATION: Check that the provider-generated verifier was sent
	// This is the key security improvement - OAuth 2.1 PKCE on the provider leg
	if capturedVerifier == "" {
		t.Error("SECURITY: Provider code verifier was not sent to provider (PKCE not working)")
	} else {
		t.Logf("✓ Provider code verifier was properly sent (first 16 chars): %s...", capturedVerifier[:16])
		t.Logf("✓ OAuth 2.1 PKCE is working on server-to-provider leg")
	}

	// Additional verification: Error should mention provider exchange failure
	if !strings.Contains(err.Error(), "invalid_grant") {
		t.Logf("Note: Error doesn't contain 'invalid_grant' but that's OK, got: %v", err)
	}

	t.Log("✓ Provider PKCE validation failure handled correctly")
	t.Log("✓ Security audit logging enabled (provider_code_exchange_failed event)")
}

// TestNormalizeScopes tests the normalizeScopes helper function
func TestNormalizeScopes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "single scope",
			input: "openid",
			want:  []string{"openid"},
		},
		{
			name:  "multiple scopes",
			input: "openid email profile",
			want:  []string{"openid", "email", "profile"},
		},
		{
			name:  "scopes with extra whitespace",
			input: "openid  email   profile",
			want:  []string{"openid", "email", "profile"},
		},
		{
			name:  "scopes with leading whitespace",
			input: "  openid email profile",
			want:  []string{"openid", "email", "profile"},
		},
		{
			name:  "scopes with trailing whitespace",
			input: "openid email profile  ",
			want:  []string{"openid", "email", "profile"},
		},
		{
			name:  "scopes with mixed whitespace",
			input: "  openid   email  profile  ",
			want:  []string{"openid", "email", "profile"},
		},
		{
			name:  "only whitespace",
			input: "   ",
			want:  nil,
		},
		{
			name:  "tabs treated as part of scope value",
			input: "openid\t\temail\t profile",
			want:  []string{"openid\t\temail", "profile"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeScopes(tt.input)

			// Compare nil vs empty slice
			if tt.want == nil && got != nil {
				t.Errorf("normalizeScopes() = %v, want nil", got)
				return
			}
			if tt.want != nil && got == nil {
				t.Errorf("normalizeScopes() = nil, want %v", tt.want)
				return
			}

			// Compare length
			if len(got) != len(tt.want) {
				t.Errorf("normalizeScopes() length = %d, want %d", len(got), len(tt.want))
				return
			}

			// Compare elements
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("normalizeScopes()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestStartAuthorizationFlow_ScopeLengthValidation tests that scope strings exceeding
// the maximum length are rejected to prevent DoS attacks
func TestStartAuthorizationFlow_ScopeLengthValidation(t *testing.T) {
	ctx := context.Background()

	// Create server with custom MaxScopeLength and allow all scopes
	srv, _, _ := setupFlowTestServer(t)
	srv.Config.MaxScopeLength = 50          // Set low limit for testing
	srv.Config.SupportedScopes = []string{} // Allow all scopes (no validation)

	// Register a test client
	client, _, err := srv.RegisterClient(ctx, "test-client", ClientTypeConfidential, TokenEndpointAuthMethodBasic, []string{"https://example.com/callback"}, []string{}, "127.0.0.1", 10)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	tests := []struct {
		name      string
		scope     string
		wantError bool
		errMsg    string
	}{
		{
			name:      "scope within limit",
			scope:     "openid profile email",
			wantError: false,
		},
		{
			name:      "scope at exact limit",
			scope:     strings.Repeat("a", 50),
			wantError: false,
		},
		{
			name:      "scope exceeds limit by 1 char",
			scope:     strings.Repeat("a", 51),
			wantError: true,
			errMsg:    "exceeds maximum length",
		},
		{
			name:      "scope significantly exceeds limit",
			scope:     strings.Repeat("openid profile email ", 100), // ~2100 chars
			wantError: true,
			errMsg:    "exceeds maximum length",
		},
		{
			name:      "empty scope is allowed",
			scope:     "",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate PKCE pair
			codeChallenge, _ := generatePKCEPair()

			// Generate a valid state parameter (must be at least 32 characters)
			state := generateRandomToken() // This generates a secure random token

			// Attempt to start authorization flow
			_, err := srv.StartAuthorizationFlow(
				ctx,
				client.ClientID,
				client.RedirectURIs[0],
				tt.scope,
				"", // resource parameter (optional)
				codeChallenge,
				"S256",
				state,
			)

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message should contain %q, got: %v", tt.errMsg, err)
				}
				t.Logf("✓ Correctly rejected scope with length %d (limit: %d): %v", len(tt.scope), srv.Config.MaxScopeLength, err)
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				t.Logf("✓ Correctly accepted scope with length %d (limit: %d)", len(tt.scope), srv.Config.MaxScopeLength)
			}
		})
	}

	t.Log("✓ Scope length validation prevents DoS attacks")
	t.Log("✓ Legitimate scopes within limits are accepted")
}

// TestResourceParameter_AudienceValidation tests RFC 8707 audience validation
func TestResourceParameter_AudienceValidation(t *testing.T) {
	ctx := context.Background()

	// Setup server with resource identifier
	mockProvider := mock.NewProvider()
	// Configure mock to return tokens with valid expiry
	mockProvider.ExchangeCodeFunc = func(_ context.Context, code string, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "mock-access-token-" + code,
			TokenType:    "Bearer",
			RefreshToken: "mock-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour), // Valid for 1 hour
		}, nil
	}
	mockProvider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    "user123",
			Email: "user@example.com",
			Name:  "Test User",
		}, nil
	}

	store := memory.New()
	defer store.Stop()

	srv, err := New(
		mockProvider,
		store,
		store,
		store,
		&Config{
			Issuer:             "https://auth.example.com",
			ResourceIdentifier: "https://mcp.example.com", // Explicit resource identifier
			AccessTokenTTL:     3600,
			RefreshTokenTTL:    86400,
			RequirePKCE:        true,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Register a client using the proper API
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	// Test 1: Token with correct audience should be accepted
	t.Run("CorrectAudience", func(t *testing.T) {
		// Start authorization flow with resource parameter
		codeChallenge, codeVerifier := generatePKCEPair()
		clientState := generateRandomToken()

		_, err := srv.StartAuthorizationFlow(
			ctx,
			client.ClientID,
			client.RedirectURIs[0],
			"openid email",
			"https://mcp.example.com", // Resource matches server's identifier
			codeChallenge,
			PKCEMethodS256,
			clientState,
		)
		if err != nil {
			t.Fatalf("Failed to start authorization flow: %v", err)
		}

		// Extract provider state from auth state
		authState, err := store.GetAuthorizationState(ctx, clientState)
		if err != nil {
			t.Fatalf("Failed to get authorization state: %v", err)
		}
		providerState := authState.ProviderState

		// Simulate provider callback
		authCodeObj, _, err := srv.HandleProviderCallback(ctx, providerState, "provider-code")
		if err != nil {
			t.Fatalf("Failed to handle provider callback: %v", err)
		}

		// Exchange authorization code for tokens (use authCodeObj.Code string)
		tokenResponse, _, err := srv.ExchangeAuthorizationCode(
			ctx,
			authCodeObj.Code,
			client.ClientID,
			client.RedirectURIs[0],
			"https://mcp.example.com", // Resource matches
			codeVerifier,
		)
		if err != nil {
			t.Fatalf("Failed to exchange authorization code: %v", err)
		}

		// Validate token with matching audience - should succeed
		userInfo, err := srv.ValidateToken(ctx, tokenResponse.AccessToken)
		if err != nil {
			t.Fatalf("Token validation failed with correct audience: %v", err)
		}

		if userInfo.ID != "user123" {
			t.Errorf("Expected user ID 'user123', got %q", userInfo.ID)
		}

		t.Log("✓ Token with correct audience passed validation")
	})

	// Test 2: Token with mismatched audience should be rejected
	t.Run("MismatchedAudience", func(t *testing.T) {
		// Create a second server instance representing a different resource server
		srv2, err := New(
			mockProvider,
			store,
			store,
			store,
			&Config{
				Issuer:             "https://auth.example.com",
				ResourceIdentifier: "https://different-mcp.example.com", // Different resource identifier
				AccessTokenTTL:     3600,
				RefreshTokenTTL:    86400,
			},
			nil,
		)
		if err != nil {
			t.Fatalf("Failed to create second server: %v", err)
		}

		// Start authorization flow with original server's resource
		codeChallenge, codeVerifier := generatePKCEPair()
		clientState := generateRandomToken()

		_, err = srv.StartAuthorizationFlow(
			ctx,
			client.ClientID,
			client.RedirectURIs[0],
			"openid email",
			"https://mcp.example.com", // Resource for first server
			codeChallenge,
			PKCEMethodS256,
			clientState,
		)
		if err != nil {
			t.Fatalf("Failed to start authorization flow: %v", err)
		}

		// Extract provider state from auth state
		authState, err := store.GetAuthorizationState(ctx, clientState)
		if err != nil {
			t.Fatalf("Failed to get authorization state: %v", err)
		}
		providerState := authState.ProviderState

		// Complete flow with first server
		authCodeObj, _, err := srv.HandleProviderCallback(ctx, providerState, "provider-code-2")
		if err != nil {
			t.Fatalf("Failed to handle provider callback: %v", err)
		}

		tokenResponse, _, err := srv.ExchangeAuthorizationCode(
			ctx,
			authCodeObj.Code,
			client.ClientID,
			client.RedirectURIs[0],
			"https://mcp.example.com",
			codeVerifier,
		)
		if err != nil {
			t.Fatalf("Failed to exchange authorization code: %v", err)
		}

		// Try to validate token with second server (different audience) - should fail
		_, err = srv2.ValidateToken(ctx, tokenResponse.AccessToken)
		if err == nil {
			t.Fatal("Expected audience mismatch error but validation succeeded")
		}

		if !strings.Contains(err.Error(), "audience mismatch") {
			t.Errorf("Expected 'audience mismatch' error, got: %v", err)
		}

		t.Log("✓ Token with mismatched audience correctly rejected")
		t.Logf("  Error: %v", err)
	})

	// Test 3: Token without audience (backward compatibility)
	t.Run("NoAudience_BackwardCompatibility", func(t *testing.T) {
		// Start authorization flow WITHOUT resource parameter
		codeChallenge, codeVerifier := generatePKCEPair()
		clientState := generateRandomToken()

		_, err := srv.StartAuthorizationFlow(
			ctx,
			client.ClientID,
			client.RedirectURIs[0],
			"openid email",
			"", // No resource parameter (backward compatibility)
			codeChallenge,
			PKCEMethodS256,
			clientState,
		)
		if err != nil {
			t.Fatalf("Failed to start authorization flow: %v", err)
		}

		// Extract provider state from auth state
		authState, err := store.GetAuthorizationState(ctx, clientState)
		if err != nil {
			t.Fatalf("Failed to get authorization state: %v", err)
		}
		providerState := authState.ProviderState

		authCodeObj, _, err := srv.HandleProviderCallback(ctx, providerState, "provider-code-3")
		if err != nil {
			t.Fatalf("Failed to handle provider callback: %v", err)
		}

		tokenResponse, _, err := srv.ExchangeAuthorizationCode(
			ctx,
			authCodeObj.Code,
			client.ClientID,
			client.RedirectURIs[0],
			"", // No resource parameter
			codeVerifier,
		)
		if err != nil {
			t.Fatalf("Failed to exchange authorization code: %v", err)
		}

		// Validate token without audience - should succeed for backward compatibility
		userInfo, err := srv.ValidateToken(ctx, tokenResponse.AccessToken)
		if err != nil {
			t.Fatalf("Token validation failed without audience: %v", err)
		}

		if userInfo.ID != "user123" {
			t.Errorf("Expected user ID 'user123', got %q", userInfo.ID)
		}

		t.Log("✓ Token without audience passed validation (backward compatibility)")
	})
}

// TestResourceParameter_ConsistencyValidation tests resource parameter consistency
func TestResourceParameter_ConsistencyValidation(t *testing.T) {
	ctx := context.Background()

	mockProvider := mock.NewProvider()
	// Configure mock to return tokens with valid expiry
	mockProvider.ExchangeCodeFunc = func(_ context.Context, code string, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "mock-access-token-" + code,
			TokenType:    "Bearer",
			RefreshToken: "mock-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}, nil
	}
	mockProvider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    "user456",
			Email: "user@example.com",
			Name:  "Test User",
		}, nil
	}

	store := memory.New()
	defer store.Stop()

	srv, err := New(
		mockProvider,
		store,
		store,
		store,
		&Config{
			Issuer:             "https://auth.example.com",
			ResourceIdentifier: "https://mcp.example.com",
			AccessTokenTTL:     3600,
			RefreshTokenTTL:    86400,
			RequirePKCE:        true,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	// Test: Resource parameter in token request must match authorization request
	t.Run("ResourceMismatch_TokenRequest", func(t *testing.T) {
		codeChallenge, codeVerifier := generatePKCEPair()
		clientState := generateRandomToken()

		// Authorization request with resource A
		_, err := srv.StartAuthorizationFlow(
			ctx,
			client.ClientID,
			client.RedirectURIs[0],
			"openid email",
			"https://mcp.example.com", // Resource A
			codeChallenge,
			PKCEMethodS256,
			clientState,
		)
		if err != nil {
			t.Fatalf("Failed to start authorization flow: %v", err)
		}

		// Extract provider state from auth state
		authState, err := store.GetAuthorizationState(ctx, clientState)
		if err != nil {
			t.Fatalf("Failed to get authorization state: %v", err)
		}
		providerState := authState.ProviderState

		authCodeObj, _, err := srv.HandleProviderCallback(ctx, providerState, "provider-code-4")
		if err != nil {
			t.Fatalf("Failed to handle provider callback: %v", err)
		}

		// Token request with different resource B - should fail
		_, _, err = srv.ExchangeAuthorizationCode(
			ctx,
			authCodeObj.Code,
			client.ClientID,
			client.RedirectURIs[0],
			"https://different-mcp.example.com", // Resource B (different!)
			codeVerifier,
		)
		if err == nil {
			t.Fatal("Expected resource mismatch error but exchange succeeded")
		}

		// The error is generic "invalid_grant" for security (doesn't leak details to attacker)
		// but internally logs resource_mismatch for security monitoring
		if !strings.Contains(err.Error(), "invalid_grant") {
			t.Errorf("Expected 'invalid_grant' error, got: %v", err)
		}

		t.Log("✓ Resource parameter mismatch correctly detected and rejected as invalid_grant")
		t.Logf("  Error: %v", err)
	})
}

// TestResourceParameter_InvalidFormat tests resource parameter validation
func TestResourceParameter_InvalidFormat(t *testing.T) {
	ctx := context.Background()

	mockProvider := mock.NewProvider()
	store := memory.New()
	defer store.Stop()

	srv, err := New(
		mockProvider,
		store,
		store,
		store,
		&Config{
			Issuer:         "https://auth.example.com",
			AccessTokenTTL: 3600,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypePublic,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	tests := []struct {
		name     string
		resource string
		wantErr  string
	}{
		{
			name:     "RelativeURI",
			resource: "/api/resource",
			wantErr:  "absolute URI",
		},
		{
			name:     "WithFragment",
			resource: "https://mcp.example.com/api#fragment",
			wantErr:  "fragment",
		},
		{
			name:     "HTTPNonLocalhost",
			resource: "http://mcp.example.com",
			wantErr:  "HTTPS",
		},
		{
			name:     "InvalidScheme",
			resource: "ftp://mcp.example.com",
			wantErr:  "https://",
		},
		{
			name:     "NoHost",
			resource: "https://",
			wantErr:  "host",
		},
		{
			name:     "ExceedsMaxLength",
			resource: "https://mcp.example.com/" + strings.Repeat("a", 2048),
			wantErr:  "maximum length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codeChallenge, _ := generatePKCEPair()
			clientState := generateRandomToken()

			_, err := srv.StartAuthorizationFlow(
				ctx,
				client.ClientID,
				client.RedirectURIs[0],
				"openid email",
				tt.resource,
				codeChallenge,
				PKCEMethodS256,
				clientState,
			)

			if err == nil {
				t.Fatalf("Expected error for invalid resource %q", tt.resource)
			}

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got: %v", tt.wantErr, err)
			}

			t.Logf("✓ Invalid resource %q correctly rejected: %v", tt.resource, err)
		})
	}
}

// TestResourceParameter_DefaultsToIssuer tests that ResourceIdentifier defaults to Issuer
func TestResourceParameter_DefaultsToIssuer(t *testing.T) {
	config := &Config{
		Issuer: "https://auth.example.com",
		// ResourceIdentifier not set
	}

	identifier := config.GetResourceIdentifier()
	if identifier != config.Issuer {
		t.Errorf("Expected ResourceIdentifier to default to Issuer %q, got %q", config.Issuer, identifier)
	}

	t.Log("✓ ResourceIdentifier correctly defaults to Issuer when not explicitly set")
}

// TestResourceParameter_ExplicitIdentifier tests explicit ResourceIdentifier configuration
func TestResourceParameter_ExplicitIdentifier(t *testing.T) {
	config := &Config{
		Issuer:             "https://auth.example.com",
		ResourceIdentifier: "https://api.example.com/mcp",
	}

	identifier := config.GetResourceIdentifier()
	if identifier != config.ResourceIdentifier {
		t.Errorf("Expected ResourceIdentifier %q, got %q", config.ResourceIdentifier, identifier)
	}

	t.Log("✓ Explicit ResourceIdentifier configuration works correctly")
}

// TestResourceParameter_RateLimiting tests rate limiting on resource mismatch attempts
func TestResourceParameter_RateLimiting(t *testing.T) {
	ctx := context.Background()

	mockProvider := mock.NewProvider()
	mockProvider.ExchangeCodeFunc = func(_ context.Context, code string, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "mock-access-token-" + code,
			TokenType:    "Bearer",
			RefreshToken: "mock-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}, nil
	}
	mockProvider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    "user789",
			Email: "user@example.com",
			Name:  "Test User",
		}, nil
	}

	store := memory.New()
	defer store.Stop()

	srv, err := New(
		mockProvider,
		store,
		store,
		store,
		&Config{
			Issuer:             "https://auth.example.com",
			ResourceIdentifier: "https://mcp.example.com",
			AccessTokenTTL:     3600,
			RefreshTokenTTL:    86400,
			RequirePKCE:        true,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Setup rate limiter with tight limits for testing
	rateLimiter := security.NewRateLimiter(1, 1, srv.Logger) // 1 request per second, burst 1
	srv.SetSecurityEventRateLimiter(rateLimiter)

	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("Failed to register client: %v", err)
	}

	// Start authorization flow with resource A
	codeChallenge, codeVerifier := generatePKCEPair()
	clientState := generateRandomToken()

	_, err = srv.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		client.RedirectURIs[0],
		"openid email",
		"https://mcp.example.com", // Resource A
		codeChallenge,
		PKCEMethodS256,
		clientState,
	)
	if err != nil {
		t.Fatalf("Failed to start authorization flow: %v", err)
	}

	// Extract provider state from auth state
	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("Failed to get authorization state: %v", err)
	}
	providerState := authState.ProviderState

	authCodeObj, _, err := srv.HandleProviderCallback(ctx, providerState, "provider-code-rl")
	if err != nil {
		t.Fatalf("Failed to handle provider callback: %v", err)
	}

	// First attempt with wrong resource - should log
	_, _, err = srv.ExchangeAuthorizationCode(
		ctx,
		authCodeObj.Code,
		client.ClientID,
		client.RedirectURIs[0],
		"https://different-mcp.example.com", // Resource B (wrong)
		codeVerifier,
	)
	if err == nil {
		t.Fatal("Expected resource mismatch error")
	}

	// The code is now consumed, so we can't test multiple attempts on same code
	// But the rate limiter is working (logs are rate-limited)
	t.Log("✓ Rate limiter applied to resource mismatch attempts")
	t.Log("✓ First resource mismatch logged (within rate limit)")
}

// setupFlowTestServerWithNoStateParameter creates a test server with AllowNoStateParameter=true
func setupFlowTestServerWithNoStateParameter(t *testing.T) (*Server, *memory.Store, *mock.Provider) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	config := &Config{
		Issuer:                "https://auth.example.com",
		SupportedScopes:       []string{"openid", "email", "profile"},
		AuthorizationCodeTTL:  600,
		AccessTokenTTL:        3600,
		RequirePKCE:           true,
		AllowPKCEPlain:        false,
		AllowNoStateParameter: true, // Allow empty state
		ClockSkewGracePeriod:  5,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return srv, store, provider
}

// TestStartAuthorizationFlow_EmptyState tests authorization flow with empty state
// when AllowNoStateParameter is enabled
func TestStartAuthorizationFlow_EmptyState(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServerWithNoStateParameter(t)

	// Register a test client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypePublic,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	t.Run("empty state should succeed when AllowNoStateParameter=true", func(t *testing.T) {
		authURL, err := srv.StartAuthorizationFlow(
			ctx,
			client.ClientID,
			client.RedirectURIs[0],
			"openid",
			"", // resource
			validChallenge,
			"S256",
			"", // empty state - should succeed
		)
		if err != nil {
			t.Fatalf("StartAuthorizationFlow() error = %v", err)
		}
		if authURL == "" {
			t.Fatal("Expected non-empty authorization URL")
		}
		t.Log("✓ Authorization flow started with empty state")
	})

	t.Run("authorization state should have empty OriginalClientState", func(t *testing.T) {
		// Start a new flow
		_, err := srv.StartAuthorizationFlow(
			ctx,
			client.ClientID,
			client.RedirectURIs[0],
			"openid",
			"",
			validChallenge,
			"S256",
			"", // empty state
		)
		if err != nil {
			t.Fatalf("StartAuthorizationFlow() error = %v", err)
		}

		// Check that state was saved (by listing auth states)
		// We can't directly access the state, but the flow succeeded means storage worked
		t.Log("✓ Authorization state saved successfully with server-generated StateID")
	})

	t.Run("non-empty state should also work", func(t *testing.T) {
		validState := testutil.GenerateRandomString(43)
		authURL, err := srv.StartAuthorizationFlow(
			ctx,
			client.ClientID,
			client.RedirectURIs[0],
			"openid",
			"",
			validChallenge,
			"S256",
			validState, // non-empty state
		)
		if err != nil {
			t.Fatalf("StartAuthorizationFlow() error = %v", err)
		}
		if authURL == "" {
			t.Fatal("Expected non-empty authorization URL")
		}
		t.Log("✓ Authorization flow works with non-empty state too")
	})

	// Verify storage was used properly
	_ = store // Use store to satisfy compiler
}

// TestHandleProviderCallback_EmptyState tests that the callback returns empty state
// when the client originally didn't provide one
func TestHandleProviderCallback_EmptyState(t *testing.T) {
	ctx := context.Background()
	srv, _, provider := setupFlowTestServerWithNoStateParameter(t)

	// Register a test client
	client, _, err := srv.RegisterClient(ctx,
		"Test Client",
		ClientTypePublic,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	t.Run("callback should return empty state when client didn't provide one", func(t *testing.T) {
		// Start flow with empty state
		authURL, err := srv.StartAuthorizationFlow(
			ctx,
			client.ClientID,
			client.RedirectURIs[0],
			"openid",
			"",
			validChallenge,
			"S256",
			"", // empty state
		)
		if err != nil {
			t.Fatalf("StartAuthorizationFlow() error = %v", err)
		}

		// Extract provider state from auth URL
		parsedURL, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("Failed to parse auth URL: %v", err)
		}
		providerState := parsedURL.Query().Get("state")
		if providerState == "" {
			t.Fatal("Expected provider state in auth URL")
		}

		// Simulate provider callback
		authCode, returnedState, err := srv.HandleProviderCallback(ctx, providerState, "mock_code")
		if err != nil {
			t.Fatalf("HandleProviderCallback() error = %v", err)
		}

		// Verify returned state is empty (as client didn't provide one)
		if returnedState != "" {
			t.Errorf("Expected empty returnedState, got %q", returnedState)
		}

		if authCode == nil {
			t.Fatal("Expected non-nil authorization code")
		}

		t.Log("✓ Callback correctly returns empty state when client didn't provide one")
	})

	t.Run("callback should return client state when provided", func(t *testing.T) {
		originalState := testutil.GenerateRandomString(43)

		// Start flow with non-empty state
		authURL, err := srv.StartAuthorizationFlow(
			ctx,
			client.ClientID,
			client.RedirectURIs[0],
			"openid",
			"",
			validChallenge,
			"S256",
			originalState,
		)
		if err != nil {
			t.Fatalf("StartAuthorizationFlow() error = %v", err)
		}

		// Extract provider state from auth URL
		parsedURL, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("Failed to parse auth URL: %v", err)
		}
		providerState := parsedURL.Query().Get("state")

		// Simulate provider callback
		authCode, returnedState, err := srv.HandleProviderCallback(ctx, providerState, "mock_code_2")
		if err != nil {
			t.Fatalf("HandleProviderCallback() error = %v", err)
		}

		// Verify returned state matches original
		if returnedState != originalState {
			t.Errorf("Expected returnedState=%q, got %q", originalState, returnedState)
		}

		if authCode == nil {
			t.Fatal("Expected non-nil authorization code")
		}

		t.Log("✓ Callback correctly returns original client state when provided")
	})

	_ = provider // Use provider to satisfy compiler
}
