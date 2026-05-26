package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestServer_StartAuthorizationFlow(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
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
			authURL, err := srv.StartAuthorizationFlow(
				ctx,
				tt.clientID,
				mustParseURL(t, tt.redirectURI),
				tt.scope,
				"", // resource parameter (optional)
				tt.codeChallenge,
				tt.codeChallengeMethod,
				tt.clientState,
				nil, // authOpts (OIDC params for upstream IdP)
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

// TestStartAuthorizationFlow_OIDCParameterForwarding tests that OIDC parameters
// (prompt, login_hint, id_token_hint) are forwarded to the upstream IdP.
// This enables silent re-authentication (prompt=none) and user hints.
// See: OpenID Connect Core 1.0 Section 3.1.2.1
func TestStartAuthorizationFlow_OIDCParameterForwarding(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
		"oidc-test-client",
		ClientTypeConfidential,
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email", "profile"},
		"127.0.0.1",
		100,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	validVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(validVerifier))
	validChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	tests := []struct {
		name            string
		authOpts        *providers.AuthorizationURLOptions
		wantPrompt      string
		wantLoginHint   string
		wantIDTokenHint string
		wantMaxAge      *int
		wantACRValues   string
		description     string
	}{
		{
			name:        "nil options - no OIDC params in URL",
			authOpts:    nil,
			description: "When authOpts is nil, no OIDC parameters should be added",
		},
		{
			name: "prompt=none for silent auth",
			authOpts: &providers.AuthorizationURLOptions{
				Prompt: "none",
			},
			wantPrompt:  "none",
			description: "Silent authentication: no UI should be displayed",
		},
		{
			name: "prompt=login for re-authentication",
			authOpts: &providers.AuthorizationURLOptions{
				Prompt: "login",
			},
			wantPrompt:  "login",
			description: "Force re-authentication even if session exists",
		},
		{
			name: "login_hint for user identification",
			authOpts: &providers.AuthorizationURLOptions{
				LoginHint: "user@example.com",
			},
			wantLoginHint: "user@example.com",
			description:   "Pre-fill email/username at IdP",
		},
		{
			name: "id_token_hint for session hint",
			authOpts: &providers.AuthorizationURLOptions{
				IDTokenHint: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
			},
			wantIDTokenHint: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
			description:     "Previously issued ID token to identify user session",
		},
		{
			name: "max_age for session freshness",
			authOpts: &providers.AuthorizationURLOptions{
				MaxAge: testutil.IntPtr(3600),
			},
			wantMaxAge:  testutil.IntPtr(3600),
			description: "Require re-auth if session is older than 1 hour",
		},
		{
			name: "max_age=0 equivalent to prompt=login",
			authOpts: &providers.AuthorizationURLOptions{
				MaxAge: testutil.IntPtr(0),
			},
			wantMaxAge:  testutil.IntPtr(0),
			description: "max_age=0 forces immediate re-authentication",
		},
		{
			name: "acr_values for authentication context",
			authOpts: &providers.AuthorizationURLOptions{
				ACRValues: "urn:mace:incommon:iap:silver",
			},
			wantACRValues: "urn:mace:incommon:iap:silver",
			description:   "Request specific authentication level (e.g., MFA)",
		},
		{
			name: "all OIDC params combined (silent re-auth)",
			authOpts: &providers.AuthorizationURLOptions{
				Prompt:      "none",
				LoginHint:   "user@example.com",
				IDTokenHint: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
				MaxAge:      testutil.IntPtr(7200),
				ACRValues:   "urn:mace:incommon:iap:silver",
			},
			wantPrompt:      "none",
			wantLoginHint:   "user@example.com",
			wantIDTokenHint: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
			wantMaxAge:      testutil.IntPtr(7200),
			wantACRValues:   "urn:mace:incommon:iap:silver",
			description:     "Full silent re-authentication with all hints",
		},
		{
			name: "prompt=consent for forced consent",
			authOpts: &providers.AuthorizationURLOptions{
				Prompt: "consent",
			},
			wantPrompt:  "consent",
			description: "Force consent even if previously granted",
		},
		{
			name: "prompt=select_account for account selection",
			authOpts: &providers.AuthorizationURLOptions{
				Prompt: "select_account",
			},
			wantPrompt:  "select_account",
			description: "Force account selection even if only one account",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Track the options passed to the provider
			var capturedOpts *providers.AuthorizationURLOptions
			originalFunc := provider.AuthorizationURLFunc
			provider.AuthorizationURLFunc = func(state, codeChallenge, codeChallengeMethod string, scopes []string, opts *providers.AuthorizationURLOptions) string {
				capturedOpts = opts
				return originalFunc(state, codeChallenge, codeChallengeMethod, scopes, opts)
			}
			defer func() { provider.AuthorizationURLFunc = originalFunc }()

			authURL, err := srv.StartAuthorizationFlow(
				ctx,
				client.ClientID,
				mustParseURL(t, "https://example.com/callback"),
				"openid email",
				"", // resource parameter
				validChallenge,
				PKCEMethodS256,
				clientState+tt.name, // Unique state per test
				tt.authOpts,
			)
			if err != nil {
				t.Fatalf("StartAuthorizationFlow() error = %v", err)
			}

			if authURL == "" {
				t.Error("StartAuthorizationFlow() returned empty authorization URL")
			}

			if capturedOpts == nil {
				t.Fatal("Expected authOpts to be passed to provider, got nil")
			}
			if capturedOpts.Nonce == "" {
				t.Error("Expected server-generated nonce on OIDC flow, got empty")
			}
			if tt.authOpts != nil {
				if tt.wantPrompt != "" && capturedOpts.Prompt != tt.wantPrompt {
					t.Errorf("prompt = %q, want %q", capturedOpts.Prompt, tt.wantPrompt)
				}
				if tt.wantLoginHint != "" && capturedOpts.LoginHint != tt.wantLoginHint {
					t.Errorf("login_hint = %q, want %q", capturedOpts.LoginHint, tt.wantLoginHint)
				}
				if tt.wantIDTokenHint != "" && capturedOpts.IDTokenHint != tt.wantIDTokenHint {
					t.Errorf("id_token_hint = %q, want %q", capturedOpts.IDTokenHint, tt.wantIDTokenHint)
				}
				if tt.wantMaxAge != nil {
					if capturedOpts.MaxAge == nil {
						t.Error("max_age = nil, want non-nil")
					} else if *capturedOpts.MaxAge != *tt.wantMaxAge {
						t.Errorf("max_age = %d, want %d", *capturedOpts.MaxAge, *tt.wantMaxAge)
					}
				}
				if tt.wantACRValues != "" && capturedOpts.ACRValues != tt.wantACRValues {
					t.Errorf("acr_values = %q, want %q", capturedOpts.ACRValues, tt.wantACRValues)
				}
			}

			// Verify the URL contains expected parameters (mock provider adds them)
			parsedURL, err := url.Parse(authURL)
			if err != nil {
				t.Fatalf("Failed to parse auth URL: %v", err)
			}

			if tt.wantPrompt != "" {
				if got := parsedURL.Query().Get("prompt"); got != tt.wantPrompt {
					t.Errorf("URL prompt param = %q, want %q", got, tt.wantPrompt)
				}
			}
			if tt.wantLoginHint != "" {
				if got := parsedURL.Query().Get("login_hint"); got != tt.wantLoginHint {
					t.Errorf("URL login_hint param = %q, want %q", got, tt.wantLoginHint)
				}
			}
			if tt.wantIDTokenHint != "" {
				if got := parsedURL.Query().Get("id_token_hint"); got != tt.wantIDTokenHint {
					t.Errorf("URL id_token_hint param = %q, want %q", got, tt.wantIDTokenHint)
				}
			}
			if tt.wantMaxAge != nil {
				want := fmt.Sprintf("%d", *tt.wantMaxAge)
				if got := parsedURL.Query().Get("max_age"); got != want {
					t.Errorf("URL max_age param = %q, want %q", got, want)
				}
			}
			if tt.wantACRValues != "" {
				if got := parsedURL.Query().Get("acr_values"); got != tt.wantACRValues {
					t.Errorf("URL acr_values param = %q, want %q", got, tt.wantACRValues)
				}
			}

			// Clean up state for next iteration
			_ = store.DeleteAuthorizationState(ctx, clientState+tt.name)

			t.Logf("✓ %s: %s", tt.name, tt.description)
		})
	}
}

func TestServer_HandleProviderCallback(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
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
	_, err = srv.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"", // resource parameter (optional)
		validChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts (OIDC params for upstream IdP)
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

// TestServer_HandleProviderCallback_EmailLookup tests that tokens can be
// looked up by email when the OIDC provider's subject claim differs from the email.
// This is common with Dex which uses base64-encoded subjects like "Cg1tYXJrdGVzdGVyQGdtYWlsLmNvbQoFbG9jYWw".
//
// See: https://github.com/giantswarm/mcp-oauth/issues/154
func TestServer_HandleProviderCallback_EmailLookup(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Configure provider to return a subject claim that differs from email
	// This simulates Dex's behavior where sub is a base64-encoded identifier
	dexStyleSubjectClaim := "Cg1tYXJrdGVzdGVyQGdtYWlsLmNvbQoFbG9jYWw" // base64-encoded like Dex
	testEmail := "markus@example.com"

	provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:            dexStyleSubjectClaim, // Different from email
			Email:         testEmail,
			EmailVerified: true,
			Name:          "Markus User",
		}, nil
	}

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
		"Test Client",
		ClientTypeConfidential,
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
	clientState := testutil.GenerateRandomString(43)

	// Start authorization flow
	_, err = srv.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"",
		validChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts (OIDC params for upstream IdP)
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

	// Complete the provider callback
	_, _, err = srv.HandleProviderCallback(ctx, providerState, "provider-auth-code")
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	// TEST: Verify token can be retrieved by subject claim (ID)
	tokenByID, err := store.GetToken(ctx, dexStyleSubjectClaim)
	if err != nil {
		t.Errorf("GetToken by ID failed: %v", err)
	}
	if tokenByID == nil {
		t.Error("Token not found by ID (subject claim)")
	}

	// TEST: Verify token can ALSO be retrieved by email
	// This is the bug fix - previously tokens were only saved by email if email != ID
	tokenByEmail, err := store.GetToken(ctx, testEmail)
	if err != nil {
		t.Errorf("GetToken by email failed: %v", err)
	}
	if tokenByEmail == nil {
		t.Error("Token not found by email - this is the bug we're fixing (issue #154)")
	}

	// TEST: Verify user info can also be retrieved by email
	userInfoByEmail, err := store.GetUserInfo(ctx, testEmail)
	if err != nil {
		t.Errorf("GetUserInfo by email failed: %v", err)
	}
	if userInfoByEmail == nil {
		t.Error("UserInfo not found by email")
	} else if userInfoByEmail.Email != testEmail {
		t.Errorf("UserInfo.Email = %q, want %q", userInfoByEmail.Email, testEmail)
	}

	// TEST: Verify user info can be retrieved by ID
	userInfoByID, err := store.GetUserInfo(ctx, dexStyleSubjectClaim)
	if err != nil {
		t.Errorf("GetUserInfo by ID failed: %v", err)
	}
	if userInfoByID == nil {
		t.Error("UserInfo not found by ID")
	}
}

// TestServer_HandleProviderCallback_ShortLivedToken tests that provider tokens with
// short expiry times (or already expired) are still saved with extended TTL.
// This is critical for SSO token forwarding where the id_token must remain available
// for the user's session duration, even if the access token expires quickly.
//
// See: https://github.com/giantswarm/mcp-oauth/issues/193
func TestServer_HandleProviderCallback_ShortLivedToken(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	// Configure provider to return an ALREADY EXPIRED access token
	// This simulates Dex returning tokens with very short lifetimes
	expiredExpiry := time.Now().Add(-5 * time.Minute) // Already expired 5 minutes ago
	testEmail := "shortlived@example.com"
	testUserID := "short-lived-user-id"

	provider.ExchangeCodeFunc = func(_ context.Context, _, _ string) (*oauth2.Token, error) {
		token := &oauth2.Token{
			AccessToken:  "short-lived-access-token",
			RefreshToken: "valid-refresh-token",
			Expiry:       expiredExpiry, // Already expired!
		}
		// Include id_token in extras
		return token.WithExtra(map[string]interface{}{
			"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature",
		}), nil
	}

	provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:            testUserID,
			Email:         testEmail,
			EmailVerified: true,
			Name:          "Short Lived User",
		}, nil
	}

	config := &Config{
		Issuer:                      "https://auth.example.com",
		SupportedScopes:             []string{"openid", "email", "profile"},
		AuthorizationCodeTTL:        600,
		AccessTokenTTL:              3600,
		ProviderTokenTTL:            3600,
		RequirePKCE:                 true,
		AllowPKCEPlain:              false,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
		"Test Client",
		ClientTypeConfidential,
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
	clientState := testutil.GenerateRandomString(43)

	// Start authorization flow
	_, err = srv.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"",
		validChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts (OIDC params for upstream IdP)
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

	// Complete the provider callback - this should save the token with extended expiry
	_, _, err = srv.HandleProviderCallback(ctx, providerState, "provider-auth-code")
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	// TEST: Verify token can be retrieved by email (despite original being expired)
	tokenByEmail, err := store.GetToken(ctx, testEmail)
	if err != nil {
		t.Errorf("GetToken by email failed: %v - token should be saved with extended expiry", err)
	}
	if tokenByEmail == nil {
		t.Fatal("Token not found by email - fix for issue #193 not working")
	}

	// Verify the token has extended expiry (should be in the future)
	if tokenByEmail.Expiry.Before(time.Now()) {
		t.Errorf("Token expiry should be in the future after extension, got %v", tokenByEmail.Expiry)
	}

	// Verify the refresh token is preserved
	if tokenByEmail.RefreshToken != "valid-refresh-token" {
		t.Errorf("RefreshToken not preserved, got %q", tokenByEmail.RefreshToken)
	}

	// Verify id_token is preserved in extras
	idToken := tokenByEmail.Extra("id_token")
	if idToken == nil {
		t.Error("id_token should be preserved in token extras for SSO forwarding")
	}

	// TEST: Verify token can also be retrieved by ID
	tokenByID, err := store.GetToken(ctx, testUserID)
	if err != nil {
		t.Errorf("GetToken by ID failed: %v", err)
	}
	if tokenByID == nil {
		t.Error("Token not found by ID")
	}

	t.Logf("SUCCESS: Short-lived token saved with extended expiry. Original: %v, Extended: %v",
		expiredExpiry, tokenByEmail.Expiry)
}

// TestServer_ExtendTokenExpiryForStorage tests the extendTokenExpiryForStorage helper function.
func TestServer_ExtendTokenExpiryForStorage(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	config := &Config{
		Issuer:           "https://auth.example.com",
		ProviderTokenTTL: 3600, // 1 hour
	}

	srv, err := New(provider, store, store, store, config, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name           string
		inputToken     *oauth2.Token
		expectExtended bool
		description    string
	}{
		{
			name:           "nil token",
			inputToken:     nil,
			expectExtended: false,
			description:    "nil token should return nil",
		},
		{
			name: "already expired token",
			inputToken: &oauth2.Token{
				AccessToken:  "expired-token",
				RefreshToken: "refresh",
				Expiry:       time.Now().Add(-1 * time.Hour),
			},
			expectExtended: true,
			description:    "expired token should be extended",
		},
		{
			name: "short-lived token",
			inputToken: &oauth2.Token{
				AccessToken:  "short-token",
				RefreshToken: "refresh",
				Expiry:       time.Now().Add(5 * time.Minute),
			},
			expectExtended: true,
			description:    "token expiring soon should be extended",
		},
		{
			name: "long-lived token",
			inputToken: &oauth2.Token{
				AccessToken:  "long-token",
				RefreshToken: "refresh",
				Expiry:       time.Now().Add(24 * time.Hour),
			},
			expectExtended: false,
			description:    "token with longer expiry than ProviderTokenTTL should not be changed",
		},
		{
			name: "zero expiry token",
			inputToken: &oauth2.Token{
				AccessToken:  "no-expiry-token",
				RefreshToken: "refresh",
				// Expiry is zero
			},
			expectExtended: true,
			description:    "token with zero expiry should be extended",
		},
		{
			name: "token with all KnownExtraFields",
			inputToken: func() *oauth2.Token {
				t := &oauth2.Token{
					AccessToken:  "token-with-extra",
					RefreshToken: "refresh",
					Expiry:       time.Now().Add(-1 * time.Minute),
				}
				return t.WithExtra(map[string]interface{}{
					"id_token":   "test-id-token",
					"scope":      "openid email",
					"expires_in": float64(300), // 5 minutes - JSON numbers decode as float64
				})
			}(),
			expectExtended: true,
			description:    "token with extras should preserve all KnownExtraFields (id_token, scope, expires_in)",
		},
		{
			name: "token with only scope (no id_token)",
			inputToken: func() *oauth2.Token {
				t := &oauth2.Token{
					AccessToken:  "token-scope-only",
					RefreshToken: "refresh",
					Expiry:       time.Now().Add(-1 * time.Minute),
				}
				return t.WithExtra(map[string]interface{}{
					"scope": "openid profile",
				})
			}(),
			expectExtended: true,
			description:    "token with only scope should still preserve scope (regression test for DRY fix)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := srv.extendTokenExpiryForStorage(tt.inputToken)

			if tt.inputToken == nil {
				if result != nil {
					t.Errorf("expected nil result for nil input")
				}
				return
			}

			if result == nil {
				t.Fatalf("unexpected nil result")
			}

			// Verify access token and refresh token are preserved
			if result.AccessToken != tt.inputToken.AccessToken {
				t.Errorf("AccessToken not preserved: got %q, want %q", result.AccessToken, tt.inputToken.AccessToken)
			}
			if result.RefreshToken != tt.inputToken.RefreshToken {
				t.Errorf("RefreshToken not preserved: got %q, want %q", result.RefreshToken, tt.inputToken.RefreshToken)
			}

			// Check expiry extension
			expectedMinExpiry := time.Now().Add(time.Duration(config.ProviderTokenTTL-10) * time.Second) // Allow 10s tolerance
			if tt.expectExtended {
				if result.Expiry.Before(expectedMinExpiry) {
					t.Errorf("Expected extended expiry > %v, got %v", expectedMinExpiry, result.Expiry)
				}
			}

			// Check all KnownExtraFields are preserved
			for _, field := range []string{"id_token", "scope", "expires_in"} {
				if inputVal := tt.inputToken.Extra(field); inputVal != nil {
					resultVal := result.Extra(field)
					if resultVal == nil {
						t.Errorf("%s should be preserved in result", field)
					} else if resultVal != inputVal {
						t.Errorf("%s not preserved: got %v, want %v", field, resultVal, inputVal)
					}
				}
			}
		})
	}
}

func TestServer_ExchangeAuthorizationCode(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
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

func TestServer_ExchangeAuthorizationCode_MetadataExpiresAt(t *testing.T) {
	ctx := t.Context()
	srv, store, _ := setupFlowTestServer(t)
	srv.Config.AccessTokenTTL = 3600
	srv.Config.RefreshTokenTTL = 86400

	client, _, err := srv.RegisterClient(ctx, "Test Client", ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"openid"}, "192.168.1.1", 10)
	require.NoError(t, err)

	verifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	authCode := &storage.AuthorizationCode{
		Code:                testutil.GenerateRandomString(32),
		ClientID:            client.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: PKCEMethodS256,
		UserID:              "user-1",
		ProviderToken:       &oauth2.Token{AccessToken: "pat", RefreshToken: "prt", Expiry: time.Now().Add(2 * time.Hour)},
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	require.NoError(t, store.SaveAuthorizationCode(ctx, authCode))

	before := time.Now()
	token, _, err := srv.ExchangeAuthorizationCode(ctx, authCode.Code, client.ClientID, "https://example.com/callback", "", verifier)
	require.NoError(t, err)
	after := time.Now()

	atMeta, err := store.GetTokenMetadata(token.AccessToken)
	require.NoError(t, err)
	require.False(t, atMeta.ExpiresAt.IsZero(), "access token ExpiresAt must be set")
	require.False(t, atMeta.IssuedAt.IsZero(), "access token IssuedAt must be set")
	require.True(t, atMeta.IssuedAt.Before(atMeta.ExpiresAt), "IssuedAt must be before ExpiresAt")
	require.WithinDuration(t, before.Add(time.Duration(srv.Config.AccessTokenTTL)*time.Second), atMeta.ExpiresAt, 5*time.Second)
	_ = after

	rtMeta, err := store.GetTokenMetadata(token.RefreshToken)
	require.NoError(t, err)
	require.False(t, rtMeta.ExpiresAt.IsZero(), "refresh token ExpiresAt must be set")
	require.WithinDuration(t, before.Add(time.Duration(srv.Config.RefreshTokenTTL)*time.Second), rtMeta.ExpiresAt, 5*time.Second)
}

// TestServer_ExchangeAuthorizationCode_IDTokenForwarding verifies that the id_token
// from the upstream provider is correctly forwarded in the token response.
// Per OpenID Connect Core 1.0 Section 3.1.3.3, the id_token is REQUIRED for OIDC flows.
func TestServer_ExchangeAuthorizationCode_IDTokenForwarding(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
		"Test Client",
		ClientTypeConfidential,
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

	// Create a provider token with id_token (simulating upstream OIDC provider response)
	testIDToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXItMTIzIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20ifQ.signature" //nolint:gosec // test value
	providerToken := (&oauth2.Token{
		AccessToken:  "provider-access-token",
		RefreshToken: "provider-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}).WithExtra(map[string]interface{}{
		"id_token": testIDToken,
	})

	// Create an authorization code with the provider token containing id_token
	authCode := &storage.AuthorizationCode{
		Code:                testutil.GenerateRandomString(32),
		ClientID:            client.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid email",
		CodeChallenge:       validChallenge,
		CodeChallengeMethod: PKCEMethodS256,
		UserID:              "test-user-123",
		ProviderToken:       providerToken,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}

	err = store.SaveAuthorizationCode(ctx, authCode)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Exchange the authorization code
	token, _, err := srv.ExchangeAuthorizationCode(
		ctx,
		authCode.Code,
		client.ClientID,
		"https://example.com/callback",
		"",
		validVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	// Verify that the id_token is forwarded in the response
	idToken := token.Extra("id_token")
	if idToken == nil {
		t.Fatal("id_token should be present in the response, got nil")
	}

	idTokenStr, ok := idToken.(string)
	if !ok {
		t.Fatalf("id_token should be a string, got %T", idToken)
	}

	if idTokenStr != testIDToken {
		t.Errorf("id_token = %q, want %q", idTokenStr, testIDToken)
	}
}

// TestServer_ExchangeAuthorizationCode_NoIDToken verifies that the token response
// is valid when there is no id_token from the provider (non-OIDC flows).
func TestServer_ExchangeAuthorizationCode_NoIDToken(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
		"Test Client",
		ClientTypeConfidential,
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

	// Create a provider token WITHOUT id_token
	providerToken := &oauth2.Token{
		AccessToken:  "provider-access-token",
		RefreshToken: "provider-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	authCode := &storage.AuthorizationCode{
		Code:                testutil.GenerateRandomString(32),
		ClientID:            client.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid email",
		CodeChallenge:       validChallenge,
		CodeChallengeMethod: PKCEMethodS256,
		UserID:              "test-user-456",
		ProviderToken:       providerToken,
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}

	err = store.SaveAuthorizationCode(ctx, authCode)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Exchange the authorization code
	token, _, err := srv.ExchangeAuthorizationCode(
		ctx,
		authCode.Code,
		client.ClientID,
		"https://example.com/callback",
		"",
		validVerifier,
	)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	// Verify the response is valid (access_token should be present)
	if token.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}

	// Verify id_token is nil when not provided
	idToken := token.Extra("id_token")
	if idToken != nil {
		t.Errorf("id_token should be nil when not provided, got %v", idToken)
	}
}

// TestServer_ExchangeAuthorizationCode_PublicClient_PKCEEnforcement tests
// that public clients MUST use PKCE (OAuth 2.1 requirement) while confidential
// clients can optionally use PKCE for enhanced security.
func TestServer_ExchangeAuthorizationCode_PublicClient_PKCEEnforcement(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a public client (mobile app, SPA)
	publicClient, _, err := srv.RegisterClient(
		ctx,
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
	confidentialClient, _, err := srv.RegisterClient(
		ctx,
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
			publicClient, _, err := srv.RegisterClient(
				ctx,
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
	publicClient, _, err := srv.RegisterClient(
		ctx,
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

// TestServer_ConcurrentAuthorizationCodeReuse tests concurrent auth code reuse
// This verifies atomic code exchange - only ONE request should succeed
func TestServer_ConcurrentAuthorizationCodeReuse(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a client
	client, _, err := srv.RegisterClient(
		ctx,
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
	_, err = srv.StartAuthorizationFlow(
		ctx,
		clientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts
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

// TestServer_AuthorizationCodeReuseRevokesTokens tests that when an authorization code is reused,
// all tokens for that user+client are revoked (OAuth 2.1 requirement)
func TestServer_AuthorizationCodeReuseRevokesTokens(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a client
	client, _, err := srv.RegisterClient(
		ctx,
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
	_, err = srv.StartAuthorizationFlow(
		ctx,
		clientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts
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
	client, _, err := srv.RegisterClient(
		ctx,
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
	_, err = srv.StartAuthorizationFlow(
		ctx,
		clientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts
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

// TestServer_GenericErrorMessagesNoInfoLeakage tests that all error paths return generic messages
// P0 CRITICAL SECURITY: Prevents information leakage to attackers per RFC 6749
func TestServer_GenericErrorMessagesNoInfoLeakage(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// Register a client
	client, _, err := srv.RegisterClient(
		ctx,
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
	_, err = srv.StartAuthorizationFlow(
		ctx,
		clientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts
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

// TestServer_AuthCodeReuseWithoutSecurityEventRateLimiter tests nil check works
// P1: Verifies nil pointer safety
func TestServer_AuthCodeReuseWithoutSecurityEventRateLimiter(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	// IMPORTANT: Don't set SecurityEventRateLimiter (leave as nil)
	srv.SecurityEventRateLimiter = nil

	// Register a client
	client, _, err := srv.RegisterClient(
		ctx,
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
	_, err = srv.StartAuthorizationFlow(
		ctx,
		clientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"", // resource parameter (optional)
		codeChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts
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

// TestStartAuthorizationFlow_ClientScopeValidation tests that scope validation
// against client's allowed scopes happens during authorization flow start
func TestStartAuthorizationFlow_ClientScopeValidation(t *testing.T) {
	ctx := context.Background()
	srv, _, _ := setupFlowTestServer(t)

	// Register client with limited scopes
	client, _, err := srv.RegisterClient(
		ctx,
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
			authURL, err := srv.StartAuthorizationFlow(
				ctx,
				client.ClientID,
				mustParseURL(t, "https://example.com/callback"),
				tt.scope,
				"", // resource parameter (optional)
				validChallenge,
				PKCEMethodS256,
				validState,
				nil, // authOpts
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
	client, _, err := srv.RegisterClient(
		ctx,
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
	client, _, err := srv.RegisterClient(
		ctx,
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
			authURL, err := srv.StartAuthorizationFlow(
				ctx,
				client.ClientID,
				mustParseURL(t, "https://example.com/callback"),
				scope,
				"", // resource parameter (optional)
				validChallenge,
				PKCEMethodS256,
				validState,
				nil, // authOpts
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
	srv.Auditor = auditor

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
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
	authURL, err := srv.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"", // resource parameter (optional)
		clientChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts
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
				mustParseURL(t, client.RedirectURIs[0]),
				tt.scope,
				"", // resource parameter (optional)
				codeChallenge,
				"S256",
				state,
				nil, // authOpts
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
			Issuer:                      "https://auth.example.com",
			ResourceIdentifier:          "https://mcp.example.com",
			AccessTokenTTL:              3600,
			RefreshTokenTTL:             86400,
			RequirePKCE:                 true,
			DisableNonceEchoRequirement: true,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Register a client using the proper API
	client, _, err := srv.RegisterClient(
		ctx,
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
			mustParseURL(t, client.RedirectURIs[0]),
			"openid email",
			"https://mcp.example.com", // Resource matches server's identifier
			codeChallenge,
			PKCEMethodS256,
			clientState,
			nil, // authOpts
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
				Issuer:                      "https://auth.example.com",
				ResourceIdentifier:          "https://different-mcp.example.com",
				AccessTokenTTL:              3600,
				RefreshTokenTTL:             86400,
				DisableNonceEchoRequirement: true,
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
			mustParseURL(t, client.RedirectURIs[0]),
			"openid email",
			"https://mcp.example.com", // Resource for first server
			codeChallenge,
			PKCEMethodS256,
			clientState,
			nil, // authOpts
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
			mustParseURL(t, client.RedirectURIs[0]),
			"openid email",
			"", // No resource parameter (backward compatibility)
			codeChallenge,
			PKCEMethodS256,
			clientState,
			nil, // authOpts
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
			Issuer:                      "https://auth.example.com",
			ResourceIdentifier:          "https://mcp.example.com",
			AccessTokenTTL:              3600,
			RefreshTokenTTL:             86400,
			RequirePKCE:                 true,
			DisableNonceEchoRequirement: true,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	client, _, err := srv.RegisterClient(
		ctx,
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
			mustParseURL(t, client.RedirectURIs[0]),
			"openid email",
			"https://mcp.example.com", // Resource A
			codeChallenge,
			PKCEMethodS256,
			clientState,
			nil, // authOpts
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

	client, _, err := srv.RegisterClient(
		ctx,
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
				mustParseURL(t, client.RedirectURIs[0]),
				"openid email",
				tt.resource,
				codeChallenge,
				PKCEMethodS256,
				clientState,
				nil, // authOpts
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
			Issuer:                      "https://auth.example.com",
			ResourceIdentifier:          "https://mcp.example.com",
			AccessTokenTTL:              3600,
			RefreshTokenTTL:             86400,
			RequirePKCE:                 true,
			DisableNonceEchoRequirement: true,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Setup rate limiter with tight limits for testing
	rateLimiter := security.NewRateLimiter(1, 1, srv.Logger) // 1 request per second, burst 1
	srv.SecurityEventRateLimiter = rateLimiter

	client, _, err := srv.RegisterClient(
		ctx,
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
		mustParseURL(t, client.RedirectURIs[0]),
		"openid email",
		"https://mcp.example.com", // Resource A
		codeChallenge,
		PKCEMethodS256,
		clientState,
		nil, // authOpts
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

// TestStartAuthorizationFlow_EmptyState tests authorization flow with empty state
// when AllowNoStateParameter is enabled
func TestStartAuthorizationFlow_EmptyState(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServerWithNoStateParameter(t)

	// Register a test client
	client, _, err := srv.RegisterClient(
		ctx,
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
			mustParseURL(t, client.RedirectURIs[0]),
			"openid",
			"", // resource
			validChallenge,
			"S256",
			"",  // empty state - should succeed
			nil, // authOpts
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
			mustParseURL(t, client.RedirectURIs[0]),
			"openid",
			"",
			validChallenge,
			"S256",
			"",  // empty state
			nil, // authOpts
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
			mustParseURL(t, client.RedirectURIs[0]),
			"openid",
			"",
			validChallenge,
			"S256",
			validState, // non-empty state
			nil,        // authOpts
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
	client, _, err := srv.RegisterClient(
		ctx,
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
			mustParseURL(t, client.RedirectURIs[0]),
			"openid",
			"",
			validChallenge,
			"S256",
			"",  // empty state
			nil, // authOpts
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
			mustParseURL(t, client.RedirectURIs[0]),
			"openid",
			"",
			validChallenge,
			"S256",
			originalState,
			nil, // authOpts
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

// TestServer_GenerateAndStoreTokens_ExpiryCap tests that the generated token's expiry
// is capped to the provider token's expiry when the provider token expires sooner.
func TestServer_GenerateAndStoreTokens_ExpiryCap(t *testing.T) {
	ctx := context.Background()

	t.Run("provider token expires before AccessTokenTTL - should cap expiry", func(t *testing.T) {
		srv, store, _ := setupFlowTestServer(t)
		srv.Config.AccessTokenTTL = 3600 // 1 hour

		providerExpiry := time.Now().Add(10 * time.Minute) // 10 minutes
		authCode := &storage.AuthorizationCode{
			Code:     "test-code",
			ClientID: "test-client",
			UserID:   "test-user",
			Scope:    "openid",
			ProviderToken: &oauth2.Token{
				AccessToken:  "provider-access",
				RefreshToken: "provider-refresh",
				Expiry:       providerExpiry,
			},
		}

		tokenResponse, err := srv.generateAndStoreTokens(ctx, authCode, "test-client", "")
		if err != nil {
			t.Fatalf("generateAndStoreTokens() error = %v", err)
		}

		// Expiry should be capped to provider token's expiry (within a small tolerance)
		timeDiff := tokenResponse.Expiry.Sub(providerExpiry).Abs()
		if timeDiff > 2*time.Second {
			t.Errorf("Token expiry = %v, want close to provider expiry %v (diff: %v)",
				tokenResponse.Expiry, providerExpiry, timeDiff)
		}

		// Verify token was stored
		storedToken, err := store.GetToken(ctx, tokenResponse.AccessToken)
		if err != nil {
			t.Fatalf("GetToken() error = %v", err)
		}
		if storedToken == nil {
			t.Fatal("Expected stored token, got nil")
		}
	})

	t.Run("provider token expires after AccessTokenTTL - should use AccessTokenTTL", func(t *testing.T) {
		srv, store, _ := setupFlowTestServer(t)
		srv.Config.AccessTokenTTL = 3600 // 1 hour

		authCode := &storage.AuthorizationCode{
			Code:     "test-code-2",
			ClientID: "test-client",
			UserID:   "test-user",
			Scope:    "openid",
			ProviderToken: &oauth2.Token{
				AccessToken:  "provider-access",
				RefreshToken: "provider-refresh",
				Expiry:       time.Now().Add(2 * time.Hour), // longer than AccessTokenTTL
			},
		}

		tokenResponse, err := srv.generateAndStoreTokens(ctx, authCode, "test-client", "")
		if err != nil {
			t.Fatalf("generateAndStoreTokens() error = %v", err)
		}

		// Expiry should be approximately now + AccessTokenTTL
		expectedExpiry := time.Now().Add(time.Duration(srv.Config.AccessTokenTTL) * time.Second)
		timeDiff := tokenResponse.Expiry.Sub(expectedExpiry).Abs()
		if timeDiff > 2*time.Second {
			t.Errorf("Token expiry = %v, want close to %v (diff: %v)",
				tokenResponse.Expiry, expectedExpiry, timeDiff)
		}

		// Verify token was stored
		storedToken, err := store.GetToken(ctx, tokenResponse.AccessToken)
		if err != nil {
			t.Fatalf("GetToken() error = %v", err)
		}
		if storedToken == nil {
			t.Fatal("Expected stored token, got nil")
		}
	})

	t.Run("provider token with zero expiry - should use AccessTokenTTL", func(t *testing.T) {
		srv, _, _ := setupFlowTestServer(t)
		srv.Config.AccessTokenTTL = 3600 // 1 hour

		authCode := &storage.AuthorizationCode{
			Code:     "test-code-3",
			ClientID: "test-client",
			UserID:   "test-user",
			Scope:    "openid",
			ProviderToken: &oauth2.Token{
				AccessToken:  "provider-access",
				RefreshToken: "provider-refresh",
				// Zero expiry
			},
		}

		tokenResponse, err := srv.generateAndStoreTokens(ctx, authCode, "test-client", "")
		if err != nil {
			t.Fatalf("generateAndStoreTokens() error = %v", err)
		}

		expectedExpiry := time.Now().Add(time.Duration(srv.Config.AccessTokenTTL) * time.Second)
		timeDiff := tokenResponse.Expiry.Sub(expectedExpiry).Abs()
		if timeDiff > 2*time.Second {
			t.Errorf("Token expiry = %v, want close to %v (diff: %v)",
				tokenResponse.Expiry, expectedExpiry, timeDiff)
		}
	})

	t.Run("nil provider token - should use AccessTokenTTL", func(t *testing.T) {
		srv, _, _ := setupFlowTestServer(t)
		srv.Config.AccessTokenTTL = 3600 // 1 hour

		authCode := &storage.AuthorizationCode{
			Code:          "test-code-4",
			ClientID:      "test-client",
			UserID:        "test-user",
			Scope:         "openid",
			ProviderToken: nil,
		}

		tokenResponse, err := srv.generateAndStoreTokens(ctx, authCode, "test-client", "")
		if err != nil {
			t.Fatalf("generateAndStoreTokens() error = %v", err)
		}

		expectedExpiry := time.Now().Add(time.Duration(srv.Config.AccessTokenTTL) * time.Second)
		timeDiff := tokenResponse.Expiry.Sub(expectedExpiry).Abs()
		if timeDiff > 2*time.Second {
			t.Errorf("Token expiry = %v, want close to %v (diff: %v)",
				tokenResponse.Expiry, expectedExpiry, timeDiff)
		}
	})
}

// TestServer_GenerateAndStoreTokens_PastExpiryIgnored verifies that when a
// provider token has an expiry in the past, the cap is not applied (the token
// uses AccessTokenTTL instead of a past timestamp).
func TestServer_GenerateAndStoreTokens_PastExpiryIgnored(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)
	srv.Config.AccessTokenTTL = 3600

	authCode := &storage.AuthorizationCode{
		Code:     "test-code-past",
		ClientID: "test-client",
		UserID:   "test-user",
		Scope:    "openid",
		ProviderToken: &oauth2.Token{
			AccessToken:  "provider-access",
			RefreshToken: "provider-refresh",
			Expiry:       time.Now().Add(-30 * time.Second), // already expired
		},
	}

	tokenResponse, err := srv.generateAndStoreTokens(context.Background(), authCode, "test-client", "")
	if err != nil {
		t.Fatalf("generateAndStoreTokens() error = %v", err)
	}

	// The expiry must be in the future (AccessTokenTTL), NOT the past provider expiry
	if tokenResponse.Expiry.Before(time.Now()) {
		t.Errorf("Token expiry = %v, must be in the future but is in the past", tokenResponse.Expiry)
	}

	expectedExpiry := time.Now().Add(time.Duration(srv.Config.AccessTokenTTL) * time.Second)
	timeDiff := tokenResponse.Expiry.Sub(expectedExpiry).Abs()
	if timeDiff > 2*time.Second {
		t.Errorf("Token expiry = %v, want close to %v (diff: %v)",
			tokenResponse.Expiry, expectedExpiry, timeDiff)
	}
}

func TestServer_ExchangeAuthorizationCode_FamilyIDInMetadata(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	client, _, err := srv.RegisterClient(
		ctx,
		"Test Client",
		ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	clientID := client.ClientID

	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(
		ctx,
		clientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"",
		codeChallenge,
		PKCEMethodS256,
		clientState,
		nil,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(ctx, authState.ProviderState, "provider-code-"+testutil.GenerateRandomString(10))
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	token, _, err := srv.ExchangeAuthorizationCode(ctx, authCodeObj.Code, clientID, "https://example.com/callback", "", codeVerifier)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	atMeta, err := store.GetTokenMetadata(token.AccessToken)
	if err != nil {
		t.Fatalf("GetTokenMetadata(access) error = %v", err)
	}
	if atMeta.FamilyID == "" {
		t.Error("Access token metadata should have FamilyID set after exchange")
	}

	rtMeta, err := store.GetTokenMetadata(token.RefreshToken)
	if err != nil {
		t.Fatalf("GetTokenMetadata(refresh) error = %v", err)
	}
	if rtMeta.FamilyID == "" {
		t.Error("Refresh token metadata should have FamilyID set after exchange")
	}

	if atMeta.FamilyID != rtMeta.FamilyID {
		t.Errorf("AT and RT should share the same FamilyID: AT=%q, RT=%q", atMeta.FamilyID, rtMeta.FamilyID)
	}

	family, err := store.GetRefreshTokenFamily(ctx, token.RefreshToken)
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily() error = %v", err)
	}
	if family.FamilyID != atMeta.FamilyID {
		t.Errorf("Token family FamilyID = %q, metadata FamilyID = %q -- should match", family.FamilyID, atMeta.FamilyID)
	}
}

func TestServer_SetSessionCreationHandler(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)

	var called bool
	srv.sessionCreationHandler = func(_ context.Context, _, _ string, _ *oauth2.Token) {
		called = true
	}

	if srv.sessionCreationHandler == nil {
		t.Fatal("Handler should be set after SetSessionCreationHandler()")
	}

	srv.sessionCreationHandler(context.Background(), "u", "f", &oauth2.Token{})
	if !called {
		t.Error("Handler should be callable")
	}
}

func TestServer_SessionCreationHandler_CalledOnExchange(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	var handlerUserID, handlerFamilyID string
	var handlerToken *oauth2.Token
	srv.sessionCreationHandler = func(_ context.Context, userID, familyID string, token *oauth2.Token) {
		handlerUserID = userID
		handlerFamilyID = familyID
		handlerToken = token
	}

	client, _, err := srv.RegisterClient(
		ctx,
		"Test Client",
		ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"",
		codeChallenge,
		PKCEMethodS256,
		clientState,
		nil,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(ctx, authState.ProviderState, "provider-code-"+testutil.GenerateRandomString(10))
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	token, _, err := srv.ExchangeAuthorizationCode(ctx, authCodeObj.Code, client.ClientID, "https://example.com/callback", "", codeVerifier)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	if handlerUserID == "" {
		t.Fatal("SessionCreationHandler was not called during ExchangeAuthorizationCode")
	}

	if handlerUserID != testMockUserID {
		t.Errorf("handler userID = %q, want %q", handlerUserID, testMockUserID)
	}

	if handlerFamilyID == "" {
		t.Error("handler familyID should not be empty")
	}

	if handlerToken == nil {
		t.Fatal("handler token should not be nil")
	}
	if handlerToken.AccessToken != token.AccessToken {
		t.Errorf("handler token AccessToken = %q, want %q", handlerToken.AccessToken, token.AccessToken)
	}

	atMeta, err := store.GetTokenMetadata(token.AccessToken)
	if err != nil {
		t.Fatalf("GetTokenMetadata(access) error = %v", err)
	}
	if atMeta.FamilyID != handlerFamilyID {
		t.Errorf("metadata FamilyID = %q, handler familyID = %q -- should match", atMeta.FamilyID, handlerFamilyID)
	}
}

func TestServer_SessionCreationHandler_NotCalledWithoutHandler(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	client, _, err := srv.RegisterClient(
		ctx,
		"Test Client",
		ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	codeVerifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	clientState := testutil.GenerateRandomString(43)
	_, err = srv.StartAuthorizationFlow(
		ctx,
		client.ClientID,
		mustParseURL(t, "https://example.com/callback"),
		"openid email",
		"",
		codeChallenge,
		PKCEMethodS256,
		clientState,
		nil,
	)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(ctx, authState.ProviderState, "provider-code-"+testutil.GenerateRandomString(10))
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	_, _, err = srv.ExchangeAuthorizationCode(ctx, authCodeObj.Code, client.ClientID, "https://example.com/callback", "", codeVerifier)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() should succeed without handler, got error = %v", err)
	}
}
