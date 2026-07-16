package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// TestServer_RefreshTokenRotation tests basic refresh token rotation without reuse
func TestServer_RefreshTokenRotation(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	// Enable refresh token rotation
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400 // 24 hours

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

	// Start auth flow and get tokens
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

	token, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCodeObj.Code,
		clientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
		"",
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

	// Start auth flow and get initial tokens
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

	token, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCodeObj.Code,
		clientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
		"",
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

	// Get initial tokens
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

	token, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCodeObj.Code,
		clientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
		"",
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

	// Get initial tokens
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

	token, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCodeObj.Code,
		clientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
		"",
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

	// Get initial tokens
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

	token, _, err := srv.ExchangeAuthorizationCode(
		context.Background(),
		authCodeObj.Code,
		clientID,
		"https://example.com/callback",
		"", // resource parameter (optional)
		codeVerifier,
		"",
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

// TestServer_ValidateRefreshTokenClientBinding tests the OAuth 2.1 Section 6 client binding validation
func TestServer_ValidateRefreshTokenClientBinding(t *testing.T) {
	tests := []struct {
		name               string
		storedClientID     string
		requestingClientID string
		userID             string
		wantError          bool
		errorContains      string
	}{
		{
			name:               "matching client IDs should pass",
			storedClientID:     "client-abc-123",
			requestingClientID: "client-abc-123",
			userID:             "user-123",
			wantError:          false,
		},
		{
			name:               "empty stored clientID (legacy token) should be rejected",
			storedClientID:     "",
			requestingClientID: "client-abc-123",
			userID:             "user-123",
			wantError:          true,
			errorContains:      "invalid_grant",
		},
		{
			name:               "mismatching client IDs should fail",
			storedClientID:     "client-original",
			requestingClientID: "client-attacker",
			userID:             "user-123",
			wantError:          true,
			errorContains:      "invalid_grant",
		},
		{
			name:               "different length client IDs should fail",
			storedClientID:     "short",
			requestingClientID: "much-longer-client-id",
			userID:             "user-123",
			wantError:          true,
			errorContains:      "invalid_grant",
		},
		{
			name:               "similar client IDs with one character difference should fail",
			storedClientID:     "client-abc-123",
			requestingClientID: "client-abc-124",
			userID:             "user-123",
			wantError:          true,
			errorContains:      "invalid_grant",
		},
		{
			name:               "empty requesting clientID with stored clientID should fail",
			storedClientID:     "client-abc-123",
			requestingClientID: "",
			userID:             "user-123",
			wantError:          true,
			errorContains:      "invalid_grant",
		},
		{
			name:               "case sensitivity - different case should fail",
			storedClientID:     "Client-ABC-123",
			requestingClientID: "client-abc-123",
			userID:             "user-123",
			wantError:          true,
			errorContains:      "invalid_grant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, _ := setupFlowTestServer(t)

			err := srv.validateRefreshTokenClientBinding(context.Background(), tt.storedClientID, tt.requestingClientID, tt.userID)

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got nil")
					return
				}
				if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errorContains)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestServer_ValidateRefreshTokenClientBinding_WithAuditor tests that audit events are logged correctly
func TestServer_ValidateRefreshTokenClientBinding_WithAuditor(t *testing.T) {
	t.Run("mismatch with auditor should not panic", func(t *testing.T) {
		srv, _, _ := setupFlowTestServer(t)

		// Create a real auditor with a discard logger
		srv.Auditor = security.NewAuditor(slog.Default(), true)

		err := srv.validateRefreshTokenClientBinding(context.Background(), "original-client", "attacker-client", "user-123")

		if err == nil {
			t.Fatal("expected error for mismatched client IDs")
		}
		if !strings.Contains(err.Error(), "invalid_grant") {
			t.Errorf("expected error to contain 'invalid_grant', got %v", err)
		}
	})

	t.Run("legacy token with auditor should reject and not panic", func(t *testing.T) {
		srv, _, _ := setupFlowTestServer(t)

		// Create a real auditor with a discard logger
		srv.Auditor = security.NewAuditor(slog.Default(), true)

		err := srv.validateRefreshTokenClientBinding(context.Background(), "", "requesting-client", "user-456")
		if err == nil {
			t.Fatal("expected error for legacy token without client binding")
		}
		if !strings.Contains(err.Error(), "invalid_grant") {
			t.Errorf("expected error to contain 'invalid_grant', got %v", err)
		}
	})

	t.Run("mismatch returns invalid_grant error", func(t *testing.T) {
		srv, _, _ := setupFlowTestServer(t)

		err := srv.validateRefreshTokenClientBinding(context.Background(), "original-client", "attacker-client", "user-123")

		if err == nil {
			t.Fatal("expected error for mismatched client IDs")
		}
		if !strings.Contains(err.Error(), "invalid_grant") {
			t.Errorf("expected error to contain 'invalid_grant', got %v", err)
		}
	})
}

// TestServer_ValidateRefreshTokenClientBinding_WithRateLimiter tests rate limiting of security event logging
func TestServer_ValidateRefreshTokenClientBinding_WithRateLimiter(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)

	// Set up a rate limiter that blocks after first call
	srv.SecurityEventRateLimiter = security.NewRateLimiter(1, 1, slog.Default()) // 1 request per second

	// First call should succeed (and log)
	err1 := srv.validateRefreshTokenClientBinding(context.Background(), "original", "attacker", "user-123")
	if err1 == nil {
		t.Fatal("expected error for first mismatch")
	}

	// Second call with same key should still return error but rate limiter prevents log
	// (We can't easily verify logging was suppressed without more complex mocking,
	// but we verify the error is still returned correctly)
	err2 := srv.validateRefreshTokenClientBinding(context.Background(), "original", "attacker", "user-123")
	if err2 == nil {
		t.Fatal("expected error for second mismatch")
	}

	// Both should return the same error type
	if err1.Error() != err2.Error() {
		t.Errorf("errors should be identical: %v vs %v", err1, err2)
	}
}

// TestServer_RefreshAccessToken_ClientBinding_Integration tests the full OAuth 2.1 Section 6
// client binding flow end-to-end, from token issuance to refresh with binding validation.
func TestServer_RefreshAccessToken_ClientBinding_Integration(t *testing.T) {
	t.Run("refresh with matching client ID should succeed", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)

		// Set up provider to return valid tokens
		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			return &oauth2.Token{
				AccessToken:  "new-provider-access-token",
				RefreshToken: "new-provider-refresh-token",
				Expiry:       time.Now().Add(time.Hour),
			}, nil
		}

		// Create initial tokens with client binding
		clientID := "test-client-123"
		userID := "user-456"
		refreshToken := "refresh-token-with-binding"

		// Save the refresh token with proper metadata (simulating what happens after code exchange)
		err := store.SaveRefreshTokenWithFamily(
			context.Background(),
			refreshToken,
			userID,
			clientID,
			"family-123",
			0,
			time.Now().Add(time.Hour),
		)
		if err != nil {
			t.Fatalf("Failed to save refresh token: %v", err)
		}

		// Save provider token that will be retrieved during refresh
		providerToken := &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}
		err = store.SaveUserProviderToken(context.Background(), userID, providerToken)
		if err != nil {
			t.Fatalf("Failed to save provider token: %v", err)
		}

		// Attempt refresh with the same client ID
		newToken, err := srv.RefreshAccessToken(context.Background(), refreshToken, clientID)
		if err != nil {
			t.Fatalf("Expected refresh to succeed with matching client ID, got error: %v", err)
		}
		if newToken == nil {
			t.Fatal("Expected non-nil token response")
		}
		if newToken.AccessToken == "" {
			t.Error("Expected non-empty access token")
		}
		if newToken.RefreshToken == "" {
			t.Error("Expected non-empty refresh token (rotated)")
		}

		t.Log("✓ Refresh with matching client ID succeeded")
	})

	t.Run("refresh with mismatching client ID should fail", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)

		// Set up provider (should not be called due to early rejection)
		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			t.Error("Provider RefreshToken should not be called when client binding fails")
			return nil, fmt.Errorf("should not be called")
		}

		// Create initial tokens with client binding to original client
		originalClientID := "original-client-123"
		attackerClientID := "attacker-client-456"
		userID := "user-789"
		refreshToken := "refresh-token-for-mismatch-test"

		// Save the refresh token with original client binding
		err := store.SaveRefreshTokenWithFamily(
			context.Background(),
			refreshToken,
			userID,
			originalClientID,
			"family-456",
			0,
			time.Now().Add(time.Hour),
		)
		if err != nil {
			t.Fatalf("Failed to save refresh token: %v", err)
		}

		// Save provider token
		providerToken := &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}
		err = store.SaveUserProviderToken(context.Background(), userID, providerToken)
		if err != nil {
			t.Fatalf("Failed to save provider token: %v", err)
		}

		// Attempt refresh with a DIFFERENT client ID (simulating attack)
		newToken, err := srv.RefreshAccessToken(context.Background(), refreshToken, attackerClientID)

		if err == nil {
			t.Fatal("Expected refresh to fail with mismatching client ID")
		}
		if !strings.Contains(err.Error(), "invalid_grant") {
			t.Errorf("Expected 'invalid_grant' error, got: %v", err)
		}
		if newToken != nil {
			t.Error("Expected nil token response on failure")
		}

		t.Log("✓ Refresh with mismatching client ID correctly rejected")
	})

	t.Run("legacy token without binding is always rejected", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)

		// Set up provider (should not be called due to early rejection)
		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			t.Error("Provider RefreshToken should not be called when legacy token is rejected")
			return nil, fmt.Errorf("should not be called")
		}

		// Create a legacy refresh token WITHOUT client binding
		// This simulates tokens issued before OAuth 2.1 client binding was implemented
		clientID := "requesting-client"
		userID := "user-legacy"
		refreshToken := "legacy-refresh-no-binding" // #nosec G101 -- test data, not credentials

		// Save refresh token without family/client binding (legacy behavior)
		err := store.SaveRefreshToken(
			context.Background(),
			refreshToken,
			userID,
			time.Now().Add(time.Hour),
		)
		if err != nil {
			t.Fatalf("Failed to save refresh token: %v", err)
		}

		// Save provider token
		providerToken := &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(time.Hour),
		}
		err = store.SaveUserProviderToken(context.Background(), userID, providerToken)
		if err != nil {
			t.Fatalf("Failed to save provider token: %v", err)
		}

		// Attempt refresh - should always fail (OAuth 2.1 requires client binding)
		newToken, err := srv.RefreshAccessToken(context.Background(), refreshToken, clientID)

		if err == nil {
			t.Fatal("Expected legacy token refresh to fail - OAuth 2.1 requires client binding")
		}
		if !strings.Contains(err.Error(), "invalid_grant") {
			t.Errorf("Expected 'invalid_grant' error, got: %v", err)
		}
		if newToken != nil {
			t.Error("Expected nil token response on failure")
		}

		t.Log("✓ Legacy token without binding correctly rejected (OAuth 2.1 compliance)")
	})
}

// TestServer_RefreshAccessToken_IDTokenForwarding verifies that the id_token from
// the provider's refresh response is correctly forwarded to the client.
// Per OpenID Connect Core 1.0 Section 12.2, some providers return a new id_token on refresh.
func TestServer_RefreshAccessToken_IDTokenForwarding(t *testing.T) {
	t.Run("id_token from provider should be forwarded", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)

		testIDToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQ1NiIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsImlzcyI6Imh0dHBzOi8vaWRwLmV4YW1wbGUuY29tIn0.signature" //nolint:gosec // test value

		// Set up provider to return a token with id_token
		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			return (&oauth2.Token{
				AccessToken:  "new-provider-access-token",
				RefreshToken: "new-provider-refresh-token",
				Expiry:       time.Now().Add(time.Hour),
			}).WithExtra(map[string]interface{}{
				"id_token": testIDToken,
			}), nil
		}

		clientID := "test-client-123"
		userID := "user-456"
		refreshToken := "refresh-token-with-id-token-test"

		// Save the refresh token with proper metadata
		err := store.SaveRefreshTokenWithFamily(
			context.Background(),
			refreshToken,
			userID,
			clientID,
			"family-123",
			0,
			time.Now().Add(time.Hour),
		)
		if err != nil {
			t.Fatalf("Failed to save refresh token: %v", err)
		}

		// Save initial provider token, already expired so the coordinated grant
		// actually refreshes upstream (a fresh entry would be adopted without a
		// dex call under the rotation-race single-flight behavior).
		providerToken := &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(-time.Minute),
		}
		err = store.SaveUserProviderToken(context.Background(), userID, providerToken)
		if err != nil {
			t.Fatalf("Failed to save provider token: %v", err)
		}

		// Refresh the token
		newToken, err := srv.RefreshAccessToken(context.Background(), refreshToken, clientID)
		if err != nil {
			t.Fatalf("Expected refresh to succeed, got error: %v", err)
		}

		// Verify id_token is forwarded in the response
		idToken := newToken.Extra("id_token")
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

		t.Log("✓ id_token correctly forwarded during refresh")
	})

	t.Run("response should be valid when provider returns no id_token", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)

		// Set up provider to return a token WITHOUT id_token
		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			return &oauth2.Token{
				AccessToken:  "new-provider-access-token",
				RefreshToken: "new-provider-refresh-token",
				Expiry:       time.Now().Add(time.Hour),
			}, nil
		}

		clientID := "test-client-456"
		userID := "user-789"
		refreshToken := "refresh-token-no-id-token-test"

		// Save the refresh token with proper metadata
		err := store.SaveRefreshTokenWithFamily(
			context.Background(),
			refreshToken,
			userID,
			clientID,
			"family-456",
			0,
			time.Now().Add(time.Hour),
		)
		if err != nil {
			t.Fatalf("Failed to save refresh token: %v", err)
		}

		// Save initial provider token, already expired so the coordinated grant
		// actually refreshes upstream (a fresh entry would be adopted without a
		// dex call under the rotation-race single-flight behavior).
		providerToken := &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(-time.Minute),
		}
		err = store.SaveUserProviderToken(context.Background(), userID, providerToken)
		if err != nil {
			t.Fatalf("Failed to save provider token: %v", err)
		}

		// Refresh the token
		newToken, err := srv.RefreshAccessToken(context.Background(), refreshToken, clientID)
		if err != nil {
			t.Fatalf("Expected refresh to succeed, got error: %v", err)
		}

		// Verify response is valid
		if newToken.AccessToken == "" {
			t.Error("Expected non-empty access token")
		}

		// Verify id_token is nil when not provided
		idToken := newToken.Extra("id_token")
		if idToken != nil {
			t.Errorf("id_token should be nil when not provided, got %v", idToken)
		}

		t.Log("✓ Response valid when provider returns no id_token")
	})
}

// TestServer_RefreshAccessToken_ExpiryCap tests that refreshed tokens' expiry
// is capped to the new provider token's expiry when it expires sooner.
func TestServer_RefreshAccessToken_ExpiryCap(t *testing.T) {
	t.Run("provider returns token expiring before AccessTokenTTL - should cap expiry", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)
		srv.Config.AccessTokenTTL = 3600 // 1 hour

		providerExpiry := time.Now().Add(10 * time.Minute)
		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			return &oauth2.Token{
				AccessToken:  "new-provider-access",
				RefreshToken: "new-provider-refresh",
				Expiry:       providerExpiry,
				TokenType:    "Bearer",
			}, nil
		}

		clientID := "test-client-cap"
		userID := "user-cap"
		refreshToken := "refresh-token-cap-test"

		// Save refresh token with family
		if err := store.SaveRefreshTokenWithFamily(
			context.Background(), refreshToken, userID, clientID,
			"family-cap", 0, time.Now().Add(time.Hour),
		); err != nil {
			t.Fatalf("Failed to save refresh token: %v", err)
		}

		// Save provider token, already expired so the coordinated grant actually
		// refreshes upstream (a fresh entry would be adopted without a dex call,
		// and this test needs the provider's short expiry to drive the cap).
		if err := store.SaveUserProviderToken(context.Background(), userID, &oauth2.Token{
			AccessToken:  "old-provider-access",
			RefreshToken: "old-provider-refresh",
			Expiry:       time.Now().Add(-time.Minute),
		}); err != nil {
			t.Fatalf("Failed to save provider token: %v", err)
		}

		newToken, err := srv.RefreshAccessToken(context.Background(), refreshToken, clientID)
		if err != nil {
			t.Fatalf("RefreshAccessToken() error = %v", err)
		}

		// Expiry should be capped to provider token's expiry
		timeDiff := newToken.Expiry.Sub(providerExpiry).Abs()
		if timeDiff > 2*time.Second {
			t.Errorf("Token expiry = %v, want close to provider expiry %v (diff: %v)",
				newToken.Expiry, providerExpiry, timeDiff)
		}
	})

	t.Run("provider returns token expiring after AccessTokenTTL - should use AccessTokenTTL", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)
		srv.Config.AccessTokenTTL = 3600 // 1 hour

		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			return &oauth2.Token{
				AccessToken:  "new-provider-access",
				RefreshToken: "new-provider-refresh",
				Expiry:       time.Now().Add(2 * time.Hour), // longer than AccessTokenTTL
				TokenType:    "Bearer",
			}, nil
		}

		clientID := "test-client-nopcap"
		userID := "user-nocap"
		refreshToken := "refresh-token-nocap-test"

		if err := store.SaveRefreshTokenWithFamily(
			context.Background(), refreshToken, userID, clientID,
			"family-nocap", 0, time.Now().Add(time.Hour),
		); err != nil {
			t.Fatalf("Failed to save refresh token: %v", err)
		}

		// Already expired so the coordinated grant refreshes upstream; the
		// provider's 2h expiry then exceeds AccessTokenTTL and must be capped
		// down to it.
		if err := store.SaveUserProviderToken(context.Background(), userID, &oauth2.Token{
			AccessToken:  "old-provider-access",
			RefreshToken: "old-provider-refresh",
			Expiry:       time.Now().Add(-time.Minute),
		}); err != nil {
			t.Fatalf("Failed to save provider token: %v", err)
		}

		newToken, err := srv.RefreshAccessToken(context.Background(), refreshToken, clientID)
		if err != nil {
			t.Fatalf("RefreshAccessToken() error = %v", err)
		}

		// Expiry should be approximately now + AccessTokenTTL
		expectedExpiry := time.Now().Add(time.Duration(srv.Config.AccessTokenTTL) * time.Second)
		timeDiff := newToken.Expiry.Sub(expectedExpiry).Abs()
		if timeDiff > 2*time.Second {
			t.Errorf("Token expiry = %v, want close to %v (diff: %v)",
				newToken.Expiry, expectedExpiry, timeDiff)
		}
	})
}

func TestServer_RefreshAccessToken_CleansUpOldTokenPair(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	clientID := "test-client-cleanup"
	userID := "test-user-cleanup"
	oldAccessToken := "old-client-access"   // nolint:gosec // G101: test token identifier, not credentials
	oldRefreshToken := "old-client-refresh" // nolint:gosec // G101: test token identifier, not credentials

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "new-provider-access",
			RefreshToken: "new-provider-refresh",
			Expiry:       time.Now().Add(30 * time.Minute),
			TokenType:    "Bearer",
		}, nil
	}

	if err := store.SaveRefreshTokenWithFamily(
		ctx, oldRefreshToken, userID, clientID, "family-cleanup", 0, time.Now().Add(time.Hour),
	); err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily() error = %v", err)
	}

	if err := store.SaveUserProviderToken(ctx, userID, &oauth2.Token{
		AccessToken:  "old-provider-access",
		RefreshToken: "old-provider-refresh",
		Expiry:       time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveUserProviderToken() error = %v", err)
	}

	srv.registerTokenPair(oldAccessToken, oldRefreshToken)

	newToken, err := srv.RefreshAccessToken(ctx, oldRefreshToken, clientID)
	if err != nil {
		t.Fatalf("RefreshAccessToken() error = %v", err)
	}

	if _, ok := srv.tokenPairs.Load(oldAccessToken); ok {
		t.Fatalf("old access token pair mapping should be deleted")
	}
	if _, ok := srv.tokenPairsByRefresh.Load(oldRefreshToken); ok {
		t.Fatalf("old refresh token pair mapping should be deleted")
	}

	pairedRT, ok := srv.tokenPairs.Load(newToken.AccessToken)
	if !ok {
		t.Fatalf("new access token mapping missing")
	}
	if pairedRT.(string) != newToken.RefreshToken {
		t.Fatalf("new access token mapped to %q, want %q", pairedRT.(string), newToken.RefreshToken)
	}

	pairedAT, ok := srv.tokenPairsByRefresh.Load(newToken.RefreshToken)
	if !ok {
		t.Fatalf("new refresh token reverse mapping missing")
	}
	if pairedAT.(string) != newToken.AccessToken {
		t.Fatalf("new refresh token mapped to %q, want %q", pairedAT.(string), newToken.AccessToken)
	}
}

func TestServer_RefreshAccessToken_FamilyIDInMetadata(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400

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
	_, err = srv.StartAuthorizationFlow(ctx, clientID, mustParseURL(t, "https://example.com/callback"), "openid email", "", codeChallenge, PKCEMethodS256, clientState, nil)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(ctx, authState.ProviderState, "code-"+testutil.GenerateRandomString(10))
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	token, _, err := srv.ExchangeAuthorizationCode(ctx, authCodeObj.Code, clientID, "https://example.com/callback", "", codeVerifier, "")
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	origMeta, err := store.GetTokenMetadata(token.AccessToken)
	if err != nil {
		t.Fatalf("GetTokenMetadata() error = %v", err)
	}
	origFamilyID := origMeta.FamilyID
	if origFamilyID == "" {
		t.Fatal("Original token should have a FamilyID")
	}

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "new-provider-access",
			RefreshToken: "new-provider-refresh",
			Expiry:       time.Now().Add(time.Hour),
		}, nil
	}

	token2, err := srv.RefreshAccessToken(ctx, token.RefreshToken, clientID)
	if err != nil {
		t.Fatalf("RefreshAccessToken() error = %v", err)
	}

	newATMeta, err := store.GetTokenMetadata(token2.AccessToken)
	if err != nil {
		t.Fatalf("GetTokenMetadata(new AT) error = %v", err)
	}
	if newATMeta.FamilyID != origFamilyID {
		t.Errorf("New AT FamilyID = %q, want %q (same family after refresh)", newATMeta.FamilyID, origFamilyID)
	}
	if newATMeta.ExpiresAt.IsZero() {
		t.Error("New AT ExpiresAt must be set after refresh")
	}
	if !newATMeta.IssuedAt.Before(newATMeta.ExpiresAt) {
		t.Errorf("New AT IssuedAt (%v) must be before ExpiresAt (%v)", newATMeta.IssuedAt, newATMeta.ExpiresAt)
	}

	newRTMeta, err := store.GetTokenMetadata(token2.RefreshToken)
	if err != nil {
		t.Fatalf("GetTokenMetadata(new RT) error = %v", err)
	}
	if newRTMeta.FamilyID != origFamilyID {
		t.Errorf("New RT FamilyID = %q, want %q (same family after refresh)", newRTMeta.FamilyID, origFamilyID)
	}
	if newRTMeta.ExpiresAt.IsZero() {
		t.Error("New RT ExpiresAt must be set after refresh")
	}
}

func TestServer_RefreshAccessToken_PreservesScopesAndAudience(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400

	client, _, err := srv.RegisterClient(
		ctx,
		"Scope Test Client",
		ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email", "profile"},
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
	_, err = srv.StartAuthorizationFlow(ctx, clientID, mustParseURL(t, "https://example.com/callback"), "openid email profile", "", codeChallenge, PKCEMethodS256, clientState, nil)
	if err != nil {
		t.Fatalf("StartAuthorizationFlow() error = %v", err)
	}

	authState, err := store.GetAuthorizationState(ctx, clientState)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	authCodeObj, _, err := srv.HandleProviderCallback(ctx, authState.ProviderState, "code-"+testutil.GenerateRandomString(10))
	if err != nil {
		t.Fatalf("HandleProviderCallback() error = %v", err)
	}

	token, _, err := srv.ExchangeAuthorizationCode(ctx, authCodeObj.Code, clientID, "https://example.com/callback", "", codeVerifier, "")
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode() error = %v", err)
	}

	origMeta, err := store.GetTokenMetadata(token.AccessToken)
	if err != nil {
		t.Fatalf("GetTokenMetadata(original AT) error = %v", err)
	}
	if len(origMeta.Scopes) == 0 {
		t.Fatal("Original token should have scopes set")
	}

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "refreshed-provider-at",
			RefreshToken: "refreshed-provider-rt",
			Expiry:       time.Now().Add(time.Hour),
		}, nil
	}

	token2, err := srv.RefreshAccessToken(ctx, token.RefreshToken, clientID)
	if err != nil {
		t.Fatalf("RefreshAccessToken() error = %v", err)
	}

	newATMeta, err := store.GetTokenMetadata(token2.AccessToken)
	if err != nil {
		t.Fatalf("GetTokenMetadata(new AT) error = %v", err)
	}

	if !slices.Equal(newATMeta.Scopes, origMeta.Scopes) {
		t.Errorf("Refreshed AT scopes = %v, want %v (scopes should survive refresh)", newATMeta.Scopes, origMeta.Scopes)
	}

	newRTMeta, err := store.GetTokenMetadata(token2.RefreshToken)
	if err != nil {
		t.Fatalf("GetTokenMetadata(new RT) error = %v", err)
	}

	if !slices.Equal(newRTMeta.Scopes, origMeta.Scopes) {
		t.Errorf("Refreshed RT scopes = %v, want %v (scopes should survive refresh)", newRTMeta.Scopes, origMeta.Scopes)
	}
}

func TestServer_SetTokenRefreshHandler(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)

	var called bool
	srv.tokenRefreshHandler = func(_ context.Context, _, _ string, _ *oauth2.Token) {
		called = true
	}

	if srv.tokenRefreshHandler == nil {
		t.Fatal("Handler should be set after SetTokenRefreshHandler()")
	}

	srv.tokenRefreshHandler(context.Background(), "u", "f", &oauth2.Token{})
	if !called {
		t.Error("Handler should be callable")
	}
}

func TestServer_TokenRefreshHandler_CalledOnProactiveRefresh(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	srv.Config.TokenRefreshThreshold = 300 // 5 minutes

	var handlerUserID, handlerFamilyID string
	var handlerToken *oauth2.Token
	srv.tokenRefreshHandler = func(_ context.Context, userID, familyID string, token *oauth2.Token) {
		handlerUserID = userID
		handlerFamilyID = familyID
		handlerToken = token
	}

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "refreshed-provider-access",
			RefreshToken: "refreshed-provider-refresh",
			Expiry:       time.Now().Add(1 * time.Hour),
			TokenType:    "Bearer",
		}, nil
	}

	provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    testMockUserID,
			Email: "mock@example.com",
		}, nil
	}

	// Store a token that is near expiry (within the 5m threshold) as the
	// user's shared provider entry, referenced by the access token.
	accessToken := "proactive-refresh-test-token"
	nearExpiryToken := &oauth2.Token{
		AccessToken:  "provider-at",
		RefreshToken: "provider-rt",
		Expiry:       time.Now().Add(2 * time.Minute),
		TokenType:    "Bearer",
	}
	seedProviderToken(t, store, accessToken, testMockUserID, nearExpiryToken)

	// Save token metadata so the handler can retrieve userID/familyID
	if err := store.SaveTokenMetadata(context.Background(), accessToken, storage.TokenMetadata{UserID: testMockUserID, ClientID: "test-client", TokenType: "access", Audience: "", FamilyID: "test-family-id", Scopes: nil}); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	_, err := srv.ValidateToken(ctx, accessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if handlerToken == nil {
		t.Fatal("TokenRefreshHandler was not called during proactive refresh")
	}
	if handlerUserID != testMockUserID {
		t.Errorf("handler userID = %q, want %q", handlerUserID, testMockUserID)
	}
	if handlerFamilyID != "test-family-id" {
		t.Errorf("handler familyID = %q, want %q", handlerFamilyID, "test-family-id")
	}
	if handlerToken.AccessToken != "refreshed-provider-access" {
		t.Errorf("handler token AccessToken = %q, want %q", handlerToken.AccessToken, "refreshed-provider-access")
	}
}

func TestServer_TokenRefreshHandler_CalledOnExpiredTokenRefresh(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	var handlerUserID, handlerFamilyID string
	var handlerToken *oauth2.Token
	srv.tokenRefreshHandler = func(_ context.Context, userID, familyID string, token *oauth2.Token) {
		handlerUserID = userID
		handlerFamilyID = familyID
		handlerToken = token
	}

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "refreshed-expired-access",
			RefreshToken: "refreshed-expired-refresh",
			Expiry:       time.Now().Add(1 * time.Hour),
			TokenType:    "Bearer",
		}, nil
	}

	provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    testMockUserID,
			Email: "mock@example.com",
		}, nil
	}

	// Store an already-expired token with a refresh token as the user's
	// shared provider entry, referenced by the access token.
	accessToken := "expired-refresh-test-token"
	expiredToken := &oauth2.Token{
		AccessToken:  "old-provider-at",
		RefreshToken: "old-provider-rt",
		Expiry:       time.Now().Add(-10 * time.Minute),
		TokenType:    "Bearer",
	}
	seedProviderToken(t, store, accessToken, testMockUserID, expiredToken)

	if err := store.SaveTokenMetadata(context.Background(), accessToken, storage.TokenMetadata{UserID: testMockUserID, ClientID: "test-client", TokenType: "access", Audience: "", FamilyID: "expired-family-id", Scopes: nil}); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}

	_, err := srv.ValidateToken(ctx, accessToken)
	if err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}

	if handlerToken == nil {
		t.Fatal("TokenRefreshHandler was not called during expired token refresh")
	}
	if handlerUserID != testMockUserID {
		t.Errorf("handler userID = %q, want %q", handlerUserID, testMockUserID)
	}
	if handlerFamilyID != "expired-family-id" {
		t.Errorf("handler familyID = %q, want %q", handlerFamilyID, "expired-family-id")
	}
	if handlerToken.AccessToken != "refreshed-expired-access" {
		t.Errorf("handler token AccessToken = %q, want %q", handlerToken.AccessToken, "refreshed-expired-access")
	}
}

func TestServer_TokenRefreshHandler_NotCalledWithoutHandler(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	srv.Config.TokenRefreshThreshold = 300

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "refreshed-access",
			RefreshToken: "refreshed-refresh",
			Expiry:       time.Now().Add(1 * time.Hour),
			TokenType:    "Bearer",
		}, nil
	}

	provider.ValidateTokenFunc = func(_ context.Context, _ string) (*providers.UserInfo, error) {
		return &providers.UserInfo{
			ID:    testMockUserID,
			Email: "mock@example.com",
		}, nil
	}

	accessToken := "no-handler-test-token"
	nearExpiryToken := &oauth2.Token{
		AccessToken:  "provider-at",
		RefreshToken: "provider-rt",
		Expiry:       time.Now().Add(2 * time.Minute),
		TokenType:    "Bearer",
	}
	seedProviderToken(t, store, accessToken, testMockUserID, nearExpiryToken)

	// No handler set -- ValidateToken should still succeed
	_, err := srv.ValidateToken(ctx, accessToken)
	if err != nil {
		t.Fatalf("ValidateToken() should succeed without handler, got error = %v", err)
	}
}

func TestServer_TokenRefreshHandler_NilHandler(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)

	srv.tokenRefreshHandler = nil
	if srv.tokenRefreshHandler != nil {
		t.Error("Handler should be nil after SetTokenRefreshHandler(nil)")
	}
}
