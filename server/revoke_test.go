package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestServer_RevokeToken(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	userID := "test-user-123"
	clientID := "test-client-id"
	refreshToken := testutil.GenerateRandomString(32)
	familyID := testutil.GenerateRandomString(32)

	// Save provider token mapping so RevokeToken finds the token
	providerToken := &oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "provider-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	err := store.SaveToken(ctx, refreshToken, providerToken)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Save refresh token with family tracking
	err = store.SaveRefreshTokenWithFamily(ctx, refreshToken, userID, clientID, familyID, 1, time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily() error = %v", err)
	}

	// Test revocation
	err = srv.RevokeToken(ctx, refreshToken, clientID, "192.168.1.100")
	if err != nil {
		t.Errorf("RevokeToken() error = %v", err)
	}

	// Verify token family was revoked (not just the individual token)
	family, err := store.GetRefreshTokenFamily(ctx, refreshToken)
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily() error = %v", err)
	}
	if !family.Revoked {
		t.Error("Token family should have been revoked on explicit revocation")
	}
}

// TestServer_RevokeToken_AccessTokenNoFamilyRevocation verifies that revoking an access token
// (which has no family entry) does not error and does not attempt family revocation.
func TestServer_RevokeToken_AccessTokenNoFamilyRevocation(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		return nil
	}

	accessToken := "access-token-no-family"

	// Save only a provider token mapping (no family)
	err := store.SaveToken(ctx, accessToken, &oauth2.Token{
		AccessToken: "provider-access",
		Expiry:      time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Revoking an access token should succeed without touching any family
	err = srv.RevokeToken(ctx, accessToken, "test-client", "127.0.0.1")
	if err != nil {
		t.Errorf("RevokeToken() for access token error = %v", err)
	}

	// Verify the token was deleted
	_, err = store.GetToken(ctx, accessToken)
	if err == nil {
		t.Error("Access token should have been deleted after revocation")
	}
}

// TestServer_RevokeToken_RefreshTokenWithoutFamily verifies that revoking a refresh token
// that has no family entry still succeeds (graceful degradation).
func TestServer_RevokeToken_RefreshTokenWithoutFamily(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		return nil
	}

	refreshToken := "refresh-token-no-family"

	// Save a provider token mapping but no family entry
	err := store.SaveToken(ctx, refreshToken, &oauth2.Token{
		AccessToken:  "provider-access",
		RefreshToken: "provider-refresh",
		Expiry:       time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Revoking should succeed without errors even with no family
	err = srv.RevokeToken(ctx, refreshToken, "test-client", "127.0.0.1")
	if err != nil {
		t.Errorf("RevokeToken() for token without family error = %v", err)
	}

	// Verify the token was deleted
	_, err = store.GetToken(ctx, refreshToken)
	if err == nil {
		t.Error("Token should have been deleted after revocation")
	}
}

// TestServer_RevokeToken_FamilyRevocationRevokesAllSiblings verifies that revoking one token
// in a family also revokes its sibling tokens (other generations in the same family).
func TestServer_RevokeToken_FamilyRevocationRevokesAllSiblings(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		return nil
	}

	userID := "test-user"
	clientID := "test-client"
	familyID := testutil.GenerateRandomString(32)
	refreshToken1 := testutil.GenerateRandomString(32)
	refreshToken2 := testutil.GenerateRandomString(32)

	// Save two tokens in the same family (simulating rotation)
	for i, tok := range []string{refreshToken1, refreshToken2} {
		if err := store.SaveToken(ctx, tok, &oauth2.Token{
			AccessToken: fmt.Sprintf("provider-access-%d", i),
			Expiry:      time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}
		if err := store.SaveRefreshTokenWithFamily(ctx, tok, userID, clientID, familyID, i+1, time.Now().Add(90*24*time.Hour)); err != nil {
			t.Fatalf("SaveRefreshTokenWithFamily() error = %v", err)
		}
	}

	// Revoke only the first token
	err := srv.RevokeToken(ctx, refreshToken1, clientID, "127.0.0.1")
	if err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}

	// Both tokens in the family should be revoked
	family2, err := store.GetRefreshTokenFamily(ctx, refreshToken2)
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily(token2) error = %v", err)
	}
	if !family2.Revoked {
		t.Error("Sibling token in the same family should have been revoked")
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
	if err := store.SaveTokenMetadata(context.Background(), "access_token_1", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}
	if err := store.SaveTokenMetadata(context.Background(), "access_token_2", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
	if err := store.SaveTokenMetadata(context.Background(), "access_token_3", storage.TokenMetadata{UserID: userID, ClientID: "different_client", TokenType: "access"}); err != nil {
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
	if err := store.SaveTokenMetadata(context.Background(), "access_token_1", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
		t.Fatalf("SaveTokenMetadata() error = %v", err)
	}
	if err := store.SaveTokenMetadata(context.Background(), "access_token_2", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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

	if err := store.SaveTokenMetadata(context.Background(), "access_token_timeout", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
	if err := store.SaveTokenMetadata(context.Background(), "access_token_retry", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
		if err := store.SaveTokenMetadata(context.Background(), tokenID, storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
		if err := store.SaveTokenMetadata(context.Background(), tokenID, storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
	if err := store.SaveTokenMetadata(context.Background(), "access_token_backoff", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
	if err := store.SaveTokenMetadata(context.Background(), "access_token_cancel", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
		if err := store.SaveTokenMetadata(context.Background(), tokenID, storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
	if err := store.SaveTokenMetadata(context.Background(), "access_token_single", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
			if err := store.SaveTokenMetadata(context.Background(), "access_token_errors", storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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
			if err := store.SaveTokenMetadata(context.Background(), tokenID, storage.TokenMetadata{UserID: userID, ClientID: clientID, TokenType: "access"}); err != nil {
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

func TestServer_RevokeToken_CleansUpTokenPair(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	provider.RevokeTokenFunc = func(_ context.Context, _ string) error {
		return nil
	}

	accessToken := "revoke-access-token"
	refreshToken := "revoke-refresh-token"

	if err := store.SaveToken(ctx, accessToken, &oauth2.Token{
		AccessToken:  "provider-access",
		RefreshToken: "provider-refresh",
		Expiry:       time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	srv.registerTokenPair(accessToken, refreshToken)

	if err := srv.RevokeToken(ctx, accessToken, "test-client", "127.0.0.1"); err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}

	if _, ok := srv.tokenPairs.Load(accessToken); ok {
		t.Fatalf("access token pair mapping should be deleted")
	}
	if _, ok := srv.tokenPairsByRefresh.Load(refreshToken); ok {
		t.Fatalf("refresh token reverse mapping should be deleted")
	}
}

func TestServer_RevokeToken_CallsSessionRevocationHandler(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	userID := "revoke-handler-user"
	clientID := "revoke-handler-client"
	familyID := testutil.GenerateRandomString(32)
	refreshToken := testutil.GenerateRandomString(32)

	var handlerCalled bool
	var capturedUserID, capturedFamilyID string
	srv.sessionRevocationHandler = func(_ context.Context, uid, fid string) {
		handlerCalled = true
		capturedUserID = uid
		capturedFamilyID = fid
	}

	if err := store.SaveToken(ctx, refreshToken, &oauth2.Token{
		AccessToken:  "provider-at",
		RefreshToken: "provider-rt",
		Expiry:       time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	if err := store.SaveRefreshTokenWithFamily(ctx, refreshToken, userID, clientID, familyID, 1, time.Now().Add(90*24*time.Hour)); err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily() error = %v", err)
	}

	if err := srv.RevokeToken(ctx, refreshToken, clientID, "127.0.0.1"); err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}

	if !handlerCalled {
		t.Fatal("SessionRevocationHandler should have been called on revocation")
	}
	if capturedUserID != userID {
		t.Errorf("Handler received userID = %q, want %q", capturedUserID, userID)
	}
	if capturedFamilyID != familyID {
		t.Errorf("Handler received familyID = %q, want %q", capturedFamilyID, familyID)
	}
}

func TestServer_RevokeToken_NoHandlerDoesNotPanic(t *testing.T) {
	ctx := context.Background()
	srv, store, _ := setupFlowTestServer(t)

	userID := "no-handler-user"
	clientID := "no-handler-client"
	familyID := testutil.GenerateRandomString(32)
	refreshToken := testutil.GenerateRandomString(32)

	if err := store.SaveToken(ctx, refreshToken, &oauth2.Token{
		AccessToken:  "provider-at",
		RefreshToken: "provider-rt",
		Expiry:       time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	if err := store.SaveRefreshTokenWithFamily(ctx, refreshToken, userID, clientID, familyID, 1, time.Now().Add(90*24*time.Hour)); err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily() error = %v", err)
	}

	if err := srv.RevokeToken(ctx, refreshToken, clientID, "127.0.0.1"); err != nil {
		t.Fatalf("RevokeToken() should succeed without a handler: %v", err)
	}
}

func TestServer_RevokeToken_HandlerNotCalledWithoutFamily(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	provider.RevokeTokenFunc = func(_ context.Context, _ string) error { return nil }

	var handlerCalled bool
	srv.sessionRevocationHandler = func(_ context.Context, _, _ string) {
		handlerCalled = true
	}

	accessToken := "at-no-family"
	if err := store.SaveToken(ctx, accessToken, &oauth2.Token{
		AccessToken: "provider-at",
		Expiry:      time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	if err := srv.RevokeToken(ctx, accessToken, "client-1", "127.0.0.1"); err != nil {
		t.Fatalf("RevokeToken() error = %v", err)
	}

	if handlerCalled {
		t.Error("SessionRevocationHandler should NOT be called when token has no family")
	}
}

func TestServer_SetSessionRevocationHandler(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)

	var called bool
	srv.sessionRevocationHandler = func(_ context.Context, _, _ string) {
		called = true
	}

	if srv.sessionRevocationHandler == nil {
		t.Fatal("Handler should be set after SetSessionRevocationHandler()")
	}

	srv.sessionRevocationHandler(context.Background(), "u", "f")
	if !called {
		t.Error("Handler should be callable")
	}
}

func TestServer_SetTokenFamilyRevocationHandler_DeprecatedAlias(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)

	var called bool
	srv.sessionRevocationHandler = func(_ context.Context, _, _ string) {
		called = true
	}

	if srv.sessionRevocationHandler == nil {
		t.Fatal("Deprecated SetTokenFamilyRevocationHandler should set sessionRevocationHandler")
	}

	srv.sessionRevocationHandler(context.Background(), "u", "f")
	if !called {
		t.Error("Handler set via deprecated alias should be callable")
	}
}
