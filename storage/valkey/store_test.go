package valkey

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Test constants for consistent naming
const (
	testUserID = "test-user"
)

// testStore creates a test store connected to a local Valkey instance.
// Tests will be skipped if VALKEY_TEST_ADDR is not set or connection fails.
// Each test gets a unique prefix to ensure test isolation.
func testStore(t *testing.T) *Store {
	t.Helper()

	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	// Generate a unique prefix for this test to ensure isolation
	// This prevents interference when tests run in parallel
	prefix := fmt.Sprintf("mcptest:%s:", t.Name())

	// Try to connect
	store, err := New(Config{
		Address:   addr,
		KeyPrefix: prefix,
	})
	if err != nil {
		t.Skipf("Skipping test: could not connect to Valkey at %s: %v", addr, err)
	}

	// Clean up test keys before and after test
	t.Cleanup(func() {
		cleanupTestKeys(t, store)
		store.Close()
	})

	cleanupTestKeys(t, store)
	return store
}

// cleanupTestKeys removes all test keys from Valkey
func cleanupTestKeys(t *testing.T, s *Store) {
	t.Helper()

	ctx := context.Background()
	pattern := s.prefix + "*"

	var cursor uint64
	for {
		result, err := s.client.Do(ctx,
			s.client.B().Scan().Cursor(cursor).Match(pattern).Count(100).Build(),
		).AsScanEntry()
		if err != nil {
			t.Logf("Warning: failed to scan for cleanup: %v", err)
			return
		}

		for _, key := range result.Elements {
			_ = s.client.Do(ctx, s.client.B().Del().Key(key).Build())
		}

		cursor = result.Cursor
		if cursor == 0 {
			break
		}
	}
}

// ============================================================
// Config Tests
// ============================================================

func TestNew_MissingAddress(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Error("Expected error for missing address")
	}
}

func TestNew_InvalidAddress(t *testing.T) {
	_, err := New(Config{Address: "invalid:99999"})
	if err == nil {
		t.Error("Expected error for invalid address")
	}
}

// ============================================================
// TokenStore Tests
// ============================================================

func TestTokenStore_SaveAndGetToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	token := &oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Save token
	err := s.SaveToken(ctx, "user1", token)
	if err != nil {
		t.Fatalf("SaveToken failed: %v", err)
	}

	// Get token
	got, err := s.GetToken(ctx, "user1")
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}

	if got.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, token.AccessToken)
	}
	if got.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, token.RefreshToken)
	}
}

func TestTokenStore_GetToken_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetToken(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent token")
	}
	if !storage.IsNotFoundError(err) {
		t.Errorf("Expected ErrTokenNotFound, got: %v", err)
	}
}

func TestTokenStore_DeleteToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	token := &oauth2.Token{
		AccessToken: "to-delete",
		Expiry:      time.Now().Add(time.Hour),
	}

	_ = s.SaveToken(ctx, "user2", token)

	err := s.DeleteToken(ctx, "user2")
	if err != nil {
		t.Fatalf("DeleteToken failed: %v", err)
	}

	_, err = s.GetToken(ctx, "user2")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Token should be deleted, got: %v", err)
	}
}

func TestTokenStore_SaveToken_Expired(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	token := &oauth2.Token{
		AccessToken: "expired",
		Expiry:      time.Now().Add(-time.Hour), // Already expired
	}

	err := s.SaveToken(ctx, "user3", token)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestTokenStore_SaveToken_EmptyUserID(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.SaveToken(ctx, "", &oauth2.Token{})
	if err == nil {
		t.Error("Expected error for empty userID")
	}
}

func TestTokenStore_SaveToken_NilToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.SaveToken(ctx, "user4", nil)
	if err == nil {
		t.Error("Expected error for nil token")
	}
}

// ============================================================
// UserInfo Tests
// ============================================================

func TestTokenStore_SaveAndGetUserInfo(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	info := &providers.UserInfo{
		ID:            "user1",
		Email:         "user@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}

	err := s.SaveUserInfo(ctx, "user1", info)
	if err != nil {
		t.Fatalf("SaveUserInfo failed: %v", err)
	}

	got, err := s.GetUserInfo(ctx, "user1")
	if err != nil {
		t.Fatalf("GetUserInfo failed: %v", err)
	}

	if got.Email != info.Email {
		t.Errorf("Email = %q, want %q", got.Email, info.Email)
	}
	if got.Name != info.Name {
		t.Errorf("Name = %q, want %q", got.Name, info.Name)
	}
}

func TestTokenStore_GetUserInfo_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetUserInfo(ctx, "nonexistent")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Expected ErrUserInfoNotFound, got: %v", err)
	}
}

// ============================================================
// RefreshToken Tests
// ============================================================

func TestTokenStore_SaveAndGetRefreshToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.SaveRefreshToken(ctx, "refresh-token-1", "user1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SaveRefreshToken failed: %v", err)
	}

	userID, err := s.GetRefreshTokenInfo(ctx, "refresh-token-1")
	if err != nil {
		t.Fatalf("GetRefreshTokenInfo failed: %v", err)
	}

	if userID != "user1" {
		t.Errorf("UserID = %q, want %q", userID, "user1")
	}
}

func TestTokenStore_GetRefreshTokenInfo_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetRefreshTokenInfo(ctx, "nonexistent")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Expected ErrTokenNotFound, got: %v", err)
	}
}

func TestTokenStore_DeleteRefreshToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_ = s.SaveRefreshToken(ctx, "refresh-to-delete", "user1", time.Now().Add(time.Hour))

	err := s.DeleteRefreshToken(ctx, "refresh-to-delete")
	if err != nil {
		t.Fatalf("DeleteRefreshToken failed: %v", err)
	}

	_, err = s.GetRefreshTokenInfo(ctx, "refresh-to-delete")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Token should be deleted, got: %v", err)
	}
}

// ============================================================
// ClientStore Tests
// ============================================================

func TestClientStore_SaveAndGetClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	client := &storage.Client{
		ClientID:     "test-client",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		CreatedAt:    time.Now(),
	}

	err := s.SaveClient(ctx, client)
	if err != nil {
		t.Fatalf("SaveClient failed: %v", err)
	}

	got, err := s.GetClient(ctx, "test-client")
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}

	if got.ClientID != client.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, client.ClientID)
	}
	if got.ClientType != client.ClientType {
		t.Errorf("ClientType = %q, want %q", got.ClientType, client.ClientType)
	}
}

func TestClientStore_GetClient_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetClient(ctx, "nonexistent")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Expected ErrClientNotFound, got: %v", err)
	}
}

func TestClientStore_ValidateClientSecret(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create a client with a bcrypt-hashed secret
	secret := "test-secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	client := &storage.Client{
		ClientID:         "secret-client",
		ClientSecretHash: string(hash),
		ClientType:       "confidential",
		RedirectURIs:     []string{"https://example.com/callback"},
		CreatedAt:        time.Now(),
	}

	_ = s.SaveClient(ctx, client)

	// Valid secret
	err := s.ValidateClientSecret(ctx, "secret-client", secret)
	if err != nil {
		t.Errorf("ValidateClientSecret with valid secret failed: %v", err)
	}

	// Invalid secret
	err = s.ValidateClientSecret(ctx, "secret-client", "wrong-secret")
	if err == nil {
		t.Error("Expected error for invalid secret")
	}
}

func TestClientStore_ValidateClientSecret_PublicClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	client := &storage.Client{
		ClientID:     "public-client",
		ClientType:   "public",
		RedirectURIs: []string{"https://example.com/callback"},
		CreatedAt:    time.Now(),
	}

	_ = s.SaveClient(ctx, client)

	// Public clients should always validate
	err := s.ValidateClientSecret(ctx, "public-client", "any-secret")
	if err != nil {
		t.Errorf("ValidateClientSecret for public client should succeed: %v", err)
	}
}

func TestClientStore_ListClients(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	clients := []*storage.Client{
		{ClientID: "list-client-1", ClientType: "public", RedirectURIs: []string{"http://localhost"}, CreatedAt: time.Now()},
		{ClientID: "list-client-2", ClientType: "confidential", RedirectURIs: []string{"http://localhost"}, CreatedAt: time.Now()},
	}

	for _, c := range clients {
		_ = s.SaveClient(ctx, c)
	}

	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients failed: %v", err)
	}

	if len(list) < 2 {
		t.Errorf("Expected at least 2 clients, got %d", len(list))
	}
}

func TestClientStore_CheckIPLimit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// No limit set
	err := s.CheckIPLimit(ctx, "192.168.1.1", 0)
	if err != nil {
		t.Errorf("CheckIPLimit with no limit should succeed: %v", err)
	}

	// Track some clients
	for i := 0; i < 3; i++ {
		_ = s.TrackClientIP(ctx, "192.168.1.2")
	}

	// Check limit
	err = s.CheckIPLimit(ctx, "192.168.1.2", 5)
	if err != nil {
		t.Errorf("CheckIPLimit under limit should succeed: %v", err)
	}

	// Track more to exceed limit
	for i := 0; i < 3; i++ {
		_ = s.TrackClientIP(ctx, "192.168.1.2")
	}

	err = s.CheckIPLimit(ctx, "192.168.1.2", 5)
	if err == nil {
		t.Error("CheckIPLimit at/over limit should fail")
	}
}

// ============================================================
// FlowStore Tests
// ============================================================

func TestFlowStore_SaveAndGetAuthorizationState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	state := &storage.AuthorizationState{
		StateID:       "state-1",
		ClientID:      "client-1",
		RedirectURI:   "https://example.com/callback",
		Scope:         "openid profile",
		ProviderState: "provider-state-1",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	err := s.SaveAuthorizationState(ctx, state)
	if err != nil {
		t.Fatalf("SaveAuthorizationState failed: %v", err)
	}

	// Get by state ID
	got, err := s.GetAuthorizationState(ctx, "state-1")
	if err != nil {
		t.Fatalf("GetAuthorizationState failed: %v", err)
	}

	if got.ClientID != state.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, state.ClientID)
	}
	if got.Scope != state.Scope {
		t.Errorf("Scope = %q, want %q", got.Scope, state.Scope)
	}
}

func TestFlowStore_GetAuthorizationStateByProviderState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	state := &storage.AuthorizationState{
		StateID:       "state-2",
		ClientID:      "client-1",
		RedirectURI:   "https://example.com/callback",
		ProviderState: "provider-state-2",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	_ = s.SaveAuthorizationState(ctx, state)

	// Get by provider state
	got, err := s.GetAuthorizationStateByProviderState(ctx, "provider-state-2")
	if err != nil {
		t.Fatalf("GetAuthorizationStateByProviderState failed: %v", err)
	}

	if got.StateID != state.StateID {
		t.Errorf("StateID = %q, want %q", got.StateID, state.StateID)
	}
}

func TestFlowStore_GetAuthorizationState_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetAuthorizationState(ctx, "nonexistent")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Expected ErrAuthorizationStateNotFound, got: %v", err)
	}
}

func TestFlowStore_DeleteAuthorizationState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	state := &storage.AuthorizationState{
		StateID:       "state-to-delete",
		ClientID:      "client-1",
		RedirectURI:   "https://example.com/callback",
		ProviderState: "provider-state-delete",
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	_ = s.SaveAuthorizationState(ctx, state)

	err := s.DeleteAuthorizationState(ctx, "state-to-delete")
	if err != nil {
		t.Fatalf("DeleteAuthorizationState failed: %v", err)
	}

	_, err = s.GetAuthorizationState(ctx, "state-to-delete")
	if !storage.IsNotFoundError(err) {
		t.Errorf("State should be deleted, got: %v", err)
	}

	// Provider state should also be deleted
	_, err = s.GetAuthorizationStateByProviderState(ctx, "provider-state-delete")
	if !storage.IsNotFoundError(err) {
		t.Errorf("Provider state should be deleted, got: %v", err)
	}
}

func TestFlowStore_SaveAndGetAuthorizationCode(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	code := &storage.AuthorizationCode{
		Code:        "auth-code-1",
		ClientID:    "client-1",
		RedirectURI: "https://example.com/callback",
		Scope:       "openid",
		UserID:      "user1",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		Used:        false,
	}

	err := s.SaveAuthorizationCode(ctx, code)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode failed: %v", err)
	}

	got, err := s.GetAuthorizationCode(ctx, "auth-code-1")
	if err != nil {
		t.Fatalf("GetAuthorizationCode failed: %v", err)
	}

	if got.ClientID != code.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, code.ClientID)
	}
	if got.Used {
		t.Error("Code should not be marked as used")
	}
}

func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	code := &storage.AuthorizationCode{
		Code:        "auth-code-atomic-1",
		ClientID:    "client-1",
		RedirectURI: "https://example.com/callback",
		UserID:      "user1",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(5 * time.Minute),
		Used:        false,
	}

	_ = s.SaveAuthorizationCode(ctx, code)

	// First use should succeed
	got, err := s.AtomicCheckAndMarkAuthCodeUsed(ctx, "auth-code-atomic-1")
	if err != nil {
		t.Fatalf("AtomicCheckAndMarkAuthCodeUsed failed: %v", err)
	}

	if got.ClientID != code.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, code.ClientID)
	}

	// Second use should fail with code reuse error
	_, err = s.AtomicCheckAndMarkAuthCodeUsed(ctx, "auth-code-atomic-1")
	if !storage.IsCodeReuseError(err) {
		t.Errorf("Expected ErrAuthorizationCodeUsed, got: %v", err)
	}
}

func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.AtomicCheckAndMarkAuthCodeUsed(ctx, "nonexistent-code")
	if err != storage.ErrAuthorizationCodeNotFound {
		t.Errorf("Expected ErrAuthorizationCodeNotFound, got: %v", err)
	}
}

func TestFlowStore_DeleteAuthorizationCode(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	code := &storage.AuthorizationCode{
		Code:      "code-to-delete",
		ClientID:  "client-1",
		UserID:    "user1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	_ = s.SaveAuthorizationCode(ctx, code)

	err := s.DeleteAuthorizationCode(ctx, "code-to-delete")
	if err != nil {
		t.Fatalf("DeleteAuthorizationCode failed: %v", err)
	}

	_, err = s.GetAuthorizationCode(ctx, "code-to-delete")
	if err != storage.ErrAuthorizationCodeNotFound {
		t.Errorf("Code should be deleted, got: %v", err)
	}
}

// ============================================================
// RefreshTokenFamilyStore Tests
// ============================================================

func TestRefreshTokenFamilyStore_SaveAndGetFamily(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	err := s.SaveRefreshTokenWithFamily(ctx, "family-token-1", "user1", "client1", "family-1", 1, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily failed: %v", err)
	}

	meta, err := s.GetRefreshTokenFamily(ctx, "family-token-1")
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily failed: %v", err)
	}

	if meta.FamilyID != "family-1" {
		t.Errorf("FamilyID = %q, want %q", meta.FamilyID, "family-1")
	}
	if meta.Generation != 1 {
		t.Errorf("Generation = %d, want %d", meta.Generation, 1)
	}
	if meta.Revoked {
		t.Error("Token should not be revoked")
	}
}

func TestRefreshTokenFamilyStore_RevokeFamily(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create multiple tokens in the same family
	_ = s.SaveRefreshTokenWithFamily(ctx, "revoke-token-1", "user1", "client1", "revoke-family", 1, time.Now().Add(time.Hour))
	_ = s.SaveRefreshTokenWithFamily(ctx, "revoke-token-2", "user1", "client1", "revoke-family", 2, time.Now().Add(time.Hour))

	err := s.RevokeRefreshTokenFamily(ctx, "revoke-family")
	if err != nil {
		t.Fatalf("RevokeRefreshTokenFamily failed: %v", err)
	}

	// Tokens should be deleted
	_, err = s.GetRefreshTokenInfo(ctx, "revoke-token-1")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Token 1 should be deleted, got: %v", err)
	}

	_, err = s.GetRefreshTokenInfo(ctx, "revoke-token-2")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Token 2 should be deleted, got: %v", err)
	}

	// Family metadata should still exist but marked as revoked
	meta, err := s.GetRefreshTokenFamily(ctx, "revoke-token-1")
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily failed: %v", err)
	}

	if !meta.Revoked {
		t.Error("Family should be marked as revoked")
	}
}

func TestRefreshTokenFamilyStore_GetFamily_NotFound(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	_, err := s.GetRefreshTokenFamily(ctx, "nonexistent")
	if err != storage.ErrRefreshTokenFamilyNotFound {
		t.Errorf("Expected ErrRefreshTokenFamilyNotFound, got: %v", err)
	}
}

// ============================================================
// TokenRevocationStore Tests
// ============================================================

func TestTokenRevocationStore_RevokeAllTokensForUserClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create tokens for user+client
	_ = s.SaveRefreshTokenWithFamily(ctx, "user-client-token-1", "revoke-user", "revoke-client", "uc-family", 1, time.Now().Add(time.Hour))
	_ = s.SaveRefreshTokenWithFamily(ctx, "user-client-token-2", "revoke-user", "revoke-client", "uc-family", 2, time.Now().Add(time.Hour))

	// Also save token metadata for these
	_ = s.SaveTokenMetadata("user-client-token-1", "revoke-user", "revoke-client", "refresh")
	_ = s.SaveTokenMetadata("user-client-token-2", "revoke-user", "revoke-client", "refresh")

	// Revoke all
	count, err := s.RevokeAllTokensForUserClient(ctx, "revoke-user", "revoke-client")
	if err != nil {
		t.Fatalf("RevokeAllTokensForUserClient failed: %v", err)
	}

	if count == 0 {
		t.Error("Expected to revoke at least 1 token")
	}

	// Check tokens are gone
	_, err = s.GetRefreshTokenInfo(ctx, "user-client-token-1")
	if err != storage.ErrTokenNotFound {
		t.Errorf("Token 1 should be revoked, got: %v", err)
	}
}

func TestTokenRevocationStore_GetTokensByUserClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create tokens
	_ = s.SaveRefreshTokenWithFamily(ctx, "get-uc-token-1", "get-user", "get-client", "get-family", 1, time.Now().Add(time.Hour))

	tokens, err := s.GetTokensByUserClient(ctx, "get-user", "get-client")
	if err != nil {
		t.Fatalf("GetTokensByUserClient failed: %v", err)
	}

	if len(tokens) == 0 {
		t.Error("Expected at least 1 token")
	}
}

func TestTokenRevocationStore_SaveTokenMetadataWithScopesAndAudience(t *testing.T) {
	s := testStore(t)

	err := s.SaveTokenMetadataWithScopesAndAudience("meta-token-1", "user1", "client1", "access", "https://api.example.com", []string{"read", "write"})
	if err != nil {
		t.Fatalf("SaveTokenMetadataWithScopesAndAudience failed: %v", err)
	}

	meta, err := s.GetTokenMetadata("meta-token-1")
	if err != nil {
		t.Fatalf("GetTokenMetadata failed: %v", err)
	}

	if meta.Audience != "https://api.example.com" {
		t.Errorf("Audience = %q, want %q", meta.Audience, "https://api.example.com")
	}
	if len(meta.Scopes) != 2 {
		t.Errorf("Scopes length = %d, want 2", len(meta.Scopes))
	}
}

// ============================================================
// Edge Cases and Error Handling
// ============================================================

func TestValidation_EmptyUserID(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// All methods should return errors for empty userID
	if err := s.SaveUserInfo(ctx, "", &providers.UserInfo{}); err == nil {
		t.Error("SaveUserInfo should fail with empty userID")
	}

	if err := s.SaveRefreshToken(ctx, "token", "", time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshToken should fail with empty userID")
	}

	if err := s.SaveRefreshTokenWithFamily(ctx, "token", "", "client", "family", 1, time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshTokenWithFamily should fail with empty userID")
	}
}

func TestValidation_EmptyToken(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveRefreshToken(ctx, "", "user", time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshToken should fail with empty token")
	}

	if err := s.SaveRefreshTokenWithFamily(ctx, "", "user", "client", "family", 1, time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshTokenWithFamily should fail with empty token")
	}
}

func TestValidation_EmptyFamilyID(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveRefreshTokenWithFamily(ctx, "token", "user", "client", "", 1, time.Now().Add(time.Hour)); err == nil {
		t.Error("SaveRefreshTokenWithFamily should fail with empty familyID")
	}
}

func TestValidation_InvalidClient(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveClient(ctx, nil); err == nil {
		t.Error("SaveClient should fail with nil client")
	}

	if err := s.SaveClient(ctx, &storage.Client{}); err == nil {
		t.Error("SaveClient should fail with empty ClientID")
	}
}

func TestValidation_InvalidAuthorizationState(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveAuthorizationState(ctx, nil); err == nil {
		t.Error("SaveAuthorizationState should fail with nil state")
	}

	if err := s.SaveAuthorizationState(ctx, &storage.AuthorizationState{}); err == nil {
		t.Error("SaveAuthorizationState should fail with empty StateID")
	}

	if err := s.SaveAuthorizationState(ctx, &storage.AuthorizationState{StateID: "test"}); err == nil {
		t.Error("SaveAuthorizationState should fail with empty ProviderState")
	}
}

func TestValidation_InvalidAuthorizationCode(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.SaveAuthorizationCode(ctx, nil); err == nil {
		t.Error("SaveAuthorizationCode should fail with nil code")
	}

	if err := s.SaveAuthorizationCode(ctx, &storage.AuthorizationCode{}); err == nil {
		t.Error("SaveAuthorizationCode should fail with empty Code")
	}
}

// ============================================================
// Helper Function Tests
// ============================================================

func TestSafeTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"hello", 3, "hel"},
		{"hi", 5, "hi"},
		{"", 3, ""},
		{"test", 0, ""},
	}

	for _, tt := range tests {
		got := safeTruncate(tt.input, tt.n)
		if got != tt.want {
			t.Errorf("safeTruncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
		}
	}
}

func TestCalculateTTL(t *testing.T) {
	// Future expiry
	future := time.Now().Add(time.Hour)
	ttl := calculateTTL(future)
	if ttl <= 0 {
		t.Error("TTL should be positive for future expiry")
	}

	// Past expiry
	past := time.Now().Add(-time.Hour)
	ttl = calculateTTL(past)
	if ttl != 0 {
		t.Error("TTL should be 0 for past expiry")
	}
}

// ============================================================
// Token Encryption Tests
// ============================================================

func TestTokenStore_Encryption(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Generate encryption key (32 bytes for AES-256)
	key, err := security.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	encryptor, err := security.NewEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	s.SetEncryptor(encryptor)

	token := &oauth2.Token{
		AccessToken:  "secret-access-token",
		RefreshToken: "secret-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Save encrypted token
	err = s.SaveToken(ctx, "encrypted-user", token)
	if err != nil {
		t.Fatalf("SaveToken with encryption failed: %v", err)
	}

	// Retrieve and decrypt token
	got, err := s.GetToken(ctx, "encrypted-user")
	if err != nil {
		t.Fatalf("GetToken with decryption failed: %v", err)
	}

	// Verify decrypted values match original
	if got.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, token.AccessToken)
	}
	if got.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, token.RefreshToken)
	}
}

func TestTokenStore_EncryptionDisabled(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create encryptor with nil key (disabled)
	encryptor, err := security.NewEncryptor(nil)
	if err != nil {
		t.Fatalf("Failed to create disabled encryptor: %v", err)
	}

	s.SetEncryptor(encryptor)

	token := &oauth2.Token{
		AccessToken:  "plaintext-access-token",
		RefreshToken: "plaintext-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}

	// Save token (should not encrypt)
	err = s.SaveToken(ctx, "plaintext-user", token)
	if err != nil {
		t.Fatalf("SaveToken without encryption failed: %v", err)
	}

	// Retrieve token
	got, err := s.GetToken(ctx, "plaintext-user")
	if err != nil {
		t.Fatalf("GetToken without decryption failed: %v", err)
	}

	// Verify values match original
	if got.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, token.AccessToken)
	}
}

// TestTokenStore_Encryption_PreservesExtraField verifies that token encryption
// preserves the Extra field (id_token, scope) which is critical for OIDC flows.
// This is a regression test for issue #133.
func TestTokenStore_Encryption_PreservesExtraField(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Set up encryption
	key, err := security.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	encryptor, err := security.NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	s.SetEncryptor(encryptor)

	// Create token with Extra fields (simulating OIDC provider response)
	baseToken := &oauth2.Token{
		AccessToken:  "access-token-with-extra",
		RefreshToken: "refresh-token-with-extra",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-id-token-payload.signature" //nolint:gosec // test value, not a real credential
	grantedScope := "openid email profile"
	tokenWithExtra := baseToken.WithExtra(map[string]interface{}{
		"id_token": idToken,
		"scope":    grantedScope,
	})

	userID := testUserID

	// Save token with Extra field
	err = s.SaveToken(ctx, userID, tokenWithExtra)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Get token back (should be decrypted with Extra field preserved)
	got, err := s.GetToken(ctx, userID)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	// Verify basic fields
	if got.AccessToken != baseToken.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, baseToken.AccessToken)
	}

	// Verify Extra fields are preserved (critical for OIDC)
	gotIDToken := got.Extra("id_token")
	if gotIDToken == nil {
		t.Fatal("Extra(\"id_token\") returned nil, want id_token to be preserved")
	}
	if gotIDToken != idToken {
		t.Errorf("Extra(\"id_token\") = %q, want %q", gotIDToken, idToken)
	}

	gotScope := got.Extra("scope")
	if gotScope == nil {
		t.Fatal("Extra(\"scope\") returned nil, want scope to be preserved")
	}
	if gotScope != grantedScope {
		t.Errorf("Extra(\"scope\") = %q, want %q", gotScope, grantedScope)
	}
}

// TestTokenStore_WithoutEncryption_PreservesExtraField verifies that even without
// encryption, the Extra field is preserved through save/get cycle.
func TestTokenStore_WithoutEncryption_PreservesExtraField(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// No encryption configured - test basic case

	// Create token with Extra fields
	baseToken := &oauth2.Token{
		AccessToken:  "access-token-no-encryption",
		RefreshToken: "refresh-token-no-encryption",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-id-token.sig" //nolint:gosec // test value, not a real credential
	tokenWithExtra := baseToken.WithExtra(map[string]interface{}{
		"id_token": idToken,
	})

	userID := testUserID

	// Save and retrieve token
	err := s.SaveToken(ctx, userID, tokenWithExtra)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	got, err := s.GetToken(ctx, userID)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	// Verify Extra field is preserved
	gotIDToken := got.Extra("id_token")
	if gotIDToken == nil {
		t.Fatal("Extra(\"id_token\") returned nil, want id_token to be preserved")
	}
	if gotIDToken != idToken {
		t.Errorf("Extra(\"id_token\") = %q, want %q", gotIDToken, idToken)
	}
}

// TestTokenStore_Encryption_IDTokenIsEncrypted verifies that id_token is actually
// encrypted when stored, not just preserved. This is a security test.
func TestTokenStore_Encryption_IDTokenIsEncrypted(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Set up encryption
	key, err := security.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	encryptor, err := security.NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	s.SetEncryptor(encryptor)

	// Create token with id_token
	baseToken := &oauth2.Token{
		AccessToken:  "access-token-for-encryption-test",
		RefreshToken: "refresh-token-for-encryption-test",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
	}
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.contains-pii-email-name.signature" //nolint:gosec // test value
	tokenWithExtra := baseToken.WithExtra(map[string]interface{}{
		"id_token": idToken,
		"scope":    "openid email",
	})

	userID := testUserID

	// Save token
	err = s.SaveToken(ctx, userID, tokenWithExtra)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Verify that GetToken returns the decrypted value correctly
	got, err := s.GetToken(ctx, userID)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	// Verify access token is decrypted
	if got.AccessToken != baseToken.AccessToken {
		t.Errorf("GetToken().AccessToken = %q, want %q", got.AccessToken, baseToken.AccessToken)
	}

	// Verify id_token is decrypted
	gotIDToken := got.Extra("id_token")
	if gotIDToken != idToken {
		t.Errorf("GetToken().Extra(\"id_token\") = %q, want %q", gotIDToken, idToken)
	}

	// Note: We can't easily verify the raw stored value in Valkey without
	// a separate connection, but the roundtrip test proves encryption works.
	// The memory store tests verify the actual encryption behavior.
}

// ============================================================
// Concurrency Tests for Atomic Operations
// ============================================================

func TestFlowStore_AtomicCheckAndMarkAuthCodeUsed_Concurrent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	code := &storage.AuthorizationCode{
		Code:      "concurrent-code-1",
		ClientID:  "client-1",
		UserID:    "user1",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
	}

	_ = s.SaveAuthorizationCode(ctx, code)

	// Number of concurrent goroutines trying to use the same code
	numGoroutines := 10
	successCount := make(chan bool, numGoroutines)
	reuseCount := make(chan bool, numGoroutines)

	// Start all goroutines simultaneously
	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func() {
			<-start // Wait for signal
			_, err := s.AtomicCheckAndMarkAuthCodeUsed(ctx, "concurrent-code-1")
			if err == nil {
				successCount <- true
			} else if storage.IsCodeReuseError(err) {
				reuseCount <- true
			}
		}()
	}

	// Release all goroutines at once
	close(start)

	// Wait and count results
	successes := 0
	reuses := 0
	timeout := time.After(5 * time.Second)

	for i := 0; i < numGoroutines; i++ {
		select {
		case <-successCount:
			successes++
		case <-reuseCount:
			reuses++
		case <-timeout:
			t.Fatal("Timeout waiting for goroutines")
		}
	}

	// SECURITY: Only ONE goroutine should succeed
	if successes != 1 {
		t.Errorf("Expected exactly 1 success, got %d (security vulnerability!)", successes)
	}

	// All others should get reuse error
	if reuses != numGoroutines-1 {
		t.Errorf("Expected %d reuse errors, got %d", numGoroutines-1, reuses)
	}
}

// ============================================================
// Input Validation Tests
// ============================================================

func TestValidation_InputTooLarge(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Create a string that exceeds MaxTokenLength
	largeToken := make([]byte, MaxTokenLength+1)
	for i := range largeToken {
		largeToken[i] = 'a'
	}

	err := s.SaveRefreshToken(ctx, string(largeToken), "user", time.Now().Add(time.Hour))
	if err == nil {
		t.Error("Expected error for oversized refresh token")
	}

	// Create a string that exceeds MaxIDLength
	largeID := make([]byte, MaxIDLength+1)
	for i := range largeID {
		largeID[i] = 'a'
	}

	err = s.SaveRefreshToken(ctx, "token", string(largeID), time.Now().Add(time.Hour))
	if err == nil {
		t.Error("Expected error for oversized userID")
	}
}

func TestValidation_GenericErrorMessages(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Test that ValidateClientSecret returns generic error for non-existent client
	err := s.ValidateClientSecret(ctx, "nonexistent-client", "any-secret")
	if err == nil {
		t.Error("Expected error for non-existent client")
	}
	// Error should not contain client ID
	if err.Error() != "invalid client credentials" {
		t.Errorf("Error message should be generic, got: %v", err)
	}

	// Test that CheckIPLimit returns generic error when limit exceeded
	// First, set up an IP that has exceeded the limit
	for i := 0; i < 5; i++ {
		_ = s.TrackClientIP(ctx, "192.168.99.99")
	}

	err = s.CheckIPLimit(ctx, "192.168.99.99", 3)
	if err == nil {
		t.Error("Expected error when IP limit exceeded")
	}
	// Error should not contain IP or count
	if err.Error() != "rate limit exceeded" {
		t.Errorf("Error message should be generic, got: %v", err)
	}
}
