package memory

import (
	"log/slog"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

const (
	testUserID       = "test-user"
	testRefreshToken = "test-refresh-token"
)

// ============================================================
// TokenStore Tests
// ============================================================

func TestStore_SaveToken(t *testing.T) {
	store := New()
	defer store.Stop()

	token := testutil.GenerateTestToken()
	userID := testUserID

	err := store.SaveToken(userID, token)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Verify token was saved
	got, err := store.GetToken(userID)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	if got.AccessToken != token.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, token.AccessToken)
	}
}

func TestStore_SaveToken_EmptyUserID(t *testing.T) {
	store := New()
	defer store.Stop()

	token := testutil.GenerateTestToken()

	err := store.SaveToken("", token)
	if err == nil {
		t.Error("SaveToken() with empty userID should return error")
	}
}

func TestStore_SaveToken_NilToken(t *testing.T) {
	store := New()
	defer store.Stop()

	err := store.SaveToken("test-user", nil)
	if err == nil {
		t.Error("SaveToken() with nil token should return error")
	}
}

func TestStore_GetToken_NotFound(t *testing.T) {
	store := New()
	defer store.Stop()

	_, err := store.GetToken("nonexistent")
	if err == nil {
		t.Error("GetToken() for nonexistent user should return error")
	}
}

func TestStore_GetToken_Expired(t *testing.T) {
	store := New()
	defer store.Stop()

	// Create expired token (without refresh token)
	expiredToken := &oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-10 * time.Minute), // 10 minutes ago
	}

	userID := testUserID
	err := store.SaveToken(userID, expiredToken)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Should return error for expired token
	_, err = store.GetToken(userID)
	if err == nil {
		t.Error("GetToken() should return error for expired token")
	}
}

func TestStore_GetToken_ExpiredWithRefreshToken(t *testing.T) {
	store := New()
	defer store.Stop()

	// Create expired token with refresh token (should still be returned)
	expiredToken := &oauth2.Token{
		AccessToken:  "test-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-10 * time.Minute),
	}

	userID := testUserID
	err := store.SaveToken(userID, expiredToken)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Should succeed because refresh token is present
	got, err := store.GetToken(userID)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	if got.RefreshToken != "refresh-token" {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, "refresh-token")
	}
}

func TestStore_DeleteToken(t *testing.T) {
	store := New()
	defer store.Stop()

	token := testutil.GenerateTestToken()
	userID := testUserID

	// Save token
	if err := store.SaveToken(userID, token); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Delete token
	if err := store.DeleteToken(userID); err != nil {
		t.Fatalf("DeleteToken() error = %v", err)
	}

	// Verify token is gone
	_, err := store.GetToken(userID)
	if err == nil {
		t.Error("GetToken() should return error after deletion")
	}
}

func TestStore_SaveUserInfo(t *testing.T) {
	store := New()
	defer store.Stop()

	userInfo := testutil.GenerateTestUserInfo()
	userID := testUserID

	err := store.SaveUserInfo(userID, userInfo)
	if err != nil {
		t.Fatalf("SaveUserInfo() error = %v", err)
	}

	// Verify user info was saved
	got, err := store.GetUserInfo(userID)
	if err != nil {
		t.Fatalf("GetUserInfo() error = %v", err)
	}

	if got.Email != userInfo.Email {
		t.Errorf("Email = %q, want %q", got.Email, userInfo.Email)
	}
}

func TestStore_SaveUserInfo_EmptyUserID(t *testing.T) {
	store := New()
	defer store.Stop()

	userInfo := testutil.GenerateTestUserInfo()

	err := store.SaveUserInfo("", userInfo)
	if err == nil {
		t.Error("SaveUserInfo() with empty userID should return error")
	}
}

func TestStore_SaveUserInfo_Nil(t *testing.T) {
	store := New()
	defer store.Stop()

	err := store.SaveUserInfo("test-user", nil)
	if err == nil {
		t.Error("SaveUserInfo() with nil userInfo should return error")
	}
}

func TestStore_GetUserInfo_NotFound(t *testing.T) {
	store := New()
	defer store.Stop()

	_, err := store.GetUserInfo("nonexistent")
	if err == nil {
		t.Error("GetUserInfo() for nonexistent user should return error")
	}
}

// ============================================================
// Refresh Token Tests
// ============================================================

func TestStore_SaveRefreshToken(t *testing.T) {
	store := New()
	defer store.Stop()

	refreshToken := testRefreshToken
	userID := testUserID
	expiresAt := time.Now().Add(90 * 24 * time.Hour)

	err := store.SaveRefreshToken(refreshToken, userID, expiresAt)
	if err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	// Verify refresh token was saved
	gotUserID, err := store.GetRefreshTokenInfo(refreshToken)
	if err != nil {
		t.Fatalf("GetRefreshTokenInfo() error = %v", err)
	}

	if gotUserID != userID {
		t.Errorf("UserID = %q, want %q", gotUserID, userID)
	}
}

func TestStore_SaveRefreshToken_EmptyToken(t *testing.T) {
	store := New()
	defer store.Stop()

	err := store.SaveRefreshToken("", "test-user", time.Now())
	if err == nil {
		t.Error("SaveRefreshToken() with empty token should return error")
	}
}

func TestStore_SaveRefreshToken_EmptyUserID(t *testing.T) {
	store := New()
	defer store.Stop()

	err := store.SaveRefreshToken("test-token", "", time.Now())
	if err == nil {
		t.Error("SaveRefreshToken() with empty userID should return error")
	}
}

func TestStore_GetRefreshTokenInfo_Expired(t *testing.T) {
	store := New()
	defer store.Stop()

	refreshToken := testRefreshToken
	userID := testUserID
	expiresAt := time.Now().Add(-1 * time.Hour) // Expired

	if err := store.SaveRefreshToken(refreshToken, userID, expiresAt); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	// Should return error for expired token
	_, err := store.GetRefreshTokenInfo(refreshToken)
	if err == nil {
		t.Error("GetRefreshTokenInfo() should return error for expired token")
	}
}

func TestStore_DeleteRefreshToken(t *testing.T) {
	store := New()
	defer store.Stop()

	refreshToken := testRefreshToken
	userID := testUserID
	expiresAt := time.Now().Add(90 * 24 * time.Hour)

	// Save refresh token
	if err := store.SaveRefreshToken(refreshToken, userID, expiresAt); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	// Delete refresh token
	if err := store.DeleteRefreshToken(refreshToken); err != nil {
		t.Fatalf("DeleteRefreshToken() error = %v", err)
	}

	// Verify refresh token is gone
	_, err := store.GetRefreshTokenInfo(refreshToken)
	if err == nil {
		t.Error("GetRefreshTokenInfo() should return error after deletion")
	}
}

// ============================================================
// Refresh Token Family Tests (OAuth 2.1)
// ============================================================

func TestStore_SaveRefreshTokenWithFamily(t *testing.T) {
	store := New()
	defer store.Stop()

	refreshToken := testRefreshToken
	userID := testUserID
	clientID := "test-client"
	familyID := "test-family"
	generation := 1
	expiresAt := time.Now().Add(90 * 24 * time.Hour)

	err := store.SaveRefreshTokenWithFamily(refreshToken, userID, clientID, familyID, generation, expiresAt)
	if err != nil {
		t.Fatalf("SaveRefreshTokenWithFamily() error = %v", err)
	}

	// Verify family metadata
	family, err := store.GetRefreshTokenFamily(refreshToken)
	if err != nil {
		t.Fatalf("GetRefreshTokenFamily() error = %v", err)
	}

	if family.FamilyID != familyID {
		t.Errorf("FamilyID = %q, want %q", family.FamilyID, familyID)
	}

	if family.Generation != generation {
		t.Errorf("Generation = %d, want %d", family.Generation, generation)
	}

	if family.UserID != userID {
		t.Errorf("UserID = %q, want %q", family.UserID, userID)
	}

	if family.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", family.ClientID, clientID)
	}
}

func TestStore_RevokeRefreshTokenFamily(t *testing.T) {
	store := New()
	defer store.Stop()

	familyID := "test-family"
	expiresAt := time.Now().Add(90 * 24 * time.Hour)

	// Create multiple tokens in the same family
	tokens := []string{"token1", "token2", "token3"}
	for i, token := range tokens {
		err := store.SaveRefreshTokenWithFamily(token, "test-user", "test-client", familyID, i+1, expiresAt)
		if err != nil {
			t.Fatalf("SaveRefreshTokenWithFamily() error = %v", err)
		}
	}

	// Revoke the family
	err := store.RevokeRefreshTokenFamily(familyID)
	if err != nil {
		t.Fatalf("RevokeRefreshTokenFamily() error = %v", err)
	}

	// Verify all tokens in family are revoked
	for _, token := range tokens {
		_, err := store.GetRefreshTokenInfo(token)
		if err == nil {
			t.Errorf("Token %q should be revoked", token)
		}
	}
}

// ============================================================
// ClientStore Tests
// ============================================================

func TestStore_SaveClient(t *testing.T) {
	store := New()
	defer store.Stop()

	client := testutil.GenerateTestClient()

	err := store.SaveClient(client)
	if err != nil {
		t.Fatalf("SaveClient() error = %v", err)
	}

	// Verify client was saved
	got, err := store.GetClient(client.ClientID)
	if err != nil {
		t.Fatalf("GetClient() error = %v", err)
	}

	if got.ClientID != client.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, client.ClientID)
	}
}

func TestStore_SaveClient_Nil(t *testing.T) {
	store := New()
	defer store.Stop()

	err := store.SaveClient(nil)
	if err == nil {
		t.Error("SaveClient() with nil client should return error")
	}
}

func TestStore_SaveClient_EmptyID(t *testing.T) {
	store := New()
	defer store.Stop()

	client := &storage.Client{
		ClientID: "",
	}

	err := store.SaveClient(client)
	if err == nil {
		t.Error("SaveClient() with empty ClientID should return error")
	}
}

func TestStore_GetClient_NotFound(t *testing.T) {
	store := New()
	defer store.Stop()

	_, err := store.GetClient("nonexistent")
	if err == nil {
		t.Error("GetClient() for nonexistent client should return error")
	}
}

func TestStore_ValidateClientSecret(t *testing.T) {
	store := New()
	defer store.Stop()

	// Hash a test secret
	secret := "test-secret"
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error = %v", err)
	}

	client := &storage.Client{
		ClientID:         "test-client",
		ClientSecretHash: string(hash),
	}

	if err := store.SaveClient(client); err != nil {
		t.Fatalf("SaveClient() error = %v", err)
	}

	// Test valid secret
	err = store.ValidateClientSecret(client.ClientID, secret)
	if err != nil {
		t.Errorf("ValidateClientSecret() with correct secret error = %v", err)
	}

	// Test invalid secret
	err = store.ValidateClientSecret(client.ClientID, "wrong-secret")
	if err == nil {
		t.Error("ValidateClientSecret() with wrong secret should return error")
	}
}

func TestStore_ValidateClientSecret_ClientNotFound(t *testing.T) {
	store := New()
	defer store.Stop()

	err := store.ValidateClientSecret("nonexistent", "secret")
	if err == nil {
		t.Error("ValidateClientSecret() for nonexistent client should return error")
	}
}

func TestStore_ListClients(t *testing.T) {
	store := New()
	defer store.Stop()

	// Save multiple clients
	client1 := &storage.Client{ClientID: "client1"}
	client2 := &storage.Client{ClientID: "client2"}

	if err := store.SaveClient(client1); err != nil {
		t.Fatalf("SaveClient() error = %v", err)
	}
	if err := store.SaveClient(client2); err != nil {
		t.Fatalf("SaveClient() error = %v", err)
	}

	// List clients
	clients, err := store.ListClients()
	if err != nil {
		t.Fatalf("ListClients() error = %v", err)
	}

	if len(clients) != 2 {
		t.Errorf("len(clients) = %d, want 2", len(clients))
	}
}

func TestStore_CheckIPLimit(t *testing.T) {
	store := New()
	defer store.Stop()

	ip := "192.168.1.1"
	maxClients := 3

	// Should succeed initially
	err := store.CheckIPLimit(ip, maxClients)
	if err != nil {
		t.Fatalf("CheckIPLimit() initial check error = %v", err)
	}

	// Register clients for this IP
	for i := 0; i < maxClients; i++ {
		store.TrackClientIP(ip)
	}

	// Should fail after reaching limit
	err = store.CheckIPLimit(ip, maxClients)
	if err == nil {
		t.Error("CheckIPLimit() should return error after reaching limit")
	}
}

func TestStore_CheckIPLimit_NoLimit(t *testing.T) {
	store := New()
	defer store.Stop()

	// With maxClientsPerIP = 0, should never fail
	err := store.CheckIPLimit("192.168.1.1", 0)
	if err != nil {
		t.Errorf("CheckIPLimit() with no limit error = %v", err)
	}
}

// ============================================================
// FlowStore Tests
// ============================================================

func TestStore_SaveAuthorizationState(t *testing.T) {
	store := New()
	defer store.Stop()

	state := testutil.GenerateTestAuthorizationState()

	err := store.SaveAuthorizationState(state)
	if err != nil {
		t.Fatalf("SaveAuthorizationState() error = %v", err)
	}

	// Verify state was saved
	got, err := store.GetAuthorizationState(state.StateID)
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	if got.StateID != state.StateID {
		t.Errorf("StateID = %q, want %q", got.StateID, state.StateID)
	}
}

func TestStore_SaveAuthorizationState_Nil(t *testing.T) {
	store := New()
	defer store.Stop()

	err := store.SaveAuthorizationState(nil)
	if err == nil {
		t.Error("SaveAuthorizationState() with nil state should return error")
	}
}

func TestStore_GetAuthorizationState_NotFound(t *testing.T) {
	store := New()
	defer store.Stop()

	_, err := store.GetAuthorizationState("nonexistent")
	if err == nil {
		t.Error("GetAuthorizationState() for nonexistent state should return error")
	}
}

func TestStore_GetAuthorizationState_Expired(t *testing.T) {
	store := New()
	defer store.Stop()

	state := testutil.GenerateTestAuthorizationState()
	state.ExpiresAt = time.Now().Add(-1 * time.Minute) // Expired

	if err := store.SaveAuthorizationState(state); err != nil {
		t.Fatalf("SaveAuthorizationState() error = %v", err)
	}

	// Should return error for expired state
	_, err := store.GetAuthorizationState(state.StateID)
	if err == nil {
		t.Error("GetAuthorizationState() should return error for expired state")
	}
}

func TestStore_GetAuthorizationStateByProviderState(t *testing.T) {
	store := New()
	defer store.Stop()

	state := testutil.GenerateTestAuthorizationState()

	if err := store.SaveAuthorizationState(state); err != nil {
		t.Fatalf("SaveAuthorizationState() error = %v", err)
	}

	// Get by provider state
	got, err := store.GetAuthorizationStateByProviderState(state.ProviderState)
	if err != nil {
		t.Fatalf("GetAuthorizationStateByProviderState() error = %v", err)
	}

	if got.StateID != state.StateID {
		t.Errorf("StateID = %q, want %q", got.StateID, state.StateID)
	}
}

func TestStore_DeleteAuthorizationState(t *testing.T) {
	store := New()
	defer store.Stop()

	state := testutil.GenerateTestAuthorizationState()

	// Save state
	if err := store.SaveAuthorizationState(state); err != nil {
		t.Fatalf("SaveAuthorizationState() error = %v", err)
	}

	// Delete state
	if err := store.DeleteAuthorizationState(state.StateID); err != nil {
		t.Fatalf("DeleteAuthorizationState() error = %v", err)
	}

	// Verify state is gone
	_, err := store.GetAuthorizationState(state.StateID)
	if err == nil {
		t.Error("GetAuthorizationState() should return error after deletion")
	}
}

func TestStore_SaveAuthorizationCode(t *testing.T) {
	store := New()
	defer store.Stop()

	code := testutil.GenerateTestAuthorizationCode()

	err := store.SaveAuthorizationCode(code)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Verify code was saved
	got, err := store.GetAuthorizationCode(code.Code)
	if err != nil {
		t.Fatalf("GetAuthorizationCode() error = %v", err)
	}

	if got.Code != code.Code {
		t.Errorf("Code = %q, want %q", got.Code, code.Code)
	}
}

func TestStore_GetAuthorizationCode_Expired(t *testing.T) {
	store := New()
	defer store.Stop()

	code := testutil.GenerateTestAuthorizationCode()
	code.ExpiresAt = time.Now().Add(-1 * time.Minute) // Expired

	if err := store.SaveAuthorizationCode(code); err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Should return error for expired code
	_, err := store.GetAuthorizationCode(code.Code)
	if err == nil {
		t.Error("GetAuthorizationCode() should return error for expired code")
	}
}

func TestStore_GetAuthorizationCode_Used(t *testing.T) {
	store := New()
	defer store.Stop()

	code := testutil.GenerateTestAuthorizationCode()
	code.Used = true

	if err := store.SaveAuthorizationCode(code); err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Should return the code even if used (for OAuth 2.1 reuse detection)
	// The caller is responsible for checking the Used flag and revoking tokens
	retrievedCode, err := store.GetAuthorizationCode(code.Code)
	if err != nil {
		t.Errorf("GetAuthorizationCode() error = %v, want nil (should return used code for reuse detection)", err)
	}
	if retrievedCode == nil {
		t.Fatal("GetAuthorizationCode() returned nil code")
	}
	if !retrievedCode.Used {
		t.Error("Retrieved code should have Used=true")
	}
}

func TestStore_DeleteAuthorizationCode(t *testing.T) {
	store := New()
	defer store.Stop()

	code := testutil.GenerateTestAuthorizationCode()

	// Save code
	if err := store.SaveAuthorizationCode(code); err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Delete code
	if err := store.DeleteAuthorizationCode(code.Code); err != nil {
		t.Fatalf("DeleteAuthorizationCode() error = %v", err)
	}

	// Verify code is gone
	_, err := store.GetAuthorizationCode(code.Code)
	if err == nil {
		t.Error("GetAuthorizationCode() should return error after deletion")
	}
}

// ============================================================
// Encryption Tests
// ============================================================

func TestStore_TokenEncryption(t *testing.T) {
	store := New()
	defer store.Stop()

	// Set up encryption
	key, err := security.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	encryptor, err := security.NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error = %v", err)
	}

	store.SetEncryptor(encryptor)

	// Save token
	token := testutil.GenerateTestToken()
	originalAccessToken := token.AccessToken
	userID := testUserID

	err = store.SaveToken(userID, token)
	if err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	// Get token back (should be decrypted)
	got, err := store.GetToken(userID)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}

	if got.AccessToken != originalAccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, originalAccessToken)
	}
}

// ============================================================
// Concurrent Access Tests
// ============================================================

func TestStore_ConcurrentTokenAccess(t *testing.T) {
	store := New()
	defer store.Stop()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			token := testutil.GenerateTestToken()
			userID := testutil.GenerateRandomString(16)
			if err := store.SaveToken(userID, token); err != nil {
				t.Errorf("SaveToken() error = %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestStore_ConcurrentClientAccess(t *testing.T) {
	store := New()
	defer store.Stop()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			client := testutil.GenerateTestClient()
			client.ClientID = testutil.GenerateRandomString(16)
			if err := store.SaveClient(client); err != nil {
				t.Errorf("SaveClient() error = %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// ============================================================
// Cleanup Tests
// ============================================================

func TestStore_CleanupExpiredTokens(t *testing.T) {
	// Use short cleanup interval for testing
	store := NewWithInterval(100 * time.Millisecond)
	defer store.Stop()

	// Save expired authorization code
	code := testutil.GenerateTestAuthorizationCode()
	code.ExpiresAt = time.Now().Add(-1 * time.Minute)
	if err := store.SaveAuthorizationCode(code); err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Wait for cleanup
	time.Sleep(200 * time.Millisecond)

	// Code should be cleaned up
	_, err := store.GetAuthorizationCode(code.Code)
	if err == nil {
		t.Error("Expired authorization code should be cleaned up")
	}
}

func TestStore_SetLogger(t *testing.T) {
	store := New()
	defer store.Stop()

	logger := &slog.Logger{}
	store.SetLogger(logger)

	// Logger should be set (we can't easily test this without reflection)
	// Just verify no panic
}
