package oauth

import (
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestStore_SaveGoogleToken_EmptyEmail(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	err := store.SaveGoogleToken("", &oauth2.Token{
		AccessToken: "test-token",
	})

	if err == nil {
		t.Error("Expected error when saving token with empty email")
	}
}

func TestStore_SaveGoogleToken_NilToken(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	err := store.SaveGoogleToken("test@example.com", nil)

	if err == nil {
		t.Error("Expected error when saving nil token")
	}
}

func TestStore_GetGoogleToken_Expired(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	// Save an expired token
	err := store.SaveGoogleToken("test@example.com", &oauth2.Token{
		AccessToken: "expired-token",
		Expiry:      time.Now().Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Try to get it - should fail because it's expired
	_, err = store.GetGoogleToken("test@example.com")
	if err == nil {
		t.Error("Expected error when getting expired token")
	}
}

func TestStore_SaveGoogleUserInfo_EmptyEmail(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	err := store.SaveGoogleUserInfo("", &GoogleUserInfo{
		Email: "test@example.com",
	})

	if err == nil {
		t.Error("Expected error when saving user info with empty email")
	}
}

func TestStore_SaveGoogleUserInfo_NilUserInfo(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	err := store.SaveGoogleUserInfo("test@example.com", nil)

	if err == nil {
		t.Error("Expected error when saving nil user info")
	}
}

func TestStore_GetGoogleUserInfo_NotFound(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	_, err := store.GetGoogleUserInfo("nonexistent@example.com")
	if err == nil {
		t.Error("Expected error when getting non-existent user info")
	}
}

func TestStore_DeleteGoogleToken_RemovesUserInfo(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	// Add token and user info
	email := "test@example.com"
	err := store.SaveGoogleToken(email, &oauth2.Token{
		AccessToken: "test-token",
		Expiry:      time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	err = store.SaveGoogleUserInfo(email, &GoogleUserInfo{
		Email: email,
		Name:  "Test User",
	})
	if err != nil {
		t.Fatalf("Failed to save user info: %v", err)
	}

	// Delete token
	err = store.DeleteGoogleToken(email)
	if err != nil {
		t.Fatalf("Failed to delete token: %v", err)
	}

	// Verify both token and user info are gone
	_, err = store.GetGoogleToken(email)
	if err == nil {
		t.Error("Expected error when getting deleted token")
	}

	_, err = store.GetGoogleUserInfo(email)
	if err == nil {
		t.Error("Expected error when getting deleted user info")
	}
}

func TestStore_CleanupExpiredTokens(t *testing.T) {
	// Create store with long cleanup interval since we'll trigger manually
	store := NewStoreWithInterval(1 * time.Hour)
	defer store.Stop()

	// Add an expired token
	store.SaveGoogleToken("expired@example.com", &oauth2.Token{
		AccessToken: "expired-token",
		Expiry:      time.Now().Add(-1 * time.Hour),
	})

	// Add a valid token
	store.SaveGoogleToken("valid@example.com", &oauth2.Token{
		AccessToken: "valid-token",
		Expiry:      time.Now().Add(1 * time.Hour),
	})

	// Manually trigger cleanup for deterministic testing
	store.TriggerCleanup()
	// Minimal sleep to allow cleanup goroutine to process the trigger
	// This is necessary because cleanup runs asynchronously in a separate goroutine
	// 10ms is sufficient and much more deterministic than the previous approach
	time.Sleep(10 * time.Millisecond)

	// Valid token should still exist
	_, err := store.GetGoogleToken("valid@example.com")
	if err != nil {
		t.Error("Valid token was cleaned up unexpectedly")
	}

	// Expired token should be gone (but GetGoogleToken might return error for expired token before cleanup)
	// So we check the stats instead
	stats := store.Stats()
	if stats["google_tokens"] != 1 {
		t.Errorf("After cleanup, google_tokens = %d, want 1", stats["google_tokens"])
	}
}

func TestStore_CleanupLogic_WithRefreshToken(t *testing.T) {
	// Create store with long cleanup interval since we'll trigger manually
	store := NewStoreWithInterval(1 * time.Hour)
	defer store.Stop()

	// Token with refresh token - should NOT be cleaned up when access token expires
	tokenWithRefresh := &oauth2.Token{
		AccessToken:  "access-token-with-refresh",
		RefreshToken: "valid-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-1 * time.Hour), // Access token Expired
	}

	// Token without refresh token - SHOULD be cleaned up when access token expires
	tokenNoRefresh := &oauth2.Token{
		AccessToken:  "access-token-no-refresh",
		RefreshToken: "", // No refresh token
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-1 * time.Hour), // Access token Expired
	}

	// Save tokens
	if err := store.SaveGoogleToken("user-with-refresh@example.com", tokenWithRefresh); err != nil {
		t.Fatalf("SaveGoogleToken() error = %v", err)
	}
	if err := store.SaveGoogleToken("user-no-refresh@example.com", tokenNoRefresh); err != nil {
		t.Fatalf("SaveGoogleToken() error = %v", err)
	}

	// Also save refresh token expiry for the one that has it (to simulate full state)
	// Set refresh token expiry to future (so it's valid)
	if err := store.SaveRefreshToken("valid-refresh-token", "user-with-refresh@example.com", time.Now().Add(24*time.Hour).Unix()); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	// Manually trigger cleanup for deterministic testing
	store.TriggerCleanup()
	// Minimal sleep to allow cleanup goroutine to process the trigger
	// This is necessary because cleanup runs asynchronously in a separate goroutine
	// 10ms is sufficient and much more deterministic than the previous approach
	time.Sleep(10 * time.Millisecond)

	// Test: Token WITHOUT refresh token should be gone
	_, err := store.GetGoogleToken("user-no-refresh@example.com")
	if err == nil {
		t.Error("Token without refresh token should have been cleaned up")
	}

	// Test: Token WITH refresh token should still be there (but expired)
	// After fix, we expect NO error and the token back.
	token, err := store.GetGoogleToken("user-with-refresh@example.com")
	if err == nil {
		// If no error, it means fix is applied or we got lucky (but token should be expired)
		if token == nil {
			t.Error("GetGoogleToken returned nil token but no error")
		} else {
			t.Logf("Token retrieved successfully: expiry=%v", token.Expiry)
		}
	} else {
		t.Errorf("GetGoogleToken error: %v. Token with refresh token was INCORRECTLY cleaned up", err)
	}
}
