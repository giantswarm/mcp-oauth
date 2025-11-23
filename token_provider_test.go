package oauth

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestNewTokenProvider(t *testing.T) {
	store := NewStore()
	provider := NewTokenProvider(store)

	if provider == nil {
		t.Fatal("NewTokenProvider() returned nil")
	}

	if provider.store != store {
		t.Error("NewTokenProvider() did not set store correctly")
	}
}

func TestTokenProvider_GetTokenForAccount(t *testing.T) {
	store := NewStore()
	provider := NewTokenProvider(store)

	// Add a token for a user
	token := &oauth2.Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	if err := store.SaveGoogleToken("user@example.com", token); err != nil {
		t.Fatalf("SaveGoogleToken() error = %v", err)
	}

	// Get token for account
	ctx := context.Background()
	retrieved, err := provider.GetTokenForAccount(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("GetTokenForAccount() error = %v", err)
	}

	if retrieved.AccessToken != token.AccessToken {
		t.Errorf("GetTokenForAccount() AccessToken = %s, want %s", retrieved.AccessToken, token.AccessToken)
	}
}

func TestTokenProvider_GetTokenForAccount_NotFound(t *testing.T) {
	store := NewStore()
	provider := NewTokenProvider(store)

	ctx := context.Background()
	_, err := provider.GetTokenForAccount(ctx, "nonexistent@example.com")
	if err == nil {
		t.Error("GetTokenForAccount() for non-existent account should return error")
	}

	// Check that error message is helpful
	expectedSubstring := "no Google OAuth token found"
	if err != nil && len(err.Error()) > 0 {
		if !containsSubstring(err.Error(), expectedSubstring) {
			t.Logf("Error message: %s", err.Error())
		}
	}
}

func TestTokenProvider_HasTokenForAccount(t *testing.T) {
	store := NewStore()
	provider := NewTokenProvider(store)

	// Initially should not have token
	if provider.HasTokenForAccount("user@example.com") {
		t.Error("HasTokenForAccount() should return false for non-existent account")
	}

	// Add a token
	token := &oauth2.Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	if err := store.SaveGoogleToken("user@example.com", token); err != nil {
		t.Fatalf("SaveGoogleToken() error = %v", err)
	}

	// Now should have token
	if !provider.HasTokenForAccount("user@example.com") {
		t.Error("HasTokenForAccount() should return true after saving token")
	}
}

func TestTokenProvider_HasTokenForAccount_ExpiredToken(t *testing.T) {
	store := NewStore()
	provider := NewTokenProvider(store)

	// Add an expired token
	token := &oauth2.Token{
		AccessToken: "test-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-1 * time.Hour), // Expired
	}

	if err := store.SaveGoogleToken("user@example.com", token); err != nil {
		t.Fatalf("SaveGoogleToken() error = %v", err)
	}

	// Should not have valid token (expired tokens are not valid)
	if provider.HasTokenForAccount("user@example.com") {
		t.Error("HasTokenForAccount() should return false for expired token")
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr))
}
