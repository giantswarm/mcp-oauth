package oauth

import (
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestNewStore(t *testing.T) {
	store := NewStore()
	defer store.Stop()
	if store == nil {
		t.Fatal("NewStore() returned nil")
	}

	stats := store.Stats()
	if stats["google_tokens"] != 0 {
		t.Errorf("New store should have 0 google_tokens, got %d", stats["google_tokens"])
	}
	if stats["user_info"] != 0 {
		t.Errorf("New store should have 0 user_info, got %d", stats["user_info"])
	}
}

func TestStore_Stats(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	token := &oauth2.Token{
		AccessToken: "google-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	userInfo := &GoogleUserInfo{
		Sub:   "12345",
		Email: "user@example.com",
	}

	if err := store.SaveGoogleToken("user@example.com", token); err != nil {
		t.Fatalf("SaveGoogleToken() error = %v", err)
	}
	if err := store.SaveGoogleUserInfo("user@example.com", userInfo); err != nil {
		t.Fatalf("SaveGoogleUserInfo() error = %v", err)
	}

	stats := store.Stats()

	if stats["google_tokens"] != 1 {
		t.Errorf("Stats() google_tokens = %d, want 1", stats["google_tokens"])
	}
	if stats["user_info"] != 1 {
		t.Errorf("Stats() user_info = %d, want 1", stats["user_info"])
	}
}

func TestStore_SaveAndGetGoogleToken(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	token := &oauth2.Token{
		AccessToken: "google-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	// Save Google token
	if err := store.SaveGoogleToken("user@example.com", token); err != nil {
		t.Fatalf("SaveGoogleToken() error = %v", err)
	}

	// Get Google token
	retrieved, err := store.GetGoogleToken("user@example.com")
	if err != nil {
		t.Fatalf("GetGoogleToken() error = %v", err)
	}

	if retrieved.AccessToken != token.AccessToken {
		t.Errorf("GetGoogleToken() AccessToken = %s, want %s", retrieved.AccessToken, token.AccessToken)
	}
}

func TestStore_SaveGoogleTokenEmptyEmail(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	token := &oauth2.Token{
		AccessToken: "google-access-token",
	}

	err := store.SaveGoogleToken("", token)
	if err == nil {
		t.Error("SaveGoogleToken() with empty email should return error")
	}
}

func TestStore_SaveGoogleTokenNil(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	err := store.SaveGoogleToken("user@example.com", nil)
	if err == nil {
		t.Error("SaveGoogleToken() with nil token should return error")
	}
}

func TestStore_GetGoogleTokenNotFound(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	_, err := store.GetGoogleToken("nonexistent@example.com")
	if err == nil {
		t.Error("GetGoogleToken() for non-existent user should return error")
	}
}

func TestStore_GetGoogleTokenExpired(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	token := &oauth2.Token{
		AccessToken: "google-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(-1 * time.Hour), // Expired
	}

	if err := store.SaveGoogleToken("user@example.com", token); err != nil {
		t.Fatalf("SaveGoogleToken() error = %v", err)
	}

	_, err := store.GetGoogleToken("user@example.com")
	if err == nil {
		t.Error("GetGoogleToken() for expired token should return error")
	}
}

func TestStore_DeleteGoogleToken(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	token := &oauth2.Token{
		AccessToken: "google-access-token",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	if err := store.SaveGoogleToken("user@example.com", token); err != nil {
		t.Fatalf("SaveGoogleToken() error = %v", err)
	}

	if err := store.DeleteGoogleToken("user@example.com"); err != nil {
		t.Fatalf("DeleteGoogleToken() error = %v", err)
	}

	_, err := store.GetGoogleToken("user@example.com")
	if err == nil {
		t.Error("GetGoogleToken() after DeleteGoogleToken() should return error")
	}
}

func TestStore_SaveAndGetGoogleUserInfo(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	userInfo := &GoogleUserInfo{
		Sub:           "12345",
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
	}

	// Save user info
	if err := store.SaveGoogleUserInfo("user@example.com", userInfo); err != nil {
		t.Fatalf("SaveGoogleUserInfo() error = %v", err)
	}

	// Get user info
	retrieved, err := store.GetGoogleUserInfo("user@example.com")
	if err != nil {
		t.Fatalf("GetGoogleUserInfo() error = %v", err)
	}

	if retrieved.Email != userInfo.Email {
		t.Errorf("GetGoogleUserInfo() Email = %s, want %s", retrieved.Email, userInfo.Email)
	}
	if retrieved.Name != userInfo.Name {
		t.Errorf("GetGoogleUserInfo() Name = %s, want %s", retrieved.Name, userInfo.Name)
	}
}

func TestStore_SaveGoogleUserInfoEmptyEmail(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	userInfo := &GoogleUserInfo{
		Sub:   "12345",
		Email: "user@example.com",
	}

	err := store.SaveGoogleUserInfo("", userInfo)
	if err == nil {
		t.Error("SaveGoogleUserInfo() with empty email should return error")
	}
}

func TestStore_SaveGoogleUserInfoNil(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	err := store.SaveGoogleUserInfo("user@example.com", nil)
	if err == nil {
		t.Error("SaveGoogleUserInfo() with nil userInfo should return error")
	}
}

func TestStore_GetGoogleUserInfoNotFound(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	_, err := store.GetGoogleUserInfo("nonexistent@example.com")
	if err == nil {
		t.Error("GetGoogleUserInfo() for non-existent user should return error")
	}
}

func TestStore_SaveAndGetRefreshToken(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	refreshToken := "refresh-token-123"
	email := "user@example.com"
	expiresAt := time.Now().Add(90 * 24 * time.Hour).Unix() // 90 days from now

	// Save refresh token
	if err := store.SaveRefreshToken(refreshToken, email, expiresAt); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	// Get refresh token
	retrieved, err := store.GetRefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("GetRefreshToken() error = %v", err)
	}

	if retrieved != email {
		t.Errorf("GetRefreshToken() = %s, want %s", retrieved, email)
	}
}

func TestStore_GetRefreshTokenExpired(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	refreshToken := "refresh-token-123"
	email := "user@example.com"
	// Expired 10 seconds ago (beyond clock skew grace period of 5 seconds)
	expiresAt := time.Now().Add(-10 * time.Second).Unix()

	if err := store.SaveRefreshToken(refreshToken, email, expiresAt); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	_, err := store.GetRefreshToken(refreshToken)
	if err == nil {
		t.Error("GetRefreshToken() for expired token should return error")
	}
	if err != nil && err.Error() != "refresh token expired" {
		t.Errorf("GetRefreshToken() error = %v, want 'refresh token expired'", err)
	}
}

func TestStore_GetRefreshTokenClockSkewGrace(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	refreshToken := "refresh-token-123"
	email := "user@example.com"
	// Expired 3 seconds ago (within clock skew grace period of 5 seconds)
	expiresAt := time.Now().Add(-3 * time.Second).Unix()

	if err := store.SaveRefreshToken(refreshToken, email, expiresAt); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	// Should still be valid due to clock skew grace period
	retrieved, err := store.GetRefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("GetRefreshToken() should succeed within clock skew grace period, got error: %v", err)
	}

	if retrieved != email {
		t.Errorf("GetRefreshToken() = %s, want %s", retrieved, email)
	}
}

func TestStore_GetRefreshTokenNotFound(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	_, err := store.GetRefreshToken("nonexistent-token")
	if err == nil {
		t.Error("GetRefreshToken() for non-existent token should return error")
	}
	if err != nil && err.Error() != "refresh token not found" {
		t.Errorf("GetRefreshToken() error = %v, want 'refresh token not found'", err)
	}
}

func TestStore_DeleteRefreshToken(t *testing.T) {
	store := NewStore()
	defer store.Stop()

	refreshToken := "refresh-token-123"
	email := "user@example.com"
	expiresAt := time.Now().Add(90 * 24 * time.Hour).Unix()

	if err := store.SaveRefreshToken(refreshToken, email, expiresAt); err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	if err := store.DeleteRefreshToken(refreshToken); err != nil {
		t.Fatalf("DeleteRefreshToken() error = %v", err)
	}

	_, err := store.GetRefreshToken(refreshToken)
	if err == nil {
		t.Error("GetRefreshToken() after DeleteRefreshToken() should return error")
	}
}
