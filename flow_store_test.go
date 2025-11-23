package oauth

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestFlowStore_AuthorizationState(t *testing.T) {
	store := NewFlowStore(slog.Default())

	now := time.Now().Unix()
	state := &AuthorizationState{
		State:               "client-state-123",
		ClientID:            "client-123",
		RedirectURI:         "http://localhost:8080/callback",
		Scope:               "email profile",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		GoogleState:         "google-state-456",
		CreatedAt:           now,
		ExpiresAt:           now + 600, // 10 minutes
		Nonce:               "nonce-789",
	}

	// Save state
	err := store.SaveAuthorizationState(state)
	if err != nil {
		t.Fatalf("SaveAuthorizationState() error = %v", err)
	}

	// Retrieve state
	retrieved, err := store.GetAuthorizationState("google-state-456")
	if err != nil {
		t.Fatalf("GetAuthorizationState() error = %v", err)
	}

	if retrieved.State != "client-state-123" {
		t.Errorf("State = %s, want client-state-123", retrieved.State)
	}

	if retrieved.ClientID != "client-123" {
		t.Errorf("ClientID = %s, want client-123", retrieved.ClientID)
	}

	if retrieved.CodeChallenge != "challenge" {
		t.Errorf("CodeChallenge = %s, want challenge", retrieved.CodeChallenge)
	}

	// Delete state
	store.DeleteAuthorizationState("google-state-456")

	// Should not be found after deletion
	_, err = store.GetAuthorizationState("google-state-456")
	if err == nil {
		t.Error("GetAuthorizationState() should return error after deletion")
	}
}

func TestFlowStore_AuthorizationState_Expired(t *testing.T) {
	store := NewFlowStore(slog.Default())

	now := time.Now().Unix()
	state := &AuthorizationState{
		State:       "client-state-123",
		ClientID:    "client-123",
		GoogleState: "google-state-456",
		CreatedAt:   now - 1000,
		ExpiresAt:   now - 100, // Expired
	}

	// Save expired state
	err := store.SaveAuthorizationState(state)
	if err != nil {
		t.Fatalf("SaveAuthorizationState() error = %v", err)
	}

	// Should return error for expired state
	_, err = store.GetAuthorizationState("google-state-456")
	if err == nil {
		t.Error("GetAuthorizationState() should return error for expired state")
	}
}

func TestFlowStore_AuthorizationCode(t *testing.T) {
	store := NewFlowStore(slog.Default())

	now := time.Now().Unix()
	authCode := &AuthorizationCode{
		Code:                "auth-code-123",
		ClientID:            "client-123",
		RedirectURI:         "http://localhost:8080/callback",
		Scope:               "email profile",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		GoogleAccessToken:   "google-access-token",
		GoogleRefreshToken:  "google-refresh-token",
		GoogleTokenExpiry:   now + 3600,
		UserEmail:           "user@example.com",
		CreatedAt:           now,
		ExpiresAt:           now + 600, // 10 minutes
		Used:                false,
	}

	// Save authorization code
	err := store.SaveAuthorizationCode(authCode)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Retrieve and use authorization code
	retrieved, err := store.GetAuthorizationCode("auth-code-123")
	if err != nil {
		t.Fatalf("GetAuthorizationCode() error = %v", err)
	}

	if retrieved.ClientID != "client-123" {
		t.Errorf("ClientID = %s, want client-123", retrieved.ClientID)
	}

	if retrieved.UserEmail != "user@example.com" {
		t.Errorf("UserEmail = %s, want user@example.com", retrieved.UserEmail)
	}

	// Authorization codes are now immediately deleted upon use for security
	// Should return error when trying to use again (code no longer exists)
	_, err = store.GetAuthorizationCode("auth-code-123")
	if err == nil {
		t.Error("GetAuthorizationCode() should return error for already used code (code should be deleted)")
	}

	// Verify the error message indicates code not found
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

func TestFlowStore_AuthorizationCode_Expired(t *testing.T) {
	store := NewFlowStore(slog.Default())

	now := time.Now().Unix()
	authCode := &AuthorizationCode{
		Code:      "auth-code-123",
		ClientID:  "client-123",
		UserEmail: "user@example.com",
		CreatedAt: now - 1000,
		ExpiresAt: now - 100, // Expired
		Used:      false,
	}

	// Save expired code
	err := store.SaveAuthorizationCode(authCode)
	if err != nil {
		t.Fatalf("SaveAuthorizationCode() error = %v", err)
	}

	// Should return error for expired code
	_, err = store.GetAuthorizationCode("auth-code-123")
	if err == nil {
		t.Error("GetAuthorizationCode() should return error for expired code")
	}
}

func TestFlowStore_AuthorizationCode_NotFound(t *testing.T) {
	store := NewFlowStore(slog.Default())

	_, err := store.GetAuthorizationCode("nonexistent")
	if err == nil {
		t.Error("GetAuthorizationCode() should return error for nonexistent code")
	}
}

func TestFlowStore_CleanupExpired(t *testing.T) {
	store := NewFlowStore(slog.Default())

	now := time.Now().Unix()

	// Add expired state
	expiredState := &AuthorizationState{
		State:       "expired-state",
		GoogleState: "expired-google-state",
		CreatedAt:   now - 1000,
		ExpiresAt:   now - 100,
	}
	store.SaveAuthorizationState(expiredState)

	// Add valid state
	validState := &AuthorizationState{
		State:       "valid-state",
		GoogleState: "valid-google-state",
		CreatedAt:   now,
		ExpiresAt:   now + 600,
	}
	store.SaveAuthorizationState(validState)

	// Add expired code
	expiredCode := &AuthorizationCode{
		Code:      "expired-code",
		CreatedAt: now - 1000,
		ExpiresAt: now - 100,
	}
	store.SaveAuthorizationCode(expiredCode)

	// Add valid code
	// Note: Used codes are immediately deleted upon use (GetAuthorizationCode),
	// so they never exist in the store long enough to be cleaned up
	validCode := &AuthorizationCode{
		Code:      "valid-code",
		CreatedAt: now,
		ExpiresAt: now + 600,
	}
	store.SaveAuthorizationCode(validCode)

	// Run cleanup
	store.cleanupExpired()

	// Expired state should be gone
	_, err := store.GetAuthorizationState("expired-google-state")
	if err == nil {
		t.Error("Expired state should be cleaned up")
	}

	// Valid state should still exist
	_, err = store.GetAuthorizationState("valid-google-state")
	if err != nil {
		t.Errorf("Valid state should not be cleaned up: %v", err)
	}

	// Expired code should be gone
	_, err = store.GetAuthorizationCode("expired-code")
	if err == nil {
		t.Error("Expired code should be cleaned up")
	}

	// Valid code should still exist
	// Note: This will also delete it, but that's expected behavior
	retrieved, err := store.GetAuthorizationCode("valid-code")
	if err != nil {
		t.Errorf("Valid code should exist before use: %v", err)
	}
	if retrieved.Code != "valid-code" {
		t.Errorf("Expected code 'valid-code', got %s", retrieved.Code)
	}

	// After retrieval, code should be deleted (security feature)
	_, err = store.GetAuthorizationCode("valid-code")
	if err == nil {
		t.Error("Code should be deleted after first use")
	}
}
