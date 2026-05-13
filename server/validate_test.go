package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
)

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
		refreshFails   bool // if true, configure provider RefreshToken to fail
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
			name:           "token expired - refresh fails - beyond grace period",
			accessToken:    "expired-token",
			tokenExpiry:    time.Now().Add(-10 * time.Minute),
			saveToken:      true,
			refreshFails:   true,
			clockSkewGrace: 5,
			wantErr:        true,
			wantErrMsg:     "access token expired",
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
			name:           "token expired - refresh fails - just beyond grace period",
			accessToken:    "just-beyond-grace",
			tokenExpiry:    time.Now().Add(-6 * time.Second),
			saveToken:      true,
			refreshFails:   true,
			clockSkewGrace: 5,
			wantErr:        true,
			wantErrMsg:     "access token expired",
		},
		{
			name:           "zero grace period - refresh fails - strict expiry check",
			accessToken:    "zero-grace-token",
			tokenExpiry:    time.Now().Add(-1 * time.Second),
			saveToken:      true,
			refreshFails:   true,
			clockSkewGrace: 0,
			wantErr:        true,
			wantErrMsg:     "access token expired",
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

			// Configure provider refresh behavior per test case
			if tt.refreshFails {
				provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
					return nil, fmt.Errorf("refresh token expired")
				}
			} else {
				provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
					return &oauth2.Token{
						AccessToken:  "refreshed-provider-token",
						RefreshToken: "refreshed-provider-refresh",
						Expiry:       time.Now().Add(1 * time.Hour),
						TokenType:    "Bearer",
					}, nil
				}
			}

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

	t.Run("token expired locally with refresh failure - local validation wins", func(t *testing.T) {
		accessToken := "locally-expired-token"

		// Configure provider refresh to fail (simulates expired refresh token)
		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			return nil, fmt.Errorf("refresh token expired")
		}

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

		// Try to validate - should fail locally (refresh fails)
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

// TestServer_ValidateToken_RefreshOnExpiry tests that expired provider tokens are
// transparently refreshed during validation when a refresh token is available.
func TestServer_ValidateToken_RefreshOnExpiry(t *testing.T) {
	ctx := context.Background()

	t.Run("expired token with refresh token - should refresh and succeed", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)

		var refreshCalled bool
		provider.RefreshTokenFunc = func(_ context.Context, refreshToken string) (*oauth2.Token, error) {
			refreshCalled = true
			if refreshToken != "provider-refresh-token" {
				t.Errorf("RefreshToken called with %q, want %q", refreshToken, "provider-refresh-token")
			}
			return &oauth2.Token{
				AccessToken:  "new-provider-access-token",
				RefreshToken: "new-provider-refresh-token",
				Expiry:       time.Now().Add(1 * time.Hour),
				TokenType:    "Bearer",
			}, nil
		}
		provider.ValidateTokenFunc = setupValidTokenProvider()

		// Save token with expired provider token that has a refresh token
		accessToken := "test-expired-with-refresh"
		token := &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(-10 * time.Minute), // expired
		}
		if err := store.SaveToken(ctx, accessToken, token); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}

		userInfo, err := srv.ValidateToken(ctx, accessToken)
		if err != nil {
			t.Fatalf("ValidateToken() unexpected error = %v", err)
		}
		if userInfo == nil {
			t.Fatal("ValidateToken() returned nil userInfo")
		}
		if !refreshCalled {
			t.Error("Expected provider.RefreshToken to be called")
		}

		// Verify the refreshed token was stored
		storedToken, err := store.GetToken(ctx, accessToken)
		if err != nil {
			t.Fatalf("GetToken() error = %v", err)
		}
		if storedToken.AccessToken != "new-provider-access-token" {
			t.Errorf("Stored token AccessToken = %q, want %q", storedToken.AccessToken, "new-provider-access-token")
		}
	})

	t.Run("expired token with refresh token but refresh fails - should reject", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)

		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			return nil, fmt.Errorf("refresh token revoked")
		}
		provider.ValidateTokenFunc = setupValidTokenProvider()

		accessToken := "test-expired-refresh-fails"
		token := &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(-10 * time.Minute), // expired
		}
		if err := store.SaveToken(ctx, accessToken, token); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}

		_, err := srv.ValidateToken(ctx, accessToken)
		if err == nil {
			t.Fatal("ValidateToken() expected error but got none")
		}
		if !strings.Contains(err.Error(), "refresh failed") {
			t.Errorf("ValidateToken() error = %q, want error containing 'refresh failed'", err.Error())
		}
	})

	t.Run("non-expired token - should not attempt refresh", func(t *testing.T) {
		srv, store, provider := setupFlowTestServer(t)

		var refreshCalled bool
		provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
			refreshCalled = true
			return nil, fmt.Errorf("should not be called")
		}
		provider.ValidateTokenFunc = setupValidTokenProvider()

		accessToken := "test-valid-no-refresh-needed" // nolint:gosec // G101: False positive - test token, not credentials
		token := &oauth2.Token{
			AccessToken:  "provider-access-token",
			RefreshToken: "provider-refresh-token",
			Expiry:       time.Now().Add(30 * time.Minute), // not expired
		}
		if err := store.SaveToken(ctx, accessToken, token); err != nil {
			t.Fatalf("SaveToken() error = %v", err)
		}

		userInfo, err := srv.ValidateToken(ctx, accessToken)
		if err != nil {
			t.Fatalf("ValidateToken() unexpected error = %v", err)
		}
		if userInfo == nil {
			t.Fatal("ValidateToken() returned nil userInfo")
		}
		if refreshCalled {
			t.Error("Expected provider.RefreshToken NOT to be called for valid token")
		}
	})
}

// TestServer_ValidateToken_RefreshUpdatesRTMapping verifies that when a provider
// token is refreshed during validation, the refresh-token storage key is also
// updated with the new provider token. This prevents stale credentials when the
// client later uses their refresh token.
func TestServer_ValidateToken_RefreshUpdatesRTMapping(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)
	srv.Config.AccessTokenTTL = 3600

	rotatedProviderRT := "provider-rt-v2"
	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken:  "new-provider-at",
			RefreshToken: rotatedProviderRT,
			Expiry:       time.Now().Add(30 * time.Minute),
			TokenType:    "Bearer",
		}, nil
	}
	provider.ValidateTokenFunc = setupValidTokenProvider()

	clientAT := "client-access-token"
	clientRT := "client-refresh-token"

	oldProviderToken := &oauth2.Token{
		AccessToken:  "old-provider-at",
		RefreshToken: "old-provider-rt",
		Expiry:       time.Now().Add(-10 * time.Minute),
	}

	if err := store.SaveToken(ctx, clientAT, oldProviderToken); err != nil {
		t.Fatalf("SaveToken(AT) error = %v", err)
	}
	if err := store.SaveToken(ctx, clientRT, oldProviderToken); err != nil {
		t.Fatalf("SaveToken(RT) error = %v", err)
	}

	srv.registerTokenPair(clientAT, clientRT)

	_, err := srv.ValidateToken(ctx, clientAT)
	if err != nil {
		t.Fatalf("ValidateToken() unexpected error = %v", err)
	}

	// The RT-key mapping must now contain the rotated provider refresh token.
	refreshKeyToken, err := store.GetToken(ctx, clientRT)
	if err != nil {
		t.Fatalf("GetToken(RT) error = %v", err)
	}
	if refreshKeyToken.RefreshToken != rotatedProviderRT {
		t.Errorf("RT-key provider token RefreshToken = %q, want %q",
			refreshKeyToken.RefreshToken, rotatedProviderRT)
	}
}

// TestServer_ValidateToken_PreservesOldRefreshToken verifies that when the
// provider omits the refresh_token in a refresh response, the old refresh
// token is preserved (per OAuth 2.0 RFC 6749 Section 5.1).
func TestServer_ValidateToken_PreservesOldRefreshToken(t *testing.T) {
	ctx := context.Background()
	srv, store, provider := setupFlowTestServer(t)

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken: "new-provider-at",
			Expiry:      time.Now().Add(30 * time.Minute),
			TokenType:   "Bearer",
			// No RefreshToken returned
		}, nil
	}
	provider.ValidateTokenFunc = setupValidTokenProvider()

	clientAT := "client-at-preserve"
	oldRT := "old-provider-refresh-token"

	if err := store.SaveToken(ctx, clientAT, &oauth2.Token{
		AccessToken:  "old-provider-at",
		RefreshToken: oldRT,
		Expiry:       time.Now().Add(-10 * time.Minute),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	_, err := srv.ValidateToken(ctx, clientAT)
	if err != nil {
		t.Fatalf("ValidateToken() unexpected error = %v", err)
	}

	refreshedToken, err := store.GetToken(ctx, clientAT)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if refreshedToken.RefreshToken != oldRT {
		t.Errorf("RefreshToken = %q, want preserved old value %q",
			refreshedToken.RefreshToken, oldRT)
	}
}

// TestServer_ValidateToken_ConcurrentRefreshDedup verifies that concurrent
// requests for the same expired token use singleflight to deduplicate the
// provider refresh call.
//
// The refresh function blocks until explicitly released so that all goroutines
// queue up inside singleflight.Do before the first call completes. Without
// this barrier the instant-returning mock gives singleflight no window to
// coalesce, making the test flaky.
func TestServer_ValidateToken_ConcurrentRefreshDedup(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	var refreshCount int
	var mu sync.Mutex
	refreshStarted := make(chan struct{}, 1)
	allowRefresh := make(chan struct{})

	provider.RefreshTokenFunc = func(_ context.Context, _ string) (*oauth2.Token, error) {
		select {
		case refreshStarted <- struct{}{}:
		default:
		}
		<-allowRefresh

		mu.Lock()
		refreshCount++
		mu.Unlock()
		return &oauth2.Token{
			AccessToken:  "new-provider-at",
			RefreshToken: "new-provider-rt",
			Expiry:       time.Now().Add(1 * time.Hour),
			TokenType:    "Bearer",
		}, nil
	}
	provider.ValidateTokenFunc = setupValidTokenProvider()

	clientAT := "concurrent-at"
	if err := store.SaveToken(context.Background(), clientAT, &oauth2.Token{
		AccessToken:  "old-provider-at",
		RefreshToken: "old-provider-rt",
		Expiry:       time.Now().Add(-10 * time.Minute),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	const goroutines = 5
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			_, _ = srv.ValidateToken(context.Background(), clientAT)
		}()
	}

	// Wait for the first refresh call to start, then give the remaining
	// goroutines time to enter singleflight.Do before releasing.
	<-refreshStarted
	time.Sleep(50 * time.Millisecond)
	close(allowRefresh)

	wg.Wait()

	mu.Lock()
	count := refreshCount
	mu.Unlock()

	if count != 1 {
		t.Errorf("provider.RefreshToken called %d times, expected exactly 1 (singleflight dedup)", count)
	}
}

func TestServer_ValidateToken_SingleflightRefreshIgnoresCanceledLeaderContext(t *testing.T) {
	srv, store, provider := setupFlowTestServer(t)

	provider.RefreshTokenFunc = func(ctx context.Context, _ string) (*oauth2.Token, error) {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("refresh context unexpectedly canceled: %w", ctx.Err())
		}
		return &oauth2.Token{
			AccessToken:  "provider-access-new",
			RefreshToken: "provider-refresh-new",
			Expiry:       time.Now().Add(30 * time.Minute),
			TokenType:    "Bearer",
		}, nil
	}
	provider.ValidateTokenFunc = setupValidTokenProvider()

	accessToken := "canceled-context-refresh-token"
	if err := store.SaveToken(context.Background(), accessToken, &oauth2.Token{
		AccessToken:  "provider-access-old",
		RefreshToken: "provider-refresh-old",
		Expiry:       time.Now().Add(-10 * time.Minute),
	}); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := srv.ValidateToken(canceledCtx, accessToken); err != nil {
		t.Fatalf("ValidateToken() unexpected error with canceled leader context: %v", err)
	}
}
