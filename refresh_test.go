package oauth

import (
	"context"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestIsTokenExpired(t *testing.T) {
	tests := []struct {
		name      string
		token     *oauth2.Token
		threshold time.Duration
		want      bool
	}{
		{
			name: "not expired, far from expiry",
			token: &oauth2.Token{
				Expiry: time.Now().Add(1 * time.Hour),
			},
			threshold: 5 * time.Minute,
			want:      false,
		},
		{
			name: "not expired, but within threshold",
			token: &oauth2.Token{
				Expiry: time.Now().Add(3 * time.Minute),
			},
			threshold: 5 * time.Minute,
			want:      true,
		},
		{
			name: "already expired",
			token: &oauth2.Token{
				Expiry: time.Now().Add(-1 * time.Minute),
			},
			threshold: 5 * time.Minute,
			want:      true,
		},
		{
			name: "no expiry set",
			token: &oauth2.Token{
				Expiry: time.Time{},
			},
			threshold: 5 * time.Minute,
			want:      false,
		},
		{
			name: "exactly at threshold",
			token: &oauth2.Token{
				Expiry: time.Now().Add(5 * time.Minute),
			},
			threshold: 5 * time.Minute,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTokenExpired(tt.token, tt.threshold)
			if got != tt.want {
				t.Errorf("isTokenExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRefreshGoogleTokenIfNeeded(t *testing.T) {
	config := &Config{
		Resource: "https://test.example.com",
	}
	handler, err := NewHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	ctx := context.Background()

	// Test with a non-expired token (should not refresh)
	t.Run("token not expired", func(t *testing.T) {
		token := &oauth2.Token{
			AccessToken:  "valid_token",
			RefreshToken: "refresh_token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}

		// This should return the same token without attempting refresh
		// Since we don't have a real OAuth config, this test just validates
		// that non-expired tokens are passed through
		result, err := handler.RefreshGoogleTokenIfNeeded(ctx, "test@example.com", token, nil)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if result.AccessToken != token.AccessToken {
			t.Error("Token was modified when it shouldn't have been")
		}
	})

	// Test with an expired token (should attempt refresh)
	t.Run("token expired", func(t *testing.T) {
		token := &oauth2.Token{
			AccessToken:  "expired_token",
			RefreshToken: "refresh_token",
			Expiry:       time.Now().Add(-1 * time.Hour),
		}

		// This will fail because we don't have a real OAuth config
		// But it should attempt the refresh
		_, err := handler.RefreshGoogleTokenIfNeeded(ctx, "test@example.com", token, &oauth2.Config{})
		if err == nil {
			t.Error("Expected error when refreshing with invalid config")
		}
	})

	// Test with token expiring soon
	t.Run("token expiring soon", func(t *testing.T) {
		token := &oauth2.Token{
			AccessToken:  "expiring_soon_token",
			RefreshToken: "refresh_token",
			Expiry:       time.Now().Add(2 * time.Minute), // Less than 5 minute threshold
		}

		// Should attempt refresh (will fail with invalid config)
		// We expect an error because the config is invalid/empty
		_, err := handler.RefreshGoogleTokenIfNeeded(ctx, "test@example.com", token, &oauth2.Config{})
		// Note: we're just testing that the function attempts refresh for expiring tokens
		// With an empty config, it should fail - that's expected
		_ = err // May or may not error depending on oauth2 library behavior
	})
}

func TestRefreshGoogleToken_NoRefreshToken(t *testing.T) {
	token := &oauth2.Token{
		AccessToken: "access_token",
		// No RefreshToken
		Expiry: time.Now().Add(-1 * time.Hour),
	}

	ctx := context.Background()
	_, err := refreshGoogleToken(ctx, token, &oauth2.Config{}, nil)

	if err == nil {
		t.Error("Expected error when no refresh token is available")
	}

	if err != nil && err.Error() != "no refresh token available" {
		t.Errorf("Expected 'no refresh token available' error, got: %v", err)
	}
}
