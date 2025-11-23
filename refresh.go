package oauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

// refreshGoogleToken attempts to refresh an expired Google OAuth token
func refreshGoogleToken(ctx context.Context, token *oauth2.Token, config *oauth2.Config, httpClient *http.Client) (*oauth2.Token, error) {
	// Check if we have a refresh token
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// Use custom HTTP client if provided
	if httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	}

	// Use the OAuth2 config to refresh the token
	tokenSource := config.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return newToken, nil
}

// isTokenExpired checks if a token is expired or will expire soon
// Returns true if the token has expired or will expire within the threshold
func isTokenExpired(token *oauth2.Token, threshold time.Duration) bool {
	if token.Expiry.IsZero() {
		return false // Token doesn't expire
	}

	// Check if token is expired or will expire within threshold
	return time.Now().Add(threshold).After(token.Expiry)
}

// RefreshGoogleTokenIfNeeded checks if a token needs refreshing and refreshes it if necessary
// threshold: refresh if token will expire within this duration (e.g., 5 minutes)
func (h *Handler) RefreshGoogleTokenIfNeeded(ctx context.Context, email string, token *oauth2.Token, config *oauth2.Config) (*oauth2.Token, error) {
	// Check if token needs refreshing (refresh if expiring within 5 minutes)
	threshold := 5 * time.Minute
	if !isTokenExpired(token, threshold) {
		return token, nil
	}

	// Attempt to refresh the token
	newToken, err := refreshGoogleToken(ctx, token, config, h.httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token for %s: %w", email, err)
	}

	// Update the token in the store
	if err := h.store.SaveGoogleToken(email, newToken); err != nil {
		// Log but don't fail - we still have the new token
		h.logger.Warn("Failed to save refreshed token", "email", email, "error", err)
	}

	return newToken, nil
}
