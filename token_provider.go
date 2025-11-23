package oauth

import (
	"context"
	"fmt"

	"golang.org/x/oauth2"
)

// TokenProvider implements google.TokenProvider using the OAuth store
// This allows Google API clients to use tokens from OAuth authentication
type TokenProvider struct {
	store *Store
}

// NewTokenProvider creates a new OAuth-based token provider
func NewTokenProvider(store *Store) *TokenProvider {
	return &TokenProvider{
		store: store,
	}
}

// GetTokenForAccount retrieves a Google OAuth token from the store
// First checks if there's an authenticated user in the context (from OAuth middleware)
// Falls back to looking up by account name for backward compatibility
func (p *TokenProvider) GetTokenForAccount(ctx context.Context, account string) (*oauth2.Token, error) {
	// First, check if there's an authenticated user in the context
	// This is set by the OAuth middleware after validating the Bearer token
	if userInfo, ok := GetUserFromContext(ctx); ok && userInfo != nil && userInfo.Email != "" {
		// User is authenticated via OAuth, use their email to look up the Google token
		token, err := p.store.GetGoogleToken(userInfo.Email)
		if err == nil {
			return token, nil
		}
		// If token not found by email, try the account name as fallback
	}

	// Fall back to account name lookup (for STDIO transport or if context lookup failed)
	token, err := p.store.GetGoogleToken(account)
	if err != nil {
		return nil, fmt.Errorf("no Google OAuth token found for account %s. Please authenticate with Google through your MCP client", account)
	}
	return token, nil
}

// HasTokenForAccount checks if a token exists in the store for the specified account
// First checks if there's an authenticated user in the context
func (p *TokenProvider) HasTokenForAccount(account string) bool {
	// Note: This method doesn't have access to context, so it can only check by account name
	// This is fine because it's only used during server initialization
	_, err := p.store.GetGoogleToken(account)
	return err == nil
}
