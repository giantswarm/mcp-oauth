package providers

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// OAuth2ConfigExchanger is an interface for the Exchange method of oauth2.Config.
// This allows us to create shared helper functions that work with any provider's config.
type OAuth2ConfigExchanger interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
}

// ExchangeCodeWithPKCE is a shared helper for exchanging authorization codes with optional PKCE.
// It handles the common pattern of:
// 1. Adding PKCE verifier if provided
// 2. Setting up the HTTP client context
// 3. Performing the exchange
// 4. Wrapping any errors consistently
//
// Parameters:
//   - ctx: context for the request (should have timeout set by caller)
//   - config: OAuth2 config that implements Exchange method
//   - httpClient: custom HTTP client to use for the exchange
//   - code: the authorization code to exchange
//   - verifier: PKCE code verifier (empty string if not using PKCE)
func ExchangeCodeWithPKCE(ctx context.Context, config OAuth2ConfigExchanger, httpClient *http.Client, code, verifier string) (*oauth2.Token, error) {
	var opts []oauth2.AuthCodeOption

	// Add PKCE verifier if provided
	if verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}

	// Use custom HTTP client
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

	// Exchange code for token
	token, err := config.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	return token, nil
}
