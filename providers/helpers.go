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

// ApplyAuthorizationURLOptions converts AuthorizationURLOptions to oauth2.AuthCodeOption slice.
// This shared helper reduces code duplication across providers and helps keep cyclomatic
// complexity low. Returns nil if opts is nil.
//
// Standard OIDC parameters supported:
//   - prompt: Controls authentication UX (none, login, consent, select_account)
//   - login_hint: Pre-fills username/email field
//   - max_age: Maximum authentication age in seconds
//   - acr_values: Authentication context class references
//   - id_token_hint: Previously issued ID token as session hint
//   - Extra: Additional custom parameters
func ApplyAuthorizationURLOptions(opts *AuthorizationURLOptions) []oauth2.AuthCodeOption {
	if opts == nil {
		return nil
	}

	var result []oauth2.AuthCodeOption
	if opts.Prompt != "" {
		result = append(result, oauth2.SetAuthURLParam("prompt", opts.Prompt))
	}
	if opts.LoginHint != "" {
		result = append(result, oauth2.SetAuthURLParam("login_hint", opts.LoginHint))
	}
	if opts.MaxAge != nil {
		result = append(result, oauth2.SetAuthURLParam("max_age", fmt.Sprintf("%d", *opts.MaxAge)))
	}
	if opts.ACRValues != "" {
		result = append(result, oauth2.SetAuthURLParam("acr_values", opts.ACRValues))
	}
	if opts.IDTokenHint != "" {
		result = append(result, oauth2.SetAuthURLParam("id_token_hint", opts.IDTokenHint))
	}
	for k, v := range opts.Extra {
		result = append(result, oauth2.SetAuthURLParam(k, v))
	}
	return result
}

// CopyScopes creates a deep copy of scopes to prevent race conditions.
// If requestedScopes is non-empty, copies those; otherwise copies defaultScopes.
func CopyScopes(requestedScopes, defaultScopes []string) []string {
	var sourceScopes []string
	if len(requestedScopes) > 0 {
		sourceScopes = requestedScopes
	} else {
		sourceScopes = defaultScopes
	}
	scopesCopy := make([]string, len(sourceScopes))
	copy(scopesCopy, sourceScopes)
	return scopesCopy
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
