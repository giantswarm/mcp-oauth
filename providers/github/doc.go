// Package github implements the OAuth provider interface for GitHub OAuth Apps.
// It supports user authentication, token exchange, and access to GitHub APIs.
//
// GitHub OAuth differs from OIDC providers in several key ways:
//   - No OIDC discovery: Endpoints are hardcoded (not dynamically discovered)
//   - Non-expiring tokens: Standard OAuth Apps issue tokens that don't expire
//   - No refresh tokens: Standard OAuth Apps don't provide refresh tokens
//   - Email privacy: User emails may be private, requiring a separate API call
//
// # Default Scopes
//
// When no custom scopes are provided, the provider uses:
//   - user:email: Read user email addresses (required for UserInfo.Email)
//   - read:user: Read user profile data
//
// # Organization Access Control
//
// The provider supports restricting authentication to members of specific GitHub
// organizations. When AllowedOrganizations is configured:
//   - The "read:org" scope is automatically added if not present
//   - User membership is validated on every token validation
//   - Users not in allowed organizations receive an access denied error
//
// # Security Considerations
//
// GitHub tokens don't expire by default, making secure storage critical.
// Use the library's encryption features (security package) for token storage.
// Consider implementing periodic token rotation or user re-authentication.
//
// # Rate Limiting
//
// GitHub API has rate limits (5,000 requests/hour for authenticated requests).
// The provider handles 403 rate limit responses gracefully, but high-volume
// applications should implement their own rate limiting.
//
// # Example Usage
//
//	provider, err := github.NewProvider(&github.Config{
//	    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
//	    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
//	    RedirectURL:  "http://localhost:8080/oauth/callback",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// With organization restriction
//	provider, err := github.NewProvider(&github.Config{
//	    ClientID:             os.Getenv("GITHUB_CLIENT_ID"),
//	    ClientSecret:         os.Getenv("GITHUB_CLIENT_SECRET"),
//	    RedirectURL:          "http://localhost:8080/oauth/callback",
//	    AllowedOrganizations: []string{"giantswarm"},
//	})
package github
