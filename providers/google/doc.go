// Package google provides a Google OAuth 2.0 provider implementation.
//
// This package implements the providers.Provider interface for Google's OAuth 2.0
// authorization server. It supports:
//   - OAuth 2.0 authorization code flow with PKCE
//   - Token refresh
//   - Token revocation via Google's revocation endpoint
//   - User info retrieval via Google's userinfo endpoint
//
// Google provider automatically includes "openid", "email", and "profile" as default
// scopes. Additional scopes can be requested for access to Google APIs like Gmail,
// Drive, Calendar, etc.
//
// Example usage:
//
//	provider, err := google.NewProvider(&google.Config{
//	    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
//	    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
//	    RedirectURL:  "http://localhost:8080/oauth/callback",
//	    Scopes: []string{
//	        "openid", "email", "profile",
//	        "https://www.googleapis.com/auth/gmail.readonly",
//	    },
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// The provider validates tokens by calling Google's userinfo endpoint and
// returns user information including email, name, and profile picture.
package google
