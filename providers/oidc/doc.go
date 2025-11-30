// Package oidc provides shared OpenID Connect client utilities for OAuth providers.
//
// This package implements secure OIDC discovery, input validation, and common
// utilities used by OIDC-based providers (Dex, Keycloak, Azure AD, etc.).
//
// # Security Features
//
//   - SSRF protection for issuer URLs (blocks private IPs, localhost, link-local)
//   - HTTPS enforcement for all endpoints
//   - Input validation for parameters and claims
//   - Discovery document caching with TTL
//   - Thread-safe operations
//
// # Example Usage
//
//	// Create discovery client
//	client := oidc.NewDiscoveryClient(nil, 1*time.Hour, logger)
//
//	// Discover OIDC endpoints
//	doc, err := client.Discover(ctx, "https://dex.example.com")
//	if err != nil {
//	    return err
//	}
//
//	// Use discovered endpoints
//	config := &oauth2.Config{
//	    Endpoint: oauth2.Endpoint{
//	        AuthURL:  doc.AuthorizationEndpoint,
//	        TokenURL: doc.TokenEndpoint,
//	    },
//	}
package oidc
