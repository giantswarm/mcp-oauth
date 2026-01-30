// Dex cross-client audience scope helper functions.
//
// This file provides utilities for formatting Dex cross-client audience scopes,
// which enable SSO scenarios where a token can be valid for multiple downstream clients.
//
// Reference: https://dexidp.io/docs/custom-scopes-claims-clients/#cross-client-trust-and-authorized-party

package dex

import (
	"strings"
)

// audienceScopePrefix is the Dex-specific prefix for cross-client audience scopes.
const audienceScopePrefix = "audience:server:client_id:"

// FormatAudienceScope formats a client ID as a Dex cross-client audience scope.
// This enables a token to be valid for the specified client in addition to the
// requesting client.
//
// Example:
//
//	FormatAudienceScope("dex-k8s-authenticator")
//	// returns "audience:server:client_id:dex-k8s-authenticator"
//
// Use case: When a user authenticates through one client but needs access to
// resources protected by another client (e.g., Kubernetes OIDC via dex-k8s-authenticator).
func FormatAudienceScope(audience string) string {
	return audienceScopePrefix + audience
}

// FormatAudienceScopes formats multiple client IDs as Dex cross-client audience scopes.
// Empty strings in the input are filtered out.
//
// Example:
//
//	FormatAudienceScopes([]string{"k8s-auth", "api-gateway", ""})
//	// returns []string{
//	//     "audience:server:client_id:k8s-auth",
//	//     "audience:server:client_id:api-gateway",
//	// }
//
// Use case: When a token needs to be valid for multiple downstream services
// simultaneously for cross-cluster or multi-service SSO.
func FormatAudienceScopes(audiences []string) []string {
	var scopes []string
	for _, audience := range audiences {
		if audience != "" {
			scopes = append(scopes, FormatAudienceScope(audience))
		}
	}
	return scopes
}

// AppendAudienceScopes appends cross-client audience scopes to an existing scope string.
// The existing scopes and audience scopes are joined with spaces, following the
// OAuth 2.0 scope format (RFC 6749 Section 3.3).
//
// If audiences is empty or contains only empty strings, the original scopes string
// is returned unchanged. If scopes is empty, only the audience scopes are returned.
//
// Example:
//
//	AppendAudienceScopes("openid profile email", []string{"k8s-auth"})
//	// returns "openid profile email audience:server:client_id:k8s-auth"
//
// Use case: Adding audience scopes to token exchange or OAuth authorization requests
// to request tokens valid for additional downstream clients.
func AppendAudienceScopes(scopes string, audiences []string) string {
	audienceScopes := FormatAudienceScopes(audiences)
	if len(audienceScopes) == 0 {
		return scopes
	}
	if scopes == "" {
		return strings.Join(audienceScopes, " ")
	}
	return scopes + " " + strings.Join(audienceScopes, " ")
}
