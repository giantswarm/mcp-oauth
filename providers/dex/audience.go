// Dex cross-client audience scope helper functions.
//
// This file provides utilities for formatting Dex cross-client audience scopes,
// which enable SSO scenarios where a token can be valid for multiple downstream clients.
//
// Security: All functions validate audience strings to prevent scope injection attacks.
// Audience strings must contain only alphanumeric characters, hyphens, and underscores.
//
// Reference: https://dexidp.io/docs/custom-scopes-claims-clients/#cross-client-trust-and-authorized-party

package dex

import (
	"fmt"
	"regexp"
	"strings"
)

// AudienceScopePrefix is the Dex-specific prefix for cross-client audience scopes.
// This can be used to check if a scope is an audience scope:
//
//	if strings.HasPrefix(scope, dex.AudienceScopePrefix) {
//	    // handle audience scope
//	}
const AudienceScopePrefix = "audience:server:client_id:"

// audienceRegex validates audience/client IDs.
// Only alphanumeric characters, hyphens, and underscores are allowed.
// This prevents scope injection attacks where spaces or special characters
// could be used to inject additional OAuth scopes.
var audienceRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// MaxAudienceLength is the maximum allowed length for an audience string.
// This prevents DoS attacks via memory exhaustion from extremely long values.
const MaxAudienceLength = 256

// MaxAudienceCount is the maximum number of audiences allowed in a single call.
// This prevents DoS attacks via excessive processing.
const MaxAudienceCount = 50

// ValidateAudience validates a client ID for use in cross-client audience scopes.
//
// Security Considerations:
//   - Character Whitelist: Only alphanumeric, hyphens, and underscores are allowed.
//     This prevents scope injection attacks where spaces could inject additional scopes.
//   - Length Limit: Prevents DoS via memory exhaustion from extremely long values.
//   - Empty Check: Empty audiences are rejected as they would create invalid scopes.
//
// Example:
//
//	if err := dex.ValidateAudience("k8s-auth"); err != nil {
//	    return fmt.Errorf("invalid audience: %w", err)
//	}
func ValidateAudience(audience string) error {
	if audience == "" {
		return fmt.Errorf("audience cannot be empty")
	}

	if len(audience) > MaxAudienceLength {
		return fmt.Errorf("audience exceeds maximum length of %d characters", MaxAudienceLength)
	}

	if !audienceRegex.MatchString(audience) {
		return fmt.Errorf("audience contains invalid characters (allowed: a-z, A-Z, 0-9, _, -)")
	}

	return nil
}

// ValidateAudiences validates multiple client IDs for use in cross-client audience scopes.
//
// Security Considerations:
//   - Count Limit: Maximum of 50 audiences to prevent DoS.
//   - Per-audience validation: Each audience is validated individually.
//
// Example:
//
//	if err := dex.ValidateAudiences([]string{"k8s-auth", "api-gateway"}); err != nil {
//	    return fmt.Errorf("invalid audiences: %w", err)
//	}
func ValidateAudiences(audiences []string) error {
	if len(audiences) > MaxAudienceCount {
		return fmt.Errorf("audiences exceed maximum count of %d", MaxAudienceCount)
	}

	for i, audience := range audiences {
		// Skip empty strings - they're filtered out by FormatAudienceScopes
		if audience == "" {
			continue
		}
		if err := ValidateAudience(audience); err != nil {
			return fmt.Errorf("audience at index %d: %w", i, err)
		}
	}

	return nil
}

// FormatAudienceScope formats a client ID as a Dex cross-client audience scope.
// This enables a token to be valid for the specified client in addition to the
// requesting client.
//
// Returns an error if the audience contains invalid characters or is empty.
// Only alphanumeric characters, hyphens, and underscores are allowed.
//
// Example:
//
//	scope, err := dex.FormatAudienceScope("dex-k8s-authenticator")
//	// scope = "audience:server:client_id:dex-k8s-authenticator"
//
// Use case: When a user authenticates through one client but needs access to
// resources protected by another client (e.g., Kubernetes OIDC via dex-k8s-authenticator).
func FormatAudienceScope(audience string) (string, error) {
	if err := ValidateAudience(audience); err != nil {
		return "", err
	}
	return AudienceScopePrefix + audience, nil
}

// FormatAudienceScopes formats multiple client IDs as Dex cross-client audience scopes.
// Empty strings in the input are filtered out (not treated as errors).
//
// Returns an error if any non-empty audience contains invalid characters.
// Only alphanumeric characters, hyphens, and underscores are allowed.
//
// Example:
//
//	scopes, err := dex.FormatAudienceScopes([]string{"k8s-auth", "api-gateway", ""})
//	// scopes = []string{
//	//     "audience:server:client_id:k8s-auth",
//	//     "audience:server:client_id:api-gateway",
//	// }
//
// Use case: When a token needs to be valid for multiple downstream services
// simultaneously for cross-cluster or multi-service SSO.
func FormatAudienceScopes(audiences []string) ([]string, error) {
	if len(audiences) == 0 {
		return nil, nil
	}

	// Validate all non-empty audiences first
	if err := ValidateAudiences(audiences); err != nil {
		return nil, err
	}

	scopes := make([]string, 0, len(audiences))
	for _, audience := range audiences {
		if audience != "" {
			// Validation already done, use direct concatenation
			scopes = append(scopes, AudienceScopePrefix+audience)
		}
	}

	if len(scopes) == 0 {
		return nil, nil
	}
	return scopes, nil
}

// AppendAudienceScopes appends cross-client audience scopes to an existing scope string.
// The existing scopes and audience scopes are joined with spaces, following the
// OAuth 2.0 scope format (RFC 6749 Section 3.3).
//
// Returns an error if any audience contains invalid characters.
// Empty audience strings are filtered out (not treated as errors).
//
// If audiences is empty or contains only empty strings, the original scopes string
// is returned unchanged. If scopes is empty, only the audience scopes are returned.
//
// Example:
//
//	result, err := dex.AppendAudienceScopes("openid profile email", []string{"k8s-auth"})
//	// result = "openid profile email audience:server:client_id:k8s-auth"
//
// Use case: Adding audience scopes to token exchange or OAuth authorization requests
// to request tokens valid for additional downstream clients.
func AppendAudienceScopes(scopes string, audiences []string) (string, error) {
	audienceScopes, err := FormatAudienceScopes(audiences)
	if err != nil {
		return "", err
	}

	if len(audienceScopes) == 0 {
		return scopes, nil
	}
	if scopes == "" {
		return strings.Join(audienceScopes, " "), nil
	}
	return scopes + " " + strings.Join(audienceScopes, " "), nil
}

// audienceRejection records one audience that partitionAudienceScopes skipped.
type audienceRejection struct {
	Audience string
	Reason   string
}

// partitionAudienceScopes formats every valid audience as a cross-client
// audience scope and reports the ones it skipped. Empty entries are skipped
// without a rejection, as in FormatAudienceScopes.
//
// It differs from FormatAudienceScopes in its failure mode: one malformed
// audience costs only its own scope, not the whole set. A caller that resolves
// audiences from external state (Kubernetes resources, a service registry)
// needs that, because a single bad value must not drop the audiences every
// other consumer depends on.
//
// At most MaxAudienceCount scopes are returned. Audiences past that cap are
// reported as rejected.
func partitionAudienceScopes(audiences []string) ([]string, []audienceRejection) {
	if len(audiences) == 0 {
		return nil, nil
	}

	scopes := make([]string, 0, min(len(audiences), MaxAudienceCount))
	var rejected []audienceRejection

	for _, audience := range audiences {
		if audience == "" {
			continue
		}
		if len(scopes) >= MaxAudienceCount {
			rejected = append(rejected, audienceRejection{
				Audience: audience,
				Reason:   fmt.Sprintf("audiences exceed maximum count of %d", MaxAudienceCount),
			})
			continue
		}
		if err := ValidateAudience(audience); err != nil {
			rejected = append(rejected, audienceRejection{Audience: audience, Reason: err.Error()})
			continue
		}
		scopes = append(scopes, AudienceScopePrefix+audience)
	}

	return scopes, rejected
}
