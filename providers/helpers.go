package providers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	if opts.Nonce != "" {
		result = append(result, oauth2.SetAuthURLParam("nonce", opts.Nonce))
	}
	for k, v := range opts.Extra {
		result = append(result, oauth2.SetAuthURLParam(k, v))
	}
	return result
}

// CrossClientAudienceScopePrefix is the Dex-specific prefix for cross-client audience scopes.
// Scopes with this prefix are mandatory and must be merged into client-requested scopes
// to enable SSO token forwarding scenarios.
//
// ADMINISTRATOR NOTE: Any scope with this prefix configured in the provider's default
// scopes will be AUTOMATICALLY MERGED into ALL authorization requests, regardless of
// what scopes the client explicitly requests. This is intentional behavior to ensure
// SSO token forwarding works correctly, but administrators should be aware that:
//
//   - Tokens will always include the configured audience claims
//   - Clients cannot opt out of these audiences
//   - This affects token size and validation requirements on downstream services
//
// Example: If defaults include "audience:server:client_id:k8s-auth", every token will
// be valid for the "k8s-auth" client, even if the requesting client didn't ask for it.
const CrossClientAudienceScopePrefix = "audience:server:client_id:"

// isMandatoryScope returns true if the scope must always be force-merged into the
// resolved scope set when present in the provider's defaults. It is the set
// CopyScopes and FilterScopes apply, and the one FilterScopesFunc takes for a
// nil predicate. Currently mandatory:
//   - "openid": Required by OIDC-compliant providers per the OpenID Connect spec.
//   - "email": Required for user identification in downstream services.
//   - "profile": Required for user display name and metadata.
//   - "groups": Required for RBAC-based authorization.
//   - "offline_access": Required for refresh token issuance.
//   - CrossClientAudienceScopePrefix: Required for SSO token forwarding scenarios.
//
// The set is the Dex and OIDC vocabulary. An IdP with a vocabulary of its own
// needs a predicate of its own, through FilterScopesFunc.
func isMandatoryScope(scope string) bool {
	switch scope {
	case "openid", "email", "profile", "groups", "offline_access":
		return true
	default:
		return strings.HasPrefix(scope, CrossClientAudienceScopePrefix)
	}
}

// CopyScopes creates a deep copy of scopes to prevent race conditions.
// If requestedScopes is empty, copies defaultScopes.
// If requestedScopes is non-empty, copies those and merges in any mandatory scopes
// from defaultScopes. Mandatory scopes (when present in defaults) are:
//   - "openid": Required by OIDC spec.
//   - "email": Required for user identification in downstream services.
//   - "profile": Required for user display name and metadata.
//   - "groups": Required for RBAC-based authorization.
//   - "offline_access": Required for refresh token issuance.
//   - Cross-client audience scopes (prefixed with CrossClientAudienceScopePrefix):
//     Required for SSO token forwarding scenarios.
//
// Example:
//
//	defaultScopes: ["openid", "profile", "email", "groups", "offline_access", "audience:server:client_id:k8s-auth"]
//	requestedScopes: ["claudeai"]
//	result: ["claudeai", "openid", "profile", "email", "groups", "offline_access", "audience:server:client_id:k8s-auth"]
//
// All identity-critical scopes from defaults are force-merged, ensuring that
// downstream services always receive the claims they need (email, groups, etc.)
// regardless of what the MCP client explicitly requests.
func CopyScopes(requestedScopes, defaultScopes []string) []string {
	return copyScopes(requestedScopes, defaultScopes, nil)
}

// copyScopes is CopyScopes with a caller-supplied mandatory-scope predicate. A
// nil predicate uses isMandatoryScope.
func copyScopes(requestedScopes, defaultScopes []string, mandatory func(string) bool) []string {
	if mandatory == nil {
		mandatory = isMandatoryScope
	}

	// If no requested scopes, use defaults entirely
	if len(requestedScopes) == 0 {
		scopesCopy := make([]string, len(defaultScopes))
		copy(scopesCopy, defaultScopes)
		return scopesCopy
	}

	// Start with a copy of requested scopes
	// Pre-allocate with extra capacity for potential mandatory scopes to avoid reallocation
	result := make([]string, len(requestedScopes), len(requestedScopes)+len(defaultScopes))
	copy(result, requestedScopes)

	// Build a set of requested scopes for deduplication
	requestedSet := make(map[string]struct{}, len(requestedScopes))
	for _, s := range requestedScopes {
		requestedSet[s] = struct{}{}
	}

	// Merge mandatory scopes from defaults
	for _, s := range defaultScopes {
		if mandatory(s) {
			if _, exists := requestedSet[s]; !exists {
				result = append(result, s)
			}
		}
	}

	return result
}

// EnsureTimeout returns ctx unchanged when it already has a deadline; otherwise
// it returns context.WithTimeout(ctx, timeout). The cancel func is always
// non-nil and safe to defer.
func EnsureTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// CloneScopes returns an independent copy of scopes (nil-safe). Used by every
// provider's DefaultScopes() so callers cannot mutate the provider's slice.
func CloneScopes(scopes []string) []string {
	if scopes == nil {
		return nil
	}
	out := make([]string, len(scopes))
	copy(out, scopes)
	return out
}

// FilterScopes applies the provider-specific `supported` predicate to the
// merged copy that CopyScopes produces from requestedScopes+defaultScopes.
// Mandatory-scope merging (openid, email, etc.) happens inside CopyScopes;
// FilterScopes is the IdP-specific overlay that drops scopes the upstream
// would reject (e.g. Google does not accept Dex audience scopes, and vice
// versa).
//
// A nil predicate is treated as "accept everything".
func FilterScopes(requestedScopes, defaultScopes []string, supported func(string) bool) []string {
	return FilterScopesFunc(requestedScopes, defaultScopes, supported, nil)
}

// FilterScopesFunc is FilterScopes with a caller-supplied mandatory-scope
// predicate. A nil mandatory predicate uses the built-in set, and a nil
// supported predicate accepts everything.
//
// A provider whose IdP has a scope vocabulary of its own needs this: under the
// built-in set, a configured default such as a Keycloak "roles" reaches the IdP
// only when the client requests no scopes at all, so a client that names one
// scope silently drops the rest of the operator's set.
func FilterScopesFunc(requestedScopes, defaultScopes []string, supported, mandatory func(string) bool) []string {
	merged := copyScopes(requestedScopes, defaultScopes, mandatory)
	if supported == nil {
		return merged
	}
	filtered := make([]string, 0, len(merged))
	for _, s := range merged {
		if supported(s) {
			filtered = append(filtered, s)
		}
	}
	return filtered
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
