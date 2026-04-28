package oauthconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/dex"
	"github.com/giantswarm/mcp-oauth/providers/github"
	"github.com/giantswarm/mcp-oauth/providers/google"
)

// dexDefaultCallbackPath is the canonical mcp-oauth provider-callback path;
// kept in sync with handler.oauthCallbackPath in the root package. Used by
// DexFromEnvWithPrefix when OAUTH_DEX_REDIRECT_URL is unset and OAUTH_ISSUER
// is available, so consumers stop having to pre-template
// ${OAUTH_ISSUER}/oauth/callback in their helm values.
const dexDefaultCallbackPath = "/oauth/callback"

// ProviderFromEnv reads OAUTH_PROVIDER (dex|google|github) and dispatches to
// the matching per-provider loader (DexFromEnv, GoogleFromEnv, GitHubFromEnv).
// Use this when the provider should be chosen at deploy time. Consumers that
// hard-code a single provider can call the specific loader directly.
//
// Returns an error when OAUTH_PROVIDER is unset, empty, or not one of the
// three supported values. Unlike other variables in this package, there is
// deliberately no default — silently picking a provider would hide
// misconfiguration.
func ProviderFromEnv() (providers.Provider, error) {
	return ProviderFromEnvWithPrefix("OAUTH_")
}

// ProviderFromEnvWithPrefix is [ProviderFromEnv] with a caller-supplied prefix.
// See [FromEnvWithPrefix] for the convention.
func ProviderFromEnvWithPrefix(prefix string) (providers.Provider, error) {
	name := os.Getenv(prefix + "PROVIDER")
	switch name {
	case "":
		return nil, fmt.Errorf("%sPROVIDER is required (one of: dex, google, github)", prefix)
	case "dex":
		return DexFromEnvWithPrefix(prefix)
	case "google":
		return GoogleFromEnvWithPrefix(prefix)
	case "github":
		return GitHubFromEnvWithPrefix(prefix)
	default:
		return nil, fmt.Errorf("%sPROVIDER: unknown provider %q (want dex, google, or github)", prefix, name)
	}
}

// DexFromEnv reads OAUTH_DEX_* variables and returns a configured Dex provider.
//
//	OAUTH_DEX_ISSUER_URL            (required) — e.g. https://dex.example.com
//	OAUTH_DEX_CLIENT_ID             (required)
//	OAUTH_DEX_CLIENT_SECRET[_FILE]  (required)
//	OAUTH_DEX_REDIRECT_URL          (optional; defaults to OAUTH_ISSUER + "/oauth/callback")
//	OAUTH_DEX_CONNECTOR_ID          (optional) — e.g. "github", "ldap"
//
// OAUTH_DEX_REDIRECT_URL is required ONLY when OAUTH_ISSUER is also unset.
// When OAUTH_ISSUER is set (the typical deployment shape), the redirect URL
// defaults to "${OAUTH_ISSUER}/oauth/callback" — the canonical mcp-oauth
// provider-callback path. A trailing slash on OAUTH_ISSUER is tolerated.
//
// Returned as providers.Provider (not *dex.Provider) so call sites stay
// provider-agnostic. Callers that need Dex-specific methods cast.
//
// Deliberately NOT exposed as env vars (opinionated defaults):
//
//   - Scopes — the default Dex-optimized scope set is strictly better than
//     what an operator would hand-configure; callers needing custom scopes
//     build dex.Config themselves.
//   - HTTPClient — overriding the HTTP client is a programmatic concern
//     (proxies, custom TLS, test doubles); the env surface would force the
//     loader to invent a serialization for *http.Client.
//   - RequestTimeout — operators tune this via the upstream IdP's latency
//     profile, which rarely varies per deployment. Default 30s is sound.
//   - MaxGroups — enterprise-specific tuning for very large AD group counts;
//     the library default (oidc.DefaultMaxGroups = 600) covers the common
//     case, and callers with unusual group counts construct Config manually.
//
// Callers needing any of these construct [dex.Config] programmatically and
// call [dex.NewProvider] directly, bypassing this loader.
func DexFromEnv() (providers.Provider, error) {
	return DexFromEnvWithPrefix("OAUTH_")
}

// DexFromEnvWithPrefix is [DexFromEnv] with a caller-supplied prefix.
func DexFromEnvWithPrefix(prefix string) (providers.Provider, error) {
	issuer, err := requireString(prefix + "DEX_ISSUER_URL")
	if err != nil {
		return nil, err
	}
	clientID, err := requireString(prefix + "DEX_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	redirectURL, err := dexRedirectURL(prefix)
	if err != nil {
		return nil, err
	}
	clientSecret, err := requireSecret(prefix + "DEX_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}

	return dex.NewProvider(&dex.Config{
		IssuerURL:    issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		ConnectorID:  os.Getenv(prefix + "DEX_CONNECTOR_ID"),
	})
}

// GoogleFromEnv reads OAUTH_GOOGLE_* variables and returns a configured Google
// provider.
//
//	OAUTH_GOOGLE_CLIENT_ID             (required)
//	OAUTH_GOOGLE_CLIENT_SECRET[_FILE]  (required)
//	OAUTH_GOOGLE_REDIRECT_URL          (required)
//	OAUTH_GOOGLE_FORCE_CONSENT         (optional; defaults to provider default of true)
//
// Deliberately NOT exposed as env vars:
//
//   - Scopes — the Google-default set ("openid", "email", "profile") matches
//     the overwhelmingly common case; custom scopes are a programmatic choice.
//   - HTTPClient / RequestTimeout — same rationale as [DexFromEnv].
//
// google.Config currently has no hosted-domain field (the Google provider
// doesn't implement Workspace domain restriction). Callers needing workspace
// restriction must construct [google.Config] programmatically once that field
// exists on the Config struct.
func GoogleFromEnv() (providers.Provider, error) {
	return GoogleFromEnvWithPrefix("OAUTH_")
}

// GoogleFromEnvWithPrefix is [GoogleFromEnv] with a caller-supplied prefix.
func GoogleFromEnvWithPrefix(prefix string) (providers.Provider, error) {
	clientID, err := requireString(prefix + "GOOGLE_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	redirectURL, err := requireString(prefix + "GOOGLE_REDIRECT_URL")
	if err != nil {
		return nil, err
	}
	clientSecret, err := requireSecret(prefix + "GOOGLE_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}

	cfg := &google.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
	}

	if v := os.Getenv(prefix + "GOOGLE_FORCE_CONSENT"); v != "" {
		fc, err := optionalBool(prefix+"GOOGLE_FORCE_CONSENT", true)
		if err != nil {
			return nil, err
		}
		cfg.ForceConsent = &fc
	}

	return google.NewProvider(cfg)
}

// GitHubFromEnv reads OAUTH_GITHUB_* variables and returns a configured GitHub
// provider.
//
//	OAUTH_GITHUB_CLIENT_ID                 (required)
//	OAUTH_GITHUB_CLIENT_SECRET[_FILE]      (required)
//	OAUTH_GITHUB_REDIRECT_URL              (required)
//	OAUTH_GITHUB_ALLOWED_ORGANIZATIONS     (optional; comma-separated) — restrict login to members
//	OAUTH_GITHUB_REQUIRE_VERIFIED_EMAIL    (optional; defaults to provider default of true)
//
// Deliberately NOT exposed as env vars:
//
//   - Scopes — the defaults ("user:email", "read:user") suit the vast
//     majority of MCP deployments; custom scopes are programmatic.
//   - HTTPClient / RequestTimeout — same rationale as [DexFromEnv].
//
// GitHub is OAuth 2.0 only (no OIDC), so [providers.IssuerOf] returns "" for
// the resulting provider. Consumers that rely on
// [Server.AcceptForwardedIDToken] must not configure GitHub as the upstream.
func GitHubFromEnv() (providers.Provider, error) {
	return GitHubFromEnvWithPrefix("OAUTH_")
}

// GitHubFromEnvWithPrefix is [GitHubFromEnv] with a caller-supplied prefix.
func GitHubFromEnvWithPrefix(prefix string) (providers.Provider, error) {
	clientID, err := requireString(prefix + "GITHUB_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	redirectURL, err := requireString(prefix + "GITHUB_REDIRECT_URL")
	if err != nil {
		return nil, err
	}
	clientSecret, err := requireSecret(prefix + "GITHUB_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}

	cfg := &github.Config{
		ClientID:             clientID,
		ClientSecret:         clientSecret,
		RedirectURL:          redirectURL,
		AllowedOrganizations: splitAndTrim(os.Getenv(prefix+"GITHUB_ALLOWED_ORGANIZATIONS"), ","),
	}

	if v := os.Getenv(prefix + "GITHUB_REQUIRE_VERIFIED_EMAIL"); v != "" {
		rv, err := optionalBool(prefix+"GITHUB_REQUIRE_VERIFIED_EMAIL", true)
		if err != nil {
			return nil, err
		}
		cfg.RequireVerifiedEmail = &rv
	}

	return github.NewProvider(cfg)
}

// dexRedirectURL resolves the OAuth provider-callback URL for the Dex
// provider. Reads OAUTH_DEX_REDIRECT_URL when set; otherwise falls back to
// "${OAUTH_ISSUER}<dexDefaultCallbackPath>" so deployments don't have to
// duplicate the issuer URL across two env vars (one explicit gap that every
// consumer's helm chart was working around with a value template).
//
// If both are unset, returns the existing requireString "required" error
// for OAUTH_DEX_REDIRECT_URL — preserving the prior failure message and
// shifting the onus back to the operator to set at least one of the two.
//
// strings.TrimRight handles a trailing slash on the issuer so we don't emit
// "https://auth.example//oauth/callback".
func dexRedirectURL(prefix string) (string, error) {
	if v := os.Getenv(prefix + "DEX_REDIRECT_URL"); v != "" {
		return v, nil
	}
	if issuer := os.Getenv(prefix + "ISSUER"); issuer != "" {
		return strings.TrimRight(issuer, "/") + dexDefaultCallbackPath, nil
	}
	return requireString(prefix + "DEX_REDIRECT_URL")
}

// requireSecret is requireString that also understands the _FILE convention
// used by [optionalSecret] — necessary because client secrets are mandatory
// but may arrive via either channel. Returns a clear error if neither the
// plain var nor the _FILE variant has a non-empty value.
func requireSecret(name string) (string, error) {
	v, err := optionalSecret(name)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", fmt.Errorf("required environment variable %s (or %s_FILE) is not set", name, name)
	}
	return v, nil
}
