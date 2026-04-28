package oauthconfig_test

import (
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
	"github.com/giantswarm/mcp-oauth/providers"
)

// githubProviderName is providers.Provider.Name() for the GitHub provider.
// Constant exists to satisfy goconst (the literal "github" appears in several
// Setenv / Name() assertions across tests in this file).
const githubProviderName = "github"

// clearProviderEnv zeroes every provider-related var this package reads.
// Per-test t.Setenv calls then re-populate what each test actually exercises.
func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"OAUTH_PROVIDER",
		"OAUTH_DEX_ISSUER_URL",
		"OAUTH_DEX_CLIENT_ID",
		"OAUTH_DEX_CLIENT_SECRET",
		"OAUTH_DEX_CLIENT_SECRET_FILE",
		"OAUTH_DEX_REDIRECT_URL",
		"OAUTH_DEX_CONNECTOR_ID",
		"OAUTH_GOOGLE_CLIENT_ID",
		"OAUTH_GOOGLE_CLIENT_SECRET",
		"OAUTH_GOOGLE_CLIENT_SECRET_FILE",
		"OAUTH_GOOGLE_REDIRECT_URL",
		"OAUTH_GOOGLE_FORCE_CONSENT",
		"OAUTH_GITHUB_CLIENT_ID",
		"OAUTH_GITHUB_CLIENT_SECRET",
		"OAUTH_GITHUB_CLIENT_SECRET_FILE",
		"OAUTH_GITHUB_REDIRECT_URL",
		"OAUTH_GITHUB_ALLOWED_ORGANIZATIONS",
		"OAUTH_GITHUB_REQUIRE_VERIFIED_EMAIL",
	} {
		t.Setenv(v, "")
	}
}

// Dex -----------------------------------------------------------------------

func TestDexFromEnv_MissingIssuer(t *testing.T) {
	clearProviderEnv(t)
	_, err := oauthconfig.DexFromEnv()
	if err == nil || !strings.Contains(err.Error(), "OAUTH_DEX_ISSUER_URL") {
		t.Fatalf("expected OAUTH_DEX_ISSUER_URL error, got %v", err)
	}
}

func TestDexFromEnv_MissingClientID(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_DEX_ISSUER_URL", "https://dex.example")
	_, err := oauthconfig.DexFromEnv()
	if err == nil || !strings.Contains(err.Error(), "OAUTH_DEX_CLIENT_ID") {
		t.Fatalf("expected OAUTH_DEX_CLIENT_ID error, got %v", err)
	}
}

func TestDexFromEnv_MissingRedirectURL(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_DEX_ISSUER_URL", "https://dex.example")
	t.Setenv("OAUTH_DEX_CLIENT_ID", "cid")
	_, err := oauthconfig.DexFromEnv()
	if err == nil || !strings.Contains(err.Error(), "OAUTH_DEX_REDIRECT_URL") {
		t.Fatalf("expected OAUTH_DEX_REDIRECT_URL error, got %v", err)
	}
}

func TestDexFromEnv_MissingClientSecret(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_DEX_ISSUER_URL", "https://dex.example")
	t.Setenv("OAUTH_DEX_CLIENT_ID", "cid")
	t.Setenv("OAUTH_DEX_REDIRECT_URL", "https://app.example/callback")
	_, err := oauthconfig.DexFromEnv()
	if err == nil || !strings.Contains(err.Error(), "OAUTH_DEX_CLIENT_SECRET") {
		t.Fatalf("expected OAUTH_DEX_CLIENT_SECRET error, got %v", err)
	}
}

// TestDexFromEnv_SecretFilePrecedence verifies the _FILE variant is honored
// by the loader. We can't easily assert the specific secret ended up on the
// provider struct (fields are unexported), but we can verify the loader
// passes secret-reading and advances to the Dex discovery network call,
// which will fail with a discovery error — not a secret error.
func TestDexFromEnv_SecretFilePrecedence(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_DEX_ISSUER_URL", "https://unreachable.invalid.example")
	t.Setenv("OAUTH_DEX_CLIENT_ID", "cid")
	t.Setenv("OAUTH_DEX_REDIRECT_URL", "https://app.example/callback")
	t.Setenv("OAUTH_DEX_CLIENT_SECRET_FILE", writeSecretFile(t, "from-file\n"))

	_, err := oauthconfig.DexFromEnv()
	if err == nil {
		t.Fatal("expected Dex discovery failure against unreachable host")
	}
	if strings.Contains(err.Error(), "CLIENT_SECRET") {
		t.Errorf("secret stage should not have errored; got %v", err)
	}
}

// Google --------------------------------------------------------------------

func TestGoogleFromEnv_Happy(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_GOOGLE_CLIENT_ID", "gid")
	t.Setenv("OAUTH_GOOGLE_CLIENT_SECRET", "gsecret")
	t.Setenv("OAUTH_GOOGLE_REDIRECT_URL", "https://app.example/callback")

	p, err := oauthconfig.GoogleFromEnv()
	if err != nil {
		t.Fatalf("GoogleFromEnv: %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
	if p.Name() != "google" {
		t.Errorf("Name() = %q, want google", p.Name())
	}
}

func TestGoogleFromEnv_MissingClientID(t *testing.T) {
	clearProviderEnv(t)
	_, err := oauthconfig.GoogleFromEnv()
	if err == nil || !strings.Contains(err.Error(), "OAUTH_GOOGLE_CLIENT_ID") {
		t.Fatalf("expected OAUTH_GOOGLE_CLIENT_ID error, got %v", err)
	}
}

func TestGoogleFromEnv_SecretFile(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_GOOGLE_CLIENT_ID", "gid")
	t.Setenv("OAUTH_GOOGLE_CLIENT_SECRET_FILE", writeSecretFile(t, "file-secret\n"))
	t.Setenv("OAUTH_GOOGLE_REDIRECT_URL", "https://app.example/callback")

	p, err := oauthconfig.GoogleFromEnv()
	if err != nil {
		t.Fatalf("GoogleFromEnv: %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
}

func TestGoogleFromEnv_ForceConsentOptional(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_GOOGLE_CLIENT_ID", "gid")
	t.Setenv("OAUTH_GOOGLE_CLIENT_SECRET", "gsecret")
	t.Setenv("OAUTH_GOOGLE_REDIRECT_URL", "https://app.example/callback")
	t.Setenv("OAUTH_GOOGLE_FORCE_CONSENT", "false")

	if _, err := oauthconfig.GoogleFromEnv(); err != nil {
		t.Fatalf("GoogleFromEnv with FORCE_CONSENT=false: %v", err)
	}
}

// GitHub --------------------------------------------------------------------

func TestGitHubFromEnv_Happy(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "ghid")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "ghsecret")
	t.Setenv("OAUTH_GITHUB_REDIRECT_URL", "https://app.example/callback")

	p, err := oauthconfig.GitHubFromEnv()
	if err != nil {
		t.Fatalf("GitHubFromEnv: %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
	if p.Name() != githubProviderName {
		t.Errorf("Name() = %q, want %s", p.Name(), githubProviderName)
	}
	// GitHub is OAuth-only — IssuerOf must return "".
	if got := providers.IssuerOf(p); got != "" {
		t.Errorf("IssuerOf(github) = %q, want \"\"", got)
	}
}

func TestGitHubFromEnv_AllowedOrganizations(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "ghid")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "ghsecret")
	t.Setenv("OAUTH_GITHUB_REDIRECT_URL", "https://app.example/callback")
	t.Setenv("OAUTH_GITHUB_ALLOWED_ORGANIZATIONS", "org-a, org-b ,")

	if _, err := oauthconfig.GitHubFromEnv(); err != nil {
		t.Fatalf("GitHubFromEnv with ALLOWED_ORGANIZATIONS: %v", err)
	}
}

func TestGitHubFromEnv_BadRequireVerifiedEmail(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "ghid")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "ghsecret")
	t.Setenv("OAUTH_GITHUB_REDIRECT_URL", "https://app.example/callback")
	t.Setenv("OAUTH_GITHUB_REQUIRE_VERIFIED_EMAIL", "maybe")

	_, err := oauthconfig.GitHubFromEnv()
	if err == nil || !strings.Contains(err.Error(), "REQUIRE_VERIFIED_EMAIL") {
		t.Fatalf("expected bool parse error, got %v", err)
	}
}

// ProviderFromEnv dispatcher ------------------------------------------------

func TestProviderFromEnv_MissingProvider(t *testing.T) {
	clearProviderEnv(t)
	_, err := oauthconfig.ProviderFromEnv()
	if err == nil || !strings.Contains(err.Error(), "OAUTH_PROVIDER") {
		t.Fatalf("expected OAUTH_PROVIDER required error, got %v", err)
	}
}

func TestProviderFromEnv_UnknownProvider(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_PROVIDER", "okta")
	_, err := oauthconfig.ProviderFromEnv()
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("expected unknown-provider error, got %v", err)
	}
}

func TestProviderFromEnv_DispatchesToGoogle(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_PROVIDER", "google")
	t.Setenv("OAUTH_GOOGLE_CLIENT_ID", "gid")
	t.Setenv("OAUTH_GOOGLE_CLIENT_SECRET", "gsecret")
	t.Setenv("OAUTH_GOOGLE_REDIRECT_URL", "https://app.example/callback")

	p, err := oauthconfig.ProviderFromEnv()
	if err != nil {
		t.Fatalf("ProviderFromEnv: %v", err)
	}
	if p.Name() != "google" {
		t.Errorf("Name() = %q, want google", p.Name())
	}
}

func TestProviderFromEnv_DispatchesToGitHub(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("OAUTH_PROVIDER", githubProviderName)
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "ghid")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "ghsecret")
	t.Setenv("OAUTH_GITHUB_REDIRECT_URL", "https://app.example/callback")

	p, err := oauthconfig.ProviderFromEnv()
	if err != nil {
		t.Fatalf("ProviderFromEnv: %v", err)
	}
	if p.Name() != githubProviderName {
		t.Errorf("Name() = %q, want %s", p.Name(), githubProviderName)
	}
}

func TestProviderFromEnv_DispatchesToDex_ParsesBeforeNetwork(t *testing.T) {
	// Dex's NewProvider performs OIDC discovery, which would network-fail here.
	// Verify ProviderFromEnv routed to DexFromEnv by leaving a required Dex
	// var unset and asserting the Dex-specific error surfaces.
	clearProviderEnv(t)
	t.Setenv("OAUTH_PROVIDER", "dex")
	_, err := oauthconfig.ProviderFromEnv()
	if err == nil || !strings.Contains(err.Error(), "OAUTH_DEX_ISSUER_URL") {
		t.Fatalf("expected DexFromEnv missing-issuer error, got %v", err)
	}
}

func TestProviderFromEnv_WithPrefix(t *testing.T) {
	clearProviderEnv(t)
	t.Setenv("MUSTER_PROVIDER", githubProviderName)
	t.Setenv("MUSTER_GITHUB_CLIENT_ID", "ghid")
	t.Setenv("MUSTER_GITHUB_CLIENT_SECRET", "ghsecret")
	t.Setenv("MUSTER_GITHUB_REDIRECT_URL", "https://app.example/callback")

	p, err := oauthconfig.ProviderFromEnvWithPrefix("MUSTER_")
	if err != nil {
		t.Fatalf("ProviderFromEnvWithPrefix: %v", err)
	}
	if p.Name() != githubProviderName {
		t.Errorf("Name() = %q, want %s", p.Name(), githubProviderName)
	}
}

