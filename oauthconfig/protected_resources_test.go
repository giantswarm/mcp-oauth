package oauthconfig_test

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
	"github.com/giantswarm/mcp-oauth/server"
)

func clearResourceEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"OAUTH_RESOURCE", "OAUTH_AUTHORIZATION_SERVERS", "OAUTH_ADDITIONAL_RESOURCES",
		"OAUTH_TRUSTED_ISSUERS", "OAUTH_REQUIRE_RESOURCE_ACCESS_TOKENS",
		"OAUTH_ENABLE_INTROSPECTION_ENDPOINT", "OAUTH_ENABLE_USERINFO_ENDPOINT",
		"OAUTH_ENABLE_CLIENT_CONFIGURATION_ENDPOINT",
		"OAUTH_DEX_SCOPES", "OAUTH_DEX_AUDIENCES", "OAUTH_DEX_CA_FILE",
	} {
		t.Setenv(name, "")
	}
}

func resourceEnv(t *testing.T) {
	t.Helper()
	clearRequired(t)
	clearResourceEnv(t)
	t.Setenv("OAUTH_ISSUER", "https://mcp.example.com")
}

func TestFromEnvProtectedResources(t *testing.T) {
	resourceEnv(t)
	t.Setenv("OAUTH_RESOURCE", "https://mcp.example.com/mcp")
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://muster.example.com, https://dex.example.com")
	t.Setenv("OAUTH_ADDITIONAL_RESOURCES", `[
		{"resource": "https://mcp.example.com/api/v1", "scopesSupported": ["read"]},
		{"resource": "https://mcp.example.com/admin", "authorizationServers": ["https://dex.example.com"]}
	]`)

	cfg, err := oauthconfig.FromEnv()
	require.NoError(t, err)
	require.Equal(t, "https://mcp.example.com/mcp", cfg.ResourceIdentifier)
	require.Equal(t, map[string]server.ProtectedResourceConfig{
		"/mcp": {
			ResourceIdentifier:   "https://mcp.example.com/mcp",
			AuthorizationServers: []string{"https://muster.example.com", "https://dex.example.com"},
		},
		"/api/v1": {
			ResourceIdentifier:   "https://mcp.example.com/api/v1",
			ScopesSupported:      []string{"read"},
			AuthorizationServers: []string{"https://muster.example.com", "https://dex.example.com"},
		},
		"/admin": {
			ResourceIdentifier:   "https://mcp.example.com/admin",
			AuthorizationServers: []string{"https://dex.example.com"},
		},
	}, cfg.ResourceMetadataByPath)
}

func TestFromEnvProtectedResourcesUnset(t *testing.T) {
	resourceEnv(t)
	cfg, err := oauthconfig.FromEnv()
	require.NoError(t, err)
	require.Empty(t, cfg.ResourceIdentifier)
	require.Nil(t, cfg.ResourceMetadataByPath)
}

func TestFromEnvProtectedResourcesRefused(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"relative resource":          {"OAUTH_RESOURCE": "/mcp"},
		"resource with fragment":     {"OAUTH_RESOURCE": "https://mcp.example.com/mcp#x"},
		"http resource":              {"OAUTH_RESOURCE": "http://mcp.example.com/mcp"},
		"authorization server query": {"OAUTH_AUTHORIZATION_SERVERS": "https://dex.example.com?x=1"},
		"http authorization server":  {"OAUTH_AUTHORIZATION_SERVERS": "http://dex.example.com"},
		"unknown field":              {"OAUTH_ADDITIONAL_RESOURCES": `[{"path": "/api"}]`},
		"other origin":               {"OAUTH_ADDITIONAL_RESOURCES": `[{"resource": "https://other.example.com/api"}]`},
		"main resource repeated": {
			"OAUTH_RESOURCE":             "https://mcp.example.com/mcp",
			"OAUTH_ADDITIONAL_RESOURCES": `[{"resource": "https://mcp.example.com/mcp/"}]`,
		},
		"listed twice":  {"OAUTH_ADDITIONAL_RESOURCES": `[{"resource": "https://mcp.example.com/api"}, {"resource": "https://mcp.example.com/api"}]`},
		"invalid path":  {"OAUTH_ADDITIONAL_RESOURCES": `[{"resource": "https://mcp.example.com/a/../../b"}]`},
		"invalid bool":  {"OAUTH_REQUIRE_RESOURCE_ACCESS_TOKENS": "maybe"},
		"invalid extra": {"OAUTH_ADDITIONAL_RESOURCES": `[{"resource": "https://mcp.example.com/api", "authorizationServers": ["dex"]}]`},
	} {
		t.Run(name, func(t *testing.T) {
			resourceEnv(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			_, err := oauthconfig.FromEnv()
			require.Error(t, err)
		})
	}
}

func TestFromEnvLoopbackResourceAllowed(t *testing.T) {
	resourceEnv(t)
	t.Setenv("OAUTH_ISSUER", "http://localhost:8080")
	t.Setenv("OAUTH_RESOURCE", "http://localhost:8080/mcp")
	cfg, err := oauthconfig.FromEnv()
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8080/mcp", cfg.ResourceIdentifier)
}

func TestFromEnvSwitches(t *testing.T) {
	resourceEnv(t)
	for _, name := range []string{
		"OAUTH_REQUIRE_RESOURCE_ACCESS_TOKENS", "OAUTH_ENABLE_INTROSPECTION_ENDPOINT",
		"OAUTH_ENABLE_USERINFO_ENDPOINT", "OAUTH_ENABLE_CLIENT_CONFIGURATION_ENDPOINT",
	} {
		t.Setenv(name, "true")
	}
	cfg, err := oauthconfig.FromEnv()
	require.NoError(t, err)
	require.True(t, cfg.RequireResourceAccessTokens)
	require.True(t, cfg.EnableIntrospectionEndpoint)
	require.True(t, cfg.EnableUserInfoEndpoint)
	require.True(t, cfg.EnableClientManagementEndpoint)
}

func writeCAFile(t *testing.T) string {
	t.Helper()
	tlsServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tlsServer.Close)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw}), 0o600))
	return caFile
}

func TestTrustedIssuersFromEnv(t *testing.T) {
	clearResourceEnv(t)
	caFile := writeCAFile(t)
	t.Setenv("OAUTH_TRUSTED_ISSUERS", `[
		{"issuer": "https://dex.example.com", "jwksURI": "https://dex.example.com/keys",
		 "audiences": ["platform"], "subjectClaim": "email", "acceptedTypHeaders": ["JWT"], "caFile": "`+caFile+`"},
		{"issuer": "https://kubernetes.default.svc", "jwksURI": "https://kubernetes.default.svc/openid/v1/jwks",
		 "audiences": ["https://mcp.example.com/mcp"], "acceptedTypHeaders": [""],
		 "allowedClaims": {"sub": "system:serviceaccount:agents:*"},
		 "allowPrivateIPJWKSHosts": ["kubernetes.default.svc"]}
	]`)

	issuers, err := oauthconfig.TrustedIssuersFromEnv()
	require.NoError(t, err)
	require.Len(t, issuers, 2)
	require.Equal(t, "https://dex.example.com/keys", issuers[0].JwksURL)
	require.Equal(t, []string{"platform"}, issuers[0].AllowedAudiences)
	require.Equal(t, "email", issuers[0].SubjectClaim)
	require.NotNil(t, issuers[0].RootCAs)
	require.Equal(t, []string{"https://mcp.example.com/mcp"}, issuers[1].AllowedAudiences)
	require.Equal(t, map[string]string{"sub": "system:serviceaccount:agents:*"}, issuers[1].AllowedClaims)
	require.Equal(t, []string{"kubernetes.default.svc"}, issuers[1].AllowPrivateIPJWKSHosts)
	require.Nil(t, issuers[1].RootCAs)
}

func TestTrustedIssuersFromEnvUnset(t *testing.T) {
	clearResourceEnv(t)
	issuers, err := oauthconfig.TrustedIssuersFromEnv()
	require.NoError(t, err)
	require.Nil(t, issuers)
}

func TestTrustedIssuersFromEnvRefused(t *testing.T) {
	entry := func(fields string) string {
		return `[{"issuer": "https://dex.example.com", "jwksURI": "https://dex.example.com/keys", "audiences": ["platform"]` + fields + `}]`
	}
	for name, raw := range map[string]string{
		"invalid JSON":       `[`,
		"old key":            `[{"issuer": "https://dex.example.com", "jwksURL": "https://dex.example.com/keys", "audiences": ["platform"]}]`,
		"no audiences":       `[{"issuer": "https://dex.example.com", "jwksURI": "https://dex.example.com/keys"}]`,
		"empty audience":     `[{"issuer": "https://dex.example.com", "jwksURI": "https://dex.example.com/keys", "audiences": [""]}]`,
		"malformed URI":      `[{"issuer": "https://dex.example.com", "jwksURI": "https://dex.example.com/keys", "audiences": [":platform"]}]`,
		"http jwksURI":       `[{"issuer": "https://dex.example.com", "jwksURI": "http://dex.example.com/keys", "audiences": ["platform"]}]`,
		"no jwksURI":         `[{"issuer": "https://dex.example.com", "audiences": ["platform"]}]`,
		"no issuer":          `[{"jwksURI": "https://dex.example.com/keys", "audiences": ["platform"]}]`,
		"http issuer":        `[{"issuer": "http://dex.example.com", "jwksURI": "https://dex.example.com/keys", "audiences": ["platform"]}]`,
		"issuer query":       `[{"issuer": "https://dex.example.com?x", "jwksURI": "https://dex.example.com/keys", "audiences": ["platform"]}]`,
		"other subjectClaim": entry(`, "subjectClaim": "name"`),
		"missing CA":         entry(`, "caFile": "/nonexistent/ca.pem"`),
		"listed twice":       `[` + entry("")[1:len(entry(""))-1] + `,` + entry("")[1:],
	} {
		t.Run(name, func(t *testing.T) {
			clearResourceEnv(t)
			t.Setenv("OAUTH_TRUSTED_ISSUERS", raw)
			_, err := oauthconfig.TrustedIssuersFromEnv()
			require.Error(t, err)
		})
	}
}

func TestDexFromEnvSettings(t *testing.T) {
	clearProviderEnv(t)
	clearResourceEnv(t)
	t.Setenv("OAUTH_DEX_ISSUER_URL", "https://dex.example.com")
	t.Setenv("OAUTH_DEX_CLIENT_ID", "mcp")
	t.Setenv("OAUTH_DEX_CLIENT_SECRET", "secret")
	t.Setenv("OAUTH_DEX_REDIRECT_URL", "https://mcp.example.com/oauth/callback")

	t.Run("scopes without openid refused", func(t *testing.T) {
		t.Setenv("OAUTH_DEX_SCOPES", "email,groups")
		_, err := oauthconfig.DexFromEnv()
		require.ErrorContains(t, err, "openid")
	})
	t.Run("invalid audience refused", func(t *testing.T) {
		t.Setenv("OAUTH_DEX_AUDIENCES", "kubernetes,not valid")
		_, err := oauthconfig.DexFromEnv()
		require.ErrorContains(t, err, "OAUTH_DEX_AUDIENCES")
	})
	t.Run("missing CA refused", func(t *testing.T) {
		t.Setenv("OAUTH_DEX_CA_FILE", "/nonexistent/ca.pem")
		_, err := oauthconfig.DexFromEnv()
		require.ErrorContains(t, err, "OAUTH_DEX_CA_FILE")
	})
}

func TestSettingsFromEnv(t *testing.T) {
	clearRequired(t)
	clearStorageEnv(t)
	clearProviderEnv(t)
	clearResourceEnv(t)
	caFile := writeCAFile(t)
	t.Setenv("OAUTH_ISSUER", "https://mcp.example.com")
	t.Setenv("OAUTH_ENCRYPTION_KEY", validKeyB64)
	t.Setenv("OAUTH_PROVIDER", "dex")
	t.Setenv("OAUTH_DEX_ISSUER_URL", "https://dex.example.com")
	t.Setenv("OAUTH_DEX_CLIENT_ID", "mcp")
	t.Setenv("OAUTH_DEX_CLIENT_SECRET", "secret")
	t.Setenv("OAUTH_DEX_SCOPES", "openid,email,groups")
	t.Setenv("OAUTH_DEX_AUDIENCES", "kubernetes")
	t.Setenv("OAUTH_DEX_CA_FILE", caFile)
	t.Setenv("OAUTH_RESOURCE", "https://mcp.example.com/mcp")
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://mcp.example.com,https://dex.example.com")
	t.Setenv("OAUTH_TRUSTED_ISSUERS", `[{"issuer": "https://dex.example.com", "jwksURI": "https://dex.example.com/keys", "audiences": ["mcp"]}]`)

	settings, err := oauthconfig.SettingsFromEnv()
	require.NoError(t, err)
	require.Equal(t, "https://mcp.example.com/mcp", settings.Server.ResourceIdentifier)
	require.NotNil(t, settings.Dex)
	require.Equal(t, []string{"openid", "email", "groups"}, settings.Dex.Scopes)
	require.Equal(t, []string{"kubernetes"}, settings.Dex.AudienceResolver())
	require.NotNil(t, settings.Dex.RootCAs)
	require.Equal(t, caFile, settings.RootCAFile)
	require.NotNil(t, settings.Encryptor)
	require.Nil(t, settings.Valkey)
	require.Len(t, settings.TrustedIssuers, 1)
}

func TestSettingsFromEnvRefusesUntrustedAuthorizationServer(t *testing.T) {
	clearRequired(t)
	clearStorageEnv(t)
	clearProviderEnv(t)
	clearResourceEnv(t)
	t.Setenv("OAUTH_ISSUER", "https://mcp.example.com")
	t.Setenv("OAUTH_PROVIDER", "github")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "gh")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "secret")
	t.Setenv("OAUTH_GITHUB_REDIRECT_URL", "https://mcp.example.com/oauth/callback")
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://dex.example.com")

	_, err := oauthconfig.SettingsFromEnv()
	require.ErrorContains(t, err, "neither OAUTH_ISSUER nor in OAUTH_TRUSTED_ISSUERS")
}

func TestSetupWithTrustedIssuersFromEnv(t *testing.T) {
	clearRequired(t)
	clearStorageEnv(t)
	clearProviderEnv(t)
	clearResourceEnv(t)
	t.Setenv("OAUTH_ISSUER", "https://mcp.example.com")
	t.Setenv("OAUTH_PROVIDER", "github")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "gh")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "secret")
	t.Setenv("OAUTH_GITHUB_REDIRECT_URL", "https://mcp.example.com/oauth/callback")
	t.Setenv("OAUTH_TRUSTED_ISSUERS", `[{"issuer": "https://dex.example.com", "jwksURI": "https://dex.example.com/keys", "audiences": ["mcp"]}]`)

	settings, err := oauthconfig.SettingsFromEnv()
	require.NoError(t, err)
	runtime, cleanup, err := oauthconfig.Setup(settings)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup(context.WithoutCancel(t.Context()))) })
	require.NotNil(t, runtime.Server)
}
