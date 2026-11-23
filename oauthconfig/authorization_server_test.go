package oauthconfig_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
	"github.com/giantswarm/mcp-oauth/providers/github"
)

const dexTrustedIssuers = `[{"issuer": "https://dex.example.com", "jwksURI": "https://dex.example.com/keys",
	"audiences": ["platform"], "acceptedTypHeaders": ["JWT"], "openIDProvider": true}]`

func authorizationServerOffEnv(t *testing.T) {
	t.Helper()
	clearRequired(t)
	clearStorageEnv(t)
	clearProviderEnv(t)
	clearResourceEnv(t)
	t.Setenv("OAUTH_ISSUER", "https://mcp.example.com")
	t.Setenv("OAUTH_RESOURCE", "https://mcp.example.com/mcp")
	t.Setenv("OAUTH_ENABLE_AUTHORIZATION_SERVER", "false")
	t.Setenv("OAUTH_TRUSTED_ISSUERS", dexTrustedIssuers)
}

func TestFromEnvRegistrationAndAuthorizationServerSwitches(t *testing.T) {
	resourceEnv(t)
	t.Setenv("OAUTH_ENABLE_AUTHORIZATION_SERVER", "false")
	t.Setenv("OAUTH_ENABLE_DYNAMIC_CLIENT_REGISTRATION", "false")

	cfg, err := oauthconfig.FromEnv()

	require.NoError(t, err)
	require.True(t, cfg.DisableAuthorizationServer)
	require.True(t, cfg.DisableDynamicClientRegistration)
}

func TestSettingsFromEnvAuthorizationServerOff(t *testing.T) {
	authorizationServerOffEnv(t)
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://dex.example.com")

	settings, err := oauthconfig.SettingsFromEnv()
	require.NoError(t, err)
	require.Nil(t, settings.Dex)
	require.Nil(t, settings.Google)
	require.Nil(t, settings.GitHub)

	runtime, cleanup, err := oauthconfig.Setup(settings)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup(context.WithoutCancel(t.Context()))) })
	require.True(t, runtime.Server.IsOpenIDProviderIssuer("https://dex.example.com"))
}

func TestSettingsFromEnvAuthorizationServerOffRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"provider set": {
			env:  map[string]string{"OAUTH_PROVIDER": "dex"},
			want: "OAUTH_PROVIDER is set but OAUTH_ENABLE_AUTHORIZATION_SERVER is false",
		},
		"own issuer advertised": {
			env:  map[string]string{"OAUTH_AUTHORIZATION_SERVERS": "https://mcp.example.com"},
			want: `"https://mcp.example.com" is not in OAUTH_TRUSTED_ISSUERS`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			authorizationServerOffEnv(t)
			for key, value := range tc.env {
				t.Setenv(key, value)
			}

			_, err := oauthconfig.SettingsFromEnv()

			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestSetupAuthorizationServerOffRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		want string
	}{
		"no trusted issuer": {
			env:  map[string]string{"OAUTH_TRUSTED_ISSUERS": ""},
			want: "DisableAuthorizationServer requires WithTrustedIssuers",
		},
		"client configuration endpoint": {
			env:  map[string]string{"OAUTH_ENABLE_CLIENT_CONFIGURATION_ENDPOINT": "true"},
			want: "EnableClientManagementEndpoint requires the authorization server",
		},
	} {
		t.Run(name, func(t *testing.T) {
			authorizationServerOffEnv(t)
			for key, value := range tc.env {
				t.Setenv(key, value)
			}
			settings, err := oauthconfig.SettingsFromEnv()
			require.NoError(t, err)

			_, _, err = oauthconfig.Setup(settings)

			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestSetupRefusesProviderWithAuthorizationServerOff(t *testing.T) {
	authorizationServerOffEnv(t)
	settings, err := oauthconfig.SettingsFromEnv()
	require.NoError(t, err)
	settings.GitHub = &github.Config{ClientID: "gh", ClientSecret: "secret", RedirectURL: "https://mcp.example.com/oauth/callback"}

	_, _, err = oauthconfig.Setup(settings)

	require.ErrorContains(t, err, "an OAuth provider configuration requires the authorization server")
}

func TestSetupRefusesClientConfigurationWithoutRegistration(t *testing.T) {
	authorizationServerOffEnv(t)
	t.Setenv("OAUTH_ENABLE_AUTHORIZATION_SERVER", "")
	t.Setenv("OAUTH_ENABLE_DYNAMIC_CLIENT_REGISTRATION", "false")
	t.Setenv("OAUTH_ENABLE_CLIENT_CONFIGURATION_ENDPOINT", "true")
	t.Setenv("OAUTH_PROVIDER", "github")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "gh")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "secret")
	t.Setenv("OAUTH_GITHUB_REDIRECT_URL", "https://mcp.example.com/oauth/callback")
	settings, err := oauthconfig.SettingsFromEnv()
	require.NoError(t, err)

	_, _, err = oauthconfig.Setup(settings)

	require.ErrorContains(t, err, "requires Dynamic Client Registration")
}

func TestSettingsFromEnvAuthorizationServerOffExtraResourceInherits(t *testing.T) {
	authorizationServerOffEnv(t)
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://dex.example.com")
	t.Setenv("OAUTH_ADDITIONAL_RESOURCES", `[{"resource": "https://mcp.example.com/other"}]`)

	settings, err := oauthconfig.SettingsFromEnv()

	require.NoError(t, err)
	require.Equal(t, []string{"https://dex.example.com"}, settings.Server.ResourceMetadataByPath["/other"].AuthorizationServers)
	require.Equal(t, []string{"https://dex.example.com"}, settings.Server.ResourceMetadataByPath["/mcp"].AuthorizationServers)
}
