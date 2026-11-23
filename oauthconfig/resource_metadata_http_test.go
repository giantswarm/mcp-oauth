package oauthconfig_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
)

func resourceRuntime(t *testing.T, resource, additionalResources string) *oauthconfig.Runtime {
	t.Helper()
	clearProviderEnv(t)
	clearStorageEnv(t)
	resourceEnv(t)
	t.Setenv("OAUTH_RESOURCE", resource)
	t.Setenv("OAUTH_ADDITIONAL_RESOURCES", additionalResources)
	t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://dex.example.com")
	t.Setenv("OAUTH_TRUSTED_ISSUERS", `[{"issuer":"https://dex.example.com","jwksURI":"https://dex.example.com/keys","audiences":["https://mcp.example.com/mcp"]}]`)
	t.Setenv("OAUTH_PROVIDER", "google")
	t.Setenv("OAUTH_GOOGLE_CLIENT_ID", "client")
	t.Setenv("OAUTH_GOOGLE_CLIENT_SECRET", "test-secret")
	t.Setenv("OAUTH_GOOGLE_REDIRECT_URL", "https://mcp.example.com/oauth/callback")
	settings, err := oauthconfig.SettingsFromEnv()
	require.NoError(t, err)
	runtime, cleanup, err := oauthconfig.Setup(settings)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, cleanup(context.WithoutCancel(t.Context()))) })
	return runtime
}

func TestProtectedResourceMetadataMainAuthorizationServers(t *testing.T) {
	runtime := resourceRuntime(t, "https://mcp.example.com/mcp", "")
	mux := http.NewServeMux()
	runtime.Handler.RegisterProtectedResourceMetadataRoutes(mux, "")
	listener := httptest.NewServer(mux)
	t.Cleanup(listener.Close)
	for _, metadataPath := range []string{"", "/mcp"} {
		response, err := listener.Client().Get(listener.URL + "/.well-known/oauth-protected-resource" + metadataPath)
		require.NoError(t, err)
		var metadata struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
		require.NoError(t, response.Body.Close())
		require.Equal(t, "https://mcp.example.com/mcp", metadata.Resource)
		require.Equal(t, []string{"https://dex.example.com"}, metadata.AuthorizationServers)
	}
}

func TestProtectedResourceMetadataLiteralPaths(t *testing.T) {
	for _, resourcePath := range []string{"/mcp/", "/mcp%2Ffiles", "/mcp%2ffiles", "/m%63p", "/mcp/%7B", "/mcp/%7Bid%7D", "/mcp?tenant=one"} {
		for _, additional := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/additional=%t", resourcePath, additional), func(t *testing.T) {
				resource := "https://mcp.example.com" + resourcePath
				mainResource, additionalResources := resource, ""
				if additional {
					mainResource = "https://mcp.example.com/main"
					additionalResources = fmt.Sprintf(`[{"resource":%q}]`, resource)
				}
				runtime := resourceRuntime(t, mainResource, additionalResources)
				mux := http.NewServeMux()
				require.NotPanics(t, func() { runtime.Handler.RegisterProtectedResourceMetadataRoutes(mux, "") })
				listener := httptest.NewServer(mux)
				t.Cleanup(listener.Close)
				response, err := listener.Client().Get(listener.URL + "/.well-known/oauth-protected-resource" + resourcePath)
				require.NoError(t, err)
				var metadata struct {
					Resource string `json:"resource"`
				}
				require.Equal(t, http.StatusOK, response.StatusCode)
				require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
				require.NoError(t, response.Body.Close())
				require.Equal(t, resource, metadata.Resource)

				response, err = listener.Client().Get(listener.URL + "/.well-known/oauth-protected-resource/mcp/unexpected")
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				require.Equal(t, http.StatusNotFound, response.StatusCode)

				request := httptest.NewRequest(http.MethodPost, resource, nil)
				challenge := httptest.NewRecorder()
				runtime.Handler.ValidateToken(http.NotFoundHandler()).ServeHTTP(challenge, request)
				require.Equal(t, http.StatusUnauthorized, challenge.Code)
				require.Contains(t, challenge.Header().Get("WWW-Authenticate"), `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource`+resourcePath+`"`)
			})
		}
	}
}

func TestFromEnvRefusesResourceRouteAliases(t *testing.T) {
	for _, resources := range []string{
		`[{"resource":"https://mcp.example.com/api"},{"resource":"https://mcp.example.com/a%70i"}]`,
		`[{"resource":"https://mcp.example.com/mcp%2Ffiles"},{"resource":"https://mcp.example.com/mcp%2ffiles"}]`,
	} {
		t.Run(resources, func(t *testing.T) {
			resourceEnv(t)
			t.Setenv("OAUTH_RESOURCE", "https://mcp.example.com/main")
			t.Setenv("OAUTH_ADDITIONAL_RESOURCES", resources)
			_, err := oauthconfig.FromEnv()
			require.ErrorContains(t, err, "listed twice")
		})
	}
}

func TestProtectedResourceMetadataEncodedSlashIsDistinct(t *testing.T) {
	runtime := resourceRuntime(t, "https://mcp.example.com/mcp%2Ffiles", `[{"resource":"https://mcp.example.com/mcp/files"}]`)
	mux := http.NewServeMux()
	require.NotPanics(t, func() { runtime.Handler.RegisterProtectedResourceMetadataRoutes(mux, "") })
	listener := httptest.NewServer(mux)
	t.Cleanup(listener.Close)
	for _, resourcePath := range []string{"/mcp%2Ffiles", "/mcp/files"} {
		response, err := listener.Client().Get(listener.URL + "/.well-known/oauth-protected-resource" + resourcePath)
		require.NoError(t, err)
		var metadata struct {
			Resource string `json:"resource"`
		}
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
		require.NoError(t, response.Body.Close())
		require.Equal(t, "https://mcp.example.com"+resourcePath, metadata.Resource)
	}
}

func TestFromEnvRefusesInvalidResourcePaths(t *testing.T) {
	for _, resourcePath := range []string{"/a/../b", "/mcp%00", "/" + strings.Repeat("a", 3000)} {
		for _, variable := range []string{"OAUTH_ISSUER", "OAUTH_RESOURCE", "OAUTH_ADDITIONAL_RESOURCES"} {
			t.Run(resourcePath[:min(30, len(resourcePath))]+"/"+variable, func(t *testing.T) {
				resourceEnv(t)
				resource := "https://mcp.example.com" + resourcePath
				if variable == "OAUTH_ADDITIONAL_RESOURCES" {
					resource = fmt.Sprintf(`[{"resource":%q}]`, resource)
				}
				t.Setenv(variable, resource)
				_, err := oauthconfig.FromEnv()
				require.Error(t, err)
			})
		}
	}
}

func TestProtectedResourceMetadataSeparateRoot(t *testing.T) {
	runtime := resourceRuntime(t, "https://mcp.example.com/mcp", `[{"resource":"https://mcp.example.com","authorizationServers":["https://mcp.example.com"]}]`)
	mux := http.NewServeMux()
	runtime.Handler.RegisterProtectedResourceMetadataRoutes(mux, "")
	listener := httptest.NewServer(mux)
	t.Cleanup(listener.Close)
	for _, testCase := range []struct {
		path     string
		resource string
		issuer   string
	}{
		{"", "https://mcp.example.com", "https://mcp.example.com"},
		{"/mcp", "https://mcp.example.com/mcp", "https://dex.example.com"},
	} {
		response, err := listener.Client().Get(listener.URL + "/.well-known/oauth-protected-resource" + testCase.path)
		require.NoError(t, err)
		var metadata struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
		require.NoError(t, response.Body.Close())
		require.Equal(t, testCase.resource, metadata.Resource)
		require.Equal(t, []string{testCase.issuer}, metadata.AuthorizationServers)
	}
}

func TestFromEnvResourceOrigins(t *testing.T) {
	for _, testCase := range []struct {
		main      string
		extra     string
		wantError bool
	}{
		{"https://mcp.example.com/mcp", "https://MCP.EXAMPLE.COM:443/api", false},
		{"https://mcp.example.com:443/mcp", "https://mcp.example.com/api", false},
		{"http://localhost:80/mcp", "http://localhost/api", false},
		{"https://mcp.example.com/mcp", "https://mcp.example.com:8443/api", true},
		{"https://mcp.example.com/mcp", "https://other.example.com/api", true},
	} {
		t.Run(testCase.extra, func(t *testing.T) {
			resourceEnv(t)
			t.Setenv("OAUTH_RESOURCE", testCase.main)
			t.Setenv("OAUTH_ADDITIONAL_RESOURCES", fmt.Sprintf(`[{"resource":%q}]`, testCase.extra))
			configuration, err := oauthconfig.FromEnv()
			if testCase.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			extraURL, err := url.Parse(testCase.extra)
			require.NoError(t, err)
			require.Equal(t, testCase.extra, configuration.ResourceMetadataByPath[extraURL.Path].ResourceIdentifier)
		})
	}
}
