package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

func TestResourceScopeDiscoveryHTTP(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		scopes   []string
		expected []string
	}{
		{name: "mixed", scopes: []string{"files:read", "offline_access", "files:write", "offline_access"}, expected: []string{"files:read", "files:write"}},
		{name: "refresh only", scopes: []string{"offline_access"}},
		{name: "empty"},
		{name: "distinct scope", scopes: []string{"custom:offline_access"}, expected: []string{"custom:offline_access"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			t.Cleanup(store.Stop)
			configuration := handler.server.Config
			configuration.SupportedScopes = slices.Clone(testCase.scopes)
			configuration.DefaultChallengeScopes = slices.Clone(testCase.scopes)
			configuration.EndpointScopeRequirements = map[string][]string{"/mcp": slices.Clone(testCase.scopes)}
			configuration.ResourceMetadataByPath = map[string]server.ProtectedResourceConfig{
				"/mcp": {ScopesSupported: slices.Clone(testCase.scopes)},
			}
			mux := http.NewServeMux()
			handler.RegisterAuthorizationServerMetadataRoutes(mux)
			handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")
			mux.HandleFunc("/mcp", func(writer http.ResponseWriter, request *http.Request) {
				handler.writeUnauthorizedError(writer, request, "invalid_token", "Authorization required")
			})
			mux.HandleFunc("/unauthorized", func(writer http.ResponseWriter, _ *http.Request) {
				handler.writeError(writer, "invalid_token", "Authorization required", http.StatusUnauthorized)
			})
			mux.HandleFunc("/forbidden", func(writer http.ResponseWriter, _ *http.Request) {
				handler.writeInsufficientScopeError(writer, configuration.SupportedScopes, "Insufficient scope")
			})
			transport := httptest.NewTLSServer(mux)
			t.Cleanup(transport.Close)

			for _, endpoint := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
				response := getScopeResponse(t, transport, endpoint)
				require.Equal(t, http.StatusOK, response.StatusCode)
				var metadata map[string]any
				require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
				require.NoError(t, response.Body.Close())
				if len(testCase.expected) == 0 {
					require.NotContains(t, metadata, "scopes_supported", endpoint)
				} else {
					expected := make([]any, len(testCase.expected))
					for index, scope := range testCase.expected {
						expected[index] = scope
					}
					require.Equal(t, expected, metadata["scopes_supported"], endpoint)
				}
			}

			for _, endpoint := range []string{"/mcp", "/unauthorized", "/forbidden"} {
				response := getScopeResponse(t, transport, endpoint)
				require.NoError(t, response.Body.Close())
				expectedStatus := http.StatusUnauthorized
				if endpoint == "/forbidden" {
					expectedStatus = http.StatusForbidden
				}
				require.Equal(t, expectedStatus, response.StatusCode)
				challenge := response.Header.Get("WWW-Authenticate")
				require.Contains(t, challenge, "resource_metadata=")
				require.NotContains(t, challenge, `"offline_access"`)
				if len(testCase.expected) == 0 {
					require.NotContains(t, challenge, "scope=")
				} else {
					require.Contains(t, challenge, `scope="`+strings.Join(testCase.expected, " ")+`"`)
				}
			}

			response := getScopeResponse(t, transport, "/.well-known/oauth-authorization-server")
			var authorizationMetadata struct {
				Scopes []string `json:"scopes_supported"`
			}
			require.NoError(t, json.NewDecoder(response.Body).Decode(&authorizationMetadata))
			require.NoError(t, response.Body.Close())
			require.Equal(t, testCase.scopes, authorizationMetadata.Scopes)
			require.Equal(t, testCase.scopes, configuration.SupportedScopes)
			require.Equal(t, testCase.scopes, configuration.DefaultChallengeScopes)
			require.Equal(t, testCase.scopes, configuration.EndpointScopeRequirements["/mcp"])
			require.Equal(t, testCase.scopes, configuration.ResourceMetadataByPath["/mcp"].ScopesSupported)
		})
	}
}

func getScopeResponse(t *testing.T, transport *httptest.Server, endpoint string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, transport.URL+endpoint, nil)
	require.NoError(t, err)
	response, err := transport.Client().Do(request)
	require.NoError(t, err)
	return response
}
