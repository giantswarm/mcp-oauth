package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

func TestMissingCredentialChallengeNamesConfiguredResource(t *testing.T) {
	for _, basePath := range []string{"", "/tenant"} {
		t.Run(basePath, func(t *testing.T) {
			issuer := "https://auth.example.test" + basePath
			handler, _, _ := newRegisterRoutesHandler(t, &server.Config{
				Issuer: issuer,
				ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
					"/mcp": {ScopesSupported: []string{"tools:read"}},
					"/api": {ScopesSupported: []string{"api:read"}},
				},
			})
			mux := http.NewServeMux()
			handler.RegisterOAuthRoutes(mux, OAuthRoutesOptions{IncludeMetadata: true})
			mux.Handle(basePath+"/mcp", handler.ValidateToken(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unauthenticated handler reached") })))
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, basePath+"/mcp", nil))
			require.Equal(t, http.StatusUnauthorized, response.Code)
			challenge := response.Header().Get("WWW-Authenticate")
			metadataURL := "https://auth.example.test/.well-known/oauth-protected-resource" + basePath + "/mcp"
			require.Contains(t, challenge, `resource_metadata="`+metadataURL+`"`)
			require.NotContains(t, challenge, "error=")
			require.NotContains(t, challenge, "error_description=")
			metadataResponse := httptest.NewRecorder()
			mux.ServeHTTP(metadataResponse, httptest.NewRequest(http.MethodGet, metadataURL, nil))
			require.Equal(t, http.StatusOK, metadataResponse.Code)
			var metadata map[string]any
			require.NoError(t, json.Unmarshal(metadataResponse.Body.Bytes(), &metadata))
			require.Equal(t, issuer+"/mcp", metadata["resource"])
		})
	}
}

func TestInvalidCredentialChallengeRetainsOAuthError(t *testing.T) {
	handler, _, _ := newRegisterRoutesHandler(t, &server.Config{Issuer: testIssuer})
	for _, authorization := range []string{"Bearer ", "Basic abc", "Bearer unknown-token"} {
		t.Run(strings.ReplaceAll(authorization, " ", "_"), func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
			request.Header.Set("Authorization", authorization)
			response := httptest.NewRecorder()
			handler.ValidateToken(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid credential accepted") })).ServeHTTP(response, request)
			require.Equal(t, http.StatusUnauthorized, response.Code)
			require.Contains(t, response.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
		})
	}
}
