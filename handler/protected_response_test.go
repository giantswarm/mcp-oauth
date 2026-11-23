package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

func TestProtectedResponsesKeepTheirBodyAndGainMissingChallenges(t *testing.T) {
	environment := newOutageEnv(t)
	pair := environment.login(t)
	environment.handler.server.Config.ResourceMetadataByPath = map[string]server.ProtectedResourceConfig{"/api": {ResourceIdentifier: "https://api.example.com/api"}}
	const body = `{"type":"about:blank","status":401,"error":{"code":"auth_required","message":"authorization required"}}`
	for _, test := range []struct {
		name      string
		status    int
		challenge string
		minimal   bool
	}{
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "existing challenge", status: http.StatusUnauthorized, challenge: `Bearer realm="application"`},
		{name: "minimal metadata", status: http.StatusUnauthorized, minimal: true},
		{name: "forbidden", status: http.StatusForbidden},
		{name: "success", status: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment.handler.server.Config.DisableWWWAuthenticateMetadata = test.minimal
			protected := httptest.NewServer(environment.handler.ValidateToken(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/problem+json")
				if test.challenge != "" {
					writer.Header().Set("WWW-Authenticate", test.challenge)
				}
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, body)
			})))
			defer protected.Close()
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, protected.URL+"/api/models", nil)
			require.NoError(t, err)
			request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
			response, err := protected.Client().Do(request)
			require.NoError(t, err)
			defer func() { require.NoError(t, response.Body.Close()) }()
			encoded, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Equal(t, test.status, response.StatusCode)
			require.Equal(t, "application/problem+json", response.Header.Get("Content-Type"))
			require.Equal(t, body, string(encoded))
			challenge := response.Header.Get("WWW-Authenticate")
			switch {
			case test.challenge != "":
				require.Equal(t, test.challenge, challenge)
			case test.status != http.StatusUnauthorized:
				require.Empty(t, challenge)
			case test.minimal:
				require.Equal(t, `Bearer realm="oauth"`, challenge)
			default:
				require.Contains(t, challenge, `resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/api"`)
				require.NotContains(t, challenge, "invalid_token")
				require.NotContains(t, challenge, "error=")
			}
		})
	}
}

type statusOnlyWriter struct{ http.ResponseWriter }

func TestProtectedResponseWriterRetainsStreamingCapabilities(t *testing.T) {
	environment := newOutageEnv(t)
	pair := environment.login(t)
	for _, supportsFlush := range []bool{false, true} {
		response := httptest.NewRecorder()
		var writer http.ResponseWriter = response
		if !supportsFlush {
			writer = statusOnlyWriter{ResponseWriter: response}
		}
		request := httptest.NewRequest(http.MethodGet, "/api/models", nil)
		request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		environment.handler.ValidateToken(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, flush := writer.(http.Flusher)
			require.Equal(t, supportsFlush, flush)
			if supportsFlush {
				require.NoError(t, http.NewResponseController(writer).Flush())
			}
			require.NoError(t, json.NewEncoder(writer).Encode(map[string]bool{"streaming": flush}))
		})).ServeHTTP(writer, request)
		require.Equal(t, http.StatusOK, response.Code)
		require.Empty(t, response.Header().Get("WWW-Authenticate"))
	}
}
