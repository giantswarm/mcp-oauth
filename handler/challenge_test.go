package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

type challengeResponseWriter struct {
	*httptest.ResponseRecorder
	statusWrites int
	bodyWrites   int
}

func (writer *challengeResponseWriter) WriteHeader(status int) {
	writer.statusWrites++
	writer.ResponseRecorder.WriteHeader(status)
}

func (writer *challengeResponseWriter) Write(body []byte) (int, error) {
	writer.bodyWrites++
	return writer.ResponseRecorder.Write(body)
}

func TestSetUnauthorizedChallengeLeavesStatusAndBodyToTheCaller(t *testing.T) {
	const metadataChallenge = `Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/api", scope="jobs:read"`
	for _, test := range []struct {
		name        string
		code        string
		description string
		minimal     bool
		challenge   string
	}{
		{name: "discovery", challenge: metadataChallenge},
		{name: "rejected inbound token", code: "invalid_token", description: "Token expired", challenge: metadataChallenge + `, error="invalid_token", error_description="Token expired"`},
		{name: "metadata disabled", code: "invalid_token", description: "Token expired", minimal: true, challenge: `Bearer realm="oauth"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			t.Cleanup(store.Stop)
			handler.server.Config.DisableWWWAuthenticateMetadata = test.minimal
			handler.server.Config.ResourceMetadataByPath = map[string]server.ProtectedResourceConfig{
				"/api": {ResourceIdentifier: "https://api.example.com/api"},
			}
			handler.server.Config.EndpointMethodScopeRequirements = map[string]map[string][]string{
				"/api/*": {http.MethodGet: {"jobs:read"}},
			}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/jobs", nil)
			writer := &challengeResponseWriter{ResponseRecorder: httptest.NewRecorder()}
			writer.Header().Set("Content-Type", "application/problem+json")

			handler.setUnauthorizedChallenge(writer, request, test.code, test.description)

			require.Zero(t, writer.statusWrites)
			require.Zero(t, writer.bodyWrites)
			require.False(t, writer.Flushed)
			require.Empty(t, writer.Body.Bytes())
			require.Equal(t, test.challenge, writer.Header().Get("WWW-Authenticate"))
			require.Equal(t, "application/problem+json", writer.Header().Get("Content-Type"))
			require.Equal(t, "nosniff", writer.Header().Get("X-Content-Type-Options"))
			require.Contains(t, writer.Header().Get("Cache-Control"), "no-store")
			writer.WriteHeader(http.StatusUnauthorized)
			_, err := io.WriteString(writer, `{"status":401}`)
			require.NoError(t, err)
			response := writer.Result()
			t.Cleanup(func() { require.NoError(t, response.Body.Close()) })
			require.Equal(t, http.StatusUnauthorized, response.StatusCode)
			require.Equal(t, test.challenge, response.Header.Get("WWW-Authenticate"))
			require.Equal(t, `{"status":401}`, writer.Body.String())
		})
	}
}

func TestBearerChallengeOmitsInvalidOptionalParameters(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	const description = "Token expired"
	for _, invalid := range []string{"\x00", "\x01", "\t", "\r\n", "\x7f", "é", "\xff", `"`, `\`} {
		t.Run(fmt.Sprintf("%q", invalid), func(t *testing.T) {
			for _, parameter := range []string{"scope", "error", "error_description"} {
				t.Run(parameter, func(t *testing.T) {
					scope, code, errorDescription := "jobs:read", "invalid_token", description
					switch parameter {
					case "scope":
						scope = "jobs:" + invalid + "read"
					case "error":
						code = "invalid" + invalid + "token"
					case "error_description":
						errorDescription = "Token" + invalid + "expired"
					}
					challenge := handler.formatWWWAuthenticate(scope, code, errorDescription)
					require.NotContains(t, challenge, parameter+"=")
					require.Contains(t, challenge, testResourceMetadataURL)
					if parameter != "scope" {
						require.Contains(t, challenge, `scope="jobs:read"`)
					}
					if parameter != "error" {
						require.Contains(t, challenge, `error="invalid_token"`)
					}
					if parameter != "error_description" {
						require.Contains(t, challenge, `error_description="`+description+`"`)
					}
				})
			}
		})
	}
}

func TestBearerChallengePreservesAllowedASCII(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	var permitted strings.Builder
	for character := byte(0x21); character <= 0x7e; character++ {
		if character != '"' && character != '\\' {
			permitted.WriteByte(character)
		}
	}
	scope := permitted.String()
	description := " " + scope + " "
	challenge := handler.formatWWWAuthenticate(scope, "invalid_token", description)
	require.Contains(t, challenge, `scope="`+scope+`"`)
	require.Contains(t, challenge, `error_description="`+description+`"`)
}

func TestUnauthorizedErrorPreservesJSONDescription(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	const description = "jeton expiré"
	protected := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handler.writeUnauthorizedError(writer, request, "invalid_token", description)
	}))
	t.Cleanup(protected.Close)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, protected.URL, nil)
	require.NoError(t, err)
	response, err := protected.Client().Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, response.Body.Close()) })
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	require.Contains(t, response.Header.Get("WWW-Authenticate"), `error="invalid_token"`)
	require.NotContains(t, response.Header.Get("WWW-Authenticate"), "error_description=")
	var payload map[string]string
	require.NoError(t, json.NewDecoder(response.Body).Decode(&payload))
	require.Equal(t, description, payload["error_description"])
}
