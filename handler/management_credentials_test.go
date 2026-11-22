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

func TestManagementResponseIncludesCurrentCredentials(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			handler := setupManagementHandler(t)
			clientID, registrationToken := registerAndExtractToken(t, handler)
			body, err := json.Marshal(map[string]any{"client_id": clientID, "client_name": "review-client", "redirect_uris": []string{"testapp://oauth/callback"}, "token_endpoint_auth_method": "client_secret_basic"})
			require.NoError(t, err)
			request := httptest.NewRequest(method, server.EndpointPathClientManagement+clientID, strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+registrationToken)
			request.RemoteAddr = testClientRemoteAddr
			response := httptest.NewRecorder()
			handler.ServeClientManagement(response, request)
			require.Equal(t, http.StatusOK, response.Code)
			var metadata map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &metadata))
			if _, exists := metadata["client_secret"]; !exists {
				t.Error("management response omits the current client_secret")
			}
			if _, exists := metadata["client_secret_expires_at"]; !exists {
				t.Error("management response omits client_secret_expires_at")
			}
		})
	}
}
