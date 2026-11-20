package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/giantswarm/mcp-oauth/server"
)

func TestClientSecretPostAuthentication(t *testing.T) {
	for _, test := range []struct {
		name      string
		secret    string
		basic     bool
		wantError bool
	}{
		{name: "valid", secret: "correct"},
		{name: "wrong secret", secret: "wrong", wantError: true},
		{name: "missing secret", wantError: true},
		{name: "multiple methods", secret: "correct", basic: true, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			t.Cleanup(store.Stop)
			client, secret, err := handler.server.RegisterClient(t.Context(), "post-client", "confidential", "client_secret_post", []string{"testapp://callback"}, []string{"mcp"}, "192.0.2.1", 10)
			require.NoError(t, err)
			if test.secret == "correct" {
				test.secret = secret
			}
			form := url.Values{"client_id": {client.ClientID}, "client_secret": {test.secret}}
			request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.basic {
				request.SetBasicAuth(client.ClientID, secret)
			}
			require.NoError(t, request.ParseForm())
			_, err = handler.authenticateClient(request, client.ClientID, "192.0.2.1")
			if test.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			authenticatedClient, err := handler.authenticateRefreshTokenClient(t.Context(), httptest.NewRecorder(), request, client.ClientID, "192.0.2.1", time.Now(), trace.SpanFromContext(t.Context()))
			if test.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.True(t, authenticatedClient.IsConfidential())
			}
		})
	}
}

func TestRegistrationScopeString(t *testing.T) {
	handler := setupManagementHandler(t)
	request := httptest.NewRequest(http.MethodPost, server.EndpointPathRegister, strings.NewReader(`{"client_name":"scope-client","redirect_uris":["testapp://callback"],"token_endpoint_auth_method":"client_secret_post","scope":"mcp"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testRegistrationToken)
	request.RemoteAddr = testClientRemoteAddr
	response := httptest.NewRecorder()
	handler.ServeClientRegistration(response, request)
	require.Equal(t, http.StatusCreated, response.Code)
	var metadata map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
	require.Equal(t, "mcp", metadata["scope"])
	client, err := handler.server.GetClient(t.Context(), metadata["client_id"].(string))
	require.NoError(t, err)
	require.Equal(t, []string{"mcp"}, client.Scopes)
}
