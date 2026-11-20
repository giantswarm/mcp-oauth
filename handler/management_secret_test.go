package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

func managementCredentialRequest(t *testing.T, handler *Handler, method, clientID, registrationToken string, metadata map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(metadata)
	require.NoError(t, err)
	request := httptest.NewRequest(method, server.EndpointPathClientManagement+clientID, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+registrationToken)
	request.RemoteAddr = testClientRemoteAddr
	response := httptest.NewRecorder()
	handler.ServeClientManagement(response, request)
	return response
}

func currentCredentialResponse(t *testing.T, response *httptest.ResponseRecorder, expectedSecret string) string {
	t.Helper()
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Header().Get("Cache-Control"), "no-store")
	require.Equal(t, "no-cache", response.Header().Get("Pragma"))
	var body struct {
		ClientSecret      string `json:"client_secret"`
		SecretExpiry      *int64 `json:"client_secret_expires_at"`
		RegistrationToken string `json:"registration_access_token"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.True(t, expectedSecret == body.ClientSecret, "response must contain the unchanged current secret")
	require.NotNil(t, body.SecretExpiry)
	require.Zero(t, *body.SecretExpiry)
	require.True(t, body.RegistrationToken != "")
	return body.RegistrationToken
}

func TestManagementSecretRecoveryAndRotation(t *testing.T) {
	for _, method := range []string{server.TokenEndpointAuthMethodBasic, server.TokenEndpointAuthMethodPost} {
		t.Run(method, func(t *testing.T) {
			handler := setupManagementHandler(t)
			registered, err := handler.server.RegisterClientV2(t.Context(), "managed", "confidential", method, []string{"testapp://oauth/callback"}, nil, "192.0.2.1", 100)
			require.NoError(t, err)
			clientID, registrationToken := registered.Client.ClientID, registered.RegistrationToken
			require.True(t, registered.Client.ClientSecretEncrypted != "")
			require.False(t, bytes.Contains([]byte(registered.Client.ClientSecretEncrypted), []byte(registered.ClientSecret)))
			response := managementCredentialRequest(t, handler, http.MethodGet, clientID, registrationToken, nil)
			returnedToken := currentCredentialResponse(t, response, registered.ClientSecret)
			require.True(t, registrationToken == returnedToken, "GET must preserve the registration token")
			metadata := map[string]any{"client_id": clientID, "client_name": "updated", "redirect_uris": []string{"testapp://oauth/callback"}, "token_endpoint_auth_method": method}
			response = managementCredentialRequest(t, handler, http.MethodPut, clientID, registrationToken, metadata)
			newToken := currentCredentialResponse(t, response, registered.ClientSecret)
			require.True(t, registrationToken != newToken)
			stored, err := handler.server.GetRegisteredClient(t.Context(), clientID)
			require.NoError(t, err)
			require.True(t, stored.ClientSecretHash == registered.Client.ClientSecretHash)
			_, err = handler.server.DecryptClientSecret(stored, registrationToken)
			require.Error(t, err)
			require.NoError(t, handler.server.ValidateClientCredentials(t.Context(), clientID, registered.ClientSecret))
			currentCredentialResponse(t, managementCredentialRequest(t, handler, http.MethodGet, clientID, newToken, nil), registered.ClientSecret)
			require.Equal(t, http.StatusUnauthorized, managementCredentialRequest(t, handler, http.MethodGet, clientID, registrationToken, nil).Code)
		})
	}
}

func TestManagementHashOnlyCredentialBackfill(t *testing.T) {
	handler := setupManagementHandler(t)
	registered, err := handler.server.RegisterClientV2(t.Context(), "legacy", "confidential", "client_secret_basic", []string{"testapp://oauth/callback"}, nil, "192.0.2.1", 100)
	require.NoError(t, err)
	legacy := *registered.Client
	legacy.ClientSecretEncrypted = ""
	require.NoError(t, handler.server.SaveClient(t.Context(), &legacy))
	response := managementCredentialRequest(t, handler, http.MethodGet, legacy.ClientID, registered.RegistrationToken, nil)
	require.Equal(t, http.StatusInternalServerError, response.Code)
	require.False(t, bytes.Contains(response.Body.Bytes(), []byte(registered.ClientSecret)))
	metadata := map[string]any{"client_id": legacy.ClientID, "redirect_uris": []string{"testapp://oauth/callback"}}
	response = managementCredentialRequest(t, handler, http.MethodPut, legacy.ClientID, registered.RegistrationToken, metadata)
	require.Equal(t, http.StatusBadRequest, response.Code)
	stored, err := handler.server.GetRegisteredClient(t.Context(), legacy.ClientID)
	require.NoError(t, err)
	require.True(t, stored.RegistrationAccessTokenHash == legacy.RegistrationAccessTokenHash)
	require.NoError(t, handler.server.ValidateClientCredentials(t.Context(), legacy.ClientID, registered.ClientSecret))
	metadata["client_secret"] = registered.ClientSecret
	response = managementCredentialRequest(t, handler, http.MethodPut, legacy.ClientID, registered.RegistrationToken, metadata)
	newToken := currentCredentialResponse(t, response, registered.ClientSecret)
	currentCredentialResponse(t, managementCredentialRequest(t, handler, http.MethodGet, legacy.ClientID, newToken, nil), registered.ClientSecret)
}

func TestManagementCredentialBindingAndPublicTransition(t *testing.T) {
	handler := setupManagementHandler(t)
	registered, err := handler.server.RegisterClientV2(t.Context(), "managed", "confidential", "client_secret_basic", []string{"testapp://oauth/callback"}, nil, "192.0.2.1", 100)
	require.NoError(t, err)
	for _, mutation := range []string{"client", "issuer", "ciphertext", "hash"} {
		t.Run(mutation, func(t *testing.T) {
			client := *registered.Client
			issuer := handler.server.Config.Issuer
			switch mutation {
			case "client":
				client.ClientID = "different-client"
			case "issuer":
				handler.server.Config.Issuer = "https://different.example.com"
			case "ciphertext":
				client.ClientSecretEncrypted = "invalid"
			case "hash":
				client.ClientSecretHash = "invalid"
			}
			_, err := handler.server.DecryptClientSecret(&client, registered.RegistrationToken)
			handler.server.Config.Issuer = issuer
			require.Error(t, err)
		})
	}
	metadata := map[string]any{"client_id": registered.Client.ClientID, "redirect_uris": []string{"testapp://oauth/callback"}, "token_endpoint_auth_method": "none"}
	response := managementCredentialRequest(t, handler, http.MethodPut, registered.Client.ClientID, registered.RegistrationToken, metadata)
	require.Equal(t, http.StatusOK, response.Code)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.NotContains(t, body, "client_secret")
	require.NotContains(t, body, "client_secret_expires_at")
	stored, err := handler.server.GetRegisteredClient(t.Context(), registered.Client.ClientID)
	require.NoError(t, err)
	require.Empty(t, stored.ClientSecretHash)
	require.Empty(t, stored.ClientSecretEncrypted)
}

func TestRegistrationRejectsConflictingClientType(t *testing.T) {
	for _, clientType := range []string{"unexpected", "public"} {
		for _, method := range []string{"client_secret_basic", "client_secret_post"} {
			t.Run(clientType+"/"+method, func(t *testing.T) {
				handler := setupManagementHandler(t)
				metadata := map[string]any{"client_type": clientType, "token_endpoint_auth_method": method, "redirect_uris": []string{"testapp://oauth/callback"}}
				body, err := json.Marshal(metadata)
				require.NoError(t, err)
				request := httptest.NewRequest(http.MethodPost, server.EndpointPathRegister, bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Authorization", "Bearer "+testRegistrationToken)
				request.RemoteAddr = testClientRemoteAddr
				response := httptest.NewRecorder()
				handler.ServeClientRegistration(response, request)
				require.Equal(t, http.StatusBadRequest, response.Code)
				require.Equal(t, "invalid_client_metadata", decodeErrorResponse(t, response).Error)
			})
		}
	}
}
