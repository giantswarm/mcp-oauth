package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

func TestPrivateKeyManagementTransitionClearsSecretCredentials(t *testing.T) {
	handler := setupManagementHandler(t)
	secretClient := newMatrixClient(t, handler, "client_secret_basic")
	keyClient := newMatrixClient(t, handler, "private_key_jwt")
	var keys jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(keyClient.client.JWKS, &keys))
	metadata := map[string]any{
		"client_id": secretClient.client.ClientID, "client_secret": secretClient.secret,
		"redirect_uris": []string{"https://example.com/callback"}, "token_endpoint_auth_method": "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256", "jwks": keys,
	}
	response := managementCredentialRequest(t, handler, http.MethodPut, secretClient.client.ClientID, secretClient.registrationToken, metadata)
	require.Equal(t, http.StatusOK, response.Code)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.NotContains(t, body, "client_secret")
	require.NotContains(t, body, "client_secret_expires_at")
	var registrationToken string
	require.NoError(t, json.Unmarshal(body["registration_access_token"], &registrationToken))
	stored, err := handler.server.GetRegisteredClient(t.Context(), secretClient.client.ClientID)
	require.NoError(t, err)
	require.Empty(t, stored.ClientSecretHash)
	require.Empty(t, stored.ClientSecretEncrypted)
	response = managementCredentialRequest(t, handler, http.MethodGet, stored.ClientID, registrationToken, nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.NotContains(t, body, "client_secret")
	require.NotContains(t, body, "client_secret_expires_at")
}

func TestPrivateKeyAuthenticationRejectsDuplicateAssertions(t *testing.T) {
	for _, endpoint := range []string{server.EndpointPathToken, server.EndpointPathRevoke, server.EndpointPathIntrospect} {
		for _, parameter := range []string{"client_assertion", "client_assertion_type"} {
			t.Run(endpoint+"/"+parameter, func(t *testing.T) {
				handler, store := setupTestHandler(t)
				t.Cleanup(store.Stop)
				client := newMatrixClient(t, handler, "private_key_jwt")
				response := matrixClientRequest(t, handler, endpoint, client, "private_key_jwt", url.Values{
					"grant_type": {"authorization_code"}, "code": {"unissued"}, "token": {"unissued"},
				}, func(request *http.Request) {
					require.NoError(t, request.ParseForm())
					request.PostForm.Add(parameter, request.PostForm.Get(parameter))
					request.Form.Add(parameter, request.Form.Get(parameter))
				})
				require.Equal(t, http.StatusBadRequest, response.Code)
				require.Equal(t, "invalid_request", decodeErrorResponse(t, response).Error)
			})
		}
	}
}
