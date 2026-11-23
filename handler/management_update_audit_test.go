package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

func TestManagementUpdateAuditsSigningAlgorithm(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keys, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "managed", Use: "sig"}}})
	require.NoError(t, err)
	registered, err := handler.server.RegisterClientWithKeys(t.Context(), "managed", server.ClientTypeConfidential,
		server.TokenEndpointAuthMethodPrivateKeyJWT, []string{"http://127.0.0.1/callback"}, nil, "192.0.2.1", 10, keys, "RS256")
	require.NoError(t, err)
	var output bytes.Buffer
	handler.server.Auditor = security.NewAuditor(slog.New(slog.NewJSONHandler(&output, nil)), true)
	metadata := map[string]any{
		"client_id": registered.Client.ClientID, "client_name": "managed",
		"redirect_uris": []string{"http://127.0.0.1/callback"}, "jwks": json.RawMessage(keys),
		"token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "PS256",
	}
	response := managementCredentialRequest(t, handler, http.MethodPut, registered.Client.ClientID, registered.RegistrationToken, metadata)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Header().Get("Cache-Control"), "no-store")
	events := auditEvents(t, &output)
	require.Len(t, events, 1)
	require.Equal(t, security.EventClientUpdated, events[0]["event_type"])
	require.Equal(t, registered.Client.ClientID, events[0]["client_id"])
	require.Equal(t, map[string]any{"changed": []any{"token_endpoint_auth_signing_alg", "registration_access_token"}}, events[0]["details"])
	var result struct {
		RegistrationToken string `json:"registration_access_token"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	require.NotEmpty(t, result.RegistrationToken)
	require.NotContains(t, output.String(), registered.RegistrationToken)
	require.NotContains(t, output.String(), result.RegistrationToken)
	current, err := store.GetClient(t.Context(), registered.Client.ClientID)
	require.NoError(t, err)
	require.Equal(t, "PS256", current.TokenEndpointAuthSigningAlg)
	require.NotContains(t, output.String(), current.RegistrationAccessTokenHash)
	require.NotContains(t, output.String(), string(keys))

	output.Reset()
	response = managementCredentialRequest(t, handler, http.MethodPut, registered.Client.ClientID, registered.RegistrationToken, metadata)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Empty(t, auditEvents(t, &output))

	metadata["token_endpoint_auth_signing_alg"] = "none"
	response = managementCredentialRequest(t, handler, http.MethodPut, registered.Client.ClientID, result.RegistrationToken, metadata)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Empty(t, auditEvents(t, &output))
}
