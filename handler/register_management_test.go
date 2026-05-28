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

const testRegistrationToken = "test-registration-token-12345"

// registerAndExtractToken performs a DCR POST and returns the client_id and
// registration_access_token from the response. Fails the test on any error.
func registerAndExtractToken(t *testing.T, h *Handler) (clientID, registrationToken string) {
	t.Helper()

	body := `{"client_name":"test-client","redirect_uris":["testapp://oauth/callback"]}`
	req := httptest.NewRequest(http.MethodPost, server.EndpointPathRegister, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testRegistrationToken)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientRegistration(w, req)

	require.Equal(t, http.StatusCreated, w.Code, "DCR should succeed")

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))

	id, ok := resp["client_id"].(string)
	require.True(t, ok, "response should contain client_id")

	token, ok := resp["registration_access_token"].(string)
	require.True(t, ok, "response should contain registration_access_token")
	require.NotEmpty(t, token)

	uri, ok := resp["registration_client_uri"].(string)
	require.True(t, ok, "response should contain registration_client_uri")
	require.Contains(t, uri, id)

	return id, token
}

func setupManagementHandler(t *testing.T) *Handler {
	t.Helper()
	h, _ := setupTestHandler(t)
	h.config.EnableClientManagementEndpoint = true
	h.config.RegistrationAccessToken = testRegistrationToken
	// Allow custom-scheme redirect URIs so tests don't require DNS resolution.
	h.config.TrustedPublicRegistrationSchemes = []string{"testapp"}
	h.config.SetTrustedSchemesMap([]string{"testapp"})
	return h
}

func TestServeClientManagement_GET(t *testing.T) {
	h := setupManagementHandler(t)
	clientID, token := registerAndExtractToken(t, h)

	req := httptest.NewRequest(http.MethodGet, server.EndpointPathClientManagement+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientManagement(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.Equal(t, clientID, resp["client_id"])
	require.Contains(t, resp, "registration_client_uri")
}

func TestServeClientManagement_GET_WrongToken(t *testing.T) {
	h := setupManagementHandler(t)
	clientID, _ := registerAndExtractToken(t, h)

	req := httptest.NewRequest(http.MethodGet, server.EndpointPathClientManagement+clientID, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientManagement(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestServeClientManagement_GET_UnknownClient(t *testing.T) {
	h := setupManagementHandler(t)

	req := httptest.NewRequest(http.MethodGet, server.EndpointPathClientManagement+"no-such-client", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientManagement(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestServeClientManagement_GET_MissingBearer(t *testing.T) {
	h := setupManagementHandler(t)
	clientID, _ := registerAndExtractToken(t, h)

	req := httptest.NewRequest(http.MethodGet, server.EndpointPathClientManagement+clientID, nil)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientManagement(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.Contains(t, w.Header().Get("WWW-Authenticate"), "Bearer")
}

func TestServeClientManagement_PUT(t *testing.T) {
	h := setupManagementHandler(t)
	clientID, token := registerAndExtractToken(t, h)

	body := `{"client_name":"updated-name"}`
	req := httptest.NewRequest(http.MethodPut, server.EndpointPathClientManagement+clientID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientManagement(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.Equal(t, "updated-name", resp["client_name"])

	// New token must be present and differ from the original.
	newToken, ok := resp["registration_access_token"].(string)
	require.True(t, ok, "PUT response must include new registration_access_token")
	require.NotEqual(t, token, newToken, "token must be rotated on PUT")
}

func TestServeClientManagement_PUT_OldTokenInvalidAfterRotation(t *testing.T) {
	h := setupManagementHandler(t)
	clientID, token := registerAndExtractToken(t, h)

	// Rotate via PUT.
	body := `{"client_name":"rotated"}`
	putReq := httptest.NewRequest(http.MethodPut, server.EndpointPathClientManagement+clientID, strings.NewReader(body))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putReq.RemoteAddr = testClientRemoteAddr
	h.ServeClientManagement(httptest.NewRecorder(), putReq)

	// Old token must now be rejected.
	getReq := httptest.NewRequest(http.MethodGet, server.EndpointPathClientManagement+clientID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getReq.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientManagement(w, getReq)

	require.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestServeClientManagement_DELETE(t *testing.T) {
	h := setupManagementHandler(t)
	clientID, token := registerAndExtractToken(t, h)

	req := httptest.NewRequest(http.MethodDelete, server.EndpointPathClientManagement+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientManagement(w, req)

	require.Equal(t, http.StatusNoContent, w.Code)

	// Subsequent GET must 404.
	getReq := httptest.NewRequest(http.MethodGet, server.EndpointPathClientManagement+clientID, nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getReq.RemoteAddr = testClientRemoteAddr
	w2 := httptest.NewRecorder()
	h.ServeClientManagement(w2, getReq)
	require.Equal(t, http.StatusNotFound, w2.Code)
}

func TestServeClientManagement_MethodNotAllowed(t *testing.T) {
	h := setupManagementHandler(t)
	clientID, token := registerAndExtractToken(t, h)

	req := httptest.NewRequest(http.MethodPatch, server.EndpointPathClientManagement+clientID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientManagement(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestServeClientManagement_DisabledByDefault(t *testing.T) {
	// With EnableClientManagementEndpoint = false, the DCR response must NOT
	// include registration_access_token or registration_client_uri.
	h, _ := setupTestHandler(t)
	h.config.RegistrationAccessToken = testRegistrationToken
	// EnableClientManagementEndpoint defaults to false.

	body := `{"client_name":"no-mgmt","redirect_uris":["testapp://oauth/callback"]}`
	req := httptest.NewRequest(http.MethodPost, server.EndpointPathRegister, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testRegistrationToken)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	h.ServeClientRegistration(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotContains(t, resp, "registration_access_token")
	require.NotContains(t, resp, "registration_client_uri")
}
