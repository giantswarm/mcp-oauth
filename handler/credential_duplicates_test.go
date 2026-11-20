package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

func TestClientAuthenticationRejectsDuplicateAuthorizationHeaders(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	client := newMatrixClient(t, handler, "client_secret_basic")
	for _, endpoint := range []string{server.EndpointPathToken, server.EndpointPathRevoke, server.EndpointPathIntrospect} {
		t.Run(endpoint, func(t *testing.T) {
			response := matrixClientRequest(t, handler, endpoint, client, "client_secret_basic", url.Values{
				"grant_type": {"authorization_code"}, "code": {"unissued"}, "token": {"unissued"},
			}, func(request *http.Request) { request.Header.Add("Authorization", request.Header.Get("Authorization")) })
			require.Equal(t, http.StatusBadRequest, response.Code)
			require.Equal(t, "invalid_request", decodeErrorResponse(t, response).Error)
		})
	}
}

func TestManagementRejectsDuplicateAuthorizationHeaders(t *testing.T) {
	handler := setupManagementHandler(t)
	clientID, registrationToken := registerAndExtractToken(t, handler)
	request := httptest.NewRequest(http.MethodGet, server.EndpointPathClientManagement+clientID, nil)
	request.Header.Set("Authorization", "Bearer "+registrationToken)
	request.RemoteAddr = testClientRemoteAddr
	request.Header.Add("Authorization", request.Header.Get("Authorization"))
	response := httptest.NewRecorder()
	handler.ServeClientManagement(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Equal(t, "invalid_request", decodeErrorResponse(t, response).Error)
}

func TestRevocationMalformedBasicAuthenticationIncludesChallenge(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	for _, authorization := range []string{"Basic !!!", "Basic"} {
		t.Run(authorization, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, server.EndpointPathRevoke, strings.NewReader("token=unknown"))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Authorization", authorization)
			response := httptest.NewRecorder()
			handler.ServeTokenRevocation(response, request)
			require.Equal(t, http.StatusUnauthorized, response.Code)
			require.Equal(t, "invalid_client", decodeErrorResponse(t, response).Error)
			require.Equal(t, `Basic realm="oauth"`, response.Header().Get("WWW-Authenticate"))
		})
	}
}
