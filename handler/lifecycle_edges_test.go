package handler

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

func TestCIMDOwnerRevocationWithoutMetadataFetch(t *testing.T) {
	var clientID string
	var fetches atomic.Int32
	metadataServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(map[string]any{
			"client_id": clientID, "client_name": "metadata client",
			"redirect_uris": []string{"http://127.0.0.1:7777/callback"}, "token_endpoint_auth_method": "none",
		}); err != nil {
			http.Error(response, "metadata encoding failed", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(metadataServer.Close)
	clientID = metadataServer.URL + "/client.json"
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	handler.server.Config.EnableClientIDMetadataDocuments = true
	handler.server.Config.AllowPrivateIPClientMetadata = true //nolint:staticcheck // The loopback TLS fixture must be fetchable.
	handler.server.Config.ClientMetadataRootCAs = x509.NewCertPool()
	handler.server.Config.ClientMetadataRootCAs.AddCert(metadataServer.Certificate())
	client, err := handler.server.GetClient(t.Context(), clientID)
	require.NoError(t, err)
	require.EqualValues(t, 1, fetches.Load())
	metadataServer.Close()
	coldServer, err := server.New(mock.NewProvider(), store, store, store, &server.Config{
		Issuer: testIssuer, EnableClientIDMetadataDocuments: true,
	}, nil)
	require.NoError(t, err)
	for index, revoker := range []*Handler{handler, New(coldServer, nil)} {
		refreshToken := []string{"warm-refresh", "cold-refresh"}[index]
		require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), refreshToken, "person", clientID, refreshToken+"-family", 1, time.Now().Add(time.Hour)))
		response := matrixClientRequest(t, revoker, server.EndpointPathRevoke, matrixClient{client: client}, "none", url.Values{"token": {refreshToken}})
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		_, err := store.GetRefreshTokenInfo(t.Context(), refreshToken)
		require.Error(t, err)
		for _, token := range []string{refreshToken, "unknown-token", "other-client-token"} {
			require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "other-client-token", "other-person", "other-client", "other-family", 1, time.Now().Add(time.Hour)))
			response := matrixClientRequest(t, revoker, server.EndpointPathRevoke, matrixClient{client: client}, "none", url.Values{"token": {token}})
			require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			require.Empty(t, response.Body.String())
			_, err := store.GetRefreshTokenInfo(t.Context(), "other-client-token")
			require.NoError(t, err)
		}
	}
	require.EqualValues(t, 1, fetches.Load())
}

func TestPublicRefreshRejectsDuplicateClientIDWithoutConsumingGrant(t *testing.T) {
	environment := newRefreshTestEnv(t)
	clientID, _ := environment.registerClient(t, "public")
	refreshToken := environment.seedRefreshToken(t, clientID, "person", "duplicate-family", time.Now().Add(time.Hour))
	values := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientID, "different-client"},
	}
	request := httptest.NewRequest(http.MethodPost, server.EndpointPathToken, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	environment.handler.ServeToken(response, request)
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	require.Equal(t, "invalid_request", decodeErrorResponse(t, response).Error)
	_, err := environment.store.GetRefreshTokenInfo(t.Context(), refreshToken)
	require.NoError(t, err)
	require.True(t, auditAuthFailureWithReason(t, environment.auditBuf, "client_credentials_malformed"))
}

func TestAuthenticationMethodMismatchAudited(t *testing.T) {
	for _, registered := range []string{"client_secret_basic", "client_secret_post"} {
		t.Run(registered, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			t.Cleanup(store.Stop)
			client := newMatrixClient(t, handler, registered)
			presented := "client_secret_basic"
			if registered == presented {
				presented = "client_secret_post"
			}
			var audit bytes.Buffer
			handler.server.Auditor = security.NewAuditor(slog.New(slog.NewJSONHandler(&audit, nil)), true)
			for _, endpoint := range []string{server.EndpointPathToken, server.EndpointPathRevoke, server.EndpointPathIntrospect} {
				audit.Reset()
				response := matrixClientRequest(t, handler, endpoint, client, presented, url.Values{
					"grant_type": {"authorization_code"}, "code": {"unissued"}, "token": {"unissued"},
				})
				require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
				require.True(t, auditAuthFailureWithReason(t, &audit, "client_authentication_method_mismatch"))
			}
		})
	}
}

func TestRegistrationScopeGrammar(t *testing.T) {
	for _, test := range []struct {
		name   string
		scope  any
		legacy bool
		valid  bool
	}{
		{"standard", "mcp profile", false, true},
		{"tab", "mcp\tprofile", false, false},
		{"newline", "mcp\nprofile", false, false},
		{"unicode", "mcp\u00a0profile", false, false},
		{"control", "mcp\x00", false, false},
		{"quote", "mcp\"", false, false},
		{"backslash", "mcp\\", false, false},
		{"empty token", "mcp  profile", false, false},
		{"array", []string{"mcp", "read:all"}, true, true},
		{"array whitespace", []string{"mcp profile"}, true, false},
		{"array empty", []string{""}, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := setupManagementHandler(t)
			metadata := map[string]any{"client_name": "scope client", "redirect_uris": []string{"testapp://callback"}}
			field := "scope"
			if test.legacy {
				field = "scopes"
			}
			metadata[field] = test.scope
			body, err := json.Marshal(metadata)
			require.NoError(t, err)
			request := httptest.NewRequest(http.MethodPost, server.EndpointPathRegister, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+testRegistrationToken)
			response := httptest.NewRecorder()
			handler.ServeClientRegistration(response, request)
			expected := http.StatusBadRequest
			if test.valid {
				expected = http.StatusCreated
			}
			require.Equal(t, expected, response.Code, response.Body.String())
		})
	}
}
