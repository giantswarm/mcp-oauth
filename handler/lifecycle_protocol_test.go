package handler

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestRevocationAuthenticationAndOwnership(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		for _, presented := range []string{"missing identifiers", "missing credentials", "other public client", "owner"} {
			t.Run(method+"/"+presented, func(t *testing.T) {
				handler, store := setupTestHandler(t)
				t.Cleanup(store.Stop)
				client := newMatrixClient(t, handler, method)
				providerToken := testutil.GenerateTestToken()
				require.NoError(t, store.SaveUserProviderToken(t.Context(), "person", providerToken))
				require.NoError(t, store.SaveProviderTokenRef(t.Context(), "issued-refresh", "person", time.Now().Add(time.Hour)))
				require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "issued-refresh", "person", client.client.ClientID, "issued-family", 1, time.Now().Add(time.Hour)))
				form := url.Values{"token": {"issued-refresh"}}
				presentedMethod := method
				if presented != "owner" {
					presentedMethod = "none"
				}
				if presented == "other public client" {
					other, _, err := handler.server.RegisterClient(t.Context(), "public", "public", "none", []string{"https://example.com/callback"}, nil, "192.0.2.1", 100)
					require.NoError(t, err)
					client.client = other
				}
				response := matrixClientRequest(t, handler, server.EndpointPathRevoke, client, presentedMethod, form, func(request *http.Request) {
					if presented == "missing identifiers" {
						require.NoError(t, request.ParseForm())
						request.PostForm.Del("client_id")
						request.Form.Del("client_id")
					}
				})
				if presented == "owner" || presented == "other public client" {
					require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				} else {
					require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
				}
				family, err := store.GetRefreshTokenFamily(t.Context(), "issued-refresh")
				require.NoError(t, err)
				require.Equal(t, presented == "owner", family.Revoked)
				_, err = store.GetRefreshTokenInfo(t.Context(), "issued-refresh")
				if presented == "owner" {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
			})
		}
	}
}

func TestClientAuthenticationEndpointMatrix(t *testing.T) {
	methods := []string{"client_secret_basic", "client_secret_post"}
	for _, endpoint := range []string{server.EndpointPathRevoke, server.EndpointPathIntrospect} {
		for _, registered := range methods {
			for _, presented := range methods {
				t.Run(endpoint+"/"+registered+"/"+presented, func(t *testing.T) {
					handler, store := setupTestHandler(t)
					t.Cleanup(store.Stop)
					client := newMatrixClient(t, handler, registered)
					response := matrixClientRequest(t, handler, endpoint, client, presented, url.Values{"token": {"unknown"}})
					expected := http.StatusUnauthorized
					if registered == presented {
						expected = http.StatusOK
					}
					require.Equal(t, expected, response.Code, response.Body.String())
				})
			}
		}
	}
}

func TestManagementReplacementValidation(t *testing.T) {
	for _, invalid := range []string{"missing identity", "different identity", "different secret", "missing redirects", "unsafe redirect", "invalid name", "scope conflict"} {
		t.Run(invalid, func(t *testing.T) {
			handler := setupManagementHandler(t)
			clientID, registrationToken := registerAndExtractToken(t, handler)
			metadata := map[string]any{"client_id": clientID, "redirect_uris": []string{"testapp://oauth/callback"}, "client_name": "replacement"}
			switch invalid {
			case "missing identity":
				delete(metadata, "client_id")
			case "different identity":
				metadata["client_id"] = "another-client"
			case "different secret":
				metadata["client_secret"] = "not-the-registered-secret"
			case "missing redirects":
				delete(metadata, "redirect_uris")
			case "unsafe redirect":
				metadata["redirect_uris"] = []string{"javascript:alert(1)"}
			case "invalid name":
				metadata["client_name"] = "name\ninjection"
			case "scope conflict":
				metadata["scope"] = "mcp"
				metadata["scopes"] = []string{"other"}
			}
			body, err := json.Marshal(metadata)
			require.NoError(t, err)
			request := httptest.NewRequest(http.MethodPut, server.EndpointPathClientManagement+clientID, strings.NewReader(string(body)))
			request.Header.Set("Authorization", "Bearer "+registrationToken)
			response := httptest.NewRecorder()
			handler.ServeClientManagement(response, request)
			require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
			stored, err := handler.server.GetClient(t.Context(), clientID)
			require.NoError(t, err)
			require.Equal(t, "test-client", stored.ClientName)
			require.Equal(t, []string{"testapp://oauth/callback"}, stored.RedirectURIs)
			request = httptest.NewRequest(http.MethodGet, server.EndpointPathClientManagement+clientID, nil)
			request.Header.Set("Authorization", "Bearer "+registrationToken)
			response = httptest.NewRecorder()
			handler.ServeClientManagement(response, request)
			require.Equal(t, http.StatusOK, response.Code)
		})
	}
}

func TestEndpointAuthenticationDiscovery(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	handler.server.Config.EnableRevocationEndpoint = true
	handler.server.Config.EnableIntrospectionEndpoint = true
	metadata := handler.buildAuthServerMetadata()
	for _, endpoint := range []string{"revocation", "introspection"} {
		methods := metadata[endpoint+"_endpoint_auth_methods_supported"].([]string)
		require.Contains(t, methods, "client_secret_basic")
		require.Contains(t, methods, "client_secret_post")
	}
	require.NotContains(t, metadata["introspection_endpoint_auth_methods_supported"], "none")
}

func TestPublicClientRevocation(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	client := newMatrixClient(t, handler, "none")
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "public-refresh", "person", client.client.ClientID, "public-family", 1, time.Now().Add(time.Hour)))
	response := matrixClientRequest(t, handler, server.EndpointPathRevoke, client, "none", url.Values{"token": {"public-refresh"}})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	_, err := store.GetRefreshTokenInfo(t.Context(), "public-refresh")
	require.Error(t, err)
}

func TestLifecycleAuthenticationDoesNotFetchMetadata(t *testing.T) {
	var fetches atomic.Int32
	var clientID string
	metadataServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		response.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(response).Encode(map[string]any{"client_id": clientID, "client_name": "public metadata", "redirect_uris": []string{"http://127.0.0.1:7777/callback"}, "token_endpoint_auth_method": "none"}); err != nil {
			http.Error(response, "metadata encoding failed", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(metadataServer.Close)
	clientID = metadataServer.URL + "/client.json"
	handler := setupManagementHandler(t)
	handler.server.Config.EnableClientIDMetadataDocuments = true
	handler.server.Config.AllowPrivateIPClientMetadata = true //nolint:staticcheck // The loopback TLS fixture must be fetchable to detect unexpected requests.
	handler.server.Config.ClientMetadataRootCAs = x509.NewCertPool()
	handler.server.Config.ClientMetadataRootCAs.AddCert(metadataServer.Certificate())
	for _, endpoint := range []string{server.EndpointPathRevoke, server.EndpointPathIntrospect} {
		response := matrixClientRequest(t, handler, endpoint, matrixClient{client: &storage.Client{ClientID: clientID}}, "none", url.Values{"token": {"unissued"}})
		require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodGet, server.EndpointPathClientManagement+clientID, nil)
	request.Header.Set("Authorization", "Bearer unissued-registration-token")
	response := httptest.NewRecorder()
	handler.ServeClientManagement(response, request)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Zero(t, fetches.Load())
	client, err := handler.server.GetClient(t.Context(), clientID)
	require.NoError(t, err)
	require.Equal(t, clientID, client.ClientID)
	require.EqualValues(t, 1, fetches.Load())
}
