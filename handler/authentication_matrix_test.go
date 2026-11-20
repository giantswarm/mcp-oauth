package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

type matrixClient struct {
	client            *storage.Client
	secret            string
	key               *ecdsa.PrivateKey
	registrationToken string
}

func newMatrixClient(t *testing.T, handler *Handler, method string) matrixClient {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var keys json.RawMessage
	algorithm := ""
	if method == "private_key_jwt" {
		algorithm = "ES256"
		keys, err = json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "matrix", Algorithm: algorithm, Use: "sig"}}})
		require.NoError(t, err)
	}
	registered, err := handler.server.RegisterClientWithKeys(t.Context(), "matrix", "confidential", method, []string{"https://example.com/callback"}, []string{"mcp"}, "192.0.2.1", 100, keys, algorithm)
	require.NoError(t, err)
	return matrixClient{client: registered.Client, secret: registered.ClientSecret, key: key, registrationToken: registered.RegistrationToken}
}

func matrixTokenRequest(t *testing.T, handler *Handler, client matrixClient, method string, form url.Values, mutations ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	return matrixClientRequest(t, handler, server.EndpointPathToken, client, method, form, mutations...)
}

func matrixClientRequest(t *testing.T, handler *Handler, endpoint string, client matrixClient, method string, form url.Values, mutations ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("client_id", client.client.ClientID)
	secret := client.secret
	if secret == "" {
		secret = "unregistered-secret"
	}
	switch method {
	case "client_secret_post":
		form.Set("client_secret", secret)
	case "private_key_jwt":
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: client.key, KeyID: "matrix"}}, nil)
		require.NoError(t, err)
		assertion, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: client.client.ClientID, Subject: client.client.ClientID, Audience: jwt.Audience{handler.server.Config.TokenEndpoint()}, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute)), ID: rand.Text()}).Serialize()
		require.NoError(t, err)
		form.Set("client_assertion_type", server.ClientAssertionTypeJWTBearer)
		form.Set("client_assertion", assertion)
	}
	request := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if method == "client_secret_basic" {
		request.SetBasicAuth(client.client.ClientID, secret)
	}
	for _, mutate := range mutations {
		mutate(request)
	}
	response := httptest.NewRecorder()
	switch endpoint {
	case server.EndpointPathRevoke:
		handler.ServeTokenRevocation(response, request)
	case server.EndpointPathIntrospect:
		handler.ServeTokenIntrospection(response, request)
	default:
		handler.ServeToken(response, request)
	}
	return response
}

func TestAuthenticationMethodMissingAndMixedCredentials(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post", "private_key_jwt"} {
		t.Run(method, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			t.Cleanup(store.Stop)
			client := newMatrixClient(t, handler, method)
			for _, grant := range []string{"authorization_code", "refresh_token"} {
				form := func() url.Values {
					return url.Values{"grant_type": {grant}, "code": {"unconsumed-code"}, "refresh_token": {"unconsumed-refresh"}}
				}
				missing := matrixTokenRequest(t, handler, client, "none", form())
				require.Equal(t, http.StatusUnauthorized, missing.Code)
				require.Contains(t, missing.Body.String(), "invalid_client")
				mixedForm := form()
				mixedForm.Set("client_secret", "mixed-secret")
				mixed := matrixTokenRequest(t, handler, client, method, mixedForm, func(request *http.Request) { request.SetBasicAuth(client.client.ClientID, "mixed-secret") })
				require.Equal(t, http.StatusBadRequest, mixed.Code)
				require.Contains(t, mixed.Body.String(), "invalid_request")
			}
		})
	}
}

func TestAuthenticationMethodMatrix(t *testing.T) {
	methods := []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}
	for _, registeredMethod := range methods {
		for _, presentedMethod := range methods {
			t.Run(registeredMethod+"/"+presentedMethod, func(t *testing.T) {
				handler, store := setupTestHandler(t)
				t.Cleanup(store.Stop)
				client := newMatrixClient(t, handler, registeredMethod)
				verifier := strings.Repeat("v", 50)
				digest := sha256.Sum256([]byte(verifier))
				providerToken := testutil.GenerateTestToken()
				require.NoError(t, store.SaveUserProviderToken(t.Context(), "matrix-user", providerToken))
				require.NoError(t, store.SaveAuthorizationCode(t.Context(), &storage.AuthorizationCode{Code: "matrix-code", ClientID: client.client.ClientID, RedirectURI: "https://example.com/callback", CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]), CodeChallengeMethod: "S256", UserID: "matrix-user", ProviderToken: providerToken, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}))
				codeForm := func() url.Values {
					return url.Values{"grant_type": {"authorization_code"}, "code": {"matrix-code"}, "redirect_uri": {"https://example.com/callback"}, "code_verifier": {verifier}}
				}
				if presentedMethod != registeredMethod {
					mismatch := matrixTokenRequest(t, handler, client, presentedMethod, codeForm())
					require.Equal(t, http.StatusUnauthorized, mismatch.Code)
					if presentedMethod == "client_secret_basic" {
						require.Equal(t, `Basic realm="oauth"`, mismatch.Header().Get("WWW-Authenticate"))
					}
				}
				response := matrixTokenRequest(t, handler, client, registeredMethod, codeForm())
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				var tokens oauth.TokenResponse
				require.NoError(t, json.NewDecoder(response.Body).Decode(&tokens))
				refreshForm := func() url.Values {
					return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}}
				}
				if presentedMethod != registeredMethod {
					require.Equal(t, http.StatusUnauthorized, matrixTokenRequest(t, handler, client, presentedMethod, refreshForm()).Code)
				}
				response = matrixTokenRequest(t, handler, client, registeredMethod, refreshForm())
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
				var refreshed oauth.TokenResponse
				require.NoError(t, json.NewDecoder(response.Body).Decode(&refreshed))
				checkAccess := func(access string) int {
					request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
					request.Header.Set("Authorization", "Bearer "+access)
					response := httptest.NewRecorder()
					handler.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(response, request)
					return response.Code
				}
				require.Equal(t, http.StatusOK, checkAccess(refreshed.AccessToken))
				deletion := httptest.NewRequest(http.MethodDelete, server.EndpointPathClientManagement+client.client.ClientID, nil)
				deletion.Header.Set("Authorization", "Bearer "+client.registrationToken)
				deletion.RemoteAddr = testClientRemoteAddr
				deleted := httptest.NewRecorder()
				handler.ServeClientManagement(deleted, deletion)
				require.Equal(t, http.StatusNoContent, deleted.Code)
				require.Equal(t, http.StatusUnauthorized, checkAccess(refreshed.AccessToken))
				require.Equal(t, http.StatusUnauthorized, matrixTokenRequest(t, handler, client, registeredMethod, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshed.RefreshToken}}).Code)
			})
		}
	}
}

func TestAuthenticationMethodAmbiguousCredentials(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		for _, shape := range []string{"duplicate secret", "query secret", "duplicate identifier", "empty mixed secret"} {
			t.Run(grant+"/"+shape, func(t *testing.T) {
				handler, store := setupTestHandler(t)
				t.Cleanup(store.Stop)
				client := newMatrixClient(t, handler, "client_secret_post")
				response := matrixTokenRequest(t, handler, client, "client_secret_post", url.Values{"grant_type": {grant}, "code": {"unconsumed-code"}, "refresh_token": {"unconsumed-refresh"}}, func(request *http.Request) {
					require.NoError(t, request.ParseForm())
					switch shape {
					case "duplicate secret":
						request.PostForm.Add("client_secret", client.secret)
						request.Form.Add("client_secret", client.secret)
					case "query secret":
						request.PostForm.Del("client_secret")
						request.URL.RawQuery = url.Values{"client_secret": {client.secret}}.Encode()
					case "duplicate identifier":
						request.Form.Add("client_id", client.client.ClientID)
					case "empty mixed secret":
						request.PostForm.Set("client_secret", "")
						request.Form.Set("client_secret", "")
						request.SetBasicAuth(client.client.ClientID, client.secret)
					}
				})
				require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
				require.Contains(t, response.Body.String(), "invalid_request")
			})
		}
	}
}
