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

func TestPrivateKeyJWTCodeAndRefresh(t *testing.T) {
	h, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "primary", Algorithm: "ES256", Use: "sig"}
	raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}})
	require.NoError(t, err)
	result, err := h.server.RegisterClientWithKeys(t.Context(), "key client", "", "private_key_jwt", []string{"https://example.com/callback"}, nil, "192.0.2.1", 10, raw, "ES256")
	require.NoError(t, err)
	require.Empty(t, result.ClientSecret)
	require.Empty(t, result.Client.ClientSecretHash)
	sign := func(identifier string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: "primary"}}, nil)
		require.NoError(t, err)
		assertion, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: result.Client.ClientID, Subject: result.Client.ClientID, Audience: jwt.Audience{h.server.Config.TokenEndpoint()}, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute)), ID: identifier}).Serialize()
		require.NoError(t, err)
		return assertion
	}
	require.NoError(t, store.SaveUserProviderToken(t.Context(), "key-user", testutil.GenerateTestToken()))
	verifier := strings.Repeat("v", 50)
	digest := sha256.Sum256([]byte(verifier))
	require.NoError(t, store.SaveAuthorizationCode(t.Context(), &storage.AuthorizationCode{
		Code: "key-code", ClientID: result.Client.ClientID, RedirectURI: "https://example.com/callback", CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]), CodeChallengeMethod: "S256", UserID: "key-user", ProviderToken: testutil.GenerateTestToken(), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}))
	exchange := func(values url.Values) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, server.EndpointPathToken, strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		h.ServeToken(response, request)
		return response
	}
	values := url.Values{"grant_type": {"authorization_code"}, "code": {"key-code"}, "redirect_uri": {"https://example.com/callback"}, "code_verifier": {verifier}, "client_assertion_type": {server.ClientAssertionTypeJWTBearer}, "client_assertion": {sign("exchange")}}
	values.Set("client_id", "")
	require.Equal(t, http.StatusUnauthorized, exchange(values).Code)
	values.Del("client_id")
	response := exchange(values)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var tokens oauth.TokenResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.RefreshToken)
	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_assertion_type": {server.ClientAssertionTypeJWTBearer}, "client_assertion": {sign("refresh")}}
	response = exchange(refresh)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	response = exchange(refresh)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Contains(t, response.Body.String(), "invalid_client")
	values.Set("client_secret", "forbidden")
	values.Set("client_assertion", sign("mixed"))
	require.Equal(t, http.StatusBadRequest, exchange(values).Code)
}

func TestPrivateKeyJWTRegistrationAndManagement(t *testing.T) {
	h := setupManagementHandler(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "first", Algorithm: "ES256", Use: "sig"}
	metadata := map[string]any{"client_name": "key client", "redirect_uris": []string{"testapp://callback"}, "token_endpoint_auth_method": "private_key_jwt", "token_endpoint_auth_signing_alg": "ES256", "jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}}}
	request := func(method, path, token string, body any) *httptest.ResponseRecorder {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		incoming := httptest.NewRequest(method, path, strings.NewReader(string(encoded)))
		incoming.Header.Set("Content-Type", "application/json")
		incoming.Header.Set("Authorization", "Bearer "+token)
		incoming.RemoteAddr = testClientRemoteAddr
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			h.ServeClientRegistration(response, incoming)
		} else {
			h.ServeClientManagement(response, incoming)
		}
		return response
	}
	response := request(http.MethodPost, server.EndpointPathRegister, testRegistrationToken, metadata)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var registration map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &registration))
	require.NotContains(t, registration, "client_secret")
	require.Contains(t, registration, "jwks")
	clientID := registration["client_id"].(string)
	managementToken := registration["registration_access_token"].(string)
	metadata["client_id"] = clientID
	next := public
	next.KeyID = "second"
	metadata["jwks"] = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public, next}}
	response = request(http.MethodPut, server.EndpointPathClientManagement+clientID, managementToken, metadata)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &registration))
	managementToken = registration["registration_access_token"].(string)
	stored, err := h.server.GetClient(t.Context(), clientID)
	require.NoError(t, err)
	var keys jose.JSONWebKeySet
	require.NoError(t, json.Unmarshal(stored.JWKS, &keys))
	require.Len(t, keys.Keys, 2)
	metadata["jwks"] = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{next}}
	response = request(http.MethodPut, server.EndpointPathClientManagement+clientID, managementToken, metadata)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	private := public
	private.Key = key
	metadata["jwks"] = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{private}}
	response = request(http.MethodPost, server.EndpointPathRegister, testRegistrationToken, metadata)
	require.Equal(t, http.StatusBadRequest, response.Code)
	metadata["jwks"] = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}}
	metadata["token_endpoint_auth_signing_alg"] = "HS256"
	require.Equal(t, http.StatusBadRequest, request(http.MethodPost, server.EndpointPathRegister, testRegistrationToken, metadata).Code)
}

func TestPrivateKeyJWTEndpointAuthentication(t *testing.T) {
	for _, endpoint := range []string{"token", "refresh", "revoke", "introspect"} {
		t.Run(endpoint, func(t *testing.T) {
			env := newRefreshTestEnv(t)
			h := env.handler
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, err)
			public := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "one", Algorithm: "ES256", Use: "sig"}
			raw, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}})
			require.NoError(t, err)
			client, err := h.server.RegisterClientWithKeys(t.Context(), "key client", "", "private_key_jwt", []string{"https://example.com/callback"}, nil, "192.0.2.2", 10, raw, "ES256")
			require.NoError(t, err)
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: "one"}}, nil)
			require.NoError(t, err)
			signed, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: client.Client.ClientID, Subject: client.Client.ClientID, Audience: jwt.Audience{h.server.Config.TokenEndpoint()}, IssuedAt: jwt.NewNumericDate(time.Now()), Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute)), ID: endpoint}).Serialize()
			require.NoError(t, err)
			invoke := func(form url.Values, basic bool) *httptest.ResponseRecorder {
				request := httptest.NewRequest(http.MethodPost, "/oauth/"+endpoint, strings.NewReader(form.Encode()))
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if basic {
					request.SetBasicAuth(client.Client.ClientID, "secret")
				}
				response := httptest.NewRecorder()
				switch endpoint {
				case "revoke":
					h.ServeTokenRevocation(response, request)
				case "introspect":
					h.ServeTokenIntrospection(response, request)
				default:
					h.ServeToken(response, request)
				}
				return response
			}
			form := url.Values{"client_id": {client.Client.ClientID}, "token": {"unknown"}, "code": {"unknown"}, "refresh_token": {"unknown"}, "grant_type": {"authorization_code"}}
			if endpoint == "refresh" {
				form.Set("grant_type", "refresh_token")
			}
			require.Equal(t, http.StatusUnauthorized, invoke(form, false).Code)
			form.Set("client_secret", "secret")
			require.Equal(t, http.StatusUnauthorized, invoke(form, false).Code)
			form.Del("client_secret")
			require.Equal(t, http.StatusUnauthorized, invoke(form, true).Code)
			form.Set("client_assertion_type", server.ClientAssertionTypeJWTBearer)
			form.Set("client_assertion", signed)
			response := invoke(form, false)
			if endpoint == "revoke" || endpoint == "introspect" {
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			} else {
				require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
				require.NotContains(t, response.Body.String(), "invalid_client")
			}
			response = invoke(form, false)
			require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
			require.NotContains(t, env.auditBuf.String(), signed)
			require.Contains(t, env.auditBuf.String(), "assertion_replayed")
		})
	}
}

func TestPrivateKeyJWTRejectedForSecretClient(t *testing.T) {
	h, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	client, _, err := h.server.RegisterClient(t.Context(), "secret client", "confidential", "client_secret_basic", []string{"https://example.com/callback"}, nil, "192.0.2.3", 10)
	require.NoError(t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: client.ClientID, Subject: client.ClientID}).Serialize()
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	request.Form = url.Values{"client_assertion_type": {server.ClientAssertionTypeJWTBearer}, "client_assertion": {signed}}
	request.PostForm = request.Form
	_, err = h.authenticateClient(request, "", "192.0.2.3")
	require.Error(t, err)
}
