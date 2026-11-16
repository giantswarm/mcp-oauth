package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

const refusalRedirectURI = "https://example.com/callback"

func requireAuthorizationErrorRedirect(t *testing.T, w *httptest.ResponseRecorder, wantCode, wantDescription, wantState string) {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code, "body: %s", w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, refusalRedirectURI, location.Scheme+"://"+location.Host+location.Path)
	q := location.Query()
	require.Equal(t, wantCode, q.Get("error"))
	require.Equal(t, wantDescription, q.Get("error_description"))
	require.Equal(t, wantState, q.Get("state"))
	require.Equal(t, testIssuer, q.Get("iss"))
}

func TestServeAuthorization_ValidationRefusalRedirectsWithItsErrorCode(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	client, _, err := handler.server.RegisterClient(t.Context(), "Test Client", "public", "",
		[]string{refusalRedirectURI}, []string{"openid"}, "192.168.1.100", 10)
	require.NoError(t, err)
	trustClient(handler.server, client.ClientID)
	state := testutil.GenerateRandomString(43)

	tests := []struct {
		name            string
		params          string
		wantCode        string
		wantDescription string
	}{
		{
			name:            "missing code_challenge",
			params:          "&scope=openid",
			wantCode:        constants.ErrorCodeInvalidRequest,
			wantDescription: "PKCE is required: code_challenge and code_challenge_method parameters are mandatory",
		},
		{
			name:            "unsupported code_challenge_method",
			params:          "&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=BOGUS",
			wantCode:        constants.ErrorCodeInvalidRequest,
			wantDescription: "code_challenge_method is not supported, use S256",
		},
		{
			name:            "scope not allowed for the client",
			params:          "&scope=openid+email&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
			wantCode:        constants.ErrorCodeInvalidScope,
			wantDescription: "scope is not allowed for this client",
		},
		{
			name:            "invalid resource",
			params:          "&scope=openid&resource=not-a-uri&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
			wantCode:        constants.ErrorCodeInvalidTarget,
			wantDescription: "resource parameter is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id="+url.QueryEscape(client.ClientID)+
				"&redirect_uri="+url.QueryEscape(refusalRedirectURI)+"&state="+state+tt.params, nil)
			w := httptest.NewRecorder()
			handler.ServeAuthorization(w, req)

			requireAuthorizationErrorRedirect(t, w, tt.wantCode, tt.wantDescription, state)
		})
	}
}

func TestServeAuthorization_ClientStoreOutageRedirectsTemporarilyUnavailable(t *testing.T) {
	env := newOutageEnv(t)
	var lookups atomic.Int32
	env.faulty.Fail(storagemock.OnOperation("get_client", func(ctx context.Context, operation string) error {
		if lookups.Add(1) == 1 {
			return nil
		}
		return storagemock.ConnectionRefused(ctx, operation)
	}))
	state := testutil.GenerateRandomString(43)

	req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id="+url.QueryEscape(env.clientID)+
		"&redirect_uri="+url.QueryEscape(refusalRedirectURI)+"&scope=openid&state="+state+
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", nil)
	w := httptest.NewRecorder()
	env.handler.ServeAuthorization(w, req)

	requireAuthorizationErrorRedirect(t, w, constants.ErrorCodeTemporarilyUnavailable,
		"The server could not reach its client store; retry the request", state)
}

func TestServeAuthorization_RedirectURIRejectedAtAuthorizationIsAnsweredDirectly(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	const privateRedirectURI = "https://10.0.0.1/callback"
	handler.server.Config.AllowPrivateIPRedirectURIs = true //nolint:staticcheck // a literal-IP redirect URI is never matched by AllowPrivateIPRedirectURIHosts
	client, _, err := handler.server.RegisterClient(t.Context(), "Test Client", "public", "",
		[]string{privateRedirectURI}, []string{"openid"}, "192.168.1.100", 10)
	require.NoError(t, err)
	trustClient(handler.server, client.ClientID)
	handler.server.Config.AllowPrivateIPRedirectURIs = false //nolint:staticcheck // see above
	handler.server.Config.ValidateRedirectURIAtAuthorization = true

	req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id="+url.QueryEscape(client.ClientID)+
		"&redirect_uri="+url.QueryEscape(privateRedirectURI)+"&scope=openid&state="+testutil.GenerateRandomString(43)+
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", nil)
	w := httptest.NewRecorder()
	handler.ServeAuthorization(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Empty(t, w.Header().Get("Location"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, constants.ErrorCodeInvalidRequest, body["error"])
	require.Equal(t, "redirect_uri failed security validation", body["error_description"])
}

func TestServeAuthorization_ClientStoreOutageBeforeRedirectURICheckAnswers503(t *testing.T) {
	env := newOutageEnv(t)
	env.faulty.Fail(storagemock.OnOperation("get_client", storagemock.ConnectionRefused))

	req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&client_id="+url.QueryEscape(env.clientID)+
		"&redirect_uri="+url.QueryEscape(refusalRedirectURI)+"&scope=openid&state="+testutil.GenerateRandomString(43)+
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", nil)
	w := httptest.NewRecorder()
	env.handler.ServeAuthorization(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.NotEmpty(t, w.Header().Get("Retry-After"))
	require.Empty(t, w.Header().Get("Location"))
}
