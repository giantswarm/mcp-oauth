package handler

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// base64Secret holds every character form encoding alters in a standard
// base64 secret: '+', '/' and the '=' padding.
const base64Secret = "ab+cd/ef+gh/ij+kl/mn+op/qr+st/uv+wx/yz+01/2=" // #nosec G101 gitleaks:allow -- a test value

const seededClientID = "agent-manager"

func seededBrokerHarness(t *testing.T, secret string) *brokeredExchangeHarness {
	t.Helper()
	h := setupBrokeredExchangeHandler(t, &stubExchanger{result: happyDownstreamResult()}, nil, "confidential")
	_, err := h.srv.EnsureConfidentialClient(t.Context(), seededClientID, secret, nil)
	require.NoError(t, err)
	h.srv.Config.TokenExchangeClientAudiences = map[string][]string{seededClientID: {"gaggle"}}
	return h
}

func basicAuthHeader(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}

func formRequest(target string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// basicAuthEndpoint is one endpoint that authenticates a client with Basic
// credentials, and the status it answers once the client is authenticated.
type basicAuthEndpoint struct {
	name     string
	serve    func(h *Handler, w http.ResponseWriter, r *http.Request)
	request  func() *http.Request
	wantCode int
}

func basicAuthEndpoints() []basicAuthEndpoint {
	return []basicAuthEndpoint{
		{
			name:     "token exchange",
			serve:    (*Handler).ServeToken,
			request:  func() *http.Request { return newTokenExchangeRequest(brokeredExchangeForm()) },
			wantCode: http.StatusOK,
		},
		{
			name:  "refresh",
			serve: (*Handler).ServeToken,
			request: func() *http.Request {
				return formRequest("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"unknown-refresh-token"}})
			},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "revoke",
			serve:    (*Handler).ServeTokenRevocation,
			request:  func() *http.Request { return formRequest("/oauth/revoke", url.Values{"token": {"unknown-token"}}) },
			wantCode: http.StatusOK,
		},
		{
			name:     "introspect",
			serve:    (*Handler).ServeTokenIntrospection,
			request:  func() *http.Request { return formRequest("/oauth/introspect", url.Values{"token": {"unknown-token"}}) },
			wantCode: http.StatusOK,
		},
	}
}

func TestBasicAuth_FormEncodedCredentials(t *testing.T) {
	tests := []struct {
		name       string
		stored     string
		clientID   string
		secret     string
		wantAuth   bool
		wantRawLog bool
	}{
		{name: "form-encoded as RFC 6749 §2.3.1 requires", stored: base64Secret, clientID: url.QueryEscape(seededClientID), secret: url.QueryEscape(base64Secret), wantAuth: true},
		{name: "not form-encoded", stored: base64Secret, clientID: seededClientID, secret: base64Secret, wantAuth: true, wantRawLog: true},
		{name: "wrong secret, form-encoded", stored: base64Secret, clientID: seededClientID, secret: url.QueryEscape(base64Secret + "x")},
		{name: "wrong secret, not form-encoded", stored: base64Secret, clientID: seededClientID, secret: strings.Replace(base64Secret, "+", " ", 1)},
		{name: "secret that does not decode is kept as sent", stored: base64Secret + "%zz", clientID: seededClientID, secret: base64Secret + "%zz", wantAuth: true},
	}
	for _, endpoint := range basicAuthEndpoints() {
		for _, tc := range tests {
			t.Run(endpoint.name+"/"+tc.name, func(t *testing.T) {
				h := seededBrokerHarness(t, tc.stored)
				req := endpoint.request()
				req.Header.Set("Authorization", basicAuthHeader(tc.clientID, tc.secret))
				w := httptest.NewRecorder()
				endpoint.serve(h.handler, w, req)

				if tc.wantAuth {
					require.Equal(t, endpoint.wantCode, w.Code, "body: %s", w.Body.String())
				} else {
					requireOAuthError(t, w, http.StatusUnauthorized, constants.ErrorCodeInvalidClient)
				}
				require.Equal(t, tc.wantRawLog, strings.Contains(h.logs.String(), "not form-encoded"), "logs: %s", h.logs.String())
				require.NotContains(t, h.logs.String(), base64Secret)
			})
		}
	}
}

func TestBasicAuth_ExchangeClientRoundTrip(t *testing.T) {
	h := seededBrokerHarness(t, base64Secret)
	broker := httptest.NewTLSServer(http.HandlerFunc(h.handler.ServeToken))
	t.Cleanup(broker.Close)

	exchanger := oidc.NewTokenExchangeClientWithOptions(oidc.TokenExchangeClientOptions{
		HTTPClient:     broker.Client(),
		Logger:         slog.New(slog.DiscardHandler),
		AllowPrivateIP: true,
	})
	result, err := exchanger.Exchange(t.Context(), oidc.TokenExchangeRequest{
		TokenEndpoint:    broker.URL + "/token",
		SubjectToken:     "subject-id-token",
		SubjectTokenType: oidc.TokenTypeIDToken,
		Audience:         "gaggle",
		ClientID:         seededClientID,
		ClientSecret:     base64Secret,
	})
	require.NoError(t, err)
	require.Equal(t, "downstream-mc-token", result.AccessToken)
	require.NotContains(t, h.logs.String(), "not form-encoded")
}
