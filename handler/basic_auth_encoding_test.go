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
const base64Secret = "ab+cd/ef+gh/ij+kl/mn+op/qr+st/uv+wx/yz+01/2=" // #nosec G101 -- a test value

const seededClientID = "agent-manager"

func seededBrokerHarness(t *testing.T) *brokeredExchangeHarness {
	t.Helper()
	h := setupBrokeredExchangeHandler(t, &stubExchanger{result: happyDownstreamResult()}, nil, "confidential")
	_, err := h.srv.EnsureConfidentialClient(t.Context(), seededClientID, base64Secret, nil)
	require.NoError(t, err)
	h.srv.Config.TokenExchangeClientAudiences = map[string][]string{seededClientID: {"gaggle"}}
	return h
}

func basicAuthHeader(clientID, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret))
}

func TestBasicAuth_FormEncodedCredentials(t *testing.T) {
	tests := []struct {
		name       string
		clientID   string
		secret     string
		wantCode   int
		wantRawLog bool
	}{
		{name: "form-encoded as RFC 6749 §2.3.1 requires", clientID: url.QueryEscape(seededClientID), secret: url.QueryEscape(base64Secret), wantCode: http.StatusOK},
		{name: "not form-encoded", clientID: seededClientID, secret: base64Secret, wantCode: http.StatusOK, wantRawLog: true},
		{name: "wrong secret, form-encoded", clientID: seededClientID, secret: url.QueryEscape(base64Secret + "x"), wantCode: http.StatusUnauthorized},
		{name: "wrong secret, not form-encoded", clientID: seededClientID, secret: strings.Replace(base64Secret, "+", " ", 1), wantCode: http.StatusUnauthorized},
		{name: "malformed escape is kept as sent", clientID: seededClientID, secret: base64Secret + "%zz", wantCode: http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := seededBrokerHarness(t)
			req := newTokenExchangeRequest(brokeredExchangeForm())
			req.Header.Set("Authorization", basicAuthHeader(tc.clientID, tc.secret))
			w := httptest.NewRecorder()
			h.handler.ServeToken(w, req)

			if tc.wantCode == http.StatusOK {
				require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			} else {
				requireOAuthError(t, w, tc.wantCode, constants.ErrorCodeInvalidClient)
			}
			require.Equal(t, tc.wantRawLog, strings.Contains(h.logs.String(), "not form-encoded"), "logs: %s", h.logs.String())
			require.NotContains(t, h.logs.String(), base64Secret)
		})
	}
}

func TestBasicAuth_ExchangeClientRoundTrip(t *testing.T) {
	h := seededBrokerHarness(t)
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
