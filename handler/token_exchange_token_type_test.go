package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

func TestBrokeredExchangeJWTUsageMethod(t *testing.T) {
	local := newExchangeContractFixture(t, false)
	localResponse := local.request(local.form())
	accessToken := issuedExchangeToken(t, localResponse.Result(), localResponse.Body.String())
	for _, test := range []struct {
		name, usage string
		valid       bool
	}{
		{name: "bearer access token", usage: "Bearer", valid: true},
		{name: "assertion", usage: "N_A", valid: true},
		{name: "missing usage"},
		{name: "unsupported usage", usage: "DPoP"},
	} {
		t.Run(test.name, func(t *testing.T) {
			broker := newExchangeContractFixture(t, true)
			broker.exchanger.result.AccessToken = accessToken
			broker.exchanger.result.IssuedTokenType = server.SubjectTokenTypeJWT
			broker.exchanger.result.TokenType = test.usage
			form := broker.form()
			form.Set("requested_token_type", server.SubjectTokenTypeJWT)
			broker.logs.Reset()
			response := broker.request(form)
			if !test.valid {
				requireOAuthError(t, response, http.StatusInternalServerError, constants.ErrorCodeServerError)
				require.NotContains(t, response.Body.String(), accessToken)
				require.True(t, auditAuthFailureWithReason(t, broker.logs, "token_exchange_invalid_result"))
				require.False(t, auditEventLogged(t, broker.logs, security.EventTokenIssued))
				return
			}
			require.Equal(t, http.StatusOK, response.Code)
			var body map[string]any
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			require.Equal(t, accessToken, body["access_token"])
			require.Equal(t, test.usage, body["token_type"])
			require.Equal(t, server.SubjectTokenTypeJWT, body["issued_token_type"])
		})
	}
}

func TestBrokeredExchangeEmptyResultIsServerError(t *testing.T) {
	for _, test := range []struct {
		name   string
		result *server.ExchangerResult
	}{
		{name: "nil result"},
		{name: "empty token", result: &server.ExchangerResult{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newExchangeContractFixture(t, true)
			fixture.exchanger.result = test.result
			fixture.logs.Reset()
			response := fixture.request(fixture.form())
			requireOAuthError(t, response, http.StatusInternalServerError, constants.ErrorCodeServerError)
			require.True(t, auditAuthFailureWithReason(t, fixture.logs, "token_exchange_downstream_empty_token"))
			require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
		})
	}
}
