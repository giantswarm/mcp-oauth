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

func TestTokenExchangeResourceAllowlistPreservesIdentity(t *testing.T) {
	fixture := newExchangeContractFixture(t, false)
	fixture.handler.server.Config.TokenExchangeAllowedResources = []string{"urn:example:allowed", "https://api.example.com/a%2Fb"}
	for _, resource := range []string{"urn:example:forbidden", "https://api.example.com/a/b"} {
		t.Run(resource, func(t *testing.T) {
			form := fixture.form()
			form.Set("resource", resource)
			fixture.logs.Reset()
			response := fixture.request(form)
			requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidTarget)
			require.True(t, auditAuthFailureWithReason(t, fixture.logs, "token_exchange_resource_not_allowed"))
			require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
		})
	}
}

func TestTokenExchangeHeaderAuthenticationFailureUsesChallenge(t *testing.T) {
	fixture := newExchangeContractFixture(t, false)
	for _, scheme := range []string{"Bearer", "Digest"} {
		t.Run(scheme, func(t *testing.T) {
			form := fixture.form()
			form.Set("client_id", fixture.clientID)
			request := newTokenExchangeRequest(form)
			request.Header.Set("Authorization", scheme+" invalid-client-credential")
			fixture.logs.Reset()
			response := serveToken(fixture.handler, request)
			requireOAuthError(t, response, http.StatusUnauthorized, constants.ErrorCodeInvalidClient)
			require.Equal(t, scheme+` realm="oauth"`, response.Header().Get("WWW-Authenticate"))
			require.True(t, auditEventLogged(t, fixture.logs, security.EventAuthFailure))
			require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
		})
	}
}

func TestBrokeredTokenExchangeRejectsBoundSubjectWithoutProof(t *testing.T) {
	exchanger := &stubExchanger{result: happyDownstreamResult()}
	broker := setupBrokeredExchangeHandler(t, exchanger, []string{"gaggle"}, "confidential")
	broker.validator.identity.ConfirmationJKT = "subject-key-thumbprint"
	request := newTokenExchangeRequest(brokeredExchangeForm())
	request.SetBasicAuth(broker.clientID, broker.clientSecret)
	broker.logs.Reset()
	response := serveToken(broker.handler, request)
	requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
	require.Nil(t, exchanger.gotReq)
	require.True(t, auditAuthFailureWithReason(t, broker.logs, "token_exchange_subject_key_mismatch"))
	require.False(t, auditEventLogged(t, broker.logs, security.EventTokenIssued))
	var events []map[string]any
	for _, record := range scanAuditRecords(t, broker.logs) {
		if event, ok := record["audit"].(map[string]any); ok && event["event_type"] == security.EventAuthFailure {
			events = append(events, event)
		}
	}
	require.Len(t, events, 1)
	require.Equal(t, broker.clientID, events[0]["client_id"])
	require.Equal(t, "warning", events[0]["details"].(map[string]any)["severity"])
}

func TestBrokeredTokenExchangePreservesDefaultIssuedType(t *testing.T) {
	for _, issued := range []string{server.SubjectTokenTypeAccessToken, server.SubjectTokenTypeIDToken, server.SubjectTokenTypeJWT} {
		t.Run(issued, func(t *testing.T) {
			fixture := newExchangeContractFixture(t, true)
			fixture.exchanger.result.IssuedTokenType = issued
			response := fixture.request(fixture.form())
			require.Equal(t, http.StatusOK, response.Code)
			require.Empty(t, fixture.exchanger.gotReq.RequestedTokenType)
			var body map[string]any
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			require.Equal(t, issued, body["issued_token_type"])
			tokenType := "N_A"
			if issued == server.SubjectTokenTypeAccessToken {
				tokenType = "Bearer"
			}
			require.Equal(t, tokenType, body["token_type"])
		})
	}
}

func TestTokenExchangeExplicitOutputTypes(t *testing.T) {
	for _, brokered := range []bool{false, true} {
		for _, outputType := range []string{server.SubjectTokenTypeAccessToken, server.SubjectTokenTypeIDToken, server.SubjectTokenTypeJWT} {
			name := "local/" + outputType
			if brokered {
				name = "brokered/" + outputType
			}
			t.Run(name, func(t *testing.T) {
				fixture := newExchangeContractFixture(t, brokered)
				form := fixture.form()
				form.Set("requested_token_type", outputType)
				if brokered {
					fixture.exchanger.result.IssuedTokenType = outputType
				}
				response := fixture.request(form)
				if !brokered && outputType != server.SubjectTokenTypeAccessToken {
					requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
					require.True(t, auditAuthFailureWithReason(t, fixture.logs, "token_exchange_requested_type_unsupported"))
					return
				}
				require.Equal(t, http.StatusOK, response.Code)
				if brokered {
					require.Equal(t, outputType, fixture.exchanger.gotReq.RequestedTokenType)
				}
			})
		}
	}
}
