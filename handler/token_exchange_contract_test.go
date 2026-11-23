package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

func TestTokenExchangeRequestParameters(t *testing.T) {
	for _, audience := range []string{"", "downstream"} {
		t.Run("audience="+audience, func(t *testing.T) {
			for _, test := range []struct {
				name, parameter, value, reason string
			}{
				{"actor type without actor", "actor_token_type", server.SubjectTokenTypeIDToken, "token_exchange_actor_token_missing"},
				{"unknown requested type", "requested_token_type", "unsupported", "token_exchange_requested_type_unsupported"},
			} {
				t.Run(test.name, func(t *testing.T) {
					handler, logs := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
					form := happyExchangeForm()
					form.Set(test.parameter, test.value)
					if audience != "" {
						form.Set("audience", audience)
					}
					response := serveToken(handler, newAuthenticatedTokenExchangeRequest(t, handler, form))
					requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
					require.True(t, auditAuthFailureWithReason(t, logs, test.reason))
					require.False(t, auditEventLogged(t, logs, security.EventTokenIssued))
				})
			}
		})
	}
}

func TestTokenExchangeRequestedAccessToken(t *testing.T) {
	handler, _ := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
	form := happyExchangeForm()
	form.Set("requested_token_type", server.SubjectTokenTypeAccessToken)
	response := serveToken(handler, newAuthenticatedTokenExchangeRequest(t, handler, form))
	issuedExchangeToken(t, response.Result(), response.Body.String())

	exchanger := &stubExchanger{result: happyDownstreamResult()}
	broker := setupBrokeredExchangeHandler(t, exchanger, []string{"gaggle"}, "confidential")
	form = brokeredExchangeForm()
	form.Set("requested_token_type", server.SubjectTokenTypeAccessToken)
	request := newTokenExchangeRequest(form)
	request.SetBasicAuth(broker.clientID, broker.clientSecret)
	response = serveToken(broker.handler, request)
	issuedExchangeToken(t, response.Result(), response.Body.String())
	require.NotNil(t, exchanger.gotReq)
}

func TestSelfIssuedExchangeRejectsClientIDOverride(t *testing.T) {
	handler, logs := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
	client := newMatrixClient(t, handler, "client_secret_basic")
	logs.Reset()
	result, err := handler.server.SelfIssuedExchange(t.Context(), server.SelfIssuedExchangeRequest{
		ClientID: client.client.ClientID,
		SubjectExchange: server.SubjectExchange{
			Subject: server.TypedToken{Token: "subject", Type: server.SubjectTokenTypeIDToken},
			Scope:   "read",
		},
		Options: server.ExchangeOptions{Extra: map[string]any{"client_id": "another-client"}},
	})
	require.ErrorContains(t, err, `reserved JWT claim "client_id"`)
	require.Nil(t, result)
	require.False(t, auditEventLogged(t, logs, security.EventTokenIssued))
	require.True(t, auditAuthFailureWithReason(t, logs, "access_token_issue_failed"))
	events := auditEvents(t, logs)
	require.Len(t, events, 1)
	require.Equal(t, client.client.ClientID, events[0]["client_id"])
	require.Equal(t, "warning", events[0]["details"].(map[string]any)["severity"])
}

func TestTokenExchangeDoesNotResolveClientMetadata(t *testing.T) {
	handler, logs := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
	handler.server.Config.EnableClientIDMetadataDocuments = true
	handler.server.Config.RestrictClientMetadata = true
	form := happyExchangeForm()
	form.Set("client_id", "https://unregistered.example.com/client.json")
	response := serveToken(handler, newTokenExchangeRequest(form))
	requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidClient)
	require.False(t, auditEventLogged(t, logs, "client_metadata_fetch_blocked"))
	require.False(t, auditEventLogged(t, logs, security.EventTokenIssued))
}

func TestTokenExchangeClientStorageUnavailable(t *testing.T) {
	for _, fault := range outageFaults {
		for _, operation := range []string{"get_client", "is_client_revoked"} {
			t.Run(fault.name+"/"+operation, func(t *testing.T) {
				environment := newOutageEnv(t)
				subject := environment.login(t).AccessToken
				environment.faulty.Fail(storagemock.OnOperation(operation, fault.fault))
				started := time.Now()
				response := environment.postToken(environment.exchangeForm(subject))
				requireTemporarilyUnavailable(t, environment, response, time.Since(started))
				require.Empty(t, response.Header().Get("WWW-Authenticate"))
				environment.faulty.Heal()
				response = environment.postToken(environment.exchangeForm(subject))
				require.Equal(t, http.StatusOK, response.Code, response.Body.String())
			})
		}
	}
}

func TestTokenExchangeClientAuthenticationErrors(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		t.Run(method, func(t *testing.T) {
			handler, _ := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
			client := newMatrixClient(t, handler, method)
			client.secret = "incorrect"
			response := matrixTokenRequest(t, handler, client, method, happyExchangeForm())
			status := http.StatusBadRequest
			challenge := ""
			if method == "client_secret_basic" {
				status = http.StatusUnauthorized
				challenge = `Basic realm="oauth"`
			}
			requireOAuthError(t, response, status, constants.ErrorCodeInvalidClient)
			require.Equal(t, challenge, response.Header().Get("WWW-Authenticate"))
		})
	}
}

func TestTokenExchangeClientRejectionAudit(t *testing.T) {
	for _, test := range []struct {
		name   string
		public bool
	}{
		{name: "missing client"},
		{name: "public client", public: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, logs := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
			form := happyExchangeForm()
			clientID := ""
			reason := "token_exchange_client_required"
			if test.public {
				client, _, err := handler.server.RegisterClient(t.Context(), "public", "public", "none",
					[]string{"http://127.0.0.1/callback"}, nil, "192.0.2.1", 100)
				require.NoError(t, err)
				clientID = client.ClientID
				form.Set("client_id", clientID)
				reason = "token_exchange_public_client"
			}
			logs.Reset()
			response := serveToken(handler, newTokenExchangeRequest(form))
			require.Equal(t, http.StatusBadRequest, response.Code)
			events := auditEvents(t, logs)
			require.Len(t, events, 1)
			require.Equal(t, security.EventAuthFailure, events[0]["event_type"])
			require.Equal(t, clientID, events[0]["client_id"])
			details := events[0]["details"].(map[string]any)
			require.Equal(t, reason, details["reason"])
			require.Equal(t, "warning", details["severity"])
			require.Equal(t, server.GrantTypeTokenExchange, details["grant_type"])
		})
	}
}
