package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

type exchangeContractFixture struct {
	handler                *Handler
	logs                   *bytes.Buffer
	exchanger              *stubExchanger
	clientID, clientSecret string
}

func newExchangeContractFixture(t *testing.T, brokered bool) exchangeContractFixture {
	t.Helper()
	if brokered {
		exchanger := &stubExchanger{result: happyDownstreamResult()}
		broker := setupBrokeredExchangeHandler(t, exchanger, []string{"gaggle"}, "confidential")
		return exchangeContractFixture{
			handler: broker.handler, logs: broker.logs, exchanger: exchanger,
			clientID: broker.clientID, clientSecret: broker.clientSecret,
		}
	}
	handler, logs := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
	client := newMatrixClient(t, handler, "client_secret_basic")
	return exchangeContractFixture{
		handler: handler, logs: logs, clientID: client.client.ClientID, clientSecret: client.secret,
	}
}

func (fixture exchangeContractFixture) form() url.Values {
	if fixture.exchanger != nil {
		return brokeredExchangeForm()
	}
	return happyExchangeForm()
}

func (fixture exchangeContractFixture) request(form url.Values) *httptest.ResponseRecorder {
	request := newTokenExchangeRequest(form)
	request.SetBasicAuth(fixture.clientID, fixture.clientSecret)
	return serveToken(fixture.handler, request)
}

func TestTokenExchangeEmptyOptionalParameters(t *testing.T) {
	for _, flow := range []string{"local", "brokered"} {
		t.Run(flow, func(t *testing.T) {
			fixture := newExchangeContractFixture(t, flow == "brokered")
			for _, parameters := range [][]string{
				{"actor_token_type"}, {"actor_token", "actor_token_type"}, {"requested_token_type"},
			} {
				t.Run(strings.Join(parameters, "+"), func(t *testing.T) {
					form := fixture.form()
					for _, parameter := range parameters {
						form.Set(parameter, "")
					}
					response := fixture.request(form)
					require.Equal(t, http.StatusOK, response.Code)
				})
			}
		})
	}
}

func TestTokenExchangeDuplicateParameters(t *testing.T) {
	for _, flow := range []string{"local", "brokered"} {
		t.Run(flow, func(t *testing.T) {
			fixture := newExchangeContractFixture(t, flow == "brokered")
			for _, parameter := range []string{"grant_type", "subject_token", "subject_token_type", "actor_token", "actor_token_type", "requested_token_type", "scope"} {
				for _, identical := range []bool{true, false} {
					name := parameter + "/conflicting"
					if identical {
						name = parameter + "/identical"
					}
					t.Run(name, func(t *testing.T) {
						form := fixture.form()
						if form.Get(parameter) == "" {
							form.Set(parameter, server.SubjectTokenTypeAccessToken)
						}
						duplicate := "different"
						if identical {
							duplicate = form.Get(parameter)
						}
						form.Add(parameter, duplicate)
						fixture.logs.Reset()
						response := fixture.request(form)
						requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
						reason := "token_exchange_duplicate_parameter"
						if parameter == "grant_type" {
							reason = "token_request_duplicate_grant_type"
						}
						require.True(t, auditAuthFailureWithReason(t, fixture.logs, reason))
						require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
						if fixture.exchanger != nil {
							require.Nil(t, fixture.exchanger.gotReq)
						}
					})
				}
			}
		})
	}
}

func TestTokenExchangeDuplicateGrantTypeOrder(t *testing.T) {
	fixture := newExchangeContractFixture(t, false)
	form := fixture.form()
	form["grant_type"] = []string{"unsupported", server.GrantTypeTokenExchange}
	fixture.logs.Reset()
	response := fixture.request(form)
	requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
	require.True(t, auditAuthFailureWithReason(t, fixture.logs, "token_request_duplicate_grant_type"))
	require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
}

func TestTokenExchangeMultipleAudiences(t *testing.T) {
	fixture := newExchangeContractFixture(t, true)
	form := fixture.form()
	form.Add("audience", "another-target")
	fixture.logs.Reset()
	response := fixture.request(form)
	requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidTarget)
	require.True(t, auditAuthFailureWithReason(t, fixture.logs, "token_exchange_multiple_audiences"))
	require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
	require.Nil(t, fixture.exchanger.gotReq)
}

func TestTokenExchangeResourceSyntax(t *testing.T) {
	for _, flow := range []string{"local", "brokered"} {
		t.Run(flow, func(t *testing.T) {
			fixture := newExchangeContractFixture(t, flow == "brokered")
			for _, resource := range []string{"relative", "https://api.example.com/#fragment", "https://api.example.com/#", "https://api.example.com/%zz", "https://api.example.com/a b", "https://api.example.com/?q=%zz", "urn:example:bad value", "https://api.example.com/" + strings.Repeat("a", server.MaxResourceLength)} {
				fixture.logs.Reset()
				form := fixture.form()
				form.Set("resource", resource)
				response := fixture.request(form)
				requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidTarget)
				require.True(t, auditAuthFailureWithReason(t, fixture.logs, "token_exchange_resource_invalid"))
				require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
				if fixture.exchanger != nil {
					require.Nil(t, fixture.exchanger.gotReq)
				}
			}
			for _, resource := range []string{"", "urn:example:resource", "https://api.example.com/?value=%23fragment"} {
				form := fixture.form()
				form.Set("resource", resource)
				response := fixture.request(form)
				require.Equal(t, http.StatusOK, response.Code)
			}
		})
	}
}

func TestBrokeredTokenExchangeRejectsUnexpectedIssuedType(t *testing.T) {
	fixture := newExchangeContractFixture(t, true)
	for _, requested := range []string{server.SubjectTokenTypeAccessToken, server.SubjectTokenTypeIDToken, server.SubjectTokenTypeJWT} {
		for _, issued := range []string{server.SubjectTokenTypeAccessToken, server.SubjectTokenTypeIDToken, server.SubjectTokenTypeJWT, "unsupported"} {
			if requested == issued {
				continue
			}
			t.Run(requested+"/"+issued, func(t *testing.T) {
				form := fixture.form()
				form.Set("requested_token_type", requested)
				fixture.exchanger.result.IssuedTokenType = issued
				fixture.logs.Reset()
				response := fixture.request(form)
				requireOAuthError(t, response, http.StatusInternalServerError, constants.ErrorCodeServerError)
				require.NotContains(t, response.Body.String(), fixture.exchanger.result.AccessToken)
				require.Equal(t, requested, fixture.exchanger.gotReq.RequestedTokenType)
				require.True(t, auditAuthFailureWithReason(t, fixture.logs, "token_exchange_issued_type_mismatch"))
				require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
				events := auditEvents(t, fixture.logs)
				require.Len(t, events, 1)
				require.Equal(t, fixture.clientID, events[0]["client_id"])
				details := events[0]["details"].(map[string]any)
				require.Equal(t, "warning", details["severity"])
				require.Equal(t, server.GrantTypeTokenExchange, details["grant_type"])
				require.Equal(t, "user@example.com", details["sub"])
				require.Equal(t, requested, details["requested_token_type"])
				require.Equal(t, issued, details["issued_token_type"])
			})
		}
	}
}
