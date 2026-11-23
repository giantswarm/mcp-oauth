package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/internal/helpers"
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
	for _, flow := range []string{"local", "brokered"} {
		t.Run(flow, func(t *testing.T) {
			fixture := newExchangeContractFixture(t, flow == "brokered")
			for _, scheme := range []string{"Bearer", "Digest", "Basic"} {
				for _, withClientID := range []bool{false, true} {
					name := scheme + "/without client_id"
					if withClientID {
						name = scheme + "/with client_id"
					}
					t.Run(name, func(t *testing.T) {
						form := fixture.form()
						if withClientID {
							form.Set("client_id", fixture.clientID)
						}
						request := newTokenExchangeRequest(form)
						request.Header.Set("Authorization", scheme+" invalid-client-credential")
						fixture.logs.Reset()
						response := serveToken(fixture.handler, request)
						requireOAuthError(t, response, http.StatusUnauthorized, constants.ErrorCodeInvalidClient)
						require.Equal(t, scheme+` realm="oauth"`, response.Header().Get("WWW-Authenticate"))
						require.True(t, auditAuthFailureWithReason(t, fixture.logs, "client_authentication_failed"))
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

func TestTokenExchangeHeaderAuthenticationRejectsMixedCredentials(t *testing.T) {
	for _, flow := range []string{"local", "brokered"} {
		t.Run(flow, func(t *testing.T) {
			fixture := newExchangeContractFixture(t, flow == "brokered")
			for _, parameter := range []string{"client_secret", "client_id", "client_assertion"} {
				t.Run(parameter, func(t *testing.T) {
					form := fixture.form()
					form.Set(parameter, "credential")
					if parameter == "client_id" {
						form.Add(parameter, "another-client")
					}
					request := newTokenExchangeRequest(form)
					request.Header.Set("Authorization", "Bearer invalid-client-credential")
					fixture.logs.Reset()
					response := serveToken(fixture.handler, request)
					requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
					require.Empty(t, response.Header().Get("WWW-Authenticate"))
					require.True(t, auditAuthFailureWithReason(t, fixture.logs, "client_credentials_malformed"))
					require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
					if fixture.exchanger != nil {
						require.Nil(t, fixture.exchanger.gotReq)
					}
				})
			}
		})
	}
}

func TestTokenExchangeKeepsSubjectIdentityInAudit(t *testing.T) {
	for _, flow := range []string{"local", "brokered"} {
		t.Run(flow, func(t *testing.T) {
			fixture := newExchangeContractFixture(t, flow == "brokered")
			fixture.logs.Reset()
			response := fixture.request(fixture.form())
			require.Equal(t, http.StatusOK, response.Code)
			issuanceAudited := false
			for _, record := range scanAuditRecords(t, fixture.logs) {
				if audit, ok := record["audit"].(map[string]any); ok {
					if audit["event_type"] == security.EventTokenIssued {
						require.Equal(t, helpers.HashForLogging("user@example.com"), audit["user_id_hash"])
						issuanceAudited = true
					}
					continue
				}
				encoded, err := json.Marshal(record)
				require.NoError(t, err)
				require.NotContains(t, string(encoded), "user@example.com")
			}
			require.True(t, issuanceAudited)
		})
	}
}

func TestTokenExchangeUnsupportedTypesUseASCIIErrorDescriptions(t *testing.T) {
	for _, flow := range []string{"local", "brokered"} {
		t.Run(flow, func(t *testing.T) {
			fixture := newExchangeContractFixture(t, flow == "brokered")
			for _, role := range []string{"subject", "actor"} {
				t.Run(role, func(t *testing.T) {
					form := fixture.form()
					if role == "actor" {
						form.Set("actor_token", "actor-jwt")
					}
					form.Set(role+"_token_type", "urn:example:\"\\☃")
					fixture.logs.Reset()
					response := fixture.request(form)
					requireOAuthError(t, response, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
					description := decodeErrorResponse(t, response).ErrorDescription
					require.NotEmpty(t, description)
					for _, character := range description {
						require.True(t, character >= 0x20 && character <= 0x21 || character >= 0x23 && character <= 0x5b || character >= 0x5d && character <= 0x7e,
							"error_description contains forbidden character %U", character)
					}
					require.True(t, auditAuthFailureWithReason(t, fixture.logs, "unsupported_"+role+"_token_type"))
					require.False(t, auditEventLogged(t, fixture.logs, security.EventTokenIssued))
					if fixture.exchanger != nil {
						require.Nil(t, fixture.exchanger.gotReq)
					}
				})
			}
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
			if issued == server.SubjectTokenTypeJWT {
				fixture.exchanger.result.TokenType = "N_A"
			}
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
					if outputType == server.SubjectTokenTypeJWT {
						fixture.exchanger.result.TokenType = "N_A"
					}
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
