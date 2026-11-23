package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/server"
)

func selfIssuedSubjectValidator() server.SubjectTokenValidator {
	return &fakeSubjectValidator{identity: server.SubjectIdentity{
		Subject: "user@example.com",
		Issuer:  "https://dex.example.com",
	}}
}

func issuedExchangeToken(t *testing.T, response *http.Response, body string) string {
	t.Helper()
	require.Equal(t, http.StatusOK, response.StatusCode, body)
	var decoded struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &decoded))
	require.NotEmpty(t, decoded.AccessToken)
	return decoded.AccessToken
}

func serveToken(handler *Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeToken(recorder, request)
	return recorder
}

func TestSelfIssuedExchangeBindsAuthenticatedClient(t *testing.T) {
	for _, method := range []string{"client_secret_basic", "client_secret_post", "private_key_jwt"} {
		t.Run(method, func(t *testing.T) {
			handler, logs := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
			client := newMatrixClient(t, handler, method)
			logs.Reset()

			recorder := matrixTokenRequest(t, handler, client, method, happyExchangeForm())
			token := issuedExchangeToken(t, recorder.Result(), recorder.Body.String())

			claims, err := oidc.ParseUnverifiedClaims(token)
			require.NoError(t, err)
			require.Equal(t, client.client.ClientID, claims["client_id"])
			require.Equal(t, "user@example.com", claims["sub"])

			info, err := handler.server.ValidateToken(t.Context(), token)
			require.NoError(t, err)
			require.Equal(t, client.client.ClientID, info.ClientID)
			require.Equal(t, "user@example.com", info.ID)
			var issuance []map[string]any
			for _, record := range scanAuditRecords(t, logs) {
				if event, ok := record["audit"].(map[string]any); ok && event["event_type"] == "token_issued" {
					issuance = append(issuance, event)
				}
			}
			require.Len(t, issuance, 1)
			require.Equal(t, client.client.ClientID, issuance[0]["client_id"])
			details := issuance[0]["details"].(map[string]any)
			require.Equal(t, client.client.ClientID, details["client_id"])
			require.Equal(t, server.GrantTypeTokenExchange, details["grant_type"])
		})
	}
}

func TestSelfIssuedExchangeRejectsUnauthenticatedClients(t *testing.T) {
	handler, _ := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))

	anonymous := newTokenExchangeRequest(happyExchangeForm())
	recorder := serveToken(handler, anonymous)
	require.Equal(t, http.StatusBadRequest, recorder.Code, recorder.Body.String())
	require.Equal(t, "invalid_client", decodeErrorResponse(t, recorder).Error)
	require.Empty(t, recorder.Header().Get("WWW-Authenticate"))

	confidential := newMatrixClient(t, handler, "client_secret_basic")
	wrongSecret := matrixTokenRequest(t, handler, matrixClient{client: confidential.client, secret: "wrong"}, "client_secret_basic", happyExchangeForm())
	require.Equal(t, http.StatusUnauthorized, wrongSecret.Code, wrongSecret.Body.String())
	require.Equal(t, "invalid_client", decodeErrorResponse(t, wrongSecret).Error)

	public, _, err := handler.server.RegisterClient(t.Context(), "public", "public", "",
		[]string{"http://127.0.0.1:8080/callback"}, nil, "192.0.2.1", 100)
	require.NoError(t, err)
	form := happyExchangeForm()
	form.Set("client_id", public.ClientID)
	recorder = serveToken(handler, newTokenExchangeRequest(form))
	require.Equal(t, http.StatusBadRequest, recorder.Code, recorder.Body.String())
	require.Equal(t, "unauthorized_client", decodeErrorResponse(t, recorder).Error)

	deleted := newMatrixClient(t, handler, "client_secret_post")
	require.NoError(t, handler.server.DeleteClient(t.Context(), deleted.client.ClientID))
	recorder = matrixTokenRequest(t, handler, deleted, "client_secret_post", happyExchangeForm())
	require.Equal(t, http.StatusBadRequest, recorder.Code, recorder.Body.String())
	require.Equal(t, "invalid_client", decodeErrorResponse(t, recorder).Error)
}

func TestSelfIssuedExchangeTokenLifecycleFollowsOwningClient(t *testing.T) {
	handler, _ := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
	owner := newMatrixClient(t, handler, "client_secret_basic")
	other := newMatrixClient(t, handler, "client_secret_basic")

	issue := func(client matrixClient) string {
		recorder := matrixTokenRequest(t, handler, client, "client_secret_basic", happyExchangeForm())
		return issuedExchangeToken(t, recorder.Result(), recorder.Body.String())
	}
	revoke := func(client matrixClient, token string) {
		recorder := matrixClientRequest(t, handler, server.EndpointPathRevoke, client, "client_secret_basic", url.Values{"token": {token}})
		require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	}

	revokedByOwner, revokedByOther, retired, otherClientToken := issue(owner), issue(owner), issue(owner), issue(other)

	revoke(other, revokedByOther)
	_, err := handler.server.ValidateToken(t.Context(), revokedByOther)
	require.NoError(t, err, "a client other than the owner must not revoke the token")

	revoke(owner, revokedByOwner)
	_, err = handler.server.ValidateToken(t.Context(), revokedByOwner)
	require.Error(t, err)

	require.NoError(t, handler.server.DeleteClient(t.Context(), owner.client.ClientID))
	_, err = handler.server.ValidateToken(t.Context(), retired)
	require.Error(t, err)
	_, err = handler.server.ValidateToken(t.Context(), otherClientToken)
	require.NoError(t, err, "deleting one client must not invalidate another client's tokens")
}

func TestSelfIssuedExchangeAdmitsOnlyRegisteredConfidentialClients(t *testing.T) {
	handler, logs := setupTokenExchangeHandler(t, withSubjectValidator(selfIssuedSubjectValidator()))
	confidential := newMatrixClient(t, handler, "client_secret_basic")
	retired := newMatrixClient(t, handler, "client_secret_basic")
	require.NoError(t, handler.server.DeleteClient(t.Context(), retired.client.ClientID))
	public, _, err := handler.server.RegisterClient(t.Context(), "public", "public", "",
		[]string{"http://127.0.0.1:8080/callback"}, nil, "192.0.2.1", 100)
	require.NoError(t, err)

	exchange := func(clientID string) (*server.TokenExchangeResult, error) {
		return handler.server.SelfIssuedExchange(t.Context(), server.SelfIssuedExchangeRequest{
			SubjectExchange: server.SubjectExchange{
				Subject: server.TypedToken{Token: "subject", Type: server.SubjectTokenTypeIDToken},
				Scope:   "read",
			},
			ClientID: clientID,
		})
	}

	for _, test := range []struct {
		name, clientID, reason string
	}{
		{"none", "", "token_exchange_client_required"},
		{"unknown", "unregistered", "token_exchange_client_unknown"},
		{"public", public.ClientID, "token_exchange_public_client"},
		{"deleted", retired.client.ClientID, "token_exchange_client_unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			logs.Reset()
			_, err := exchange(test.clientID)
			require.ErrorIs(t, err, server.ErrExchangeClientRequired)
			events := auditEvents(t, logs)
			require.Len(t, events, 1)
			require.Equal(t, test.clientID, events[0]["client_id"])
			details := events[0]["details"].(map[string]any)
			require.Equal(t, test.reason, details["reason"])
			require.Equal(t, "warning", details["severity"])
			require.NotEmpty(t, details["session_id"])
		})
	}

	result, err := exchange(confidential.client.ClientID)
	require.NoError(t, err)
	claims, err := oidc.ParseUnverifiedClaims(result.AccessToken)
	require.NoError(t, err)
	require.Equal(t, confidential.client.ClientID, claims["client_id"])
}
