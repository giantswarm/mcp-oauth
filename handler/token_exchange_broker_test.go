package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type stubExchanger struct {
	gotReq *server.ExchangerRequest
	result *server.ExchangerResult
	err    error
}

func (f *stubExchanger) Exchange(_ context.Context, req *server.ExchangerRequest) (*server.ExchangerResult, error) {
	f.gotReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

type brokeredExchangeHarness struct {
	handler      *Handler
	srv          *server.Server
	logs         *bytes.Buffer
	clientID     string
	clientSecret string
}

// setupBrokeredExchangeHandler builds a handler with a registered confidential
// client, a happy-path subject validator, and (unless exchanger is nil) the
// given Exchanger. allowedAudiences populates the registered client's
// audience allowlist.
func setupBrokeredExchangeHandler(t *testing.T, exchanger server.Exchanger, allowedAudiences []string, clientType string) *brokeredExchangeHarness {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	serverCfg := &server.Config{
		Issuer:                      "https://broker.example.com",
		DisableNonceEchoRequirement: true,
		DisableDNSValidation:        true,
	}

	validator := &fakeSubjectValidator{identity: server.SubjectIdentity{
		Subject: "user@example.com",
		Issuer:  "https://dex.example.com",
	}}

	srvOpts := []server.Option{
		server.WithAuditor(security.NewAuditor(logger, true)),
		server.WithSubjectTokenValidator(server.SubjectTokenTypeIDToken, validator),
	}
	if exchanger != nil {
		srvOpts = append(srvOpts, server.WithExchanger(exchanger))
	}

	srv, err := server.New(mock.NewProvider(), store, store, store, serverCfg, logger, srvOpts...)
	require.NoError(t, err)

	client, clientSecret, err := srv.RegisterClient(t.Context(), "broker-client", clientType, "",
		[]string{"https://broker-client.example.com/callback"}, nil, "127.0.0.1", 10)
	require.NoError(t, err)

	if len(allowedAudiences) > 0 {
		srv.Config.TokenExchangeClientAudiences = map[string][]string{
			client.ClientID: allowedAudiences,
		}
	}

	return &brokeredExchangeHarness{
		handler:      New(srv, logger),
		srv:          srv,
		logs:         &buf,
		clientID:     client.ClientID,
		clientSecret: clientSecret,
	}
}

func brokeredExchangeForm() url.Values {
	return url.Values{
		"grant_type":         {server.GrantTypeTokenExchange},
		"subject_token":      {"subject-id-token"},
		"subject_token_type": {server.SubjectTokenTypeIDToken},
		"audience":           {"gaggle"},
		"scope":              {"openid groups"},
	}
}

func happyDownstreamResult() *server.ExchangerResult {
	return &server.ExchangerResult{
		AccessToken: "downstream-mc-token",
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Scope:       "openid groups",
	}
}

func TestHandleBrokeredTokenExchange_HappyPath(t *testing.T) {
	ex := &stubExchanger{result: happyDownstreamResult()}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "confidential")

	req := newTokenExchangeRequest(brokeredExchangeForm())
	req.SetBasicAuth(h.clientID, h.clientSecret)
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "downstream-mc-token", body["access_token"])
	require.Equal(t, server.SubjectTokenTypeAccessToken, body["issued_token_type"])
	require.Equal(t, "Bearer", body["token_type"])
	require.Equal(t, "openid groups", body["scope"])
	require.NotContains(t, body, "refresh_token", "brokered exchange must never issue a refresh token")

	expiresIn, ok := body["expires_in"].(float64)
	require.True(t, ok)
	require.Positive(t, expiresIn)
	require.LessOrEqual(t, expiresIn, float64(15*60), "expires_in must be bounded by the downstream token expiry")

	require.NotNil(t, ex.gotReq)
	require.Equal(t, h.clientID, ex.gotReq.ClientID)
	require.Equal(t, "gaggle", ex.gotReq.Audience)
	require.Equal(t, "subject-id-token", ex.gotReq.SubjectToken)
	require.Equal(t, "user@example.com", ex.gotReq.Subject.Subject)

	require.True(t, auditEventLogged(t, h.logs, security.EventTokenIssued),
		"missing token_issued audit in: %s", h.logs.String())
}

func TestHandleBrokeredTokenExchange_FormClientAuth(t *testing.T) {
	ex := &stubExchanger{result: happyDownstreamResult()}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "confidential")

	form := brokeredExchangeForm()
	form.Set("client_id", h.clientID)
	req := newTokenExchangeRequest(form)
	req.SetBasicAuth(h.clientID, h.clientSecret)
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
}

func requireOAuthError(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	require.Equal(t, wantStatus, w.Code, "body: %s", w.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, wantCode, body["error"])
}

func TestHandleBrokeredTokenExchange_AudienceNotAllowed(t *testing.T) {
	ex := &stubExchanger{result: happyDownstreamResult()}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "confidential")

	form := brokeredExchangeForm()
	form.Set("audience", "not-allowed")
	req := newTokenExchangeRequest(form)
	req.SetBasicAuth(h.clientID, h.clientSecret)
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	requireOAuthError(t, w, http.StatusBadRequest, constants.ErrorCodeInvalidTarget)
	require.Nil(t, ex.gotReq, "exchanger must not run for a disallowed audience")
	require.True(t, auditAuthFailureWithReason(t, h.logs, "token_exchange_audience_not_allowed"),
		"missing audit in: %s", h.logs.String())
}

func TestHandleBrokeredTokenExchange_NoExchangerConfigured(t *testing.T) {
	h := setupBrokeredExchangeHandler(t, nil, []string{"gaggle"}, "confidential")

	req := newTokenExchangeRequest(brokeredExchangeForm())
	req.SetBasicAuth(h.clientID, h.clientSecret)
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	requireOAuthError(t, w, http.StatusBadRequest, constants.ErrorCodeInvalidTarget)
}

func TestHandleBrokeredTokenExchange_MissingClientAuth(t *testing.T) {
	ex := &stubExchanger{result: happyDownstreamResult()}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "confidential")

	req := newTokenExchangeRequest(brokeredExchangeForm())
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	requireOAuthError(t, w, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
	require.Nil(t, ex.gotReq)
}

func TestHandleBrokeredTokenExchange_WrongClientSecret(t *testing.T) {
	ex := &stubExchanger{result: happyDownstreamResult()}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "confidential")

	req := newTokenExchangeRequest(brokeredExchangeForm())
	req.SetBasicAuth(h.clientID, "wrong-secret")
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	requireOAuthError(t, w, http.StatusUnauthorized, constants.ErrorCodeInvalidClient)
	require.Nil(t, ex.gotReq)
}

func TestHandleBrokeredTokenExchange_PublicClientRejected(t *testing.T) {
	ex := &stubExchanger{result: happyDownstreamResult()}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "public")

	form := brokeredExchangeForm()
	form.Set("client_id", h.clientID)
	req := newTokenExchangeRequest(form)
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	requireOAuthError(t, w, http.StatusBadRequest, constants.ErrorCodeUnauthorizedClient)
	require.Nil(t, ex.gotReq)
}

func TestHandleBrokeredTokenExchange_DPoPRejected(t *testing.T) {
	ex := &stubExchanger{result: happyDownstreamResult()}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "confidential")

	req := newTokenExchangeRequest(brokeredExchangeForm())
	req.SetBasicAuth(h.clientID, h.clientSecret)
	req.Header.Set("DPoP", "some-proof")
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	requireOAuthError(t, w, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
	require.Nil(t, ex.gotReq)
}

func TestHandleBrokeredTokenExchange_DownstreamFailure(t *testing.T) {
	ex := &stubExchanger{err: context.DeadlineExceeded}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "confidential")

	req := newTokenExchangeRequest(brokeredExchangeForm())
	req.SetBasicAuth(h.clientID, h.clientSecret)
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	requireOAuthError(t, w, http.StatusBadRequest, constants.ErrorCodeInvalidGrant)
}

// The local-issuance path (no audience parameter) must be unaffected by the
// presence of an Exchanger: resource stays mandatory and the local JWT flow
// handles the request.
func TestHandleBrokeredTokenExchange_NoAudienceFallsBackToLocalPath(t *testing.T) {
	ex := &stubExchanger{result: happyDownstreamResult()}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "confidential")

	form := brokeredExchangeForm()
	form.Del("audience")
	req := newTokenExchangeRequest(form)
	req.SetBasicAuth(h.clientID, h.clientSecret)
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	// Local path requires resource; this proves the broker path was not taken.
	requireOAuthError(t, w, http.StatusBadRequest, constants.ErrorCodeInvalidRequest)
	require.Nil(t, ex.gotReq)
}

func TestHandleBrokeredTokenExchange_ActorTokenForwarded(t *testing.T) {
	ex := &stubExchanger{result: happyDownstreamResult()}
	h := setupBrokeredExchangeHandler(t, ex, []string{"gaggle"}, "confidential")

	form := brokeredExchangeForm()
	form.Set("actor_token", "actor-jwt")
	form.Set("actor_token_type", server.SubjectTokenTypeIDToken)
	req := newTokenExchangeRequest(form)
	req.SetBasicAuth(h.clientID, h.clientSecret)
	w := httptest.NewRecorder()
	h.handler.ServeToken(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	require.NotNil(t, ex.gotReq)
	require.Equal(t, "actor-jwt", ex.gotReq.ActorToken)
	require.Equal(t, server.SubjectTokenTypeIDToken, ex.gotReq.ActorTokenType)
	// Actor identity comes from the same fakeSubjectValidator used for the subject.
	require.NotNil(t, ex.gotReq.Actor)
}
