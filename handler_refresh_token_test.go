package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type refreshTestEnv struct {
	handler  *Handler
	store    *memory.Store
	auditBuf *bytes.Buffer
}

func newRefreshTestEnv(t *testing.T) *refreshTestEnv {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	auditBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(auditBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &server.Config{
		Issuer:                    testIssuer,
		AllowRefreshTokenRotation: true,
	}

	auditor := security.NewAuditor(logger, true)

	srv, err := server.New(provider, store, store, store, config, logger, server.WithAuditor(auditor))
	require.NoError(t, err)

	return &refreshTestEnv{
		handler:  NewHandler(srv, logger),
		store:    store,
		auditBuf: auditBuf,
	}
}

func (e *refreshTestEnv) registerClient(t *testing.T, clientType string) (string, string) {
	t.Helper()
	client, secret, err := e.handler.server.RegisterClient(
		context.Background(),
		"refresh-grant-test-client",
		clientType,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.0.2.10",
		10,
	)
	require.NoError(t, err)
	return client.ClientID, secret
}

func (e *refreshTestEnv) seedRefreshToken(t *testing.T, clientID, userID, familyID string, expiresAt time.Time) string {
	t.Helper()
	refreshToken := "rt-" + clientID + "-" + familyID
	err := e.store.SaveRefreshTokenWithFamily(
		context.Background(),
		refreshToken,
		userID,
		clientID,
		familyID,
		0,
		expiresAt,
	)
	require.NoError(t, err)
	err = e.store.SaveToken(context.Background(), refreshToken, &oauth2.Token{
		AccessToken:  "provider-access-" + refreshToken,
		RefreshToken: "provider-refresh-" + refreshToken,
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	})
	require.NoError(t, err)
	return refreshToken
}

// seedLegacyRefreshToken stores a refresh token without family metadata so the
// stored client_id is empty — the legacy branch in validateRefreshTokenClientBinding.
func (e *refreshTestEnv) seedLegacyRefreshToken(t *testing.T, userID string, expiresAt time.Time) string {
	t.Helper()
	refreshToken := "legacy-rt-" + userID
	err := e.store.SaveRefreshToken(context.Background(), refreshToken, userID, expiresAt)
	require.NoError(t, err)
	err = e.store.SaveToken(context.Background(), refreshToken, &oauth2.Token{
		AccessToken:  "provider-access-" + refreshToken,
		RefreshToken: "provider-refresh-" + refreshToken,
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	})
	require.NoError(t, err)
	return refreshToken
}

func doRefreshRequest(handler *Handler, form url.Values, basicAuth [2]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicAuth[0] != "" {
		request.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	recorder := httptest.NewRecorder()
	handler.ServeToken(recorder, request)
	return recorder
}

func decodeTokenResponse(t *testing.T, recorder *httptest.ResponseRecorder) TokenResponse {
	t.Helper()
	var response TokenResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	return response
}

func decodeErrorResponse(t *testing.T, recorder *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var response ErrorResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	return response
}

func auditEventLogged(t *testing.T, auditBuf *bytes.Buffer, eventType string) bool {
	t.Helper()
	for _, line := range strings.Split(strings.TrimRight(auditBuf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		audit, ok := record["audit"].(map[string]any)
		if !ok {
			continue
		}
		if audit["event_type"] == eventType {
			return true
		}
	}
	return false
}

func auditAuthFailureWithReason(t *testing.T, auditBuf *bytes.Buffer, reason string) bool {
	t.Helper()
	for _, line := range strings.Split(strings.TrimRight(auditBuf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		audit, ok := record["audit"].(map[string]any)
		if !ok {
			continue
		}
		if audit["event_type"] != security.EventAuthFailure {
			continue
		}
		details, ok := audit["details"].(map[string]any)
		if !ok {
			continue
		}
		if details["reason"] == reason {
			return true
		}
	}
	return false
}

func TestHandler_ServeToken_RefreshGrant_HappyPath_ConfidentialClient(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientID, secret := env.registerClient(t, ClientTypeConfidential)
	refreshToken := env.seedRefreshToken(t, clientID, "user-confidential", "family-conf", time.Now().Add(time.Hour))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	recorder := doRefreshRequest(env.handler, form, [2]string{clientID, secret})

	require.Equal(t, http.StatusOK, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeTokenResponse(t, recorder)
	require.NotEmpty(t, response.AccessToken)
	require.NotEmpty(t, response.RefreshToken)
	require.NotEqual(t, refreshToken, response.RefreshToken, "rotation must mint a new refresh token")
	require.Equal(t, testTokenTypeBearer, response.TokenType)
	require.True(t, auditEventLogged(t, env.auditBuf, security.EventTokenRefreshed))
}

func TestHandler_ServeToken_RefreshGrant_HappyPath_PublicClient(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientID, _ := env.registerClient(t, ClientTypePublic)
	refreshToken := env.seedRefreshToken(t, clientID, "user-public", "family-pub", time.Now().Add(time.Hour))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	recorder := doRefreshRequest(env.handler, form, [2]string{})

	require.Equal(t, http.StatusOK, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeTokenResponse(t, recorder)
	require.NotEmpty(t, response.AccessToken)
	require.NotEmpty(t, response.RefreshToken)
	require.NotEqual(t, refreshToken, response.RefreshToken)
	require.True(t, auditEventLogged(t, env.auditBuf, security.EventTokenRefreshed))
}

func TestHandler_ServeToken_RefreshGrant_ConfidentialClient_NoAuth(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientID, _ := env.registerClient(t, ClientTypeConfidential)
	refreshToken := env.seedRefreshToken(t, clientID, "user-noauth", "family-noauth", time.Now().Add(time.Hour))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	recorder := doRefreshRequest(env.handler, form, [2]string{})

	require.Equal(t, http.StatusUnauthorized, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeErrorResponse(t, recorder)
	require.Equal(t, ErrorCodeInvalidClient, response.Error)
	require.True(t, auditAuthFailureWithReason(t, env.auditBuf, "confidential_client_refresh_missing_auth"))
}

// Basic Auth client_id wins over the form client_id silently. A future change
// that adds strict mismatch detection (returning invalid_client) breaks this
// test by design.
func TestHandler_ServeToken_RefreshGrant_BasicAuthOverridesFormClientID(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientID, secret := env.registerClient(t, ClientTypeConfidential)
	refreshToken := env.seedRefreshToken(t, clientID, "user-mismatch", "family-mismatch", time.Now().Add(time.Hour))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", "form-value-does-not-match")

	recorder := doRefreshRequest(env.handler, form, [2]string{clientID, secret})

	require.Equal(t, http.StatusOK, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeTokenResponse(t, recorder)
	require.NotEmpty(t, response.AccessToken)
	require.NotEmpty(t, response.RefreshToken)
}

func TestHandler_ServeToken_RefreshGrant_WrongClientBinding(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientA, _ := env.registerClient(t, ClientTypeConfidential)
	clientB, secretB := env.registerClient(t, ClientTypeConfidential)

	refreshToken := env.seedRefreshToken(t, clientA, "user-binding", "family-binding", time.Now().Add(time.Hour))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	recorder := doRefreshRequest(env.handler, form, [2]string{clientB, secretB})

	require.Equal(t, http.StatusBadRequest, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeErrorResponse(t, recorder)
	require.Equal(t, ErrorCodeInvalidGrant, response.Error)
	require.True(t, auditEventLogged(t, env.auditBuf, security.EventRefreshTokenClientBindingMismatch))
}

func TestHandler_ServeToken_RefreshGrant_ReusedRefreshToken(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientID, secret := env.registerClient(t, ClientTypeConfidential)
	refreshToken := env.seedRefreshToken(t, clientID, "user-reuse", "family-reuse", time.Now().Add(time.Hour))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	firstRecorder := doRefreshRequest(env.handler, form, [2]string{clientID, secret})
	require.Equal(t, http.StatusOK, firstRecorder.Code, "first refresh body: %s", firstRecorder.Body.String())

	secondRecorder := doRefreshRequest(env.handler, form, [2]string{clientID, secret})
	require.Equal(t, http.StatusBadRequest, secondRecorder.Code, "second refresh body: %s", secondRecorder.Body.String())
	response := decodeErrorResponse(t, secondRecorder)
	require.Equal(t, ErrorCodeInvalidGrant, response.Error)
	require.True(t, auditEventLogged(t, env.auditBuf, security.EventRefreshTokenReuseDetected))
}

func TestHandler_ServeToken_RefreshGrant_ExpiredRefreshToken(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientID, secret := env.registerClient(t, ClientTypeConfidential)
	refreshToken := env.seedRefreshToken(t, clientID, "user-expired", "family-expired", time.Now().Add(-time.Hour))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	recorder := doRefreshRequest(env.handler, form, [2]string{clientID, secret})

	require.Equal(t, http.StatusBadRequest, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeErrorResponse(t, recorder)
	require.Equal(t, ErrorCodeInvalidGrant, response.Error)
}

func TestHandler_ServeToken_RefreshGrant_LegacyRefreshTokenWithoutBinding(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientID, secret := env.registerClient(t, ClientTypeConfidential)
	refreshToken := env.seedLegacyRefreshToken(t, "user-legacy", time.Now().Add(time.Hour))

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	recorder := doRefreshRequest(env.handler, form, [2]string{clientID, secret})

	require.Equal(t, http.StatusBadRequest, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeErrorResponse(t, recorder)
	require.Equal(t, ErrorCodeInvalidGrant, response.Error)
	require.True(t, auditEventLogged(t, env.auditBuf, security.EventRefreshTokenMissingClientBinding))
}

func TestHandler_ServeToken_RefreshGrant_MissingRefreshToken(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientID, secret := env.registerClient(t, ClientTypeConfidential)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")

	recorder := doRefreshRequest(env.handler, form, [2]string{clientID, secret})

	require.Equal(t, http.StatusBadRequest, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeErrorResponse(t, recorder)
	require.Equal(t, ErrorCodeInvalidRequest, response.Error)
}

func TestHandler_ServeToken_RefreshGrant_MissingClientID_PublicClient(t *testing.T) {
	env := newRefreshTestEnv(t)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "any-refresh-token")

	recorder := doRefreshRequest(env.handler, form, [2]string{})

	require.Equal(t, http.StatusBadRequest, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeErrorResponse(t, recorder)
	require.Equal(t, ErrorCodeInvalidRequest, response.Error)
}

func TestHandler_ServeToken_RefreshGrant_UnknownClient(t *testing.T) {
	env := newRefreshTestEnv(t)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "any-refresh-token")
	form.Set("client_id", "client-that-was-never-registered")

	recorder := doRefreshRequest(env.handler, form, [2]string{})

	require.Equal(t, http.StatusUnauthorized, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeErrorResponse(t, recorder)
	require.Equal(t, ErrorCodeInvalidClient, response.Error)
}

func TestHandler_ServeToken_RefreshGrant_BadClientSecret(t *testing.T) {
	env := newRefreshTestEnv(t)
	clientID, _ := env.registerClient(t, ClientTypeConfidential)

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", "any-refresh-token")

	recorder := doRefreshRequest(env.handler, form, [2]string{clientID, "wrong-secret"})

	require.Equal(t, http.StatusUnauthorized, recorder.Code, "body: %s", recorder.Body.String())
	response := decodeErrorResponse(t, recorder)
	require.Equal(t, ErrorCodeInvalidClient, response.Error)
}
