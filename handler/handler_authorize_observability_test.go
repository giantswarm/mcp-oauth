package handler

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

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// observabilityEnv bundles the capture surfaces tests assert against:
// span attributes/status via a tracetest.SpanRecorder, and audit-event JSON
// records via a slog handler writing to auditBuf.
type observabilityEnv struct {
	handler  *Handler
	provider *mock.Provider
	recorder *tracetest.SpanRecorder
	auditBuf *bytes.Buffer
}

func newObservabilityEnv(t *testing.T) *observabilityEnv {
	t.Helper()

	store := memory.New()
	t.Cleanup(store.Stop)

	provider := mock.NewProvider()

	auditBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(auditBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditor := security.NewAuditor(logger, true)

	// Propagate a no-op Instrumentation into storage so its startStorageSpan
	// uses the noop tracer instead of falling back to trace.SpanFromContext —
	// the latter would let storage's defer span.End() end the handler's
	// parent span and erase the attributes the test pins.
	inst, err := instrumentation.New(instrumentation.Config{Enabled: false})
	require.NoError(t, err)

	srv, err := server.New(
		provider, store, store, store,
		&server.Config{Issuer: testIssuer, DisableNonceEchoRequirement: true},
		logger,
		server.WithAuditor(auditor),
		server.WithInstrumentation(inst),
	)
	require.NoError(t, err)

	handler := New(srv, logger)

	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	handler.tracer = tp.Tracer("http")

	return &observabilityEnv{
		handler:  handler,
		provider: provider,
		recorder: recorder,
		auditBuf: auditBuf,
	}
}

// soleEndedSpan returns the single span finished during the call. Fails the
// test when zero or multiple spans were emitted so drift in span boundaries
// surfaces in the same assertion path that pins the attributes.
func (e *observabilityEnv) soleEndedSpan(t *testing.T) sdktrace.ReadOnlySpan {
	t.Helper()
	spans := e.recorder.Ended()
	require.Lenf(t, spans, 1, "expected exactly 1 ended span, got %d", len(spans))
	return spans[0]
}

func spanAttr(t *testing.T, span sdktrace.ReadOnlySpan, key string) (string, bool) {
	t.Helper()
	for _, a := range span.Attributes() {
		if string(a.Key) == key {
			return a.Value.AsString(), true
		}
	}
	return "", false
}

// requireSpanError asserts span.Status() is codes.Error with the given
// description, plus oauth.error == errorCode and a non-empty
// oauth.error_description.
func requireSpanError(t *testing.T, span sdktrace.ReadOnlySpan, wantStatusDesc, wantErrorCode string) {
	t.Helper()
	require.Equal(t, codes.Error, span.Status().Code, "span status code")
	require.Equal(t, wantStatusDesc, span.Status().Description, "span status description")

	gotCode, ok := spanAttr(t, span, "oauth.error")
	require.True(t, ok, "oauth.error attribute missing")
	require.Equal(t, wantErrorCode, gotCode)

	gotDesc, ok := spanAttr(t, span, "oauth.error_description")
	require.True(t, ok, "oauth.error_description attribute missing")
	require.NotEmpty(t, gotDesc, "oauth.error_description must be non-empty")
}

// auditRecord is the shape security.Auditor.LogEvent emits via slog: each
// audit field lives under the "audit" group.
type auditRecord struct {
	Audit struct {
		EventType  string `json:"event_type"`
		UserIDHash string `json:"user_id_hash"`
		ClientID   string `json:"client_id"`
		IPAddress  string `json:"ip_address"`
		Details    struct {
			Reason string `json:"reason"`
		} `json:"details"`
	} `json:"audit"`
}

// requireAuthFailureAudit asserts an EventAuthFailure record with the given
// reason, populated clientID, and an empty userID (no user context at the
// /authorize gate). security.hashForLogging("") returns the sentinel
// "<empty>", which is what the userID hash field will contain when no user
// context is known.
const emptyUserIDHashSentinel = "<empty>"

func requireAuthFailureAudit(t *testing.T, buf *bytes.Buffer, wantClientID, wantReason string) {
	t.Helper()

	for _, line := range bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec auditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.Audit.EventType != security.EventAuthFailure {
			continue
		}
		if rec.Audit.Details.Reason != wantReason {
			continue
		}
		require.Equal(t, wantClientID, rec.Audit.ClientID, "audit clientID")
		require.Equal(t, emptyUserIDHashSentinel, rec.Audit.UserIDHash, "userID must be empty at /authorize gate")
		return
	}
	t.Fatalf("no auth_failure audit with reason=%q found in:\n%s", wantReason, buf.String())
}

// TestHandler_ServeAuthorization_StateMissing_Observability pins the span
// attributes + status for the state-missing redirect branch.
func TestHandler_ServeAuthorization_StateMissing_Observability(t *testing.T) {
	env := newObservabilityEnv(t)

	client, _, err := env.handler.server.RegisterClient(
		context.Background(),
		"obs-client", "confidential", "",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.0.2.1", 10,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"https://example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)

	w := httptest.NewRecorder()
	env.handler.ServeAuthorization(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	requireSpanError(t, env.soleEndedSpan(t), "state missing", oauth.ErrorCodeInvalidRequest)
}

func TestHandler_ServeAuthorization_StateTooShort_Observability(t *testing.T) {
	env := newObservabilityEnv(t)

	client, _, err := env.handler.server.RegisterClient(
		context.Background(),
		"obs-client", "confidential", "",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.0.2.1", 10,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"https://example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {"short"},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)

	w := httptest.NewRecorder()
	env.handler.ServeAuthorization(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	requireSpanError(t, env.soleEndedSpan(t), "state too short", oauth.ErrorCodeInvalidRequest)
}

func TestHandler_ServeAuthorization_UnsupportedResponseType_Observability(t *testing.T) {
	env := newObservabilityEnv(t)

	client, _, err := env.handler.server.RegisterClient(
		context.Background(),
		"obs-client", "confidential", "",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.0.2.1", 10,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"https://example.com/callback"},
		"response_type":         {"token"},
		"scope":                 {"openid"},
		"state":                 {testutil.GenerateRandomString(43)},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)

	w := httptest.NewRecorder()
	env.handler.ServeAuthorization(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	requireSpanError(t, env.soleEndedSpan(t), "unsupported response_type", oauth.ErrorCodeUnsupportedResponseType)
}

// TestHandler_ServeAuthorization_InvalidProviderURL_Observability triggers
// the "invalid authorization URL" branch of respondAuthorizationError via a
// mock provider returning a non-http(s) URL, and pins the resulting span
// shape.
func TestHandler_ServeAuthorization_InvalidProviderURL_Observability(t *testing.T) {
	env := newObservabilityEnv(t)

	env.provider.AuthorizationURLFunc = func(state, codeChallenge, codeChallengeMethod string, _ []string, _ *providers.AuthorizationURLOptions) string {
		return "javascript:alert(1)"
	}

	client, _, err := env.handler.server.RegisterClient(
		context.Background(),
		"obs-client", "confidential", "",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.0.2.1", 10,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"https://example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {testutil.GenerateRandomString(43)},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)

	w := httptest.NewRecorder()
	env.handler.ServeAuthorization(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	requireSpanError(t, env.soleEndedSpan(t), "invalid authorization URL", oauth.ErrorCodeServerError)
}

// TestHandler_ServeAuthorization_InvalidClient_AuditEvent pins the audit
// emission on the ValidateRedirectURIForAuthorization failure: an unknown
// client must yield an auth_failure record with reason=invalid_client,
// clientID populated, userID empty.
func TestHandler_ServeAuthorization_InvalidClient_AuditEvent(t *testing.T) {
	env := newObservabilityEnv(t)

	const unknownClientID = "client-does-not-exist"
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {unknownClientID},
		"redirect_uri":          {"https://example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {testutil.GenerateRandomString(43)},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)

	w := httptest.NewRecorder()
	env.handler.ServeAuthorization(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, "unknown client must JSON-error (no redirect target)")
	requireAuthFailureAudit(t, env.auditBuf, unknownClientID, oauth.ErrorCodeInvalidClient)
}

// TestHandler_ServeAuthorization_InvalidRedirectURI_AuditEvent pins the
// audit emission on a known client with an unregistered redirect_uri.
func TestHandler_ServeAuthorization_InvalidRedirectURI_AuditEvent(t *testing.T) {
	env := newObservabilityEnv(t)

	client, _, err := env.handler.server.RegisterClient(
		context.Background(),
		"obs-client", "confidential", "",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"192.0.2.1", 10,
	)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {"https://attacker.example/landing"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"state":                 {testutil.GenerateRandomString(43)},
		"code_challenge":        {"test-challenge"},
		"code_challenge_method": {"S256"},
	}.Encode(), nil)

	w := httptest.NewRecorder()
	env.handler.ServeAuthorization(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Empty(t, w.Header().Get("Location"), "unregistered redirect_uri must not redirect")
	requireAuthFailureAudit(t, env.auditBuf, client.ClientID, oauth.ErrorCodeInvalidRedirectURI)
}

// TestHandler_ServeCallback_IPRateLimit_AuditEmitted pins the audit-event
// side-effect of the new /oauth/callback gate (issue #339). The 429 path
// itself is covered by the table-driven test; this test proves the audit
// surface a downstream SIEM dashboard relies on still fires for the new
// endpoint.
func TestHandler_ServeCallback_IPRateLimit_AuditEmitted(t *testing.T) {
	store := memory.New()
	t.Cleanup(store.Stop)

	auditBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(auditBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditor := security.NewAuditor(logger, true)

	srv, err := server.New(
		mock.NewProvider(), store, store, store,
		&server.Config{Issuer: testIssuer},
		logger,
		server.WithAuditor(auditor),
	)
	require.NoError(t, err)

	srv.RateLimiter = security.NewRateLimiter(0, 1, nil) // 1 token, no refill
	t.Cleanup(srv.RateLimiter.Stop)

	handler := New(srv, logger)

	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+testStateMinLen+"&code=x", nil)
		req.RemoteAddr = testClientRemoteAddr
		w := httptest.NewRecorder()
		handler.ServeCallback(w, req)
		return w
	}

	send() // consume the single bucket token
	w := send()

	require.Equal(t, http.StatusTooManyRequests, w.Code)
	require.NotEmpty(t, w.Header().Get("Retry-After"), "Retry-After header missing on 429")

	var found bool
	for _, line := range bytes.Split(bytes.TrimRight(auditBuf.Bytes(), "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if strings.Contains(string(line), `"event_type":"`+security.EventRateLimitExceeded+`"`) {
			found = true
			break
		}
	}
	require.True(t, found, "expected %s audit event for /oauth/callback rate-limit reject; got:\n%s", security.EventRateLimitExceeded, auditBuf.String())
}
