package handler

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// installSpanRecorder swaps the handler's tracer for an in-memory recorder.
// White-box: handler.tracer is unexported but accessible within package handler.
func installSpanRecorder(t *testing.T, h *Handler) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })
	h.tracer = tp.Tracer("http")
	return sr
}

// installAuditCapture wires a JSON-buffer auditor onto the server.
func installAuditCapture(h *Handler) *bytes.Buffer {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	h.server.Auditor = security.NewAuditor(logger, true)
	return &buf
}

// findAuthSpan returns the recorded "oauth.http.authorization" span.
func findAuthSpan(t *testing.T, sr *tracetest.SpanRecorder) tracetest.SpanStub {
	t.Helper()
	for _, s := range tracetest.SpanStubsFromReadOnlySpans(sr.Ended()) {
		if s.Name == "oauth.http.authorization" {
			return s
		}
	}
	t.Fatal("no oauth.http.authorization span recorded")
	return tracetest.SpanStub{}
}

// spanAttrString finds a string attribute by key in a span stub.
func spanAttrString(span tracetest.SpanStub, key attribute.Key) (string, bool) {
	for _, kv := range span.Attributes {
		if kv.Key == key {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

// parseAuditGroup parses the first auth_failure audit line from a JSON log buffer.
func parseAuditGroup(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		audit, ok := record["audit"].(map[string]any)
		if !ok {
			continue
		}
		if audit["event_type"] == security.EventAuthFailure {
			return audit
		}
	}
	t.Fatal("no auth_failure audit event logged")
	return nil
}

// registerMinimalClient registers a client with a single redirect URI and returns its ID.
func registerMinimalClient(t *testing.T, h *Handler) string {
	t.Helper()
	client, _, err := h.server.RegisterClient(
		t.Context(),
		"test-client",
		"confidential",
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid"},
		"127.0.0.1",
		10,
	)
	require.NoError(t, err)
	return client.ClientID
}

// TestServeAuthorization_RespondAuthorizationError_PinsSpanAttributes asserts that every
// respondAuthorizationError site in ServeAuthorization sets oauth.error, oauth.error_description,
// and the span error status. A test break here means a dashboard label has drifted.
func TestServeAuthorization_RespondAuthorizationError_PinsSpanAttributes(t *testing.T) {
	const (
		redirectParam = "&redirect_uri=https://example.com/callback"
		responseCode  = "&response_type=code"
		validPKCE     = "&code_challenge=testchallenge&code_challenge_method=S256"
		// 36 chars, well above the 24-char minimum.
		validState = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)

	t.Run("state missing", func(t *testing.T) {
		handler, store := setupTestHandler(t)
		defer store.Stop()
		sr := installSpanRecorder(t, handler)
		clientID := registerMinimalClient(t, handler)

		req := httptest.NewRequest(http.MethodGet,
			"/authorize?client_id="+clientID+redirectParam+responseCode,
			nil)
		handler.ServeAuthorization(httptest.NewRecorder(), req)

		span := findAuthSpan(t, sr)
		require.Equal(t, codes.Error, span.Status.Code)
		require.Equal(t, "state missing", span.Status.Description)
		v, ok := spanAttrString(span, attribute.Key(instrumentation.AttrError))
		require.True(t, ok, "span missing %s attribute", instrumentation.AttrError)
		require.Equal(t, constants.ErrorCodeInvalidRequest, v)
		_, ok = spanAttrString(span, attribute.Key(instrumentation.AttrErrorDescription))
		require.True(t, ok, "span missing %s attribute", instrumentation.AttrErrorDescription)
	})

	t.Run("state too short", func(t *testing.T) {
		handler, store := setupTestHandler(t)
		defer store.Stop()
		sr := installSpanRecorder(t, handler)
		clientID := registerMinimalClient(t, handler)

		req := httptest.NewRequest(http.MethodGet,
			"/authorize?client_id="+clientID+redirectParam+responseCode+"&state=short",
			nil)
		handler.ServeAuthorization(httptest.NewRecorder(), req)

		span := findAuthSpan(t, sr)
		require.Equal(t, codes.Error, span.Status.Code)
		require.Equal(t, "state too short", span.Status.Description)
		v, ok := spanAttrString(span, attribute.Key(instrumentation.AttrError))
		require.True(t, ok)
		require.Equal(t, constants.ErrorCodeInvalidRequest, v)
		_, ok = spanAttrString(span, attribute.Key(instrumentation.AttrErrorDescription))
		require.True(t, ok)
	})

	t.Run("unsupported response_type", func(t *testing.T) {
		handler, store := setupTestHandler(t)
		defer store.Stop()
		sr := installSpanRecorder(t, handler)
		clientID := registerMinimalClient(t, handler)

		req := httptest.NewRequest(http.MethodGet,
			"/authorize?client_id="+clientID+redirectParam+"&response_type=token&state="+validState,
			nil)
		handler.ServeAuthorization(httptest.NewRecorder(), req)

		span := findAuthSpan(t, sr)
		require.Equal(t, codes.Error, span.Status.Code)
		require.Equal(t, "unsupported response_type", span.Status.Description)
		v, ok := spanAttrString(span, attribute.Key(instrumentation.AttrError))
		require.True(t, ok)
		require.Equal(t, constants.ErrorCodeUnsupportedResponseType, v)
		_, ok = spanAttrString(span, attribute.Key(instrumentation.AttrErrorDescription))
		require.True(t, ok)
	})

	t.Run("authorization flow failed", func(t *testing.T) {
		handler, store := setupTestHandler(t)
		defer store.Stop()
		sr := installSpanRecorder(t, handler)
		clientID := registerMinimalClient(t, handler)

		// Unsupported code_challenge_method causes StartAuthorizationFlow to fail.
		req := httptest.NewRequest(http.MethodGet,
			"/authorize?client_id="+clientID+redirectParam+responseCode+
				"&state="+validState+"&code_challenge=x&code_challenge_method=BOGUS",
			nil)
		handler.ServeAuthorization(httptest.NewRecorder(), req)

		span := findAuthSpan(t, sr)
		require.Equal(t, codes.Error, span.Status.Code)
		require.Equal(t, "authorization flow failed", span.Status.Description)
		v, ok := spanAttrString(span, attribute.Key(instrumentation.AttrError))
		require.True(t, ok)
		require.Equal(t, constants.ErrorCodeServerError, v)
		_, ok = spanAttrString(span, attribute.Key(instrumentation.AttrErrorDescription))
		require.True(t, ok)
	})

	t.Run("invalid authorization URL", func(t *testing.T) {
		// Build a handler whose provider returns a non-http URL so the scheme
		// check in ServeAuthorization fires after StartAuthorizationFlow succeeds.
		store := memory.New()
		defer store.Stop()
		provider := mock.NewProvider()
		provider.AuthorizationURLFunc = func(_, _, _ string, _ []string, _ *providers.AuthorizationURLOptions) string {
			return "ftp://evil.example.com/auth"
		}
		cfg := &server.Config{
			Issuer:                      testIssuer,
			DisableNonceEchoRequirement: true,
		}
		srv, err := server.New(provider, store, store, store, cfg, nil)
		require.NoError(t, err)
		handler := New(srv, nil)

		sr := installSpanRecorder(t, handler)
		clientID := registerMinimalClient(t, handler)

		req := httptest.NewRequest(http.MethodGet,
			"/authorize?client_id="+clientID+redirectParam+responseCode+
				"&state="+validState+validPKCE,
			nil)
		handler.ServeAuthorization(httptest.NewRecorder(), req)

		span := findAuthSpan(t, sr)
		require.Equal(t, codes.Error, span.Status.Code)
		require.Equal(t, "invalid authorization URL", span.Status.Description)
		v, ok := spanAttrString(span, attribute.Key(instrumentation.AttrError))
		require.True(t, ok)
		require.Equal(t, constants.ErrorCodeServerError, v)
		_, ok = spanAttrString(span, attribute.Key(instrumentation.AttrErrorDescription))
		require.True(t, ok)
	})
}

// TestServeAuthorization_ClientValidationGate_EmitsAuditEvent asserts that the
// redirect-URI/client validation gate fires an auth_failure audit event with the
// correct reason enum and client context. A test break here means the audit reason
// string that dashboards aggregate by has drifted.
func TestServeAuthorization_ClientValidationGate_EmitsAuditEvent(t *testing.T) {
	tests := []struct {
		name         string
		setupStore   func(t *testing.T, h *Handler) string // returns the client_id to use in the request
		redirectURI  string
		wantReason   string
		wantClientID func(clientID string) string // derive the expected client_id in the audit event
	}{
		{
			name: "invalid_client — unregistered client_id",
			setupStore: func(_ *testing.T, _ *Handler) string {
				return "no-such-client"
			},
			redirectURI:  "https://example.com/callback",
			wantReason:   server.ErrorCodeInvalidClient,
			wantClientID: func(clientID string) string { return clientID },
		},
		{
			name: "invalid_redirect_uri — redirect_uri not registered for client",
			setupStore: func(t *testing.T, h *Handler) string {
				return registerMinimalClient(t, h)
			},
			redirectURI:  "https://attacker.example.com/callback",
			wantReason:   server.ErrorCodeInvalidRedirectURI,
			wantClientID: func(clientID string) string { return clientID },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()
			buf := installAuditCapture(handler)

			clientID := tt.setupStore(t, handler)

			req := httptest.NewRequest(http.MethodGet,
				"/authorize?client_id="+clientID+"&redirect_uri="+tt.redirectURI+"&response_type=code",
				nil)
			handler.ServeAuthorization(httptest.NewRecorder(), req)

			audit := parseAuditGroup(t, buf)
			require.Equal(t, security.EventAuthFailure, audit["event_type"])
			details, ok := audit["details"].(map[string]any)
			require.True(t, ok, "audit details missing")
			require.Equal(t, tt.wantReason, details["reason"])
			require.Equal(t, tt.wantClientID(clientID), audit["client_id"])
			// user_id is always hashed; empty user_id hashes to the literal "<empty>",
			// confirming no user context exists at the pre-auth validation stage.
			require.Equal(t, "<empty>", audit["user_id_hash"])
		})
	}
}
