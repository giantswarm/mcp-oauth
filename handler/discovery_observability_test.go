package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

func findSpan(t *testing.T, sr *tracetest.SpanRecorder, name string) tracetest.SpanStub {
	t.Helper()
	for _, s := range tracetest.SpanStubsFromReadOnlySpans(sr.Ended()) {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no span named %q recorded; got %v", name, spanNames(sr))
	return tracetest.SpanStub{}
}

func spanNames(sr *tracetest.SpanRecorder) []string {
	var names []string
	for _, s := range tracetest.SpanStubsFromReadOnlySpans(sr.Ended()) {
		names = append(names, s.Name)
	}
	return names
}

func spanAttr(span tracetest.SpanStub, key attribute.Key) (string, bool) {
	for _, kv := range span.Attributes {
		if kv.Key == key {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

// TestDiscoveryHandlers_SpanNames verifies that each discovery endpoint opens
// exactly one top-level span with the expected name and oauth.discovery attribute.
func TestDiscoveryHandlers_SpanNames(t *testing.T) {
	type tc struct {
		name          string
		url           string
		serve         func(h *Handler, w http.ResponseWriter, r *http.Request)
		wantSpan      string
		wantDiscovery string
	}

	jwtHandler := newJWTModeHandler(t)

	cases := []tc{
		{
			name:          "AS metadata",
			url:           "/.well-known/oauth-authorization-server",
			serve:         func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeAuthorizationServerMetadata(w, r) },
			wantSpan:      "oauth.http.discovery.as",
			wantDiscovery: "authorization_server",
		},
		{
			name:          "OIDC configuration",
			url:           "/.well-known/openid-configuration",
			serve:         func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeOpenIDConfiguration(w, r) },
			wantSpan:      "oauth.http.discovery.oidc",
			wantDiscovery: "openid_configuration",
		},
		{
			name:          "Protected resource metadata",
			url:           "/.well-known/oauth-protected-resource",
			serve:         func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ServeProtectedResourceMetadata(w, r) },
			wantSpan:      "oauth.http.discovery.prm",
			wantDiscovery: "protected_resource",
		},
		{
			name:          "JWKS",
			url:           server.EndpointPathJWKS,
			serve:         func(h *Handler, w http.ResponseWriter, r *http.Request) { jwtHandler.ServeJWKS(w, r) },
			wantSpan:      "oauth.http.jwks",
			wantDiscovery: "jwks",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var h *Handler
			if tc.wantSpan == "oauth.http.jwks" {
				h = jwtHandler
			} else {
				handler, store := setupTestHandler(t)
				defer store.Stop()
				h = handler
			}

			sr := installSpanRecorder(t, h)

			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			w := httptest.NewRecorder()
			tc.serve(h, w, req)

			require.Equal(t, http.StatusOK, w.Code)

			span := findSpan(t, sr, tc.wantSpan)

			val, ok := spanAttr(span, attribute.Key(instrumentation.AttrDiscovery))
			require.True(t, ok, "oauth.discovery attribute missing on span %q", tc.wantSpan)
			require.Equal(t, tc.wantDiscovery, val)
		})
	}
}

// TestServeProtectedResourceMetadata_RateLimitAnnotatesSpan verifies that when
// the IP rate limit is exhausted on PRM, the handler records the 429 on the span.
func TestServeProtectedResourceMetadata_RateLimitAnnotatesSpan(t *testing.T) {
	srv := newOAuthTestServer(t)
	// burst=1, rate=0: first request passes, second is rejected.
	srv.RateLimiter = security.NewRateLimiter(0, 1, nil)
	t.Cleanup(srv.RateLimiter.Stop)

	h := New(srv, nil)
	sr := installSpanRecorder(t, h)

	hit := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		h.ServeProtectedResourceMetadata(w, req)
		return w
	}

	require.Equal(t, http.StatusOK, hit().Code, "first request should pass")
	w429 := hit()
	require.Equal(t, http.StatusTooManyRequests, w429.Code, "second request should be rate-limited")

	// Find the rejected span — it must carry an error status.
	var rejectedSpan *tracetest.SpanStub
	for _, s := range tracetest.SpanStubsFromReadOnlySpans(sr.Ended()) {
		if s.Name == "oauth.http.discovery.prm" && s.Status.Code == codes.Error {
			copy := s
			rejectedSpan = &copy
			break
		}
	}
	require.NotNil(t, rejectedSpan, "no oauth.http.discovery.prm span with error status found after 429")
}
