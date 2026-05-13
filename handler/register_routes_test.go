package handler

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// newRegisterRoutesHandler builds a minimal Handler + capturing logger for
// RegisterOAuthRoutes tests. A capturing logger lets us assert the "MCPPath
// alongside ResourceMetadataByPath" warn log without otherwise changing
// test-time defaults.
func newRegisterRoutesHandler(t *testing.T, cfg *server.Config) (*Handler, *memory.Store, *bytes.Buffer) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()
	if cfg == nil {
		cfg = &server.Config{Issuer: testIssuer}
	}
	srv, err := server.New(provider, store, store, store, cfg, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	return New(srv, logger), store, &buf
}

// assertMuxResolves checks that mux resolves path to a handler registered at
// exactly the expected pattern. http.ServeMux.Handler returns the registered
// pattern for a matched route, or "" for the implicit NotFoundHandler.
func assertMuxResolves(t *testing.T, mux *http.ServeMux, path, wantPattern string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	_, gotPattern := mux.Handler(req)
	if gotPattern != wantPattern {
		t.Errorf("mux.Handler(%q) pattern = %q, want %q", path, gotPattern, wantPattern)
	}
}

// assertMuxUnregistered verifies that path is not registered on mux (the
// returned pattern is empty — http.ServeMux's sentinel for NotFoundHandler).
func assertMuxUnregistered(t *testing.T, mux *http.ServeMux, path string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	_, gotPattern := mux.Handler(req)
	if gotPattern != "" {
		t.Errorf("mux.Handler(%q) unexpectedly resolved to pattern %q", path, gotPattern)
	}
}

func TestHandler_RegisterOAuthRoutes_FlowEndpoints(t *testing.T) {
	handler, _, _ := newRegisterRoutesHandler(t, nil)
	mux := http.NewServeMux()
	handler.RegisterOAuthRoutes(mux, OAuthRoutesOptions{})

	for _, tc := range []struct {
		name, path string
	}{
		{"authorize", "/oauth/authorize"},
		{"callback", "/oauth/callback"},
		{"token", "/oauth/token"},
		{"revoke", "/oauth/revoke"},
		{"register", "/oauth/register"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertMuxResolves(t, mux, tc.path, tc.path)
		})
	}
}

func TestHandler_RegisterOAuthRoutes_IncludeMetadataFalse(t *testing.T) {
	handler, _, _ := newRegisterRoutesHandler(t, nil)
	mux := http.NewServeMux()
	handler.RegisterOAuthRoutes(mux, OAuthRoutesOptions{IncludeMetadata: false})

	// Flow endpoints still registered.
	assertMuxResolves(t, mux, "/oauth/authorize", "/oauth/authorize")
	// Metadata endpoints not registered.
	assertMuxUnregistered(t, mux, "/.well-known/oauth-protected-resource")
	assertMuxUnregistered(t, mux, "/.well-known/oauth-authorization-server")
	assertMuxUnregistered(t, mux, "/.well-known/openid-configuration")
}

func TestHandler_RegisterOAuthRoutes_IncludeMetadataTrue(t *testing.T) {
	handler, _, _ := newRegisterRoutesHandler(t, nil)
	mux := http.NewServeMux()
	handler.RegisterOAuthRoutes(mux, OAuthRoutesOptions{IncludeMetadata: true})

	assertMuxResolves(t, mux, "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource")
	assertMuxResolves(t, mux, "/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server")
	assertMuxResolves(t, mux, "/.well-known/openid-configuration", "/.well-known/openid-configuration")
}

func TestHandler_RegisterOAuthRoutes_MCPPathBackCompat(t *testing.T) {
	handler, _, _ := newRegisterRoutesHandler(t, nil)
	mux := http.NewServeMux()
	handler.RegisterOAuthRoutes(mux, OAuthRoutesOptions{
		MCPPath:         "/mcp",
		IncludeMetadata: true,
	})

	assertMuxResolves(t, mux, "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource/mcp")
}

func TestHandler_RegisterOAuthRoutes_MCPPathWithResourceMetadataByPath_WarnsOnce(t *testing.T) {
	cfg := &server.Config{
		Issuer: testIssuer,
		ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
			"/mcp/files": {ScopesSupported: []string{"files:read"}},
		},
	}
	handler, _, buf := newRegisterRoutesHandler(t, cfg)
	mux := http.NewServeMux()
	handler.RegisterOAuthRoutes(mux, OAuthRoutesOptions{
		MCPPath:         "/mcp",
		IncludeMetadata: true,
	})

	got := buf.String()
	if !strings.Contains(got, "MCPPath is set alongside non-empty Config.ResourceMetadataByPath") {
		t.Errorf("expected warn log about MCPPath + ResourceMetadataByPath conflict, got: %q", got)
	}

	// Both configured and legacy paths resolve — the warn is just a visibility
	// aid, it does not suppress the MCPPath route.
	assertMuxResolves(t, mux, "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource/mcp")
	assertMuxResolves(t, mux, "/.well-known/oauth-protected-resource/mcp/files", "/.well-known/oauth-protected-resource/mcp/files")

	// Emit the warn at most once per registration (no more than one occurrence
	// in the log buffer).
	if c := strings.Count(got, "MCPPath is set alongside"); c != 1 {
		t.Errorf("expected exactly one warn log, got %d:\n%s", c, got)
	}
}

func TestHandler_RegisterOAuthRoutes_IntrospectGatedOnEnableFlag(t *testing.T) {
	t.Run("disabled-by-default", func(t *testing.T) {
		handler, _, _ := newRegisterRoutesHandler(t, nil)
		mux := http.NewServeMux()
		handler.RegisterOAuthRoutes(mux, OAuthRoutesOptions{IncludeMetadata: true})
		// ServeTokenIntrospection does not self-gate on
		// Config.EnableIntrospectionEndpoint, so the bundle must not register
		// the route unless explicitly enabled.
		assertMuxUnregistered(t, mux, "/oauth/introspect")
	})

	t.Run("enabled-via-config", func(t *testing.T) {
		cfg := &server.Config{
			Issuer:                      testIssuer,
			EnableIntrospectionEndpoint: true,
		}
		handler, _, _ := newRegisterRoutesHandler(t, cfg)
		mux := http.NewServeMux()
		handler.RegisterOAuthRoutes(mux, OAuthRoutesOptions{IncludeMetadata: true})
		assertMuxResolves(t, mux, "/oauth/introspect", "/oauth/introspect")
	})
}

func TestHandler_RegisterOAuthRoutes_NoWarnWithoutConflict(t *testing.T) {
	handler, _, buf := newRegisterRoutesHandler(t, nil)
	mux := http.NewServeMux()
	handler.RegisterOAuthRoutes(mux, OAuthRoutesOptions{
		MCPPath:         "/mcp",
		IncludeMetadata: true,
	})

	got := buf.String()
	if strings.Contains(got, "MCPPath is set alongside") {
		t.Errorf("did not expect MCPPath-conflict warn when ResourceMetadataByPath is empty; got: %q", got)
	}
}
