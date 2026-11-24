package handler

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestServeOpenIDConfiguration_OpaqueModeIsDeprecated(t *testing.T) {
	tests := []struct {
		name          string
		jwtMode       bool
		serve         func(*Handler) http.HandlerFunc
		path          string
		wantDeprecate bool
	}{
		{name: "opaque mode OIDC discovery", serve: func(h *Handler) http.HandlerFunc { return h.ServeOpenIDConfiguration }, path: "/.well-known/openid-configuration", wantDeprecate: true},
		{name: "opaque mode OAuth metadata", serve: func(h *Handler) http.HandlerFunc { return h.ServeAuthorizationServerMetadata }, path: "/.well-known/oauth-authorization-server"},
		{name: "JWT mode OIDC discovery", jwtMode: true, serve: func(h *Handler) http.HandlerFunc { return h.ServeOpenIDConfiguration }, path: "/.well-known/openid-configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var handler *Handler
			if tt.jwtMode {
				handler = newJWTModeHandler(t)
			} else {
				handler, _ = setupTestHandler(t)
			}
			var logs bytes.Buffer
			handler.logger = slog.New(slog.NewTextHandler(&logs, nil))

			w := httptest.NewRecorder()
			tt.serve(handler)(w, httptest.NewRequest(http.MethodGet, tt.path, nil))

			require.Equal(t, http.StatusOK, w.Code)
			if tt.wantDeprecate {
				require.Contains(t, logs.String(), "DEPRECATED")
				require.Contains(t, logs.String(), "oauth-authorization-server")
			} else {
				require.NotContains(t, logs.String(), "DEPRECATED")
			}
		})
	}
}
