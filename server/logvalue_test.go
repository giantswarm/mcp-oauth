package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// captureHandler is a slog.Handler that retains every record it sees so
// tests can assert on level distribution and attributes.
type captureHandler struct {
	records []slog.Record
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *captureHandler) infoLines() []string {
	var lines []string
	for _, r := range h.records {
		if r.Level == slog.LevelInfo {
			lines = append(lines, r.Message)
		}
	}
	return lines
}

func TestServer_New_EmitsNoInfo(t *testing.T) {
	h := &captureHandler{}
	logger := slog.New(h)

	_, err := New(
		mock.NewProvider(),
		memory.New(), memory.New(), memory.New(),
		&Config{Issuer: "https://oauth.example.com", RegistrationAccessToken: "tok"},
		logger,
	)
	require.NoError(t, err)

	if got := h.infoLines(); len(got) != 0 {
		t.Fatalf("server.New emitted %d INFO record(s); want 0:\n%s",
			len(got), strings.Join(got, "\n"))
	}
}

func TestServer_LogValue_ExposesEffectiveConfig(t *testing.T) {
	setup := newTestServerSetup(false)
	srv, err := setup.createServer(&Config{
		Issuer:                     "https://oauth.example.com",
		RegistrationAccessToken:    "tok",
		AllowLocalhostRedirectURIs: true,
	})
	require.NoError(t, err)

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("test", "server", srv)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	server, ok := payload["server"].(map[string]any)
	require.True(t, ok, "expected server group in log payload, got %v", payload)
	require.Equal(t, "https://oauth.example.com", server["issuer"])
	require.Equal(t, true, server["production_mode"], "applySecureDefaults should flip production_mode on")
	require.Equal(t, false, server["instrumentation_on"])

	policy, ok := server["redirect_uri_policy"].(map[string]any)
	require.True(t, ok, "expected redirect_uri_policy group, got %v", server)
	require.Equal(t, true, policy["dns_validation"])
	require.Equal(t, true, policy["dns_validation_strict"])
	require.Equal(t, true, policy["authorization_time_validation"])
	require.Equal(t, true, policy["allow_localhost"])
	require.Equal(t, false, policy["allow_private_ip"])
	require.Equal(t, false, policy["allow_link_local"])
}
