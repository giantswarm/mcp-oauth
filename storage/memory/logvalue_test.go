package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

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

func TestStore_Construction_EmitsNoInfo(t *testing.T) {
	h := &captureHandler{}
	logger := slog.New(h)

	key, err := security.GenerateKey()
	require.NoError(t, err)
	enc, err := security.NewEncryptor(key)
	require.NoError(t, err)

	_ = New(
		WithLogger(logger),
		WithRevokedFamilyRetentionDays(30),
		WithEncryptor(enc),
	)

	if got := h.infoLines(); len(got) != 0 {
		t.Fatalf("store construction emitted %d INFO record(s); want 0:\n%s",
			len(got), strings.Join(got, "\n"))
	}
}

func TestStore_LogValue_ReflectsPosture(t *testing.T) {
	store := New()

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("snapshot", "store", store)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	got, ok := payload["store"].(map[string]any)
	require.True(t, ok, "expected store group, got %v", payload)
	require.Equal(t, storage.BackendMemory, got["backend"])
	require.Equal(t, false, got["encryption_at_rest"])
	require.Equal(t, false, got["instrumentation_on"])

	// A store built with an encryptor reports encryption_at_rest=true.
	key, err := security.GenerateKey()
	require.NoError(t, err)
	enc, err := security.NewEncryptor(key)
	require.NoError(t, err)
	storeWithEnc := New(WithEncryptor(enc))
	defer storeWithEnc.Stop()

	buf.Reset()
	logger.Info("snapshot", "store", storeWithEnc)
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))
	got = payload["store"].(map[string]any)
	require.Equal(t, true, got["encryption_at_rest"])
}
