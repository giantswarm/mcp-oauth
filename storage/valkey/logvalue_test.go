package valkey

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// TestStore_LogValue_ReflectsPosture exercises Store.LogValue without
// opening a live Valkey connection — LogValue reads only struct fields,
// so a directly-constructed Store{} is sufficient.
func TestStore_LogValue_ReflectsPosture(t *testing.T) {
	store := &Store{}

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("snapshot", "store", store)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))

	got, ok := payload["store"].(map[string]any)
	require.True(t, ok, "expected store group, got %v", payload)
	require.Equal(t, storage.BackendValkey, got["backend"])
	require.Equal(t, false, got["encryption_at_rest"])
	require.Equal(t, false, got["instrumentation_on"])

	key, err := security.GenerateKey()
	require.NoError(t, err)
	enc, err := security.NewEncryptor(key)
	require.NoError(t, err)
	store.encryptor = enc

	buf.Reset()
	logger.Info("snapshot", "store", store)
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))
	got = payload["store"].(map[string]any)
	require.Equal(t, true, got["encryption_at_rest"])
	require.Equal(t, false, got["instrumentation_on"])

	store.inst = &instrumentation.Instrumentation{}

	buf.Reset()
	logger.Info("snapshot", "store", store)
	require.NoError(t, json.Unmarshal(buf.Bytes(), &payload))
	got = payload["store"].(map[string]any)
	require.Equal(t, true, got["instrumentation_on"])
}
