package valkey

import (
	"log/slog"

	"github.com/giantswarm/mcp-oauth/storage"
)

// LogValue implements [slog.LogValuer] so callers can emit a structured
// snapshot of the store's posture:
//
//	logger.Info("storage initialized", "store", store)
func (s *Store) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("backend", storage.BackendValkey),
		slog.Bool("encryption_at_rest", s.encryptor != nil && s.encryptor.IsEnabled()),
		slog.Bool("instrumentation_on", s.inst != nil),
	)
}
