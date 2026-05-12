package memory

import (
	"log/slog"

	"github.com/giantswarm/mcp-oauth/storage"
)

// LogValue implements [slog.LogValuer] so callers can emit a one-shot
// structured snapshot of the store's posture:
//
//	logger.Info("storage initialized", "store", store)
func (s *Store) LogValue() slog.Value {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slog.GroupValue(
		slog.String("backend", storage.BackendMemory),
		slog.Bool("encryption_at_rest", s.encryptor != nil && s.encryptor.IsEnabled()),
		slog.Bool("instrumentation_on", s.instrumentation != nil),
	)
}
