package valkey

import (
	"log/slog"

	"github.com/giantswarm/mcp-oauth/storage"
)

// LogValue implements [slog.LogValuer] so callers can emit a one-shot
// structured snapshot of the store's posture:
//
//	logger.Info("storage initialized", "store", store)
func (s *Store) LogValue() slog.Value {
	s.encryptorMu.RLock()
	enc := s.encryptor
	s.encryptorMu.RUnlock()
	return slog.GroupValue(
		slog.String("backend", storage.BackendValkey),
		slog.Bool("encryption_at_rest", enc != nil && enc.IsEnabled()),
	)
}
