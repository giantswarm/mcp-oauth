// Package memory provides an in-memory implementation of the OAuth storage interfaces.
//
// This package implements TokenStore, ClientStore, and FlowStore interfaces using
// Go's built-in maps with mutex protection for thread safety. It is suitable for
// development, testing, and single-instance deployments where persistence is not required.
//
// Features:
//   - Thread-safe operations using sync.RWMutex
//   - Automatic cleanup of expired tokens, codes, and flows
//   - Configurable cleanup intervals
//   - Token encryption support via Encryptor
//   - Audit logging support via Auditor
//
// For production deployments requiring persistence or multi-instance deployments,
// use the storage/valkey package instead.
//
// Example usage:
//
//	store := memory.New()
//	defer store.Stop()
//
//	// Use store for TokenStore, ClientStore, and FlowStore interfaces
//	server, _ := oauth.NewServer(provider, store, store, store, config, logger)
package memory
