// Package storage provides interfaces and utilities for OAuth token, client, and flow persistence.
//
// The storage package defines the core storage interfaces used throughout the mcp-oauth library:
//   - TokenStore: Manages OAuth access and refresh tokens
//   - ClientStore: Manages registered OAuth clients
//   - FlowStore: Manages OAuth authorization flow state and codes
//
// This package also provides shared types and utility functions used by storage implementations,
// including token encryption/decryption helpers for sensitive token fields.
//
// Implementations are provided in subpackages:
//   - storage/memory: In-memory storage for development and testing
//   - storage/mock: Mock storage for unit testing
//   - storage/valkey: Valkey/Redis-compatible distributed storage for production
//
// # Deadlines and failure classification
//
// Every operation of a network-backed store runs under a per-operation
// deadline layered on the caller's context ([DefaultOperationTimeout] unless
// the backend is configured otherwise), so an unreachable or unresponsive
// backend fails the call within that budget rather than for as long as the
// outage lasts. The in-memory store performs no I/O and never blocks.
//
// A store reports the outcomes a caller can act on through sentinels
// ([ErrTokenNotFound], [ErrTokenExpired], [ErrAuthorizationCodeUsed],
// [ErrInvalidClientCredentials], ...). Any other error means the record's
// state is unknown — the backend could not be reached or did not answer in
// time — and [IsTransientError] reports it as such. Callers on request paths
// answer a transient error as "temporarily unavailable" and leave tokens,
// codes and refresh-token families untouched, so a storage outage is never
// mistaken for an invalid grant.
package storage
