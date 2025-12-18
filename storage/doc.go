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
package storage
