// Package integration contains integration tests for mcp-oauth that require
// external dependencies like Valkey/Redis.
//
// These tests validate horizontal scaling behavior where multiple mcp-oauth
// instances share a single Valkey storage backend without session stickiness.
//
// # Running the tests
//
// These tests require a running Valkey/Redis instance:
//
//	# Start Valkey locally
//	docker run -d --name valkey-test -p 6379:6379 valkey/valkey:latest
//
//	# Run integration tests
//	VALKEY_TEST_ADDR=localhost:6379 go test -v -tags=integration ./integration/...
//
//	# Run with race detector (recommended)
//	VALKEY_TEST_ADDR=localhost:6379 go test -v -race -tags=integration ./integration/...
//
// # Test coverage
//
// The integration tests cover:
//   - Cross-pod OAuth authorization flows
//   - Authorization code atomicity (only one pod can exchange a code)
//   - Refresh token rotation atomicity
//   - State visibility across pods
//   - Refresh token reuse detection and family revocation
//   - Concurrent operations from multiple pods
package integration
