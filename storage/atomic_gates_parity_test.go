package storage_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	valkeygo "github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

// TestAtomicGates_BackendParity verifies that the memory and valkey backends
// produce identical outcomes for the OAuth 2.1 single-use enforcement gates
// (RFC 6749 §4.1.2 authorization code reuse, refresh-token reuse). Divergence
// here would mean one backend silently allows replay where the other rejects.
//
// The factory returns storage.Combined deliberately, to keep assertions
// backend-agnostic; backend-specific behaviour belongs in the per-backend
// test files.
func TestAtomicGates_BackendParity(t *testing.T) {
	backends := []struct {
		name    string
		factory func(t *testing.T) storage.Combined
	}{
		{name: storage.BackendMemory, factory: newMemoryBackend},
		{name: storage.BackendValkey, factory: newValkeyBackend},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			t.Run("auth_code_first_use_then_reuse", func(t *testing.T) {
				s := b.factory(t)

				code := &storage.AuthorizationCode{
					Code:      fmt.Sprintf("parity-ac-%s", b.name),
					ClientID:  "client-parity",
					UserID:    "user-parity",
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(5 * time.Minute),
				}
				require.NoError(t, s.SaveAuthorizationCode(t.Context(), code))

				first, err := s.AtomicCheckAndMarkAuthCodeUsed(t.Context(), code.Code)
				require.NoError(t, err)
				require.NotNil(t, first)

				reused, err := s.AtomicCheckAndMarkAuthCodeUsed(t.Context(), code.Code)
				require.ErrorIs(t, err, storage.ErrAuthorizationCodeUsed)
				require.NotNil(t, reused, "reuse case must surface the stored code")
				require.True(t, reused.Used)
			})

			t.Run("auth_code_unknown_returns_not_found", func(t *testing.T) {
				s := b.factory(t)
				got, err := s.AtomicCheckAndMarkAuthCodeUsed(t.Context(), "parity-ac-unknown")
				require.ErrorIs(t, err, storage.ErrAuthorizationCodeNotFound)
				require.Nil(t, got)
			})

			t.Run("refresh_token_first_use_then_reuse", func(t *testing.T) {
				s := b.factory(t)

				refreshToken := fmt.Sprintf("parity-rt-%s", b.name)
				providerToken := &oauth2.Token{
					AccessToken:  "provider-access",
					RefreshToken: "provider-refresh",
					TokenType:    "Bearer",
					Expiry:       time.Now().Add(time.Hour),
				}
				require.NoError(t, s.SaveToken(t.Context(), refreshToken, providerToken))
				require.NoError(t, s.SaveRefreshToken(t.Context(), refreshToken, "user-parity", time.Now().Add(time.Hour)))

				userID, _, gotToken, err := s.AtomicGetAndDeleteRefreshToken(t.Context(), refreshToken)
				require.NoError(t, err)
				require.Equal(t, "user-parity", userID)
				require.NotNil(t, gotToken)

				_, _, _, err = s.AtomicGetAndDeleteRefreshToken(t.Context(), refreshToken)
				require.ErrorIs(t, err, storage.ErrTokenNotFound)
			})

			t.Run("refresh_token_unknown_returns_not_found", func(t *testing.T) {
				s := b.factory(t)
				_, _, _, err := s.AtomicGetAndDeleteRefreshToken(t.Context(), "parity-rt-unknown")
				require.ErrorIs(t, err, storage.ErrTokenNotFound, "backends MUST agree on the sentinel error type")
			})
		})
	}
}

func newMemoryBackend(t *testing.T) storage.Combined {
	t.Helper()
	s := memory.New(memory.WithCleanupInterval(time.Hour))
	t.Cleanup(s.Stop)
	return s
}

func newValkeyBackend(t *testing.T) storage.Combined {
	t.Helper()

	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	prefix := fmt.Sprintf("mcptest-parity:%s:", t.Name())

	flushValkeyPrefix(t, addr, prefix)

	s, err := valkey.New(valkey.Config{Address: addr, KeyPrefix: prefix})
	if err != nil {
		t.Skipf("skipping valkey parity: no server at VALKEY_TEST_ADDR=%s: %v", addr, err)
	}
	t.Cleanup(func() {
		flushValkeyPrefix(t, addr, prefix)
		s.Close()
	})
	return s
}

// flushValkeyPrefix SCAN+DELs every key matching prefix+"*". Mirrors the
// cleanupTestKeys ritual used by storage/valkey/store_test.go so the parity
// test is resilient to keys left over from a crashed prior run with the same
// t.Name().
func flushValkeyPrefix(t *testing.T, addr, prefix string) {
	t.Helper()

	client, err := valkeygo.NewClient(valkeygo.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		return
	}
	defer client.Close()

	ctx := context.Background()
	pattern := prefix + "*"
	var cursor uint64
	for {
		entry, err := client.Do(ctx, client.B().Scan().Cursor(cursor).Match(pattern).Count(100).Build()).AsScanEntry()
		if err != nil {
			t.Logf("warning: failed to scan for cleanup: %v", err)
			return
		}
		for _, key := range entry.Elements {
			_ = client.Do(ctx, client.B().Del().Key(key).Build())
		}
		cursor = entry.Cursor
		if cursor == 0 {
			return
		}
	}
}
