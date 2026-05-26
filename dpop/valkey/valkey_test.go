package valkey_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	vk "github.com/valkey-io/valkey-go"
	"github.com/stretchr/testify/require"

	dpopvalkey "github.com/giantswarm/mcp-oauth/dpop/valkey"
)

func testClient(t *testing.T) vk.Client {
	t.Helper()
	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	client, err := vk.NewClient(vk.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		t.Skipf("skipping: could not connect to Valkey at %s: %v", addr, err)
	}
	// Probe with PING to confirm connectivity.
	if err := client.Do(t.Context(), client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		t.Skipf("skipping: Valkey at %s not reachable: %v", addr, err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestReplayCache_NewJTI(t *testing.T) {
	client := testClient(t)
	prefix := fmt.Sprintf("dpoptest:%s:", t.Name())
	cache := dpopvalkey.New(client, prefix)

	seen, err := cache.Seen(t.Context(), "jti-new-1", 5*time.Minute)
	require.NoError(t, err)
	require.False(t, seen, "first occurrence should not be seen")
}

func TestReplayCache_ReplayedJTI(t *testing.T) {
	client := testClient(t)
	prefix := fmt.Sprintf("dpoptest:%s:", t.Name())
	cache := dpopvalkey.New(client, prefix)

	seen, err := cache.Seen(t.Context(), "jti-replay-1", 5*time.Minute)
	require.NoError(t, err)
	require.False(t, seen)

	seen, err = cache.Seen(t.Context(), "jti-replay-1", 5*time.Minute)
	require.NoError(t, err)
	require.True(t, seen, "second occurrence must be detected as replay")
}

func TestReplayCache_DifferentJTIsAreIndependent(t *testing.T) {
	client := testClient(t)
	prefix := fmt.Sprintf("dpoptest:%s:", t.Name())
	cache := dpopvalkey.New(client, prefix)

	for i := range 5 {
		jti := fmt.Sprintf("jti-distinct-%d", i)
		seen, err := cache.Seen(t.Context(), jti, 5*time.Minute)
		require.NoError(t, err)
		require.False(t, seen, "each distinct JTI must be treated as new")
	}
}

func TestReplayCache_TTLExpiry(t *testing.T) {
	client := testClient(t)
	prefix := fmt.Sprintf("dpoptest:%s:", t.Name())
	cache := dpopvalkey.New(client, prefix)

	// Use a 1-second TTL; after expiry the JTI should be accepted again.
	seen, err := cache.Seen(t.Context(), "jti-ttl-1", 1*time.Second)
	require.NoError(t, err)
	require.False(t, seen)

	// Confirm replay within TTL.
	seen, err = cache.Seen(t.Context(), "jti-ttl-1", 1*time.Second)
	require.NoError(t, err)
	require.True(t, seen)

	// Wait for expiry then confirm the JTI is accepted again.
	time.Sleep(2 * time.Second)
	seen, err = cache.Seen(t.Context(), "jti-ttl-1", 1*time.Second)
	require.NoError(t, err)
	require.False(t, seen, "JTI should be accepted again after TTL expiry")
}

func TestReplayCache_KeyPrefix(t *testing.T) {
	client := testClient(t)
	// Two caches with different prefixes must not share state.
	cacheA := dpopvalkey.New(client, fmt.Sprintf("dpoptest:%s:a:", t.Name()))
	cacheB := dpopvalkey.New(client, fmt.Sprintf("dpoptest:%s:b:", t.Name()))

	seen, err := cacheA.Seen(t.Context(), "jti-shared", 5*time.Minute)
	require.NoError(t, err)
	require.False(t, seen)

	seen, err = cacheB.Seen(t.Context(), "jti-shared", 5*time.Minute)
	require.NoError(t, err)
	require.False(t, seen, "different prefix must not see the other cache's entry")
}
