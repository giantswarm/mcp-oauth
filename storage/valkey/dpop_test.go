package valkey_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	vk "github.com/valkey-io/valkey-go"
	"golang.org/x/sync/errgroup"

	"github.com/giantswarm/mcp-oauth/server"
	valkeystore "github.com/giantswarm/mcp-oauth/storage/valkey"
)

func testDPoPClient(t *testing.T) vk.Client {
	t.Helper()
	addr := os.Getenv("VALKEY_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	client, err := vk.NewClient(vk.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		t.Skipf("skipping: could not connect to Valkey at %s: %v", addr, err)
	}
	if err := client.Do(t.Context(), client.B().Ping().Build()).Error(); err != nil {
		client.Close()
		t.Skipf("skipping: Valkey at %s not reachable: %v", addr, err)
	}
	t.Cleanup(client.Close)
	return client
}

func flushDPoPPrefix(t *testing.T, client vk.Client, prefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cursor uint64
	for {
		entry, err := client.Do(
			ctx,
			client.B().Scan().Cursor(cursor).Match(prefix+"*").Count(100).Build(),
		).AsScanEntry()
		if err != nil {
			return
		}
		for _, key := range entry.Elements {
			_ = client.Do(ctx, client.B().Del().Key(key).Build()).Error()
		}
		cursor = entry.Cursor
		if cursor == 0 {
			return
		}
	}
}

func newTestDPoPCache(t *testing.T) server.DPoPReplayCache {
	t.Helper()
	client := testDPoPClient(t)
	prefix := fmt.Sprintf("dpoptest:%s:", t.Name())
	flushDPoPPrefix(t, client, prefix)
	t.Cleanup(func() { flushDPoPPrefix(t, client, prefix) })
	return valkeystore.NewDPoPReplayCache(client, prefix)
}

func TestDPoPReplayCache_FirstUseReturnsFalse(t *testing.T) {
	cache := newTestDPoPCache(t)

	seen, err := cache.Seen(t.Context(), "jti-new", 5*time.Minute)
	require.NoError(t, err)
	require.False(t, seen, "first occurrence must not be reported as seen")
}

func TestDPoPReplayCache_ReplayWithinTTLReturnsTrue(t *testing.T) {
	cache := newTestDPoPCache(t)

	seen, err := cache.Seen(t.Context(), "jti-replay", 5*time.Minute)
	require.NoError(t, err)
	require.False(t, seen)

	seen, err = cache.Seen(t.Context(), "jti-replay", 5*time.Minute)
	require.NoError(t, err)
	require.True(t, seen, "second occurrence within TTL must be detected as replay")
}

func TestDPoPReplayCache_DistinctJTIsAreIndependent(t *testing.T) {
	cache := newTestDPoPCache(t)

	for i := range 5 {
		jti := fmt.Sprintf("jti-distinct-%d", i)
		seen, err := cache.Seen(t.Context(), jti, 5*time.Minute)
		require.NoError(t, err)
		require.Falsef(t, seen, "distinct JTI %q must be treated as new", jti)
	}
}

func TestDPoPReplayCache_TTLIsHonoured(t *testing.T) {
	cache := newTestDPoPCache(t)
	const jti = "jti-ttl"
	const ttl = 1 * time.Second // Valkey SET EX granularity is one second

	seen, err := cache.Seen(t.Context(), jti, ttl)
	require.NoError(t, err)
	require.False(t, seen)

	require.Never(t, func() bool {
		got, err := cache.Seen(t.Context(), jti, ttl)
		return err != nil || !got
	}, 500*time.Millisecond, 50*time.Millisecond,
		"JTI must remain seen during its TTL window")

	require.Eventually(t, func() bool {
		got, err := cache.Seen(t.Context(), jti, ttl)
		return err == nil && !got
	}, 5*time.Second, 50*time.Millisecond,
		"JTI must be evicted once its TTL elapses")
}

func TestDPoPReplayCache_ConcurrentFirstUseHasOneWinner(t *testing.T) {
	const n = 100
	cache := newTestDPoPCache(t)

	var newJTI, replay atomic.Int32
	ready := make(chan struct{})
	g, ctx := errgroup.WithContext(t.Context())
	for range n {
		g.Go(func() error {
			<-ready
			seen, err := cache.Seen(ctx, "jti-concurrent", 5*time.Minute)
			if err != nil {
				return err
			}
			if seen {
				replay.Add(1)
			} else {
				newJTI.Add(1)
			}
			return nil
		})
	}
	close(ready)
	require.NoError(t, g.Wait())

	require.Equal(t, int32(1), newJTI.Load(),
		"more than one goroutine seeing the JTI as new would break RFC 9449 §11.1 uniqueness")
	require.Equal(t, int32(n-1), replay.Load())
}

func TestDPoPReplayCache_DifferentPrefixesAreIsolated(t *testing.T) {
	client := testDPoPClient(t)
	prefixA := fmt.Sprintf("dpoptest:%s:a:", t.Name())
	prefixB := fmt.Sprintf("dpoptest:%s:b:", t.Name())
	flushDPoPPrefix(t, client, prefixA)
	flushDPoPPrefix(t, client, prefixB)
	t.Cleanup(func() {
		flushDPoPPrefix(t, client, prefixA)
		flushDPoPPrefix(t, client, prefixB)
	})

	cacheA := valkeystore.NewDPoPReplayCache(client, prefixA)
	cacheB := valkeystore.NewDPoPReplayCache(client, prefixB)

	seen, err := cacheA.Seen(t.Context(), "jti-shared", 5*time.Minute)
	require.NoError(t, err)
	require.False(t, seen)

	seen, err = cacheB.Seen(t.Context(), "jti-shared", 5*time.Minute)
	require.NoError(t, err)
	require.False(t, seen, "different prefixes must not share key space")
}
