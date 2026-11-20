package valkey_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	valkeystore "github.com/giantswarm/mcp-oauth/storage/valkey"
)

func TestClientAssertionReplayStore(t *testing.T) {
	client := testDPoPClient(t)
	prefix := fmt.Sprintf("test:client-assertion:%d:", time.Now().UnixNano())
	t.Cleanup(func() { flushDPoPPrefix(t, client, prefix) })
	first := valkeystore.NewClientAssertionReplayStore(client, prefix)
	second := valkeystore.NewClientAssertionReplayStore(client, prefix)
	seen, err := first.Seen(t.Context(), "shared", 1500*time.Millisecond)
	require.NoError(t, err)
	require.False(t, seen)
	seen, err = second.Seen(t.Context(), "shared", time.Minute)
	require.NoError(t, err)
	require.True(t, seen)
	ttl, err := client.Do(t.Context(), client.B().Ttl().Key(prefix+"shared").Build()).AsInt64()
	require.NoError(t, err)
	require.EqualValues(t, 2, ttl)
}
