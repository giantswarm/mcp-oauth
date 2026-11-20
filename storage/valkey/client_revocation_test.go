package valkey

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

func TestClientRetirement(t *testing.T) {
	store := testStore(t)
	client := &storage.Client{ClientID: "retired-client", ClientType: storage.ClientTypePublic}
	require.NoError(t, store.SaveClient(t.Context(), client))
	require.NoError(t, store.DeleteClient(t.Context(), client.ClientID))
	revoked, err := store.IsClientRevoked(t.Context(), client.ClientID)
	require.NoError(t, err)
	require.True(t, revoked)
	_, err = store.GetClient(t.Context(), client.ClientID)
	require.ErrorIs(t, err, storage.ErrClientNotFound)
	require.ErrorIs(t, store.SaveClient(t.Context(), client), storage.ErrClientNotFound)
	require.ErrorIs(t, store.DeleteClient(t.Context(), client.ClientID), storage.ErrClientNotFound)
	clients, err := store.ListClients(t.Context())
	require.NoError(t, err)
	require.Empty(t, clients)
	address := os.Getenv("VALKEY_TEST_ADDR")
	if address == "" {
		address = "localhost:6379"
	}
	observer, err := New(Config{Address: address, KeyPrefix: fmt.Sprintf("mcptest:%s:", t.Name()), StartupTimeout: testStartupTimeout})
	require.NoError(t, err)
	t.Cleanup(observer.Close)
	revoked, err = observer.IsClientRevoked(t.Context(), client.ClientID)
	require.NoError(t, err)
	require.True(t, revoked)
	require.ErrorIs(t, observer.SaveClient(t.Context(), client), storage.ErrClientNotFound)
}
