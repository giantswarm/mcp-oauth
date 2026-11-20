package memory

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

func TestClientManagementConcurrentUpdates(t *testing.T) {
	store := New()
	t.Cleanup(store.Stop)
	client := &storage.Client{ClientID: "managed-client", RegistrationAccessTokenHash: "previous-rat", ClientSecretHash: "previous-secret"}
	require.NoError(t, store.SaveClient(t.Context(), client))
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, nextHash := range []string{"first-rat", "second-rat"} {
		workers.Go(func() {
			<-start
			updated := *client
			updated.RegistrationAccessTokenHash = nextHash
			results <- store.UpdateClientRegistration(t.Context(), &updated, client.RegistrationAccessTokenHash, client.ClientSecretHash)
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var successes, conflicts int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, storage.ErrInvalidClientCredentials):
			conflicts++
		default:
			require.NoError(t, err)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, conflicts)
	current, err := store.GetClient(t.Context(), client.ClientID)
	require.NoError(t, err)
	require.ErrorIs(t, store.UpdateClientRegistration(t.Context(), current, current.RegistrationAccessTokenHash, "replaced-secret"), storage.ErrInvalidClientCredentials)
	require.NoError(t, store.DeleteClient(t.Context(), client.ClientID))
	require.ErrorIs(t, store.UpdateClientRegistration(t.Context(), current, current.RegistrationAccessTokenHash, current.ClientSecretHash), storage.ErrInvalidClientCredentials)
}
