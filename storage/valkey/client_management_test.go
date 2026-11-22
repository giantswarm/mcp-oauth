package valkey

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/storage"
)

func TestClientManagementConcurrentUpdates(t *testing.T) {
	store := testStore(t)
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

func TestClientManagementStorageFailureIsRetryable(t *testing.T) {
	store := testStore(t)
	client := &storage.Client{ClientID: "managed", RegistrationAccessTokenHash: "current-rat", ClientSecretHash: "current-secret", ClientSecretEncrypted: "encrypted-current-secret"}
	require.NoError(t, store.SaveClient(t.Context(), client))
	updated := *client
	updated.RegistrationAccessTokenHash = "next-rat"
	updated.ClientSecretEncrypted = "encrypted-next-secret"
	sentinel := store.prefix + "invalid-counter"
	require.NoError(t, store.client.Do(t.Context(), store.client.B().Set().Key(sentinel).Value("not-an-integer").Build()).Error())
	wrapped := &failingFamilyCommandClient{Client: store.client, operation: "EVAL", key: store.clientKey(client.ClientID), sentinel: sentinel}
	store.client = wrapped
	wrapped.enabled.Store(true)
	err := store.UpdateClientRegistration(t.Context(), &updated, client.RegistrationAccessTokenHash, client.ClientSecretHash)
	require.Error(t, err)
	require.True(t, storage.IsTransientError(err))
	current, err := store.GetClient(t.Context(), client.ClientID)
	require.NoError(t, err)
	require.True(t, current.RegistrationAccessTokenHash == client.RegistrationAccessTokenHash)
	require.True(t, current.ClientSecretEncrypted == client.ClientSecretEncrypted)
	wrapped.enabled.Store(false)
	require.NoError(t, store.UpdateClientRegistration(t.Context(), &updated, client.RegistrationAccessTokenHash, client.ClientSecretHash))
	current, err = store.GetClient(t.Context(), client.ClientID)
	require.NoError(t, err)
	require.True(t, current.RegistrationAccessTokenHash == updated.RegistrationAccessTokenHash)
	require.True(t, current.ClientSecretEncrypted == updated.ClientSecretEncrypted)
}
