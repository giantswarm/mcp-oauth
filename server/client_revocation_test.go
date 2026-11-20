package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

func TestClientDeletionInvalidatesIssuedAccess(t *testing.T) {
	server, store, _ := setupFlowTestServer(t)
	seedProviderToken(t, store, "old-access", "first-user", &oauth2.Token{AccessToken: "upstream", Expiry: time.Now().Add(time.Hour)})
	seedProviderToken(t, store, "second-user-access", "second-user", &oauth2.Token{AccessToken: "upstream-second", Expiry: time.Now().Add(time.Hour)})
	seedProviderToken(t, store, "other-client-access", "first-user", &oauth2.Token{AccessToken: "upstream", Expiry: time.Now().Add(time.Hour)})
	require.NoError(t, store.SaveClient(t.Context(), &storage.Client{ClientID: "test-client"}))
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "other-client-access", storage.TokenMetadata{ClientID: "other-client", UserID: "first-user", TokenType: "access", Audience: server.Config.GetResourceIdentifier(), ExpiresAt: time.Now().Add(time.Hour)}))
	_, err := server.validateStoredToken(t.Context(), "old-access")
	require.NoError(t, err)
	require.NoError(t, server.DeleteClient(t.Context(), "test-client"))
	for _, access := range []string{"old-access", "second-user-access"} {
		_, err := server.validateStoredToken(t.Context(), access)
		require.ErrorIs(t, err, errInvalidAccessToken)
	}
	_, err = server.validateStoredToken(t.Context(), "other-client-access")
	require.NoError(t, err)
}

type unavailableRevocationStore struct {
	storage.ClientStore
}

func (unavailableRevocationStore) IsClientRevoked(context.Context, string) (bool, error) {
	return false, errors.New("store unavailable")
}

func TestClientRevocationFailureIsUnavailable(t *testing.T) {
	server, _, _ := setupFlowTestServer(t)
	server.clientStore = unavailableRevocationStore{ClientStore: server.clientStore}
	require.ErrorIs(t, server.checkClientRevocation(t.Context(), "client"), ErrStorageUnavailable)
}

func TestClientDeletionInvalidatesSignedAccess(t *testing.T) {
	server := newJWTModeServer(t, "https://api.example.com/mcp")
	require.NoError(t, server.SaveClient(t.Context(), &storage.Client{ClientID: "signed-client"}))
	access, err := server.issueAccessToken(t.Context(), accessTokenIssueParams{UserID: "person", ClientID: "signed-client", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	_, err = server.ValidateToken(t.Context(), access)
	require.NoError(t, err)
	require.NoError(t, server.DeleteClient(t.Context(), "signed-client"))
	_, err = server.ValidateToken(t.Context(), access)
	require.ErrorIs(t, err, errInvalidAccessToken)
	introspection, err := server.IntrospectToken(t.Context(), access, "signed-client")
	require.NoError(t, err)
	require.Equal(t, false, introspection["active"])
}

type clientStoreWithoutRevocation struct{ storage.ClientStore }

func TestClientDeletionRequiresRevocationSupport(t *testing.T) {
	server, store, _ := setupFlowTestServer(t)
	require.NoError(t, store.SaveClient(t.Context(), &storage.Client{ClientID: "client"}))
	server.clientStore = clientStoreWithoutRevocation{ClientStore: store}
	require.Error(t, server.DeleteClient(t.Context(), "client"))
	_, err := store.GetClient(t.Context(), "client")
	require.NoError(t, err)
}

func TestRevocationCannotRevokeAnotherClientsSignedAccess(t *testing.T) {
	server := newJWTModeServer(t, "https://api.example.com/mcp")
	access, err := server.issueAccessToken(t.Context(), accessTokenIssueParams{UserID: "person", ClientID: "owner", ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	require.NoError(t, server.RevokeToken(t.Context(), access, "different-client", "192.0.2.1"))
	_, err = server.ValidateToken(t.Context(), access)
	require.NoError(t, err)
	require.NoError(t, server.RevokeToken(t.Context(), access, "owner", "192.0.2.1"))
	_, err = server.ValidateToken(t.Context(), access)
	require.Error(t, err)
}
