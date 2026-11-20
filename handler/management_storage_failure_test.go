package handler

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type managementUnavailableStore struct {
	*memory.Store
	failRead   bool
	failUpdate bool
}

func (s *managementUnavailableStore) GetClient(ctx context.Context, clientID string) (*storage.Client, error) {
	if s.failRead {
		return nil, errors.New("client read unavailable")
	}
	return s.Store.GetClient(ctx, clientID)
}

func (s *managementUnavailableStore) UpdateClientRegistration(ctx context.Context, client *storage.Client, registrationTokenHash, clientSecretHash string) error {
	if s.failUpdate {
		return errors.New("client update unavailable")
	}
	return s.Store.UpdateClientRegistration(ctx, client, registrationTokenHash, clientSecretHash)
}

func TestManagementStorageFailuresPreserveCurrentCredentialsForRetry(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			store := memory.New()
			wrapped := &managementUnavailableStore{Store: store}
			oauthServer, err := server.New(mock.NewProvider(), store, wrapped, store, &server.Config{Issuer: testIssuer, DisableNonceEchoRequirement: true}, nil)
			if err != nil {
				store.Stop()
			}
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, oauthServer.Shutdown(context.WithoutCancel(t.Context()))) })
			handler := New(oauthServer, nil)
			client := newMatrixClient(t, handler, "client_secret_basic")
			metadata := map[string]any{"client_id": client.client.ClientID, "redirect_uris": []string{"https://example.com/callback"}}
			wrapped.failRead = method == http.MethodGet
			wrapped.failUpdate = method == http.MethodPut
			response := managementCredentialRequest(t, handler, method, client.client.ClientID, client.registrationToken, metadata)
			require.Equal(t, http.StatusServiceUnavailable, response.Code)
			require.Contains(t, response.Header().Get("Content-Type"), "text/plain")
			require.Empty(t, response.Header().Get("WWW-Authenticate"))
			require.NotEmpty(t, response.Header().Get("Retry-After"))
			wrapped.failRead, wrapped.failUpdate = false, false
			current, err := oauthServer.GetRegisteredClient(t.Context(), client.client.ClientID)
			require.NoError(t, err)
			require.True(t, current.RegistrationAccessTokenHash == client.client.RegistrationAccessTokenHash)
			require.NoError(t, oauthServer.ValidateClientCredentials(t.Context(), client.client.ClientID, client.secret))
			response = managementCredentialRequest(t, handler, method, client.client.ClientID, client.registrationToken, metadata)
			currentCredentialResponse(t, response, client.secret)
		})
	}
}
