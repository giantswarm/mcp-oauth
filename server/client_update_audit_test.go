package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestUpdateClientRegistrationAudit(t *testing.T) {
	key := assertionKey(t, jose.RS256)
	key.Algorithm = ""
	previous := assertionClient(t, key)
	previous.TokenEndpointAuthSigningAlg = "RS256"
	previous.RegistrationAccessTokenHash = "previous-registration-hash"
	nextKeys := assertionClient(t, assertionKey(t, jose.RS256)).JWKS

	for _, test := range []struct {
		name   string
		mutate func(*storage.Client)
	}{
		{"client_name", func(client *storage.Client) { client.ClientName = "updated name" }},
		{"client_type", func(client *storage.Client) { client.ClientType = ClientTypePublic }},
		{"redirect_uris", func(client *storage.Client) { client.RedirectURIs = []string{"http://127.0.0.1/callback"} }},
		{"grant_types", func(client *storage.Client) { client.GrantTypes = []string{"authorization_code"} }},
		{"response_types", func(client *storage.Client) { client.ResponseTypes = []string{"code"} }},
		{"scope", func(client *storage.Client) { client.Scopes = []string{"openid"} }},
		{"token_endpoint_auth_method", func(client *storage.Client) { client.TokenEndpointAuthMethod = TokenEndpointAuthMethodNone }},
		{"token_endpoint_auth_signing_alg", func(client *storage.Client) { client.TokenEndpointAuthSigningAlg = "PS256" }},
		{"jwks", func(client *storage.Client) { client.JWKS = nextKeys }},
		{"client_secret", func(client *storage.Client) { client.ClientSecretHash = "updated-secret-hash" }},
		{"registration_access_token", func(client *storage.Client) { client.RegistrationAccessTokenHash = "updated-registration-hash" }},
		{"unchanged", func(*storage.Client) {}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, store, _ := setupFlowTestServer(t)
			require.NoError(t, store.SaveClient(t.Context(), previous))
			output := captureAudit(server)
			updated := *previous
			test.mutate(&updated)
			require.NoError(t, server.UpdateClientRegistration(t.Context(), &updated, previous))

			event := onlyAuditLine(t, output, security.EventClientUpdated)
			require.Equal(t, previous.ClientID, event.ClientID)
			changed := []any{}
			if test.name != "unchanged" {
				changed = append(changed, test.name)
			}
			require.Equal(t, map[string]any{"changed": changed}, event.Details)
			persisted, err := store.GetClient(t.Context(), previous.ClientID)
			require.NoError(t, err)
			require.Equal(t, &updated, persisted)
		})
	}
}

type failingClientRegistrationStore struct {
	storage.ClientStore
	updateError error
}

func (store failingClientRegistrationStore) UpdateClientRegistration(context.Context, *storage.Client, string, string) error {
	return store.updateError
}

func TestUpdateClientRegistrationFailureDoesNotAuditSuccess(t *testing.T) {
	for _, test := range []struct {
		name     string
		prepare  func(*testing.T, *Server, *storage.Client)
		expected error
	}{
		{
			name: "stale registration access token",
			prepare: func(t *testing.T, server *Server, client *storage.Client) {
				current := *client
				current.RegistrationAccessTokenHash = "concurrent-registration-hash"
				require.NoError(t, server.clientStore.SaveClient(t.Context(), &current))
			},
			expected: storage.ErrInvalidClientCredentials,
		},
		{
			name: "concurrent credential replacement",
			prepare: func(t *testing.T, server *Server, client *storage.Client) {
				current := *client
				current.ClientSecretHash = "concurrent-secret-hash"
				require.NoError(t, server.clientStore.SaveClient(t.Context(), &current))
			},
			expected: storage.ErrInvalidClientCredentials,
		},
		{
			name: "deleted registration",
			prepare: func(t *testing.T, server *Server, client *storage.Client) {
				require.NoError(t, server.clientStore.DeleteClient(t.Context(), client.ClientID))
			},
			expected: storage.ErrInvalidClientCredentials,
		},
		{
			name: "storage unavailable",
			prepare: func(_ *testing.T, server *Server, _ *storage.Client) {
				server.clientStore = failingClientRegistrationStore{server.clientStore, errors.New("backend unavailable")}
			},
			expected: ErrStorageUnavailable,
		},
		{
			name: "wrapped credential rejection",
			prepare: func(_ *testing.T, server *Server, _ *storage.Client) {
				server.clientStore = failingClientRegistrationStore{server.clientStore, fmt.Errorf("update: %w", storage.ErrInvalidClientCredentials)}
			},
			expected: storage.ErrInvalidClientCredentials,
		},
		{
			name: "unsupported store",
			prepare: func(_ *testing.T, server *Server, _ *storage.Client) {
				server.clientStore = struct{ storage.ClientStore }{server.clientStore}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, store, _ := setupFlowTestServer(t)
			previous := &storage.Client{ClientID: "managed-audit-client", RegistrationAccessTokenHash: "previous-registration-hash"}
			require.NoError(t, store.SaveClient(t.Context(), previous))
			test.prepare(t, server, previous)
			output := captureAudit(server)
			updated := *previous
			updated.RegistrationAccessTokenHash = "updated-registration-hash"
			err := server.UpdateClientRegistration(t.Context(), &updated, previous)
			if test.expected == nil {
				require.EqualError(t, err, "client store does not support atomic registration updates")
			} else {
				require.ErrorIs(t, err, test.expected)
			}
			decoder := json.NewDecoder(output)
			for decoder.More() {
				var entry struct {
					Audit auditLine `json:"audit"`
				}
				require.NoError(t, decoder.Decode(&entry))
				require.NotEqual(t, security.EventClientUpdated, entry.Audit.EventType)
			}
		})
	}
}
