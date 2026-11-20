package memory

import (
	"context"
	"fmt"

	"github.com/giantswarm/mcp-oauth/storage"
)

// UpdateClientRegistration atomically replaces the authenticated registration.
func (s *Store) UpdateClientRegistration(_ context.Context, client *storage.Client, registrationTokenHash, clientSecretHash string) error {
	if client == nil || client.ClientID == "" {
		return fmt.Errorf("invalid client")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.clients[client.ClientID]
	if current == nil || s.revokedClients[client.ClientID] || current.RegistrationAccessTokenHash != registrationTokenHash || current.ClientSecretHash != clientSecretHash {
		return storage.ErrInvalidClientCredentials
	}
	s.clients[client.ClientID] = client
	return nil
}
