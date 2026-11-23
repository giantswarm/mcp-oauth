package server

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"slices"

	"golang.org/x/crypto/bcrypt"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// UpdateClientRegistration persists a management update without overwriting a
// concurrent credential change or reviving a deleted registration.
func (s *Server) UpdateClientRegistration(ctx context.Context, client, previous *storage.Client) error {
	updater, ok := s.clientStore.(storage.ClientRegistrationUpdater)
	if !ok {
		return fmt.Errorf("client store does not support atomic registration updates")
	}
	err := updater.UpdateClientRegistration(ctx, client, previous.RegistrationAccessTokenHash, previous.ClientSecretHash)
	if storage.IsTransientError(err) {
		return s.storageUnavailable(ctx, "update client registration", client.ClientID, "", err)
	}
	if err != nil {
		return err
	}
	s.Auditor.LogEvent(ctx, security.Event{
		Type:     security.EventClientUpdated,
		ClientID: client.ClientID,
		Details:  map[string]any{"changed": changedRegistrationFields(previous, client)},
	})
	return nil
}

// changedRegistrationFields names the registration fields an update changed,
// so an operator restoring an older store state can tell which updates the
// restore undid. Credential fields are compared by hash and reported by name only.
func changedRegistrationFields(previous, current *storage.Client) []string {
	changed := []string{}
	add := func(name string, differs bool) {
		if differs {
			changed = append(changed, name)
		}
	}
	add("client_name", previous.ClientName != current.ClientName)
	add("redirect_uris", !slices.Equal(previous.RedirectURIs, current.RedirectURIs))
	add("grant_types", !slices.Equal(previous.GrantTypes, current.GrantTypes))
	add("scope", !slices.Equal(previous.Scopes, current.Scopes))
	add("token_endpoint_auth_method", previous.TokenEndpointAuthMethod != current.TokenEndpointAuthMethod)
	add("jwks", !bytes.Equal(previous.JWKS, current.JWKS))
	add("client_secret", previous.ClientSecretHash != current.ClientSecretHash)
	add("registration_access_token", previous.RegistrationAccessTokenHash != current.RegistrationAccessTokenHash)
	return changed
}

func (s *Server) clientSecretEncryptor(clientID, registrationToken string) (*security.Encryptor, error) {
	if registrationToken == "" {
		return nil, fmt.Errorf("registration access token required")
	}
	key, err := hkdf.Key(sha256.New, []byte(registrationToken), []byte(s.Config.Issuer), "mcp-oauth client secret v1:"+clientID, 32)
	if err != nil {
		return nil, fmt.Errorf("derive client credential key: %w", err)
	}
	return security.NewEncryptor(key)
}

// EncryptClientSecret seals the current secret to its client's registration access token.
func (s *Server) EncryptClientSecret(client *storage.Client, clientSecret, registrationToken string) error {
	if client.ClientSecretHash == "" {
		client.ClientSecretEncrypted = ""
		return nil
	}
	if bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)) != nil {
		return fmt.Errorf("client secret does not match registered credential")
	}
	encryptor, err := s.clientSecretEncryptor(client.ClientID, registrationToken)
	if err != nil {
		return err
	}
	encrypted, err := encryptor.Encrypt(clientSecret)
	if err != nil {
		return err
	}
	client.ClientSecretEncrypted = encrypted
	return nil
}

// DecryptClientSecret recovers a managed credential without changing it.
// Hash-only registrations need a PUT supplying their current secret before retrieval.
func (s *Server) DecryptClientSecret(client *storage.Client, registrationToken string) (string, error) {
	if client.ClientSecretHash == "" {
		return "", nil
	}
	if client.ClientSecretEncrypted == "" {
		return "", fmt.Errorf("current client secret unavailable; PUT the existing client_secret to enable credential retrieval")
	}
	encryptor, err := s.clientSecretEncryptor(client.ClientID, registrationToken)
	if err != nil {
		return "", err
	}
	clientSecret, err := encryptor.Decrypt(client.ClientSecretEncrypted)
	if err != nil {
		return "", fmt.Errorf("decrypt registered client credential: %w", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)) != nil {
		return "", fmt.Errorf("stored client credential does not match its hash")
	}
	return clientSecret, nil
}
