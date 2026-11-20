package server

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

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
	return err
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
