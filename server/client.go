package server

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// Client type constants
const (
	// ClientTypeConfidential represents a confidential OAuth client
	ClientTypeConfidential = "confidential"

	// ClientTypePublic represents a public OAuth client
	ClientTypePublic = "public"
)

// RegisterClient registers a new OAuth client with IP-based DoS protection
func (s *Server) RegisterClient(ctx context.Context, clientName, clientType string, redirectURIs []string, scopes []string, clientIP string, maxClientsPerIP int) (*storage.Client, string, error) {
	// Check IP limit to prevent DoS via mass client registration
	if err := s.clientStore.CheckIPLimit(ctx, clientIP, maxClientsPerIP); err != nil {
		return nil, "", err
	}
	// Generate client ID using oauth2.GenerateVerifier (same quality)
	clientID := generateRandomToken()

	// Generate client secret for confidential clients
	var clientSecret string
	var clientSecretHash string

	if clientType == "" {
		clientType = ClientTypeConfidential
	}

	if clientType == ClientTypeConfidential {
		clientSecret = generateRandomToken()

		// Hash the secret for storage
		hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", fmt.Errorf("failed to hash client secret: %w", err)
		}
		clientSecretHash = string(hash)
	}

	// Create client object
	client := &storage.Client{
		ClientID:                clientID,
		ClientSecretHash:        clientSecretHash,
		ClientType:              clientType,
		RedirectURIs:            redirectURIs,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              clientName,
		Scopes:                  scopes,
		CreatedAt:               time.Now(),
	}

	// Public clients use "none" auth method
	if clientType == ClientTypePublic {
		client.TokenEndpointAuthMethod = "none"
	}

	// Save client
	if err := s.clientStore.SaveClient(ctx, client); err != nil {
		return nil, "", fmt.Errorf("failed to save client: %w", err)
	}

	// Track IP for DoS protection
	if memStore, ok := s.clientStore.(*memory.Store); ok {
		memStore.TrackClientIP(clientIP)
	}

	if s.Auditor != nil {
		s.Auditor.LogClientRegistered(clientID, clientType, clientIP)
	}

	s.Logger.Info("Registered new OAuth client",
		"client_id", clientID,
		"client_name", clientName,
		"client_type", clientType,
		"client_ip", clientIP)

	return client, clientSecret, nil
}

// ValidateClientCredentials validates client credentials for token endpoint
func (s *Server) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) error {
	return s.clientStore.ValidateClientSecret(ctx, clientID, clientSecret)
}

// GetClient retrieves a client by ID (for use by handler)
func (s *Server) GetClient(ctx context.Context, clientID string) (*storage.Client, error) {
	return s.clientStore.GetClient(ctx, clientID)
}
