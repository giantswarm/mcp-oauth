package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ClientStore manages registered OAuth clients
type ClientStore struct {
	clients      map[string]*RegisteredClient
	clientsPerIP map[string]int // Track number of clients per IP for DoS protection
	mu           sync.RWMutex
	logger       *slog.Logger
}

// NewClientStore creates a new client store
func NewClientStore(logger *slog.Logger) *ClientStore {
	if logger == nil {
		logger = slog.Default()
	}

	return &ClientStore{
		clients:      make(map[string]*RegisteredClient),
		clientsPerIP: make(map[string]int),
		logger:       logger,
	}
}

// CheckIPLimit checks if an IP has reached the client registration limit
// Returns an error if the limit is reached
func (s *ClientStore) CheckIPLimit(ip string, maxClientsPerIP int) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if maxClientsPerIP <= 0 {
		return nil // No limit
	}

	count := s.clientsPerIP[ip]
	if count >= maxClientsPerIP {
		return fmt.Errorf("client registration limit reached for IP %s (%d/%d)", ip, count, maxClientsPerIP)
	}

	return nil
}

// RegisterClient registers a new OAuth client and returns the client info
// clientIP is used for DoS protection via per-IP limits
func (s *ClientStore) RegisterClient(req *ClientRegistrationRequest, clientIP string) (*ClientRegistrationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate client ID
	clientID, err := generateSecureToken(ClientIDTokenLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	// Generate client secret
	clientSecret, err := generateSecureToken(ClientSecretTokenLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client secret: %w", err)
	}

	// Hash the client secret for storage
	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash client secret: %w", err)
	}

	now := time.Now().Unix()

	// Set defaults for missing fields
	tokenEndpointAuthMethod := req.TokenEndpointAuthMethod
	if tokenEndpointAuthMethod == "" {
		tokenEndpointAuthMethod = DefaultTokenEndpointAuthMethod
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = DefaultGrantTypes
	}

	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = DefaultResponseTypes
	}

	// Determine client type (default: confidential)
	clientType := req.ClientType
	if clientType == "" {
		clientType = "confidential"
	}

	// Security: Validate client type and auth method compatibility
	// RFC 6749: Public clients CANNOT use client_secret authentication
	// Only public clients can use "none" auth method
	if err := validateClientTypeAuthMethod(clientType, tokenEndpointAuthMethod); err != nil {
		return nil, err
	}

	// For public clients, don't generate or store a client secret
	var responseSecret string
	var secretHashStr string
	if clientType == "public" {
		responseSecret = "" // No secret for public clients
		secretHashStr = ""
	} else {
		responseSecret = clientSecret
		secretHashStr = string(secretHash)
	}

	// Create registered client
	client := &RegisteredClient{
		ClientID:                clientID,
		ClientSecret:            "", // Don't store plain text
		ClientSecretHash:        secretHashStr,
		ClientIDIssuedAt:        now,
		ClientSecretExpiresAt:   0, // Never expires
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		ClientName:              req.ClientName,
		Scope:                   req.Scope,
		ClientType:              clientType,
	}

	// Store the client
	s.clients[clientID] = client

	// Increment IP counter for DoS protection
	if clientIP != "" {
		s.clientsPerIP[clientIP]++
	}

	s.logger.Info("Registered new OAuth client",
		"client_id", clientID,
		"client_name", req.ClientName,
		"client_ip", clientIP,
		"clients_from_ip", s.clientsPerIP[clientIP],
		"redirect_uris", req.RedirectURIs,
		"grant_types", grantTypes,
	)

	// Return registration response
	return &ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            responseSecret, // Only returned once (empty for public clients)
		ClientIDIssuedAt:        now,
		ClientSecretExpiresAt:   0,
		RedirectURIs:            req.RedirectURIs,
		ClientType:              clientType,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		ClientName:              req.ClientName,
		Scope:                   req.Scope,
	}, nil
}

// GetClient retrieves a registered client by ID
func (s *ClientStore) GetClient(clientID string) (*RegisteredClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found")
	}

	return client, nil
}

// ValidateClientSecret validates a client's secret
func (s *ClientStore) ValidateClientSecret(clientID, clientSecret string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return fmt.Errorf("client not found")
	}

	// Compare with bcrypt hash
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)); err != nil {
		return fmt.Errorf("invalid client secret")
	}

	return nil
}

// ValidateRedirectURI checks if a redirect URI is registered for a client
func (s *ClientStore) ValidateRedirectURI(clientID, redirectURI string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return fmt.Errorf("client not found")
	}

	// Check if redirect_uri is in the registered list
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return nil
		}
	}

	return fmt.Errorf("redirect_uri not registered for this client")
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

// validateClientTypeAuthMethod validates that the client type and auth method are compatible
// Security enforcement:
//   - Public clients MUST use "none" auth method (no client secret)
//   - Confidential clients MUST NOT use "none" auth method (requires client secret)
func validateClientTypeAuthMethod(clientType, authMethod string) error {
	switch clientType {
	case "public":
		// Public clients must use "none" authentication
		if authMethod != "none" {
			return fmt.Errorf("public clients must use 'none' token_endpoint_auth_method")
		}
	case "confidential":
		// Confidential clients must NOT use "none" authentication
		if authMethod == "none" {
			return fmt.Errorf("confidential clients cannot use 'none' token_endpoint_auth_method (use 'client_secret_basic' or 'client_secret_post')")
		}
		// Validate that the auth method is supported
		validMethod := false
		for _, method := range SupportedTokenAuthMethods {
			if authMethod == method && method != "none" {
				validMethod = true
				break
			}
		}
		if !validMethod {
			return fmt.Errorf("unsupported token_endpoint_auth_method for confidential client: %s", authMethod)
		}
	default:
		return fmt.Errorf("invalid client_type: %s (must be 'public' or 'confidential')", clientType)
	}
	return nil
}
