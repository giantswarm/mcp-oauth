package server

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// Client type constants (also defined in root package constants.go)
// These are duplicated to avoid import cycles since root package imports server package
const (
	// ClientTypeConfidential represents a confidential OAuth client
	ClientTypeConfidential = "confidential"

	// ClientTypePublic represents a public OAuth client
	ClientTypePublic = "public"
)

// Token endpoint authentication method constants (RFC 7591)
// These are duplicated to avoid import cycles since root package imports server package
const (
	// TokenEndpointAuthMethodNone represents no authentication (public clients)
	TokenEndpointAuthMethodNone = "none"

	// TokenEndpointAuthMethodBasic represents HTTP Basic authentication
	TokenEndpointAuthMethodBasic = "client_secret_basic"

	// TokenEndpointAuthMethodPost represents POST form parameters
	TokenEndpointAuthMethodPost = "client_secret_post"
)

// RegisterClient registers a new OAuth client with IP-based DoS protection
// tokenEndpointAuthMethod determines how the client authenticates at the token endpoint:
// - "none": Public client (no secret, PKCE-only auth) - used by native/CLI apps
// - "client_secret_basic": Confidential client (Basic Auth with secret) - default
// - "client_secret_post": Confidential client (POST form with secret)
//
// Security: This function validates redirect URIs against the security configuration
// (ProductionMode, AllowPrivateIPRedirectURIs, etc.) to prevent SSRF and open redirect attacks.
func (s *Server) RegisterClient(ctx context.Context, clientName, clientType, tokenEndpointAuthMethod string, redirectURIs []string, scopes []string, clientIP string, maxClientsPerIP int) (*storage.Client, string, error) {
	if err := s.clientStore.CheckIPLimit(ctx, clientIP, maxClientsPerIP); err != nil {
		return nil, "", err
	}

	if err := s.validateRedirectURIsWithAudit(ctx, redirectURIs, clientIP); err != nil {
		return nil, "", err
	}

	clientID := generateRandomToken()
	clientType, tokenEndpointAuthMethod = resolveClientTypeAndAuthMethod(clientType, tokenEndpointAuthMethod)
	clientSecret, clientSecretHash, err := generateClientSecret(clientType)
	if err != nil {
		return nil, "", err
	}

	client := &storage.Client{
		ClientID:                clientID,
		ClientSecretHash:        clientSecretHash,
		ClientType:              clientType,
		RedirectURIs:            redirectURIs,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              clientName,
		Scopes:                  scopes,
		CreatedAt:               time.Now(),
	}

	if err := s.clientStore.SaveClient(ctx, client); err != nil {
		return nil, "", fmt.Errorf("failed to save client: %w", err)
	}

	s.trackClientIPAndLog(client, clientSecret, clientIP)
	return client, clientSecret, nil
}

// validateRedirectURIsWithAudit validates redirect URIs and logs failures for auditing.
func (s *Server) validateRedirectURIsWithAudit(ctx context.Context, redirectURIs []string, clientIP string) error {
	if err := s.ValidateRedirectURIsForRegistration(ctx, redirectURIs); err != nil {
		if s.Auditor != nil {
			category := GetRedirectURIErrorCategory(err)
			s.Auditor.LogEvent(security.Event{
				Type: security.EventClientRegistrationRejected,
				Details: map[string]any{
					"reason":    "redirect_uri_validation_failed",
					"category":  category,
					"client_ip": clientIP,
				},
			})
		}
		s.Logger.Warn("Client registration rejected: redirect URI validation failed",
			"error", err.Error(),
			"client_ip", clientIP)
		return fmt.Errorf("invalid_redirect_uri: %w", err)
	}
	return nil
}

// resolveClientTypeAndAuthMethod determines the client type and auth method.
// Per RFC 7591 Section 2: token_endpoint_auth_method determines client type.
func resolveClientTypeAndAuthMethod(clientType, tokenEndpointAuthMethod string) (string, string) {
	if tokenEndpointAuthMethod == TokenEndpointAuthMethodNone {
		clientType = ClientTypePublic
	} else if clientType == "" {
		clientType = ClientTypeConfidential
	}

	if tokenEndpointAuthMethod == "" {
		if clientType == ClientTypePublic {
			tokenEndpointAuthMethod = TokenEndpointAuthMethodNone
		} else {
			tokenEndpointAuthMethod = TokenEndpointAuthMethodBasic
		}
	}

	return clientType, tokenEndpointAuthMethod
}

// generateClientSecret generates a secret for confidential clients.
func generateClientSecret(clientType string) (string, string, error) {
	if clientType != ClientTypeConfidential {
		return "", "", nil
	}

	clientSecret := generateRandomToken()
	hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash client secret: %w", err)
	}
	return clientSecret, string(hash), nil
}

// trackClientIPAndLog tracks the IP for DoS protection and logs the registration.
func (s *Server) trackClientIPAndLog(client *storage.Client, _ /* clientSecret - not logged for security */, clientIP string) {
	if memStore, ok := s.clientStore.(*memory.Store); ok {
		memStore.TrackClientIP(clientIP)
	}

	if s.Auditor != nil {
		s.Auditor.LogClientRegistered(client.ClientID, client.ClientType, clientIP)
	}

	s.Logger.Info("Registered new OAuth client",
		"client_id", client.ClientID,
		"client_name", client.ClientName,
		"client_type", client.ClientType,
		"token_endpoint_auth_method", client.TokenEndpointAuthMethod,
		"client_ip", clientIP)
}

// ValidateClientCredentials validates client credentials for token endpoint
func (s *Server) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) error {
	return s.clientStore.ValidateClientSecret(ctx, clientID, clientSecret)
}

// GetClient retrieves a client by ID (for use by handler)
// Supports both pre-registered clients and URL-based Client ID Metadata Documents (MCP 2025-11-25)
func (s *Server) GetClient(ctx context.Context, clientID string) (*storage.Client, error) {
	return s.getOrFetchClient(ctx, clientID)
}

// CanRegisterWithTrustedScheme checks if a registration request can proceed without
// a registration access token based on the redirect URIs using trusted custom URI schemes.
//
// This enables compatibility with MCP clients like Cursor that don't support
// registration tokens, while maintaining security for other clients.
//
// Security: Custom URI schemes are harder to hijack than web URLs, but protection
// varies by platform (strong on Android App Links, moderate on macOS/Windows/iOS,
// weak on Linux). PKCE is the primary security control and is always enforced.
// See docs/security.md for platform-specific considerations.
//
// Parameters:
//   - redirectURIs: The redirect URIs from the registration request
//
// Returns:
//   - allowed: true if registration can proceed without a token
//   - scheme: the first trusted scheme found (for audit logging), empty if not allowed
//   - error: validation error if any URI is invalid
func (s *Server) CanRegisterWithTrustedScheme(redirectURIs []string) (allowed bool, scheme string, err error) {
	// No trusted schemes configured - require token
	// Use the pre-computed map for O(1) lookup
	if len(s.Config.trustedSchemesMap) == 0 {
		return false, "", nil
	}

	// No redirect URIs provided - require token
	if len(redirectURIs) == 0 {
		return false, "", nil
	}

	// Strict matching is enabled by default unless explicitly disabled
	strictMatching := !s.Config.DisableStrictSchemeMatching

	var firstTrustedScheme string
	trustedCount := 0

	for _, uri := range redirectURIs {
		parsed, err := url.Parse(uri)
		if err != nil {
			// Invalid URI - cannot determine scheme, require token for safety
			return false, "", fmt.Errorf("invalid redirect URI: %w", err)
		}

		// Normalize scheme to lowercase for case-insensitive matching (RFC 3986)
		uriScheme := strings.ToLower(parsed.Scheme)
		if uriScheme == "" {
			// No scheme - require token for safety
			return false, "", fmt.Errorf("redirect URI missing scheme: %s", uri)
		}

		if s.Config.trustedSchemesMap[uriScheme] {
			trustedCount++
			if firstTrustedScheme == "" {
				firstTrustedScheme = uriScheme
			}
		} else if strictMatching {
			// Strict mode: all URIs must use trusted schemes
			// Found an untrusted scheme, require token
			return false, "", nil
		}
	}

	// At least one trusted scheme must be found
	if trustedCount == 0 {
		return false, "", nil
	}

	return true, firstTrustedScheme, nil
}
