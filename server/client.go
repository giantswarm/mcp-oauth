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
	// Check IP limit to prevent DoS via mass client registration
	if err := s.clientStore.CheckIPLimit(ctx, clientIP, maxClientsPerIP); err != nil {
		return nil, "", err
	}

	// SECURITY: Validate redirect URIs for security (SSRF, dangerous schemes, private IPs)
	// This validation is critical for preventing open redirect and SSRF vulnerabilities
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
		return nil, "", fmt.Errorf("invalid_redirect_uri: %w", err)
	}

	// Generate client ID using oauth2.GenerateVerifier (same quality)
	clientID := generateRandomToken()

	// OAUTH 2.1 COMPLIANCE: Determine client type from token_endpoint_auth_method
	// Per RFC 7591 Section 2: token_endpoint_auth_method determines client type
	// - "none" = public client (no secret)
	// - any other method = confidential client (has secret)
	if tokenEndpointAuthMethod == TokenEndpointAuthMethodNone {
		// Client explicitly requests public client (no secret)
		clientType = ClientTypePublic
	} else if clientType == "" {
		// No explicit client_type, infer from auth method
		// Default to confidential for backward compatibility
		clientType = ClientTypeConfidential
	}

	// Set default auth method if not specified
	if tokenEndpointAuthMethod == "" {
		if clientType == ClientTypePublic {
			tokenEndpointAuthMethod = TokenEndpointAuthMethodNone
		} else {
			tokenEndpointAuthMethod = TokenEndpointAuthMethodBasic
		}
	}

	// Generate client secret for confidential clients
	var clientSecret string
	var clientSecretHash string

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
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              clientName,
		Scopes:                  scopes,
		CreatedAt:               time.Now(),
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
		"token_endpoint_auth_method", tokenEndpointAuthMethod,
		"client_ip", clientIP)

	return client, clientSecret, nil
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
// Security: Custom URI schemes (cursor://, vscode://) can only be intercepted
// by the application that registered the scheme with the OS. This makes them
// inherently safe for public registration - an attacker cannot register a
// malicious client with cursor:// because they can't receive the callback.
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
	if len(s.Config.TrustedPublicRegistrationSchemes) == 0 {
		return false, "", nil
	}

	// No redirect URIs provided - require token
	if len(redirectURIs) == 0 {
		return false, "", nil
	}

	// Build a map of trusted schemes for efficient lookup (case-insensitive)
	trustedSchemes := make(map[string]bool, len(s.Config.TrustedPublicRegistrationSchemes))
	for _, trusted := range s.Config.TrustedPublicRegistrationSchemes {
		trustedSchemes[strings.ToLower(trusted)] = true
	}

	var firstTrustedScheme string
	trustedCount := 0

	for _, uri := range redirectURIs {
		parsed, err := url.Parse(uri)
		if err != nil {
			// Invalid URI - cannot determine scheme, require token for safety
			return false, "", fmt.Errorf("invalid redirect URI: %w", err)
		}

		scheme := strings.ToLower(parsed.Scheme)
		if scheme == "" {
			// No scheme - require token for safety
			return false, "", fmt.Errorf("redirect URI missing scheme: %s", uri)
		}

		if trustedSchemes[scheme] {
			trustedCount++
			if firstTrustedScheme == "" {
				firstTrustedScheme = scheme
			}
		} else if s.Config.StrictSchemeMatching {
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
