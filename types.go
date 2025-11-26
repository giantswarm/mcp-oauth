package oauth

// ProtectedResourceMetadata represents OAuth 2.0 Protected Resource Metadata (RFC 9728)
type ProtectedResourceMetadata struct {
	// Resource is the identifier for the protected resource
	Resource string `json:"resource"`

	// AuthorizationServers lists the authorization servers that can issue tokens for this resource
	AuthorizationServers []string `json:"authorization_servers"`

	// BearerMethodsSupported lists the ways Bearer tokens can be sent (RFC 6750)
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// ResourceSigningAlgValuesSupported lists supported signing algorithms
	ResourceSigningAlgValuesSupported []string `json:"resource_signing_alg_values_supported,omitempty"`

	// ScopesSupported lists the scopes understood by this resource
	ScopesSupported []string `json:"scopes_supported,omitempty"`
}

// ErrorResponse represents an OAuth error response
type ErrorResponse struct {
	// Error is the error code
	Error string `json:"error"`

	// ErrorDescription provides additional information
	ErrorDescription string `json:"error_description,omitempty"`

	// ErrorURI points to error documentation
	ErrorURI string `json:"error_uri,omitempty"`
}

// ==================== OAuth 2.1 Authorization Server Types ====================

// AuthorizationServerMetadata represents OAuth 2.0 Authorization Server Metadata (RFC 8414)
type AuthorizationServerMetadata struct {
	// Issuer is the authorization server's issuer identifier URL
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is the URL of the authorization endpoint
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// TokenEndpoint is the URL of the token endpoint
	TokenEndpoint string `json:"token_endpoint"`

	// RegistrationEndpoint is the URL of the dynamic client registration endpoint (RFC 7591)
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`

	// ScopesSupported lists the OAuth scopes supported
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// ResponseTypesSupported lists the OAuth response types supported
	ResponseTypesSupported []string `json:"response_types_supported"`

	// GrantTypesSupported lists the OAuth grant types supported
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`

	// TokenEndpointAuthMethodsSupported lists the client authentication methods supported at the token endpoint
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// CodeChallengeMethodsSupported lists the PKCE code challenge methods supported
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`

	// RevocationEndpoint is the URL of the OAuth 2.0 token revocation endpoint (RFC 7009)
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// IntrospectionEndpoint is the URL of the OAuth 2.0 token introspection endpoint (RFC 7662)
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`

	// ClientIDMetadataDocumentSupported indicates support for Client ID Metadata Documents (MCP 2025-11-25)
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported,omitempty"`
}

// ==================== Dynamic Client Registration (RFC 7591) Types ====================

// ClientRegistrationRequest represents a dynamic client registration request
type ClientRegistrationRequest struct {
	// RedirectURIs is the array of redirection URIs for use in redirect-based flows
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// TokenEndpointAuthMethod is the requested authentication method for the token endpoint
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// GrantTypes is the array of OAuth 2.0 grant types the client will use
	GrantTypes []string `json:"grant_types,omitempty"`

	// ResponseTypes is the array of OAuth 2.0 response types the client will use
	ResponseTypes []string `json:"response_types,omitempty"`

	// ClientName is the human-readable name of the client
	ClientName string `json:"client_name,omitempty"`

	// ClientURI is the URL of the client's home page
	ClientURI string `json:"client_uri,omitempty"`

	// Scope is the space-separated list of scope values
	Scope string `json:"scope,omitempty"`

	// ClientType indicates if this is a "public" or "confidential" client
	// Public clients (mobile, SPA) can use "none" auth method
	// Confidential clients (server-side) must use client_secret_basic or client_secret_post
	ClientType string `json:"client_type,omitempty"`
}

// ClientRegistrationResponse represents a dynamic client registration response
type ClientRegistrationResponse struct {
	// ClientID is the unique client identifier
	ClientID string `json:"client_id"`

	// ClientSecret is the client secret (for confidential clients)
	ClientSecret string `json:"client_secret,omitempty"`

	// ClientIDIssuedAt is the time the client_id was issued
	ClientIDIssuedAt int64 `json:"client_id_issued_at,omitempty"`

	// ClientSecretExpiresAt is when the client_secret expires (0 = never)
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`

	// RedirectURIs is the array of redirection URIs
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// TokenEndpointAuthMethod is the authentication method for the token endpoint
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// GrantTypes is the array of OAuth 2.0 grant types
	GrantTypes []string `json:"grant_types,omitempty"`

	// ResponseTypes is the array of OAuth 2.0 response types
	ResponseTypes []string `json:"response_types,omitempty"`

	// ClientName is the human-readable name of the client
	ClientName string `json:"client_name,omitempty"`

	// Scope is the space-separated list of scope values
	Scope string `json:"scope,omitempty"`

	// ClientType indicates if this is a "public" or "confidential" client
	ClientType string `json:"client_type,omitempty"`
}

// TokenResponse represents an OAuth 2.0 token response
type TokenResponse struct {
	// AccessToken is the access token
	AccessToken string `json:"access_token"`

	// TokenType is the type of token (always "Bearer")
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime in seconds of the access token
	ExpiresIn int64 `json:"expires_in,omitempty"`

	// RefreshToken is the refresh token (optional)
	RefreshToken string `json:"refresh_token,omitempty"`

	// Scope is the scope of the access token
	Scope string `json:"scope,omitempty"`
}
