package handler

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

// ServeProtectedResourceMetadata serves RFC 9728 Protected Resource Metadata
// with support for path-specific metadata discovery per MCP 2025-11-25.
//
// The handler extracts the resource path from the request URL and looks up
// path-specific configuration in ResourceMetadataByPath. If a match is found,
// path-specific metadata is returned; otherwise, default server-wide metadata is used.
//
// Path matching uses longest-prefix matching. For example, given paths
// "/mcp/files" and "/mcp/files/admin", a request for "/mcp/files/admin/users"
// would match "/mcp/files/admin".
func (h *Handler) ServeProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	security.SetDiscoveryCacheHeaders(w, h.server.Config.DiscoveryCacheMaxAge)

	// Extract the resource path from the request URL
	// Request path: /.well-known/oauth-protected-resource/mcp/files
	// Resource path: /mcp/files
	resourcePath := h.extractResourcePath(r.URL.Path)

	// Look up path-specific configuration
	pathConfig := h.findPathConfig(resourcePath)

	// Build metadata response
	metadata := h.buildProtectedResourceMetadata(resourcePath, pathConfig)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// extractResourcePath extracts the resource path from a Protected Resource Metadata URL.
// For example: "/.well-known/oauth-protected-resource/mcp/files" -> "/mcp/files"
func (h *Handler) extractResourcePath(requestPath string) string {
	prefix := oauth.MetadataPathProtectedResource
	if strings.HasPrefix(requestPath, prefix) {
		resourcePath := strings.TrimPrefix(requestPath, prefix)
		if resourcePath == "" {
			return "/"
		}
		return resourcePath
	}
	return "/"
}

// findPathConfig finds the best matching ProtectedResourceConfig for a given resource path.
// It uses longest-prefix matching to find the most specific configuration.
// Returns nil if no specific configuration is found.
//
// Note: Iteration over ResourceMetadataByPath map is non-deterministic in Go.
// This is handled by longest-match logic - when multiple paths match, the longest
// one wins. If two paths have equal length, the result may vary between runs,
// but this is an unlikely edge case in practice.
func (h *Handler) findPathConfig(resourcePath string) *server.ProtectedResourceConfig {
	if len(h.server.Config.ResourceMetadataByPath) == 0 {
		return nil
	}

	var bestMatch string
	var bestConfig *server.ProtectedResourceConfig

	for configPath, config := range h.server.Config.ResourceMetadataByPath {
		// Normalize the config path
		normalizedConfigPath := path.Clean("/" + strings.TrimPrefix(configPath, "/"))

		// Check if this path is a prefix of the resource path
		if helpers.PathMatchesPrefix(resourcePath, normalizedConfigPath) {
			// Use longest match
			if len(normalizedConfigPath) > len(bestMatch) {
				bestMatch = normalizedConfigPath
				configCopy := config // Create a copy to get a stable pointer
				bestConfig = &configCopy
			}
		}
	}

	return bestConfig
}

// buildProtectedResourceMetadata builds the Protected Resource Metadata response.
// It uses path-specific configuration if provided, falling back to server defaults.
func (h *Handler) buildProtectedResourceMetadata(resourcePath string, pathConfig *server.ProtectedResourceConfig) map[string]any {
	// Default values from server configuration
	resource := h.server.Config.GetResourceIdentifier()
	authServers := []string{h.server.Config.Issuer}
	bearerMethods := []string{"header"}
	var scopesSupported []string

	// Apply path-specific configuration if available
	if pathConfig != nil {
		// Use path-specific resource identifier if configured
		if pathConfig.ResourceIdentifier != "" {
			resource = pathConfig.ResourceIdentifier
		} else if resourcePath != "/" && resourcePath != "" {
			// For sub-paths, append the path to the base resource identifier
			resource = h.server.Config.GetResourceIdentifier() + resourcePath
		}

		// Use path-specific authorization servers if configured
		if len(pathConfig.AuthorizationServers) > 0 {
			authServers = pathConfig.AuthorizationServers
		}

		// Use path-specific bearer methods if configured
		if len(pathConfig.BearerMethodsSupported) > 0 {
			bearerMethods = pathConfig.BearerMethodsSupported
		}

		// Use path-specific scopes if configured
		if len(pathConfig.ScopesSupported) > 0 {
			scopesSupported = pathConfig.ScopesSupported
		}
	}

	// Fall back to server-wide scopes if no path-specific scopes
	if len(scopesSupported) == 0 && len(h.server.Config.SupportedScopes) > 0 {
		scopesSupported = h.server.Config.SupportedScopes
	}

	metadata := map[string]any{
		"resource":                 resource,
		"authorization_servers":    authServers,
		"bearer_methods_supported": bearerMethods,
	}

	// Include scopes_supported if configured (MCP 2025-11-25)
	if len(scopesSupported) > 0 {
		metadata["scopes_supported"] = scopesSupported
	}

	return metadata
}

// RegisterProtectedResourceMetadataRoutes registers all Protected Resource Metadata discovery routes.
// It registers the root endpoint and optional sub-path endpoints based on configuration.
//
// Route registration is done for:
//  1. Root endpoint: /.well-known/oauth-protected-resource (always registered)
//  2. Explicit mcpPath endpoint if provided (backward compatibility)
//  3. All paths from ResourceMetadataByPath configuration (MCP 2025-11-25)
//
// Security: This function validates all paths to prevent path traversal attacks and DoS through
// excessively long paths. Invalid paths are logged and skipped.
//
// Example usage:
//
//	// Legacy single-path registration
//	handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")
//
//	// With per-path configuration (new in MCP 2025-11-25)
//	// Configure in server.Config.ResourceMetadataByPath, then:
//	handler.RegisterProtectedResourceMetadataRoutes(mux, "")
//	// This registers routes for all configured paths automatically
func (h *Handler) RegisterProtectedResourceMetadataRoutes(mux *http.ServeMux, mcpPath string) {
	// Always register root metadata endpoint
	mux.HandleFunc(oauth.MetadataPathProtectedResource, h.ServeProtectedResourceMetadata)

	// Track registered paths to avoid duplicate registrations
	registeredPaths := make(map[string]bool)
	registeredPaths[oauth.MetadataPathProtectedResource] = true

	// Register explicit mcpPath if provided (backward compatibility)
	if mcpPath != "" && mcpPath != "/" {
		h.registerMetadataSubPath(mux, mcpPath, registeredPaths)
	}

	// Register paths from ResourceMetadataByPath configuration (MCP 2025-11-25)
	for configPath := range h.server.Config.ResourceMetadataByPath {
		h.registerMetadataSubPath(mux, configPath, registeredPaths)
	}
}

// registerMetadataSubPath registers a single sub-path for Protected Resource Metadata.
// It validates the path for security concerns and avoids duplicate registrations.
func (h *Handler) registerMetadataSubPath(mux *http.ServeMux, resourcePath string, registered map[string]bool) {
	// SECURITY: Validate path before registration to prevent attacks
	if err := h.validateMetadataPath(resourcePath); err != nil {
		h.logger.Warn("Rejecting invalid metadata path registration",
			"path", resourcePath,
			"error", err,
			"security_event", "invalid_metadata_path")
		return
	}

	// Clean and normalize the path
	cleanPath := path.Clean("/" + strings.TrimPrefix(resourcePath, "/"))
	subPath := oauth.MetadataPathProtectedResource + cleanPath

	// Skip if already registered
	if registered[subPath] {
		h.logger.Debug("Skipping duplicate metadata path registration",
			"path", subPath)
		return
	}

	h.logger.Debug("Registering metadata sub-path endpoint",
		"path", subPath,
		"resource_path", resourcePath)

	mux.HandleFunc(subPath, h.ServeProtectedResourceMetadata)
	registered[subPath] = true
}

// validateMetadataPath validates a metadata path for security concerns.
// It checks for path traversal attempts, excessive length, and other malicious patterns.
// This is a thin wrapper around helpers.ValidateMetadataPath for use by the Handler.
func (h *Handler) validateMetadataPath(mcpPath string) error {
	return helpers.ValidateMetadataPath(mcpPath)
}

// RegisterAuthorizationServerMetadataRoutes registers all Authorization Server Metadata discovery routes.
// This supports multi-tenant deployments with path-based issuers per MCP 2025-11-25.
//
// For issuer URLs with path components (e.g., https://auth.example.com/tenant1), registers:
//  1. Path insertion OAuth: /.well-known/oauth-authorization-server/tenant1
//  2. Path insertion OIDC: /.well-known/openid-configuration/tenant1
//  3. Path appending OIDC: /tenant1/.well-known/openid-configuration
//
// For issuer URLs without path components (e.g., https://auth.example.com), registers:
//  1. Standard OAuth: /.well-known/oauth-authorization-server
//  2. Standard OIDC: /.well-known/openid-configuration
//
// Example usage:
//
//	// Single-tenant: Configure issuer without path
//	config := &ServerConfig{
//		Issuer: "https://auth.example.com",
//	}
//	// Registers: /.well-known/oauth-authorization-server
//	//            /.well-known/openid-configuration
//	handler.RegisterAuthorizationServerMetadataRoutes(mux)
//
//	// Multi-tenant: Configure issuer with path
//	config := &ServerConfig{
//		Issuer: "https://auth.example.com/tenant1",
//	}
//	// Registers: /.well-known/oauth-authorization-server/tenant1
//	//            /.well-known/openid-configuration/tenant1
//	//            /tenant1/.well-known/openid-configuration
//	//            (plus standard endpoints for backward compatibility)
//	handler.RegisterAuthorizationServerMetadataRoutes(mux)
func (h *Handler) RegisterAuthorizationServerMetadataRoutes(mux *http.ServeMux) {
	issuerPath := h.extractIssuerPath()

	// Helper to register standard endpoints (always registered for backward compatibility)
	registerStandardEndpoints := func() {
		mux.HandleFunc("/.well-known/oauth-authorization-server", h.ServeAuthorizationServerMetadata)
		mux.HandleFunc("/.well-known/openid-configuration", h.ServeOpenIDConfiguration)
	}

	if issuerPath == "" || issuerPath == "/" {
		// Single-tenant deployment
		registerStandardEndpoints()
		h.logger.Debug("Registered authorization server metadata endpoints",
			"oauth_endpoint", "/.well-known/oauth-authorization-server",
			"oidc_endpoint", "/.well-known/openid-configuration")
		return
	}

	// Multi-tenant deployment with path-based issuer
	// Per MCP 2025-11-25 spec, support multiple discovery patterns

	// 1. OAuth 2.0 AS Metadata with path insertion
	// Example: /.well-known/oauth-authorization-server/tenant1
	oauthPathInsert := "/.well-known/oauth-authorization-server" + issuerPath
	mux.HandleFunc(oauthPathInsert, h.ServeAuthorizationServerMetadata)

	// 2. OpenID Connect Discovery with path insertion
	// Example: /.well-known/openid-configuration/tenant1
	oidcPathInsert := "/.well-known/openid-configuration" + issuerPath
	mux.HandleFunc(oidcPathInsert, h.ServeOpenIDConfiguration)

	// 3. OpenID Connect Discovery with path appending
	// Example: /tenant1/.well-known/openid-configuration
	oidcPathAppend := issuerPath + "/.well-known/openid-configuration"
	mux.HandleFunc(oidcPathAppend, h.ServeOpenIDConfiguration)

	// Backward compatibility
	registerStandardEndpoints()

	h.logger.Debug("Registered multi-tenant authorization server metadata endpoints",
		"issuer_path", issuerPath,
		"oauth_path_insert", oauthPathInsert,
		"oidc_path_insert", oidcPathInsert,
		"oidc_path_append", oidcPathAppend,
		"standard_endpoints", "also registered for backward compatibility")
}

// extractIssuerPath extracts the path component from the issuer URL.
// Returns empty string if the issuer has no path or only "/".
// Example: "https://auth.example.com/tenant1" -> "/tenant1"
func (h *Handler) extractIssuerPath() string {
	if h.server.Config.Issuer == "" {
		return ""
	}

	parsed, err := url.Parse(h.server.Config.Issuer)
	if err != nil {
		h.logger.Warn("Failed to parse issuer URL for path extraction",
			"issuer", h.server.Config.Issuer,
			"error", err)
		return ""
	}

	// Clean the path to remove trailing slashes and normalize
	cleanedPath := path.Clean(parsed.Path)

	// Return empty string if no path or just "/"
	if cleanedPath == "" || cleanedPath == "/" || cleanedPath == "." {
		return ""
	}

	return cleanedPath
}

// ServeAuthorizationServerMetadata serves RFC 8414 Authorization Server Metadata
func (h *Handler) ServeAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.discovery")
	defer endSpan()

	if r.Method != http.MethodGet {
		h.recordHTTPMetrics(r.Context(), endpointDiscovery, http.MethodGet, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, ok := h.gateIPRateLimit(w, r, span, endpointDiscovery, http.MethodGet, startTime); !ok {
		return
	}

	h.setCORSHeaders(w, r)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	security.SetDiscoveryCacheHeaders(w, h.server.Config.DiscoveryCacheMaxAge)

	metadata := h.buildAuthServerMetadata()

	h.recordHTTPMetrics(r.Context(), endpointDiscovery, http.MethodGet, http.StatusOK, startTime)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}


// buildAuthServerMetadata returns the metadata served at both
// /.well-known/oauth-authorization-server (RFC 8414) and
// /.well-known/openid-configuration (OIDC Discovery 1.0 §3).
func (h *Handler) buildAuthServerMetadata() map[string]any {
	metadata := map[string]any{
		"issuer":                                h.server.Config.Issuer,
		"authorization_endpoint":                h.server.Config.AuthorizationEndpoint(),
		"token_endpoint":                        h.server.Config.TokenEndpoint(),
		"response_types_supported":              oauth.DefaultResponseTypes,
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{oauth.PKCEMethodS256},
		"token_endpoint_auth_methods_supported": oauth.SupportedTokenAuthMethods,
		// RFC 9207: advertise that authorization responses include the `iss` parameter
		// so clients can verify the response came from the expected authorization server.
		"authorization_response_iss_parameter_supported": true,
		"claims_supported":                      []string{"sub", "aud", "iss", "exp", "iat", "nonce"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": h.idTokenSigningAlgs(),
	}

	h.addOptionalMetadata(metadata)
	return metadata
}

// idTokenSigningAlgs returns the alg values advertised in
// id_token_signing_alg_values_supported. OIDC Discovery 1.0 §3 mandates that
// RS256 be included; in JWT access-token mode the server's own signing alg
// is appended when distinct.
func (h *Handler) idTokenSigningAlgs() []string {
	algs := []string{"RS256"}
	if h.server.Config.IsJWTAccessTokenFormat() {
		if alg := h.server.Config.AccessTokenSigningAlgorithm; alg != "" && alg != "RS256" {
			algs = append(algs, alg)
		}
	}
	return algs
}

// addOptionalMetadata adds optional endpoints based on configuration.
func (h *Handler) addOptionalMetadata(metadata map[string]any) {
	if len(h.server.Config.SupportedScopes) > 0 {
		metadata["scopes_supported"] = h.server.Config.SupportedScopes
	}

	if h.isRegistrationAvailable() {
		metadata["registration_endpoint"] = h.server.Config.RegistrationEndpoint()
	}

	if h.server.Config.EnableRevocationEndpoint {
		metadata["revocation_endpoint"] = h.server.Config.RevocationEndpoint()
	}

	if h.server.Config.EnableIntrospectionEndpoint {
		metadata["introspection_endpoint"] = h.server.Config.IntrospectionEndpoint()
	}

	if h.server.Config.EnableUserInfoEndpoint {
		metadata["userinfo_endpoint"] = h.server.Config.UserInfoEndpoint()
	}

	if h.server.Config.EnableClientIDMetadataDocuments {
		metadata["client_id_metadata_document_supported"] = true
	}

	// jwks_uri (RFC 8414) is advertised only in JWT mode. Advertising it in
	// opaque mode would point clients at an endpoint that responds 404,
	// which is worse than silence — clients that follow the URL would log
	// errors on every discovery refresh.
	if h.server.Config.IsJWTAccessTokenFormat() {
		metadata["jwks_uri"] = h.server.Config.JWKSEndpoint()
		metadata["access_token_signing_alg_values_supported"] = []string{
			h.server.Config.AccessTokenSigningAlgorithm,
		}
	}
}

// isRegistrationAvailable checks if client registration is available.
func (h *Handler) isRegistrationAvailable() bool {
	return h.server.Config.AllowPublicClientRegistration ||
		h.server.Config.RegistrationAccessToken != "" ||
		len(h.server.Config.TrustedPublicRegistrationSchemes) > 0 ||
		len(h.server.Config.TrustedPublicRegistrationRedirectURIs) > 0
}

// ServeOpenIDConfiguration handles OpenID Connect Discovery 1.0 requests
// Per RFC 8414 Section 5, this endpoint returns the same metadata as the
// Authorization Server Metadata endpoint for compatibility with OpenID Connect clients
func (h *Handler) ServeOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	// OpenID Connect Discovery uses the same metadata as OAuth 2.0 AS Metadata
	// This ensures compatibility with both OAuth 2.0 and OpenID Connect clients
	h.ServeAuthorizationServerMetadata(w, r)
}

// ServeJWKS publishes the public half of the access-token signing key as a
// JSON Web Key Set per RFC 7517. Returns 404 when the server is configured
// for opaque-mode access tokens — the endpoint exists but advertising
// nothing is the honest response.
//
// Cache-Control is set to one hour: keys rotate manually (operator changes
// AccessTokenSigningKeyID and restarts), and verifiers caching for an hour
// is the conventional middle ground between churn and freshness.
func (h *Handler) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.jwks")
	defer endSpan()

	if r.Method != http.MethodGet {
		h.recordHTTPMetrics(r.Context(), endpointJWKS, http.MethodGet, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointJWKS, http.MethodGet, startTime)
	if !ok {
		return
	}

	if !h.server.Config.IsJWTAccessTokenFormat() {
		h.recordHTTPMetrics(r.Context(), endpointJWKS, http.MethodGet, http.StatusNotFound, startTime)
		http.NotFound(w, r)
		return
	}

	jwks, err := h.server.PublicJWKS()
	if err != nil {
		h.logger.Error("Failed to build JWKS for discovery endpoint",
			"error", err,
			"ip", clientIP)
		h.recordHTTPMetrics(r.Context(), endpointJWKS, http.MethodGet, http.StatusInternalServerError, startTime)
		http.Error(w, "JWKS unavailable", http.StatusInternalServerError)
		return
	}
	if jwks == nil || len(jwks.Keys) == 0 {
		h.recordHTTPMetrics(r.Context(), endpointJWKS, http.MethodGet, http.StatusNotFound, startTime)
		http.NotFound(w, r)
		return
	}

	h.setCORSHeaders(w, r)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	h.recordHTTPMetrics(r.Context(), endpointJWKS, http.MethodGet, http.StatusOK, startTime)
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		h.logger.Warn("Failed to encode JWKS response", "error", err)
	}
}
