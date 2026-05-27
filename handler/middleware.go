package handler

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// ValidateToken is middleware that validates OAuth tokens
func (h *Handler) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		clientIP := h.clientIP(r)

		if h.checkIPRateLimit(w, r, clientIP) {
			h.recordHTTPMetrics(r.Context(), endpointValidateToken, r.Method, http.StatusTooManyRequests, startTime)
			return
		}

		accessToken, ok := h.extractBearerToken(w, r)
		if !ok {
			return
		}

		userInfo, err := h.server.ValidateToken(r.Context(), accessToken)
		if err != nil {
			h.logger.Warn("Token validation failed", "ip", clientIP, "error", err)
			h.writeUnauthorizedError(w, r, constants.ErrorCodeInvalidToken, "Token validation failed")
			return
		}

		// Single metadata lookup: used for both scope validation and session ID
		metadata := h.getTokenMetadata(accessToken)

		// Enforce DPoP sender-constraint (RFC 9449 §6.1, §7).
		// tokenJKT is the key thumbprint the token was bound to at issuance.
		// proofJKT is the thumbprint of the key that signed the DPoP proof on
		// this request, set in context by DPoPMiddleware.
		tokenJKT := jktFromToken(accessToken, metadata)
		proofJKT := dpopProofJKTFromContext(r.Context())
		if tokenJKT != "" {
			if proofJKT == "" {
				// #383: DPoP-bound token presented as plain Bearer — reject.
				h.logger.Warn("DPoP-bound token presented without DPoP proof",
					"ip", clientIP,
					"token_suffix", accessToken[max(0, len(accessToken)-8):])
				h.server.Auditor.LogAuthFailure(r.Context(), "", "", clientIP, "dpop_bound_token_bearer_bypass")
				h.writeUnauthorizedError(w, r, constants.ErrorCodeInvalidToken, "DPoP-bound token must be presented with a DPoP proof")
				return
			}
			if proofJKT != tokenJKT {
				// #384: Proof was signed with a different key than the one bound to the token.
				h.logger.Warn("DPoP proof key does not match token cnf.jkt",
					"ip", clientIP,
					"token_suffix", accessToken[max(0, len(accessToken)-8):])
				h.server.Auditor.LogAuthFailure(r.Context(), "", "", clientIP, "dpop_key_binding_mismatch")
				h.writeUnauthorizedError(w, r, constants.ErrorCodeInvalidToken, "DPoP proof key does not match token binding")
				return
			}
		}

		if !h.validateTokenScopesFromMetadata(w, r, metadata, userInfo, clientIP) {
			return
		}

		if h.checkUserRateLimit(w, r, userInfo.ID, clientIP) {
			h.recordHTTPMetrics(r.Context(), endpointValidateToken, r.Method, http.StatusTooManyRequests, startTime)
			return
		}

		ctx := contextWithValidatedToken(r.Context(), userInfo, metadata)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// jktFromToken returns the JWK thumbprint bound to the token. For opaque tokens
// it reads from stored metadata; for self-issued JWTs it parses the cnf.jkt
// claim without re-verifying the signature (safe: token was verified by
// ValidateToken immediately before this call).
func jktFromToken(accessToken string, metadata *storage.TokenMetadata) string {
	if metadata != nil && metadata.JKT != "" {
		return metadata.JKT
	}
	if !oidc.IsJWT(accessToken) {
		return ""
	}
	claims, err := oidc.ParseUnverifiedClaims(accessToken)
	if err != nil {
		return ""
	}
	cnf, _ := claims["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

// contextWithValidatedToken stamps the authenticated UserInfo on ctx and,
// when metadata is available, also propagates the session ID (refresh-token
// family) and the access token's granted scopes. Zero-valued metadata fields
// are skipped so downstream consumers can distinguish "absent" from "empty".
func contextWithValidatedToken(ctx context.Context, userInfo *providers.UserInfo, metadata *storage.TokenMetadata) context.Context {
	ctx = ContextWithUserInfo(ctx, userInfo)
	if metadata == nil {
		return ctx
	}
	if metadata.FamilyID != "" {
		ctx = ContextWithSessionID(ctx, metadata.FamilyID)
	}
	if len(metadata.Scopes) > 0 {
		ctx = ContextWithScopes(ctx, metadata.Scopes)
	}
	return ctx
}

// checkIPRateLimit checks if the client IP is rate limited. Returns true if limited.
func (h *Handler) checkIPRateLimit(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	if h.server.RateLimiter == nil || h.server.RateLimiter.Allow(security.RateLimitBucket(clientIP)) {
		return false
	}

	h.logger.Warn("Rate limit exceeded", "ip", clientIP)
	h.recordRateLimitExceeded(r.Context(), "ip", clientIP, "", r.URL.Path)
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecondsForRate(h.server.RateLimiter.Rate())))
	h.writeError(w, constants.ErrorCodeRateLimitExceeded, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
	return true
}

// checkUserRateLimit checks if the user is rate limited. Returns true if limited.
func (h *Handler) checkUserRateLimit(w http.ResponseWriter, r *http.Request, userID, clientIP string) bool {
	if h.server.UserRateLimiter == nil || h.server.UserRateLimiter.Allow(userID) {
		return false
	}

	h.logger.Warn("User rate limit exceeded", "user_id", userID, "ip", clientIP)
	h.recordUserRateLimitExceeded(r.Context(), clientIP, userID)
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecondsForRate(h.server.UserRateLimiter.Rate())))
	h.writeError(w, constants.ErrorCodeRateLimitExceeded, "Rate limit exceeded for user. Please try again later.", http.StatusTooManyRequests)
	return true
}

// recordRateLimitExceeded records rate limit metrics and audit events.
func (h *Handler) recordRateLimitExceeded(ctx context.Context, limitType, clientIP, userID, endpoint string) {
	h.server.Instrumentation.Metrics().RecordRateLimitExceeded(ctx, limitType)
	h.server.Auditor.LogEvent(ctx, security.Event{
		Type:      security.EventRateLimitExceeded,
		IPAddress: clientIP,
		Details:   map[string]any{"endpoint": endpoint},
	})
	h.server.Auditor.LogRateLimitExceeded(ctx, clientIP, userID)
}

// recordUserRateLimitExceeded records user rate limit metrics and audit events.
func (h *Handler) recordUserRateLimitExceeded(ctx context.Context, clientIP, userID string) {
	h.server.Instrumentation.Metrics().RecordRateLimitExceeded(ctx, "user")
	h.server.Auditor.LogRateLimitExceeded(ctx, clientIP, userID)
}

// extractBearerToken extracts the Bearer token from the Authorization header.
// Returns the token and true if successful, or writes an error and returns false.
func (h *Handler) extractBearerToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.writeUnauthorizedError(w, r, constants.ErrorCodeInvalidToken, "Missing Authorization header")
		return "", false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		h.writeUnauthorizedError(w, r, constants.ErrorCodeInvalidToken, "Invalid Authorization header format")
		return "", false
	}

	return parts[1], true
}

// writeUnauthorizedError writes a 401 Unauthorized response with endpoint-specific scope guidance.
// It implements MCP 2025-11-25 scope selection strategy by including endpoint-specific scopes
// in the WWW-Authenticate header when available.
//
// Unlike writeError(), this method accepts a request object to determine endpoint-specific scope
// requirements. The scope resolution priority is:
//  1. EndpointMethodScopeRequirements or EndpointScopeRequirements (endpoint-specific)
//  2. DefaultChallengeScopes (configured fallback)
//  3. No scope parameter (if nothing configured)
//
// Example response for /api/files/* endpoint:
//
//	HTTP/1.1 401 Unauthorized
//	WWW-Authenticate: Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource",
//	                         scope="files:read files:write",
//	                         error="invalid_token",
//	                         error_description="Missing Authorization header"
//
// This helps MCP clients discover exactly which scopes they need to request for a specific endpoint,
// improving the authorization flow UX and reducing unnecessary authorization requests.
//
// Parameters:
//   - w: HTTP response writer
//   - r: HTTP request (used to determine endpoint-specific scopes)
//   - code: OAuth error code (e.g., "invalid_token")
//   - description: Human-readable error description
func (h *Handler) writeUnauthorizedError(w http.ResponseWriter, r *http.Request, code, description string) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	// MCP 2025-11-25: Include WWW-Authenticate header with endpoint-specific scope guidance
	if !h.server.Config.DisableWWWAuthenticateMetadata {
		// Get endpoint-specific scopes (or fallback to defaults)
		scope := h.getChallengeScopes(r)
		w.Header().Set("WWW-Authenticate", h.formatWWWAuthenticate(scope, code, description))
	} else {
		// Minimal header for backward compatibility with legacy clients (opt-in)
		w.Header().Set("WWW-Authenticate", tokenTypeBearer)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// writeInsufficientScopeError writes a 403 Forbidden response with insufficient_scope error.
// This implements MCP 2025-11-25 scope challenge handling for protected resources.
// Per RFC 6750 Section 3.1, the response includes WWW-Authenticate header with:
//   - error="insufficient_scope"
//   - scope parameter listing required scopes
//   - resource_metadata URL for discovery
//
// Example response:
//
//	HTTP/1.1 403 Forbidden
//	WWW-Authenticate: Bearer error="insufficient_scope",
//	                         scope="files:read files:write",
//	                         resource_metadata="https://example.com/.well-known/oauth-protected-resource"
//
// Parameters:
//   - w: HTTP response writer
//   - requiredScopes: List of scopes needed to access the resource
//   - description: Optional human-readable error description
func (h *Handler) writeInsufficientScopeError(w http.ResponseWriter, requiredScopes []string, description string) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	// Build scope string for WWW-Authenticate header
	scope := strings.Join(requiredScopes, " ")

	// Use formatWWWAuthenticate to build the header with error details
	w.Header().Set("WWW-Authenticate", h.formatWWWAuthenticate(scope, constants.ErrorCodeInsufficientScope, description))

	// Write JSON error response body
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             constants.ErrorCodeInsufficientScope,
		"error_description": description,
	})
}

// formatWWWAuthenticate formats the WWW-Authenticate header value per RFC 6750 and RFC 9728
// It includes the resource_metadata URL for MCP 2025-11-25 compliance, along with optional
// scope, error, and error_description parameters.
//
// Parameters:
//   - scope: Space-separated list of scopes required (e.g., "files:read user:profile")
//   - error: OAuth error code (e.g., "invalid_token", "insufficient_scope")
//   - errorDesc: Human-readable error description
//
// Example output:
//
//	Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource",
//	       scope="files:read user:profile",
//	       error="invalid_token",
//	       error_description="Token has expired"
func (h *Handler) formatWWWAuthenticate(scope, errCode, errorDesc string) string {
	// Build the challenge parameters (excluding the Bearer scheme)
	var params []string

	// Include resource_metadata URL when using WWW-Authenticate discovery (MCP 2025-11-25)
	// Note: MCP servers must implement EITHER WWW-Authenticate OR well-known URI discovery.
	// When using WWW-Authenticate (this implementation), resource_metadata parameter is required.
	resourceMetadataURL := h.server.Config.ProtectedResourceMetadataEndpoint()
	params = append(params, fmt.Sprintf(`resource_metadata="%s"`, resourceMetadataURL))

	// Optional: Include scope if configured
	// SECURITY: Sanitize scope to prevent header injection (defense-in-depth)
	// While RFC 6749 Section 3.3 restricts scope to a limited character set,
	// we escape special characters as a defense-in-depth measure.
	if scope != "" {
		// Escape backslashes first, then quotes (order matters!)
		// This follows RFC 2616/7230 quoted-string rules for HTTP headers
		escapedScope := strings.ReplaceAll(scope, `\`, `\\`)
		escapedScope = strings.ReplaceAll(escapedScope, `"`, `\"`)
		params = append(params, fmt.Sprintf(`scope="%s"`, escapedScope))
	}

	// Optional: Include error code if provided
	if errCode != "" {
		params = append(params, fmt.Sprintf(`error="%s"`, errCode))
	}

	// Optional: Include error description if provided
	if errorDesc != "" {
		// Escape backslashes first, then quotes (order matters!)
		// This follows RFC 2616/7230 quoted-string rules for HTTP headers
		escapedDesc := strings.ReplaceAll(errorDesc, `\`, `\\`)
		escapedDesc = strings.ReplaceAll(escapedDesc, `"`, `\"`)
		params = append(params, fmt.Sprintf(`error_description="%s"`, escapedDesc))
	}

	// Format: "Bearer param1="value1", param2="value2"" per RFC 6750 Section 3
	// Note: Space after "Bearer", then comma-space between parameters
	return "Bearer " + strings.Join(params, ", ")
}

// Context key for user info
type contextKey string

const userInfoKey contextKey = "user_info"

// UserInfoFromContext retrieves user info from the request context
func UserInfoFromContext(ctx context.Context) (*providers.UserInfo, bool) {
	userInfo, ok := ctx.Value(userInfoKey).(*providers.UserInfo)
	return userInfo, ok
}

// ContextWithUserInfo creates a context with the given user info.
// This is useful for testing code that depends on authenticated user context.
//
// WARNING: This function should ONLY be used for testing. In production,
// user info should ONLY be set by the ValidateToken middleware after
// proper token validation. Using this function to bypass authentication
// in production code is a security vulnerability.
//
// Note: if userInfo is nil, UserInfoFromContext will return (nil, true).
// Callers should check both the ok value and nil-ness of the returned userInfo.
func ContextWithUserInfo(ctx context.Context, userInfo *providers.UserInfo) context.Context {
	return context.WithValue(ctx, userInfoKey, userInfo)
}

type sessionIDKey struct{}

// ContextWithSessionID creates a context carrying a stable session identifier
// derived from the OAuth refresh token family. This allows consumers to
// associate per-session state with the current authenticated request.
func ContextWithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey{}, sessionID)
}

// SessionIDFromContext retrieves the session identifier from the request context.
// Returns the session ID and true if present and non-empty, or ("", false) otherwise.
func SessionIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(sessionIDKey{}).(string)
	return id, ok && id != ""
}

type scopesKey struct{}

// ContextWithScopes carries the scopes granted to the access token on the
// current request. Set by [Handler.ValidateToken] from the token's metadata.
func ContextWithScopes(ctx context.Context, scopes []string) context.Context {
	return context.WithValue(ctx, scopesKey{}, scopes)
}

// ScopesFromContext returns the scopes granted to the access token on the
// current request. The bool is false when no scopes are present in the context.
func ScopesFromContext(ctx context.Context) ([]string, bool) {
	scopes, ok := ctx.Value(scopesKey{}).([]string)
	return scopes, ok
}

// getTokenMetadata retrieves token metadata from storage.
// Returns nil if the store doesn't support metadata or if metadata cannot be retrieved.
func (h *Handler) getTokenMetadata(accessToken string) *storage.TokenMetadata {
	metadataStore, ok := h.server.TokenStore().(storage.TokenMetadataGetter)
	if !ok {
		return nil
	}

	metadata, err := metadataStore.GetTokenMetadata(accessToken)
	if err != nil {
		h.logger.Warn("Failed to retrieve token metadata", "error", err)
		return nil
	}

	return metadata
}

// validateTokenScopesFromMetadata checks if the token has required scopes using
// pre-fetched metadata (avoids a redundant GetTokenMetadata call).
// Returns true if validation passes, false if insufficient scopes (response already written).
func (h *Handler) validateTokenScopesFromMetadata(w http.ResponseWriter, r *http.Request, metadata *storage.TokenMetadata, userInfo *providers.UserInfo, clientIP string) bool {
	requiredScopes := h.getRequiredScopes(r)
	if len(requiredScopes) == 0 {
		return true
	}

	var tokenScopes []string
	if metadata != nil {
		tokenScopes = metadata.Scopes
	}

	if hasRequiredScopes(tokenScopes, requiredScopes) {
		return true
	}

	h.logger.Warn("Insufficient scope for endpoint",
		"user_id", userInfo.ID,
		"endpoint", r.URL.Path,
		"method", r.Method,
		"token_scopes", tokenScopes,
		"required_scopes", requiredScopes,
		"ip", clientIP)

	h.server.Auditor.LogAuthFailure(r.Context(), userInfo.ID, "", clientIP, "insufficient_scope")

	var description string
	if h.server.Config.HideEndpointPathInErrors {
		// SECURITY: Hide endpoint path to prevent information disclosure
		description = "Token lacks required scopes for this endpoint"
	} else {
		// SECURITY: Sanitize path in error message to prevent log injection.
		// Truncate very long paths to prevent log pollution.
		safePath := r.URL.Path
		if len(safePath) > 100 {
			safePath = safePath[:100] + "..."
		}
		description = fmt.Sprintf("Token lacks required scopes for endpoint %s", safePath)
	}
	h.writeInsufficientScopeError(w, requiredScopes, description)
	return false
}

// getRequiredScopes returns the scopes required for accessing a given request path and method.
// It checks both EndpointMethodScopeRequirements (method-aware) and EndpointScopeRequirements
// (method-agnostic) configurations.
//
// Path matching supports:
//   - Exact match: "/api/files" matches only "/api/files"
//   - Prefix match: "/api/files/*" matches any path starting with "/api/files/"
//   - Longest prefix wins when multiple wildcards match
//
// Method matching (EndpointMethodScopeRequirements only):
//   - Exact method match (e.g., "GET", "POST")
//   - Wildcard "*" matches any method (fallback)
//
// Precedence:
//  1. EndpointMethodScopeRequirements with exact method match
//  2. EndpointMethodScopeRequirements with "*" method (fallback)
//  3. EndpointScopeRequirements (method-agnostic)
//  4. No requirements (access allowed)
//
// SECURITY: Path is normalized using path.Clean() to prevent traversal bypasses
// via double slashes, "..", etc.
//
// Returns an empty slice if no scope requirements are configured for the path.
func (h *Handler) getRequiredScopes(r *http.Request) []string {
	// Check if any scope requirements are configured
	hasMethodScopes := h.server.Config.EndpointMethodScopeRequirements != nil
	hasPathScopes := h.server.Config.EndpointScopeRequirements != nil

	if !hasMethodScopes && !hasPathScopes {
		return nil
	}

	// SECURITY: Normalize path to prevent bypass via path traversal
	// This prevents attacks using:
	// - Double slashes: /api//files
	// - Path traversal: /api/files/../admin
	// - Relative paths: /api/./files
	normalizedPath := path.Clean("/" + r.URL.Path)
	method := r.Method

	// Priority 1: Check method-aware scope requirements
	if hasMethodScopes {
		if scopes := h.getMethodScopesForPath(normalizedPath, method); scopes != nil {
			return scopes
		}
	}

	// Priority 2: Fallback to method-agnostic scope requirements
	if hasPathScopes {
		return h.getPathScopes(normalizedPath)
	}

	return nil
}

// getMethodScopesForPath looks up scopes from EndpointMethodScopeRequirements.
// Returns nil if no matching configuration is found.
func (h *Handler) getMethodScopesForPath(normalizedPath, method string) []string {
	// First, try exact path match
	if methodMap, ok := h.server.Config.EndpointMethodScopeRequirements[normalizedPath]; ok {
		if scopes := getScopesFromMethodMap(methodMap, method); scopes != nil {
			return scopes
		}
	}

	// Then try prefix matches (patterns ending with /*)
	matchedMethodMap := h.findLongestPrefixMethodMap(normalizedPath)
	return getScopesFromMethodMap(matchedMethodMap, method)
}

// findLongestPrefixMethodMap finds the method map for the longest matching prefix pattern.
func (h *Handler) findLongestPrefixMethodMap(normalizedPath string) map[string][]string {
	var longestPrefix string
	var matchedMethodMap map[string][]string

	for pattern, methodMap := range h.server.Config.EndpointMethodScopeRequirements {
		if !strings.HasSuffix(pattern, "/*") {
			continue
		}
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(normalizedPath, prefix) && len(prefix) > len(longestPrefix) {
			longestPrefix = prefix
			matchedMethodMap = methodMap
		}
	}

	return matchedMethodMap
}

// getScopesFromMethodMap gets scopes for a method from a method map.
// Tries exact method match first, then wildcard fallback.
func getScopesFromMethodMap(methodMap map[string][]string, method string) []string {
	if methodMap == nil {
		return nil
	}
	if scopes, ok := methodMap[method]; ok {
		return scopes
	}
	if scopes, ok := methodMap["*"]; ok {
		return scopes
	}
	return nil
}

// getPathScopes looks up scopes from EndpointScopeRequirements (method-agnostic).
// Returns nil if no matching configuration is found.
func (h *Handler) getPathScopes(normalizedPath string) []string {
	// First, try exact match
	if scopes, ok := h.server.Config.EndpointScopeRequirements[normalizedPath]; ok {
		return scopes
	}

	// Then try prefix matches (patterns ending with /*)
	// Use longest-prefix-match to ensure most specific pattern wins
	var longestPrefix string
	var matchedScopes []string

	for pattern, scopes := range h.server.Config.EndpointScopeRequirements {
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "*")
			// Check if this prefix matches and is longer than current match
			if strings.HasPrefix(normalizedPath, prefix) && len(prefix) > len(longestPrefix) {
				longestPrefix = prefix
				matchedScopes = scopes
			}
		}
	}

	return matchedScopes
}

// hasRequiredScopes checks if the token has all required scopes.
// Returns true if:
//   - No required scopes (empty list)
//   - Token has all required scopes
//
// Returns false if token is missing any required scope.
// Scope matching is case-sensitive per OAuth 2.0 spec.
func hasRequiredScopes(tokenScopes, requiredScopes []string) bool {
	// If no scopes required, allow access
	if len(requiredScopes) == 0 {
		return true
	}

	// Build a set of token scopes for efficient lookup
	tokenScopeSet := make(map[string]bool, len(tokenScopes))
	for _, scope := range tokenScopes {
		tokenScopeSet[scope] = true
	}

	// Check if all required scopes are present
	for _, required := range requiredScopes {
		if !tokenScopeSet[required] {
			return false
		}
	}

	return true
}

// getChallengeScopes returns the scopes to include in WWW-Authenticate challenges for 401 responses.
// It follows the MCP 2025-11-25 scope selection strategy to help clients discover required scopes.
//
// Scope resolution priority (per MCP 2025-11-25):
//  1. Endpoint-specific scopes (from EndpointMethodScopeRequirements or EndpointScopeRequirements)
//  2. DefaultChallengeScopes (configured fallback)
//  3. Empty string (no scope parameter in challenge)
//
// This enables intelligent scope selection where clients can see exactly what scopes are needed
// for a specific endpoint, rather than generic default scopes.
//
// Example:
//   - Request to /api/files/* → returns "files:read files:write"
//   - Request to /api/admin/* → returns "admin:access"
//   - Request with no endpoint config → returns DefaultChallengeScopes
func (h *Handler) getChallengeScopes(r *http.Request) string {
	// Priority 1: Try endpoint-specific scopes first
	// This gives clients precise guidance about what scopes are needed for this specific resource
	requiredScopes := h.getRequiredScopes(r)
	if len(requiredScopes) > 0 {
		return strings.Join(requiredScopes, " ")
	}

	// Priority 2: Fallback to default challenge scopes
	// These are generic scopes that apply across the application
	if len(h.server.Config.DefaultChallengeScopes) > 0 {
		return strings.Join(h.server.Config.DefaultChallengeScopes, " ")
	}

	// Priority 3: No scope guidance available
	// WWW-Authenticate header won't include a scope parameter
	return ""
}

// setCORSHeaders sets CORS headers if configured and the origin is allowed.
// Enables browser-based MCP clients to make cross-origin requests.
// Only applies if AllowedOrigins is configured, Origin header is present, and origin is allowed.
func (h *Handler) setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	// Skip if CORS not configured
	if len(h.server.Config.CORS.AllowedOrigins) == 0 {
		return
	}

	// Skip if not a browser CORS request (no Origin header)
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}

	// Skip if origin not allowed
	if !h.isAllowedOrigin(origin) {
		h.logger.Debug("CORS request from disallowed origin", "origin", origin)
		return
	}

	// Set CORS headers for allowed origin
	// Echo back the specific origin rather than using "*" for security
	w.Header().Set("Access-Control-Allow-Origin", origin)

	// Set Vary header to ensure proper caching by browsers and CDNs
	// This prevents serving cached responses with wrong CORS headers to different origins
	w.Header().Add("Vary", "Origin")

	// Set credentials header if enabled (required for Bearer tokens)
	if h.server.Config.CORS.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	// Set preflight cache duration
	maxAge := h.server.Config.CORS.MaxAge
	if maxAge == 0 {
		maxAge = defaultCORSMaxAge
	}

	// Set allowed methods for preflight requests
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

	// Set allowed headers for preflight requests
	// Authorization: for Bearer tokens
	// Content-Type: for POST request bodies
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

	// Set max age for preflight cache
	w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", maxAge))
}

// isAllowedOrigin checks if the given origin is in the allowed origins list.
// Supports exact matching and wildcard "*" for development.
func (h *Handler) isAllowedOrigin(origin string) bool {
	// Check for wildcard (allow all origins)
	for _, allowed := range h.server.Config.CORS.AllowedOrigins {
		if allowed == "*" {
			h.logger.Warn("⚠️  CORS: Wildcard origin (*) allows ALL origins",
				"risk", "CSRF attacks possible from any website",
				"recommendation", "Use specific origins in production")
			return true
		}

		// Exact match (case-sensitive per CORS spec)
		if allowed == origin {
			return true
		}
	}

	return false
}

// ServePreflightRequest handles CORS preflight (OPTIONS) requests.
// Required for non-simple requests (POST with JSON, custom headers, etc.).
func (h *Handler) ServePreflightRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodOptions {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.setCORSHeaders(w, r)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNoContent)
}
