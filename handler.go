package oauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

const (
	defaultCORSMaxAge = 3600 // 1 hour default for preflight cache
	tokenTypeBearer   = "Bearer"
)

// schemeToAppName maps custom URL schemes to human-readable application names.
// This provides better UX by showing the actual app name in the interstitial page.
var schemeToAppName = map[string]string{
	"cursor":     "Cursor",
	"vscode":     "Visual Studio Code",
	"code":       "Visual Studio Code",
	"codium":     "VSCodium",
	"slack":      "Slack",
	"notion":     "Notion",
	"obsidian":   "Obsidian",
	"discord":    "Discord",
	"figma":      "Figma",
	"linear":     "Linear",
	"raycast":    "Raycast",
	"warp":       "Warp",
	"iterm":      "iTerm",
	"iterm2":     "iTerm2",
	"zed":        "Zed",
	"sublime":    "Sublime Text",
	"atom":       "Atom",
	"windsurf":   "Windsurf",
	"positron":   "Positron",
	"theia":      "Theia",
	"jupyterlab": "JupyterLab",
}

// Handler is a thin HTTP adapter for the OAuth Server.
// It handles HTTP requests and delegates to the Server for business logic.
type Handler struct {
	server *Server
	logger *slog.Logger
	tracer trace.Tracer // OpenTelemetry tracer for HTTP layer
}

// NewHandler creates a new HTTP handler
func NewHandler(server *Server, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}

	h := &Handler{
		server: server,
		logger: logger,
	}

	// Initialize tracer if instrumentation is enabled
	if server.Instrumentation != nil {
		h.tracer = server.Instrumentation.Tracer("http")
	}

	return h
}

// successInterstitialTemplate is the HTML template for OAuth success pages.
// This is served when redirecting to custom URL schemes (cursor://, vscode://, etc.)
// where browsers may fail silently on 302 redirects.
//
// Per RFC 8252 Section 7.1, native apps should handle the case where the browser
// cannot redirect to the custom scheme. This interstitial page:
// - Shows a success message so users know authentication worked
// - Attempts JavaScript redirect after a brief delay
// - Provides a manual button as fallback
// - Instructs users they can close the browser window
//
// SECURITY: The inline script is static (reads redirect URL from the button's href
// attribute) so it has a stable SHA-256 hash for CSP allowlisting. If you modify
// the script, you MUST regenerate the hash in security/headers.go:
//
//	echo -n '<script content without tags>' | openssl dgst -sha256 -binary | base64
const successInterstitialTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization Successful</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 480px;
        }
        .success-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 1.5rem;
            border-radius: 50%;
            background: linear-gradient(135deg, #00d26a 0%, #00a855 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            animation: scaleIn 0.5s ease-out;
        }
        .success-icon svg {
            width: 40px;
            height: 40px;
            stroke: #fff;
            stroke-width: 3;
            fill: none;
        }
        @keyframes scaleIn {
            0% { transform: scale(0); opacity: 0; }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); opacity: 1; }
        }
        @keyframes checkmark {
            0% { stroke-dashoffset: 50; }
            100% { stroke-dashoffset: 0; }
        }
        .checkmark {
            stroke-dasharray: 50;
            stroke-dashoffset: 50;
            animation: checkmark 0.5s ease-out 0.3s forwards;
        }
        h1 {
            font-size: 1.75rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: #fff;
        }
        .message {
            color: rgba(255, 255, 255, 0.7);
            font-size: 1rem;
            line-height: 1.6;
            margin-bottom: 1.5rem;
        }
        .app-name {
            color: #00d26a;
            font-weight: 500;
        }
        .button {
            display: inline-block;
            padding: 0.875rem 2rem;
            background: linear-gradient(135deg, #00d26a 0%, #00a855 100%);
            color: #fff;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 500;
            font-size: 1rem;
            border: none;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-bottom: 1rem;
        }
        .button:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0, 210, 106, 0.3);
        }
        .button:active {
            transform: translateY(0);
        }
        .close-hint {
            color: rgba(255, 255, 255, 0.5);
            font-size: 0.875rem;
            margin-top: 1rem;
        }
        .spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top-color: #fff;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin-right: 8px;
            vertical-align: middle;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .redirecting {
            color: rgba(255, 255, 255, 0.6);
            font-size: 0.875rem;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">
            <svg viewBox="0 0 24 24">
                <polyline class="checkmark" points="4 12 9 17 20 6"></polyline>
            </svg>
        </div>
        <h1>Authorization Successful</h1>
        <p class="message">
            You have been authenticated successfully.
            {{if .AppName}}Return to <span class="app-name">{{.AppName}}</span> to continue.{{else}}You can now return to the application.{{end}}
        </p>
        <p class="redirecting" id="redirecting">
            <span class="spinner"></span>Redirecting automatically...
        </p>
        <a href="{{.RedirectURL}}" class="button" id="openApp">
            {{if .AppName}}Open {{.AppName}}{{else}}Open Application{{end}}
        </a>
        <p class="close-hint">You can close this window after the application opens.</p>
    </div>
    <script>(function(){var btn=document.getElementById("openApp");if(!btn)return;var redirectURL=btn.href;var redirected=false;setTimeout(function(){if(!redirected){redirected=true;window.location.href=redirectURL;}},500);setTimeout(function(){var el=document.getElementById("redirecting");if(el){el.style.display="none";}},3000);})();</script>
</body>
</html>`

// successInterstitialTmpl is the parsed HTML template for OAuth success pages.
// Parsed once at package initialization for efficiency.
var successInterstitialTmpl = template.Must(template.New("success").Parse(successInterstitialTemplate))

// successInterstitialData holds the template data for the success interstitial page
type successInterstitialData struct {
	RedirectURL template.URL // template.URL marks URLs as safe for href attributes
	AppName     string
}

// isCustomURLScheme checks if the given URI uses a custom URL scheme
// (not http or https). Custom schemes like cursor://, vscode://, slack://
// require special handling because browsers may fail silently on 302 redirects.
//
// Returns true for custom schemes that need an interstitial page,
// false for http/https which can use standard redirects.
func isCustomURLScheme(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}

	scheme := strings.ToLower(parsed.Scheme)

	// Standard HTTP schemes can use regular redirects
	if scheme == SchemeHTTP || scheme == SchemeHTTPS {
		return false
	}

	// Any other scheme (cursor://, vscode://, slack://, etc.) needs interstitial
	return scheme != ""
}

// getAppNameFromScheme extracts a human-readable app name from a custom URL scheme.
// This provides better UX by showing the actual app name in the interstitial page.
// Uses the package-level schemeToAppName map for known applications.
func getAppNameFromScheme(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil {
		return ""
	}

	scheme := strings.ToLower(parsed.Scheme)

	// Check the package-level map for known app names
	if name, ok := schemeToAppName[scheme]; ok {
		return name
	}

	// For unknown schemes, capitalize the first letter
	if len(scheme) > 0 {
		return strings.ToUpper(scheme[:1]) + scheme[1:]
	}

	return ""
}

// serveSuccessInterstitial serves an HTML success page for OAuth callbacks
// to custom URL schemes (RFC 8252 Section 7.1).
//
// This solves the problem where browsers fail silently on 302 redirects to
// custom URL schemes like cursor://, vscode://, etc. Instead of leaving users
// on a blank page, this serves a friendly page that:
// - Confirms authentication was successful
// - Attempts JavaScript redirect after brief delay
// - Provides manual button as fallback
// - Tells users they can close the window
func (h *Handler) serveSuccessInterstitial(w http.ResponseWriter, redirectURL string) {
	// Extract app name from the redirect URL scheme
	appName := getAppNameFromScheme(redirectURL)

	// SECURITY: We must use template.URL to allow custom URL schemes in href attributes.
	// Go's html/template filters URLs to only allow http, https, mailto by default.
	// Custom schemes like cursor://, vscode:// are legitimate OAuth redirect URIs
	// per RFC 8252 (OAuth 2.0 for Native Apps) and have already been validated
	// during client registration and authorization flow.
	data := successInterstitialData{
		RedirectURL: template.URL(redirectURL), //nolint:gosec // URL validated during OAuth flow
		AppName:     appName,
	}

	// Set security headers with CSP hash exception for the inline redirect script
	// This allows the static inline script while blocking any injected scripts
	security.SetInterstitialSecurityHeaders(w, h.server.Config.Issuer)

	// Set content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Execute pre-parsed template (parsed at package initialization)
	if err := successInterstitialTmpl.Execute(w, data); err != nil {
		h.logger.Error("Failed to execute success interstitial template", "error", err)
		// Fall back to plain text if template execution fails
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Authorization successful. Please return to your application."))
	}
}

// ValidateToken is middleware that validates OAuth tokens
func (h *Handler) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP for rate limiting and logging
		clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

		// Apply IP-based rate limiting BEFORE token validation
		if h.server.RateLimiter != nil {
			if !h.server.RateLimiter.Allow(clientIP) {
				h.logger.Warn("Rate limit exceeded", "ip", clientIP)

				// Record rate limit exceeded metric
				if h.server.Instrumentation != nil {
					h.server.Instrumentation.Metrics().RecordRateLimitExceeded(r.Context(), "ip")
				}

				if h.server.Auditor != nil {
					h.server.Auditor.LogEvent(security.Event{
						Type:      security.EventRateLimitExceeded,
						IPAddress: clientIP,
						Details: map[string]any{
							"endpoint": r.URL.Path,
						},
					})
					h.server.Auditor.LogRateLimitExceeded(clientIP, "")
				}
				w.Header().Set("Retry-After", "60")
				h.writeError(w, ErrorCodeRateLimitExceeded, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
				return
			}
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.writeUnauthorizedError(w, r, ErrorCodeInvalidToken, "Missing Authorization header")
			return
		}

		// Parse Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			h.writeUnauthorizedError(w, r, ErrorCodeInvalidToken, "Invalid Authorization header format")
			return
		}

		accessToken := parts[1]

		// Validate token with server
		userInfo, err := h.server.ValidateToken(r.Context(), accessToken)
		if err != nil {
			h.logger.Warn("Token validation failed", "ip", clientIP, "error", err)
			// SECURITY: Don't leak internal error details to client
			// Log detailed error but return generic message
			h.writeUnauthorizedError(w, r, ErrorCodeInvalidToken, "Token validation failed")
			return
		}

		// MCP 2025-11-25: Validate token scopes against endpoint requirements
		// This implements OAuth 2.0 scope-based access control for protected resources
		if !h.validateTokenScopes(w, r, accessToken, userInfo, clientIP) {
			return
		}

		// Apply per-user rate limiting AFTER authentication
		// This is a separate, higher limit for authenticated users
		if h.server.UserRateLimiter != nil {
			if !h.server.UserRateLimiter.Allow(userInfo.ID) {
				h.logger.Warn("User rate limit exceeded", "user_id", userInfo.ID, "ip", clientIP)

				// Record rate limit exceeded metric
				if h.server.Instrumentation != nil {
					h.server.Instrumentation.Metrics().RecordRateLimitExceeded(r.Context(), "user")
				}

				if h.server.Auditor != nil {
					h.server.Auditor.LogRateLimitExceeded(clientIP, userInfo.ID)
				}
				w.Header().Set("Retry-After", "60")
				h.writeError(w, ErrorCodeRateLimitExceeded, "Rate limit exceeded for user. Please try again later.", http.StatusTooManyRequests)
				return
			}
		}

		// Store user info in context
		ctx := context.WithValue(r.Context(), userInfoKey, userInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ServeProtectedResourceMetadata serves RFC 9728 Protected Resource Metadata
func (h *Handler) ServeProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	metadata := map[string]any{
		"resource": h.server.Config.Issuer,
		"authorization_servers": []string{
			h.server.Config.Issuer,
		},
		"bearer_methods_supported": []string{"header"},
	}

	// Include scopes_supported if configured (MCP 2025-11-25)
	if len(h.server.Config.SupportedScopes) > 0 {
		metadata["scopes_supported"] = h.server.Config.SupportedScopes
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// RegisterProtectedResourceMetadataRoutes registers all Protected Resource Metadata discovery routes.
// It registers both the root endpoint and optional sub-path endpoint if mcpPath is provided.
//
// Security: This function validates the mcpPath to prevent path traversal attacks and DoS through
// excessively long paths. Invalid paths are logged and skipped.
//
// Example usage:
//
//	mux := http.NewServeMux()
//	handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")
//	// This registers both:
//	//   /.well-known/oauth-protected-resource
//	//   /.well-known/oauth-protected-resource/mcp
func (h *Handler) RegisterProtectedResourceMetadataRoutes(mux *http.ServeMux, mcpPath string) {
	// Always register root metadata endpoint
	mux.HandleFunc(MetadataPathProtectedResource, h.ServeProtectedResourceMetadata)

	// Register sub-path metadata endpoint if MCP endpoint has a path
	if mcpPath != "" && mcpPath != "/" {
		// SECURITY: Validate path before registration to prevent attacks
		if err := h.validateMetadataPath(mcpPath); err != nil {
			h.logger.Warn("Rejecting invalid metadata path registration",
				"path", mcpPath,
				"error", err,
				"security_event", "invalid_metadata_path")
			return
		}

		// Clean and normalize the path
		cleanPath := path.Clean("/" + strings.TrimPrefix(mcpPath, "/"))
		subPath := MetadataPathProtectedResource + cleanPath

		h.logger.Info("Registering metadata sub-path endpoint",
			"path", subPath,
			"original_mcp_path", mcpPath)

		mux.HandleFunc(subPath, h.ServeProtectedResourceMetadata)
	}
}

// validateMetadataPath validates a metadata path for security concerns.
// It checks for path traversal attempts, excessive length, and other malicious patterns.
func (h *Handler) validateMetadataPath(mcpPath string) error {
	// SECURITY: Reject paths containing path traversal sequences
	// Defense in depth: path.Clean() would normalize these, but explicit check prevents confusion
	if strings.Contains(mcpPath, "..") {
		return fmt.Errorf("path contains '..' sequence (path traversal attempt)")
	}

	// SECURITY: Prevent DoS through excessively long paths
	// Long paths consume memory and can cause issues with storage, logging, and HTTP headers
	if len(mcpPath) > MaxMetadataPathLength {
		return fmt.Errorf("path exceeds maximum length of %d characters (DoS prevention)", MaxMetadataPathLength)
	}

	// SECURITY: Reject paths with suspicious patterns
	// Null bytes can cause issues in some HTTP implementations
	if strings.Contains(mcpPath, "\x00") {
		return fmt.Errorf("path contains null byte")
	}

	// SECURITY: Reject paths with excessive slashes (potential DoS or confusion)
	if strings.Count(mcpPath, "/") > 10 {
		return fmt.Errorf("path contains too many segments (DoS prevention)")
	}

	return nil
}

// ServeAuthorizationServerMetadata serves RFC 8414 Authorization Server Metadata
func (h *Handler) ServeAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	metadata := map[string]any{
		"issuer":                           h.server.Config.Issuer,
		"authorization_endpoint":           h.server.Config.AuthorizationEndpoint(),
		"token_endpoint":                   h.server.Config.TokenEndpoint(),
		"response_types_supported":         []string{"code"},
		"grant_types_supported":            []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{PKCEMethodS256},

		// RFC 8414: Token endpoint authentication methods
		// These methods are always supported for the authorization_code flow
		"token_endpoint_auth_methods_supported": SupportedTokenAuthMethods,
	}

	// RFC 8414: scopes_supported is OPTIONAL but RECOMMENDED
	// Only include if scopes are configured to avoid empty arrays
	if len(h.server.Config.SupportedScopes) > 0 {
		metadata["scopes_supported"] = h.server.Config.SupportedScopes
	}

	// Only advertise registration_endpoint if client registration is actually available
	// RFC 8414: registration_endpoint is OPTIONAL and should only be included if supported
	if h.server.Config.AllowPublicClientRegistration || h.server.Config.RegistrationAccessToken != "" {
		metadata["registration_endpoint"] = h.server.Config.RegistrationEndpoint()
	}

	// RFC 7009: Only advertise revocation_endpoint if the feature is enabled and implemented
	// This prevents advertising capabilities that don't exist (security issue)
	if h.server.Config.EnableRevocationEndpoint {
		metadata["revocation_endpoint"] = h.server.Config.RevocationEndpoint()
	}

	// RFC 7662: Only advertise introspection_endpoint if the feature is enabled and implemented
	// This prevents advertising capabilities that don't exist (security issue)
	if h.server.Config.EnableIntrospectionEndpoint {
		metadata["introspection_endpoint"] = h.server.Config.IntrospectionEndpoint()
	}

	// MCP 2025-11-25: Advertise Client ID Metadata Documents support
	// Per draft-ietf-oauth-client-id-metadata-document-00
	// Only advertise if actually enabled to avoid false capabilities
	if h.server.Config.EnableClientIDMetadataDocuments {
		metadata["client_id_metadata_document_supported"] = true
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// ServeOpenIDConfiguration handles OpenID Connect Discovery 1.0 requests
// Per RFC 8414 Section 5, this endpoint returns the same metadata as the
// Authorization Server Metadata endpoint for compatibility with OpenID Connect clients
func (h *Handler) ServeOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	// OpenID Connect Discovery uses the same metadata as OAuth 2.0 AS Metadata
	// This ensures compatibility with both OAuth 2.0 and OpenID Connect clients
	h.ServeAuthorizationServerMetadata(w, r)
}

// ServeAuthorization handles OAuth authorization requests
func (h *Handler) ServeAuthorization(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Create span if tracing is enabled
	var span trace.Span
	ctx := r.Context()
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.authorization")
		defer span.End()
		// Update request context to include span context
		r = r.WithContext(ctx)
	}

	if r.Method != http.MethodGet {
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	// Parse query parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	resource := r.URL.Query().Get("resource") // RFC 8707: Target resource server identifier
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	if clientID == "" {
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "client_id missing")
		h.writeError(w, ErrorCodeInvalidRequest, "client_id is required", http.StatusBadRequest)
		return
	}

	// CRITICAL SECURITY: State parameter is required for CSRF protection
	// Input validation at HTTP layer to return proper status codes
	// Can be disabled for clients that don't support state (e.g., some MCP clients)
	if state == "" && !h.server.Config.AllowNoStateParameter {
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "state missing")
		h.writeError(w, ErrorCodeInvalidRequest, "state parameter is required for CSRF protection", http.StatusBadRequest)
		return
	}
	if state != "" && len(state) < MinStateLength {
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "state too short")
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at least %d characters for security", MinStateLength), http.StatusBadRequest)
		return
	}

	// Add attributes to span
	instrumentation.SetSpanAttributes(span,
		attribute.String("oauth.client_id", clientID),
		attribute.String("oauth.pkce_method", codeChallengeMethod),
	)

	// Start authorization flow with client state (server also validates for defense in depth)
	authURL, err := h.server.StartAuthorizationFlow(ctx, clientID, redirectURI, scope, resource, codeChallenge, codeChallengeMethod, state)
	if err != nil {
		h.logger.Error("Failed to start authorization flow", "error", err)
		h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusInternalServerError, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "authorization flow failed")
		h.writeError(w, ErrorCodeServerError, "Failed to start authorization flow", http.StatusInternalServerError)
		return
	}

	// Record authorization started metric
	h.recordAuthorizationStarted(clientID)

	h.recordHTTPMetrics("authorization", http.MethodGet, http.StatusFound, startTime)
	instrumentation.SetSpanSuccess(span)

	// Redirect to provider
	http.Redirect(w, r, authURL, http.StatusFound)
}

// ServeCallback handles the OAuth provider callback
func (h *Handler) ServeCallback(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Create span if tracing is enabled
	var span trace.Span
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.callback")
		defer span.End()
	}

	if r.Method != http.MethodGet {
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	// Parse callback parameters
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errorParam := r.URL.Query().Get("error")

	// Check for provider errors
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		h.logger.Warn("Provider returned error", "error", errorParam, "description", errorDesc)
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed("", false)
		instrumentation.SetSpanError(span, errorParam)
		h.writeError(w, errorParam, errorDesc, http.StatusBadRequest)
		return
	}

	// CRITICAL SECURITY: Validate state and code parameters
	// Input validation at HTTP layer to return proper status codes
	if state == "" || code == "" {
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed("", false)
		instrumentation.SetSpanError(span, "missing state or code")
		h.writeError(w, ErrorCodeInvalidRequest, "state and code are required", http.StatusBadRequest)
		return
	}
	if len(state) < MinStateLength {
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed("", false)
		instrumentation.SetSpanError(span, "state too short")
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at least %d characters for security", MinStateLength), http.StatusBadRequest)
		return
	}

	// Handle callback (state here is the provider state, not client state)
	// Server also validates state length for defense in depth
	authCode, clientState, err := h.server.HandleProviderCallback(ctx, state, code)
	if err != nil {
		h.logger.Error("Failed to handle callback", "error", err)
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusInternalServerError, startTime)
		h.recordCallbackProcessed("", false)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "callback handling failed")
		h.writeError(w, ErrorCodeServerError, "Authorization failed", http.StatusInternalServerError)
		return
	}

	// Record successful callback
	h.recordCallbackProcessed(authCode.ClientID, true)
	instrumentation.SetSpanAttributes(span, attribute.String("oauth.client_id", authCode.ClientID))
	instrumentation.SetSpanSuccess(span)

	// CRITICAL SECURITY: Redirect back to client with their original state parameter
	// This allows the client to verify the callback is for their original request (CSRF protection)
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", authCode.RedirectURI, authCode.Code, clientState)

	// RFC 8252 Section 7.1: Custom URL schemes require special handling
	// Browsers may fail silently on 302 redirects to custom schemes (cursor://, vscode://, etc.)
	// Serve an HTML interstitial page that shows success and attempts JS redirect with manual fallback
	if isCustomURLScheme(authCode.RedirectURI) {
		// Parse URI to safely extract scheme for logging (avoid strings.Split edge cases)
		scheme := ""
		if parsed, err := url.Parse(authCode.RedirectURI); err == nil {
			scheme = parsed.Scheme
		}
		h.logger.Info("Serving success interstitial for custom URL scheme",
			"client_id", authCode.ClientID,
			"scheme", scheme)
		h.recordHTTPMetrics("callback", http.MethodGet, http.StatusOK, startTime)
		h.serveSuccessInterstitial(w, redirectURL)
		return
	}

	// Standard HTTP/HTTPS redirects work reliably
	h.recordHTTPMetrics("callback", http.MethodGet, http.StatusFound, startTime)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ServeToken handles the OAuth token endpoint
func (h *Handler) ServeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r)
	default:
		h.writeError(w, ErrorCodeUnsupportedGrantType, fmt.Sprintf("Grant type %s not supported", grantType), http.StatusBadRequest)
	}
}

func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Create span if tracing is enabled
	var span trace.Span
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.token_exchange")
		defer span.End()
	}

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse parameters
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	resource := r.FormValue("resource") // RFC 8707: Target resource server identifier
	codeVerifier := r.FormValue("code_verifier")

	if code == "" {
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "code missing")
		h.writeError(w, ErrorCodeInvalidRequest, "Required parameter 'code' missing", http.StatusBadRequest)
		return
	}

	// Authenticate client
	client, err := h.authenticateClient(r, clientID, clientIP)
	if err != nil {
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusUnauthorized, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "client authentication failed")
		// authenticateClient returns OAuthError, extract details
		if oauthErr, ok := err.(*OAuthError); ok {
			h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		} else {
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		}
		return
	}

	// Add span attributes
	instrumentation.SetSpanAttributes(span,
		attribute.String("oauth.client_id", client.ClientID),
		attribute.String("oauth.client_type", client.ClientType),
	)

	// Exchange authorization code for tokens
	tokenResponse, scope, err := h.server.ExchangeAuthorizationCode(ctx, code, client.ClientID, redirectURI, resource, codeVerifier)
	if err != nil {
		h.logger.Error("Failed to exchange authorization code", "client_id", client.ClientID, "ip", clientIP, "error", err)
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "code exchange failed")
		// SECURITY: Don't leak internal error details to client
		// Audit logging is done in ExchangeAuthorizationCode
		h.writeError(w, ErrorCodeInvalidGrant, "Authorization code is invalid or expired", http.StatusBadRequest)
		return
	}

	h.logger.Info("Token exchange successful", "client_id", client.ClientID, "ip", clientIP)

	// Record code exchanged metric
	pkceMethod := ""
	if codeVerifier != "" {
		pkceMethod = PKCEMethodS256
	}
	h.recordCodeExchanged(client.ClientID, pkceMethod)

	h.recordHTTPMetrics("token", http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, scope)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Create span if tracing is enabled
	var span trace.Span
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.token_refresh")
		defer span.End()
	}

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse parameters
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	if refreshToken == "" {
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "refresh_token missing")
		h.writeError(w, ErrorCodeInvalidRequest, "refresh_token is required", http.StatusBadRequest)
		return
	}

	// Get client credentials from Authorization header (if present)
	if authClientID, authClientSecret := h.parseBasicAuth(r); authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(ctx, clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed", "client_id", clientID, "ip", clientIP, "error", err)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "client_authentication_failed")
			}
			h.recordHTTPMetrics("token", http.MethodPost, http.StatusUnauthorized, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "client authentication failed")
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return
		}
	}

	instrumentation.SetSpanAttributes(span, attribute.String("oauth.client_id", clientID))

	// Refresh token
	tokenResponse, err := h.server.RefreshAccessToken(ctx, refreshToken, clientID)
	if err != nil {
		h.logger.Error("Failed to refresh token", "client_id", clientID, "ip", clientIP, "error", err)
		h.recordHTTPMetrics("token", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "token refresh failed")
		// SECURITY: Don't leak internal error details to client
		// Audit logging is already done in RefreshAccessToken
		h.writeError(w, ErrorCodeInvalidGrant, "Refresh token is invalid or expired", http.StatusBadRequest)
		return
	}

	// Record token refreshed metric (check if it was rotated)
	rotated := h.server.Config.AllowRefreshTokenRotation
	h.recordTokenRefreshed(clientID, rotated)

	h.recordHTTPMetrics("token", http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, "")
}

// ServeTokenRevocation handles the RFC 7009 token revocation endpoint
func (h *Handler) ServeTokenRevocation(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Create span if tracing is enabled
	var span trace.Span
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.token_revocation")
		defer span.End()
	}

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "parse form failed")
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	clientID := r.FormValue("client_id")

	if token == "" {
		h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "token missing")
		h.writeError(w, ErrorCodeInvalidRequest, "token is required", http.StatusBadRequest)
		return
	}

	// Get client credentials from Authorization header (if present)
	if authClientID, authClientSecret := h.parseBasicAuth(r); authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(ctx, clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed for revocation", "client_id", clientID, "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "revocation_auth_failed")
			}
			h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusUnauthorized, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "client authentication failed")
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return
		}
	}

	instrumentation.SetSpanAttributes(span, attribute.String("oauth.client_id", clientID))

	// Revoke token
	if err := h.server.RevokeToken(ctx, token, clientID, clientIP); err != nil {
		h.logger.Error("Failed to revoke token", "client_id", clientID, "ip", clientIP, "error", err)
		instrumentation.RecordError(span, err)
		// Per RFC 7009, don't fail the request even if revocation failed
	}
	// Per RFC 7009, return 200 even if revocation fails

	// Record token revoked metric
	h.recordTokenRevoked(clientID)

	h.recordHTTPMetrics("revoke", http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return success (per RFC 7009)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.WriteHeader(http.StatusOK)
}

// ServeClientRegistration handles dynamic client registration (RFC 7591)
func (h *Handler) ServeClientRegistration(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Create span if tracing is enabled
	var span trace.Span
	ctx := r.Context()
	if h.tracer != nil {
		ctx, span = h.tracer.Start(ctx, "oauth.http.client_registration")
		defer span.End()
		// Update request context to include span context
		r = r.WithContext(ctx)
	}

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics("register", http.MethodPost, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	// Get client IP for DoS protection
	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// OAuth 2.1: Require authentication for client registration (secure by default)
	// Only allow unauthenticated registration if explicitly configured
	if !h.server.Config.AllowPublicClientRegistration {
		// Check for registration access token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			h.logger.Warn("Client registration rejected: missing authorization",
				"client_ip", clientIP)
			h.writeError(w, ErrorCodeInvalidToken,
				"Registration access token required. "+
					"Set AllowPublicClientRegistration=true to disable authentication (NOT recommended).",
				http.StatusUnauthorized)
			return
		}

		// Verify Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			h.logger.Warn("Client registration rejected: invalid authorization header",
				"client_ip", clientIP)
			h.writeError(w, ErrorCodeInvalidToken, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		// Validate registration access token
		providedToken := parts[1]
		if h.server.Config.RegistrationAccessToken == "" {
			h.logger.Error("RegistrationAccessToken not configured but AllowPublicClientRegistration=false")
			h.writeError(w, ErrorCodeServerError,
				"Server configuration error: registration token not configured",
				http.StatusInternalServerError)
			return
		}

		// SECURITY: Use constant-time comparison to prevent timing attacks
		// that could allow guessing the registration token character by character
		if subtle.ConstantTimeCompare([]byte(providedToken), []byte(h.server.Config.RegistrationAccessToken)) != 1 {
			h.logger.Warn("Client registration rejected: invalid registration token",
				"client_ip", clientIP)
			h.writeError(w, ErrorCodeInvalidToken, "Invalid registration access token", http.StatusUnauthorized)
			return
		}

		h.logger.Info("Client registration authenticated with valid token")
	} else {
		h.logger.Warn("⚠️  Unauthenticated client registration (DoS risk)",
			"client_ip", clientIP)
	}

	// SECURITY: Check time-windowed rate limit BEFORE processing request
	// This prevents resource exhaustion through repeated registration/deletion cycles
	if h.server.ClientRegistrationRateLimiter != nil {
		if !h.server.ClientRegistrationRateLimiter.Allow(clientIP) {
			h.logger.Warn("Client registration rate limit exceeded",
				"ip", clientIP,
				"max_per_window", h.server.Config.MaxRegistrationsPerHour,
				"window", time.Duration(h.server.Config.RegistrationRateLimitWindow)*time.Second)
			if h.server.Auditor != nil {
				h.server.Auditor.LogClientRegistrationRateLimitExceeded(clientIP)
			}
			h.writeError(w, ErrorCodeInvalidRequest,
				"Client registration rate limit exceeded. Please try again later.",
				http.StatusTooManyRequests)
			return
		}
	}

	// Check per-IP registration limit to prevent DoS attacks
	maxClients := h.server.Config.MaxClientsPerIP
	if maxClients == 0 {
		maxClients = 10 // Default limit
	}

	// Parse registration request
	var req struct {
		ClientName              string   `json:"client_name"`
		ClientType              string   `json:"client_type"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		RedirectURIs            []string `json:"redirect_uris"`
		Scopes                  []string `json:"scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// OAUTH 2.1 COMPLIANCE: Validate token_endpoint_auth_method
	// Per RFC 7591 Section 2, only these methods are standardized
	if req.TokenEndpointAuthMethod != "" && !isValidAuthMethod(req.TokenEndpointAuthMethod) {
		h.logger.Warn("Unsupported token_endpoint_auth_method requested",
			"method", req.TokenEndpointAuthMethod,
			"supported_methods", SupportedTokenAuthMethods,
			"ip", clientIP)
		// SECURITY: Don't reveal full list of supported methods in error response
		// Supported methods are already advertised in /.well-known/oauth-authorization-server
		h.writeError(w, ErrorCodeInvalidRequest,
			fmt.Sprintf("Unsupported token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod),
			http.StatusBadRequest)
		return
	}

	// SECURITY: Validate public client registration is allowed
	// When client requests "none" auth method, they're requesting a public client
	// This is common for native/CLI apps that can't securely store secrets
	if req.TokenEndpointAuthMethod == TokenEndpointAuthMethodNone || req.ClientType == ClientTypePublic {
		// CRITICAL: Enforce AllowPublicClientRegistration policy
		// Even with a valid registration access token, public client creation must be explicitly allowed
		if !h.server.Config.AllowPublicClientRegistration {
			h.logger.Warn("Public client registration rejected (not allowed by configuration)",
				"token_endpoint_auth_method", req.TokenEndpointAuthMethod,
				"client_type", req.ClientType,
				"ip", clientIP,
				"recommendation", "Set AllowPublicClientRegistration=true to enable public client registration")
			h.recordHTTPMetrics("register", http.MethodPost, http.StatusBadRequest, startTime)
			if span != nil {
				instrumentation.SetSpanAttributes(span,
					attribute.String("oauth.client_type", "public"),
					attribute.String("security.event", "public_client_registration_denied"),
				)
				instrumentation.SetSpanError(span, "public client registration not allowed")
			}
			h.writeError(w, ErrorCodeInvalidRequest,
				"Public client registration is not enabled on this server. Contact the server administrator.",
				http.StatusBadRequest)
			return
		}

		h.logger.Info("Public client registration authorized",
			"token_endpoint_auth_method", req.TokenEndpointAuthMethod,
			"client_type", req.ClientType,
			"ip", clientIP)
	}

	// Register client with IP tracking
	client, clientSecret, err := h.server.RegisterClient(ctx, req.ClientName, req.ClientType, req.TokenEndpointAuthMethod, req.RedirectURIs, req.Scopes, clientIP, maxClients)
	if err != nil {
		// Check if it's a rate limit error
		if strings.Contains(err.Error(), "registration limit") {
			h.logger.Warn("Client registration limit exceeded", "ip", clientIP, "error", err)
			h.recordHTTPMetrics("register", http.MethodPost, http.StatusTooManyRequests, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "registration limit exceeded")
			// SECURITY: Generic error message to prevent enumeration
			h.writeError(w, ErrorCodeInvalidRequest, "Client registration limit exceeded", http.StatusTooManyRequests)
			return
		}
		h.logger.Error("Failed to register client", "ip", clientIP, "error", err)
		h.recordHTTPMetrics("register", http.MethodPost, http.StatusInternalServerError, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "registration failed")
		// SECURITY: Don't leak internal error details
		h.writeError(w, ErrorCodeServerError, "Failed to register client", http.StatusInternalServerError)
		return
	}

	// Record client registered metric
	h.recordClientRegistered(client.ClientType)

	h.recordHTTPMetrics("register", http.MethodPost, http.StatusCreated, startTime)
	instrumentation.SetSpanAttributes(span,
		attribute.String("oauth.client_id", client.ClientID),
		attribute.String("oauth.client_type", client.ClientType),
	)
	instrumentation.SetSpanSuccess(span)

	// Build response
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	response := map[string]any{
		"client_id":                  client.ClientID,
		"client_name":                client.ClientName,
		"client_type":                client.ClientType,
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
	}

	if clientSecret != "" {
		response["client_secret"] = clientSecret
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// Helper methods

func (h *Handler) parseBasicAuth(r *http.Request) (username, password string) {
	username, password, _ = r.BasicAuth()
	return
}

// authenticateClient validates client credentials from either Basic Auth or form parameters
// Returns the validated client or an error with the OAuth error code
func (h *Handler) authenticateClient(r *http.Request, clientID, clientIP string) (*storage.Client, error) {
	ctx := r.Context()

	// Get client credentials from Authorization header (if present)
	authClientID, authClientSecret := h.parseBasicAuth(r)
	if authClientID != "" {
		clientID = authClientID
	}

	if clientID == "" {
		return nil, ErrInvalidRequest("client_id is required")
	}

	// Fetch client
	client, err := h.server.GetClient(ctx, clientID)
	if err != nil {
		h.logger.Warn("Unknown client", "client_id", clientID, "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure("", clientID, clientIP, ErrorCodeInvalidClient)
		}
		return nil, ErrInvalidClient("Client authentication failed")
	}

	// CRITICAL SECURITY: Confidential clients MUST authenticate
	if client.ClientType == ClientTypeConfidential {
		if authClientSecret == "" {
			h.logger.Warn("Confidential client missing credentials", "client_id", clientID, "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "confidential_client_auth_required")
			}
			return nil, ErrInvalidClient("Client authentication required")
		}

		// Validate client credentials
		if err := h.server.ValidateClientCredentials(ctx, clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed", "client_id", clientID, "ip", clientIP, "error", err)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "client_authentication_failed")
			}
			return nil, ErrInvalidClient("Client authentication failed")
		}
	}

	return client, nil
}

func (h *Handler) writeTokenResponse(w http.ResponseWriter, token *oauth2.Token, scope string) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	expiresIn := int64(time.Until(token.Expiry).Seconds())
	if expiresIn < 0 {
		expiresIn = 3600
	}

	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = tokenTypeBearer
	}

	response := map[string]any{
		"access_token": token.AccessToken,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
	}

	if token.RefreshToken != "" {
		response["refresh_token"] = token.RefreshToken
	}

	if scope != "" {
		response["scope"] = scope
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

func (h *Handler) writeError(w http.ResponseWriter, code, description string, status int) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	// MCP 2025-11-25: Include WWW-Authenticate header for 401 responses
	// This helps clients discover the authorization server and required scopes
	if status == http.StatusUnauthorized {
		if !h.server.Config.DisableWWWAuthenticateMetadata {
			// Full MCP 2025-11-25 compliant header with discovery metadata (default)
			scope := ""
			if len(h.server.Config.DefaultChallengeScopes) > 0 {
				scope = strings.Join(h.server.Config.DefaultChallengeScopes, " ")
			}
			w.Header().Set("WWW-Authenticate", h.formatWWWAuthenticate(scope, code, description))
		} else {
			// Minimal header for backward compatibility with legacy clients (opt-in)
			w.Header().Set("WWW-Authenticate", tokenTypeBearer)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
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
	w.Header().Set("WWW-Authenticate", h.formatWWWAuthenticate(scope, ErrorCodeInsufficientScope, description))

	// Write JSON error response body
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             ErrorCodeInsufficientScope,
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
func (h *Handler) formatWWWAuthenticate(scope, error, errorDesc string) string {
	// Build the challenge parameters (excluding the Bearer scheme)
	var params []string

	// MUST: Include resource_metadata URL per MCP 2025-11-25
	resourceMetadataURL := h.server.Config.ProtectedResourceMetadataEndpoint()
	params = append(params, fmt.Sprintf(`resource_metadata="%s"`, resourceMetadataURL))

	// Optional: Include scope if configured
	if scope != "" {
		params = append(params, fmt.Sprintf(`scope="%s"`, scope))
	}

	// Optional: Include error code if provided
	if error != "" {
		params = append(params, fmt.Sprintf(`error="%s"`, error))
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

// ServeTokenIntrospection handles the RFC 7662 token introspection endpoint
// This allows resource servers to validate access tokens
// Security: Requires client authentication to prevent token scanning attacks
func (h *Handler) ServeTokenIntrospection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		h.writeError(w, ErrorCodeInvalidRequest, "token parameter is required", http.StatusBadRequest)
		return
	}

	// SECURITY: Require client authentication to prevent token scanning attacks
	// Per RFC 7662 Section 2.1: the authorization server MUST authenticate the client
	authClientID, authClientSecret := h.parseBasicAuth(r)
	var clientID string
	if authClientID != "" {
		clientID = authClientID
		// Validate client credentials
		if err := h.server.ValidateClientCredentials(ctx, clientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed for introspection", "client_id", clientID, "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", clientID, clientIP, "introspection_auth_failed")
			}
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return
		}
	} else {
		// Try form parameter as fallback (but still require authentication)
		clientID = r.FormValue("client_id")
		if clientID == "" {
			// No client authentication provided - reject per RFC 7662 security considerations
			h.logger.Warn("Token introspection rejected: missing client authentication", "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", "", clientIP, "introspection_missing_auth")
			}
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication required for token introspection", http.StatusUnauthorized)
			return
		}
		// Client ID provided but no credentials - also reject
		h.logger.Warn("Token introspection rejected: client_id without credentials", "client_id", clientID, "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure("", clientID, clientIP, "introspection_missing_credentials")
		}
		h.writeError(w, ErrorCodeInvalidClient, "Client authentication required for token introspection", http.StatusUnauthorized)
		return
	}

	// Validate the token
	userInfo, err := h.server.ValidateToken(r.Context(), token)

	// Build introspection response per RFC 7662
	response := map[string]interface{}{
		"active": false,
	}

	if err == nil && userInfo != nil {
		// Token is valid and active
		response["active"] = true
		response["sub"] = userInfo.ID
		response["email"] = userInfo.Email
		response["email_verified"] = userInfo.EmailVerified

		// Optional claims
		if userInfo.Name != "" {
			response["name"] = userInfo.Name
		}
		if clientID != "" {
			response["client_id"] = clientID
		}
		response["token_type"] = "Bearer"
	} else {
		// Token is invalid or expired
		h.logger.Debug("Token introspection failed", "error", err, "ip", clientIP)
	}

	// Always return 200 OK per RFC 7662
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// Context key for user info
type contextKey string

const userInfoKey contextKey = "user_info"

// UserInfoFromContext retrieves user info from the request context
func UserInfoFromContext(ctx context.Context) (*providers.UserInfo, bool) {
	userInfo, ok := ctx.Value(userInfoKey).(*providers.UserInfo)
	return userInfo, ok
}

// validateTokenScopes checks if the token has required scopes for the endpoint.
// Returns true if validation passes, false if insufficient scopes (response already written).
func (h *Handler) validateTokenScopes(w http.ResponseWriter, r *http.Request, accessToken string, userInfo *providers.UserInfo, clientIP string) bool {
	requiredScopes := h.getRequiredScopes(r)
	if len(requiredScopes) == 0 {
		return true // No scopes required
	}

	tokenScopes := h.getTokenScopes(accessToken)

	if hasRequiredScopes(tokenScopes, requiredScopes) {
		return true
	}

	// Log and audit the failure
	h.logger.Warn("Insufficient scope for endpoint",
		"user_id", userInfo.ID,
		"endpoint", r.URL.Path,
		"method", r.Method,
		"token_scopes", tokenScopes,
		"required_scopes", requiredScopes,
		"ip", clientIP)

	if h.server.Auditor != nil {
		h.server.Auditor.LogAuthFailure(userInfo.ID, "", clientIP, "insufficient_scope")
	}

	// Build error description based on configuration
	var description string
	if h.server.Config.HideEndpointPathInErrors {
		// SECURITY: Hide endpoint path to prevent information disclosure
		description = "Token lacks required scopes for this endpoint"
	} else {
		// SECURITY: Sanitize path in error message to prevent log injection
		// Truncate very long paths to prevent log pollution
		safePath := r.URL.Path
		if len(safePath) > 100 {
			safePath = safePath[:100] + "..."
		}
		description = fmt.Sprintf("Token lacks required scopes for endpoint %s", safePath)
	}
	h.writeInsufficientScopeError(w, requiredScopes, description)
	return false
}

// getTokenScopes retrieves scopes from token metadata.
// Returns nil if the store doesn't support metadata or if metadata cannot be retrieved.
func (h *Handler) getTokenScopes(accessToken string) []string {
	metadataStore, ok := h.server.TokenStore().(storage.TokenMetadataGetter)
	if !ok {
		return nil
	}

	metadata, err := metadataStore.GetTokenMetadata(accessToken)
	if err != nil {
		h.logger.Warn("Failed to retrieve token metadata for scope validation", "error", err)
		return nil
	}

	if metadata == nil {
		return nil
	}

	return metadata.Scopes
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
		// Try exact method match
		if scopes, ok := methodMap[method]; ok {
			return scopes
		}
		// Try wildcard method fallback
		if scopes, ok := methodMap["*"]; ok {
			return scopes
		}
	}

	// Then try prefix matches (patterns ending with /*)
	// Use longest-prefix-match to ensure most specific pattern wins
	var longestPrefix string
	var matchedMethodMap map[string][]string

	for pattern, methodMap := range h.server.Config.EndpointMethodScopeRequirements {
		if strings.HasSuffix(pattern, "/*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(normalizedPath, prefix) && len(prefix) > len(longestPrefix) {
				longestPrefix = prefix
				matchedMethodMap = methodMap
			}
		}
	}

	if matchedMethodMap != nil {
		// Try exact method match
		if scopes, ok := matchedMethodMap[method]; ok {
			return scopes
		}
		// Try wildcard method fallback
		if scopes, ok := matchedMethodMap["*"]; ok {
			return scopes
		}
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

// isValidAuthMethod checks if the given token endpoint auth method is supported
func isValidAuthMethod(method string) bool {
	for _, supported := range SupportedTokenAuthMethods {
		if method == supported {
			return true
		}
	}
	return false
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

// recordHTTPMetrics records HTTP request metrics (total count and duration)
func (h *Handler) recordHTTPMetrics(endpoint, method string, status int, startTime time.Time) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	ctx := context.Background()

	// Record total requests with duration
	duration := time.Since(startTime).Seconds() * 1000 // convert to milliseconds
	metrics.RecordHTTPRequest(ctx, method, endpoint, status, duration)
}

// recordAuthorizationStarted records when an authorization flow is started
func (h *Handler) recordAuthorizationStarted(clientID string) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordAuthorizationStarted(context.Background(), clientID)
}

// recordCallbackProcessed records when a callback is processed
func (h *Handler) recordCallbackProcessed(clientID string, success bool) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordCallbackProcessed(context.Background(), clientID, success)
}

// recordCodeExchanged records when an authorization code is exchanged
func (h *Handler) recordCodeExchanged(clientID, pkceMethod string) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordCodeExchange(context.Background(), clientID, pkceMethod)
}

// recordTokenRefreshed records when a token is refreshed
func (h *Handler) recordTokenRefreshed(clientID string, rotated bool) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordTokenRefresh(context.Background(), clientID, rotated)
}

// recordTokenRevoked records when a token is revoked
func (h *Handler) recordTokenRevoked(clientID string) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordTokenRevocation(context.Background(), clientID)
}

// recordClientRegistered records when a client is registered
func (h *Handler) recordClientRegistered(clientType string) {
	if h.server.Instrumentation == nil {
		return
	}

	metrics := h.server.Instrumentation.Metrics()
	metrics.RecordClientRegistration(context.Background(), clientType)
}
