package oauth

import (
	"bytes"
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
	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

const (
	defaultCORSMaxAge = 3600 // 1 hour default for preflight cache
	tokenTypeBearer   = "Bearer"
)

// clientRegistrationRequest represents the JSON request for client registration
type clientRegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	ClientType              string   `json:"client_type"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RedirectURIs            []string `json:"redirect_uris"`
	Scopes                  []string `json:"scopes"`
}

// checkClientRegistrationRateLimit checks if client registration is rate limited
// Returns true if request should be rejected, false if allowed
func (h *Handler) checkClientRegistrationRateLimit(w http.ResponseWriter, clientIP string, _ time.Time) bool {
	if h.server.ClientRegistrationRateLimiter == nil {
		return false
	}

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
		return true
	}
	return false
}

// validateRegistrationToken validates the registration access token
// Returns true if valid token was provided
func (h *Handler) validateRegistrationToken(authHeader string) bool {
	if authHeader == "" || h.server.Config.RegistrationAccessToken == "" {
		return false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(h.server.Config.RegistrationAccessToken)) == 1
}

// authorizeClientRegistration checks if client registration is authorized
// Returns (registeredViaTrustedScheme, trustedScheme, error)
func (h *Handler) authorizeClientRegistration(w http.ResponseWriter, r *http.Request, req *clientRegistrationRequest, clientIP string) (bool, string, bool) {
	if h.server.Config.AllowPublicClientRegistration {
		h.logger.Warn("Unauthenticated client registration (DoS risk)", "client_ip", clientIP)
		return false, "", true
	}

	authHeader := r.Header.Get("Authorization")
	if h.validateRegistrationToken(authHeader) {
		h.logger.Info("Client registration authenticated with valid token")
		return false, "", true
	}

	// Check trusted schemes
	if authHeader != "" {
		h.logger.Warn("Invalid registration token provided, checking trusted schemes as fallback",
			"client_ip", clientIP, "has_trusted_schemes_configured", len(h.server.Config.TrustedPublicRegistrationSchemes) > 0)
	}

	allowed, scheme, err := h.server.CanRegisterWithTrustedScheme(req.RedirectURIs)
	if err != nil {
		h.logger.Warn("Client registration rejected: invalid redirect URI", "client_ip", clientIP, "error", err)
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("Invalid redirect URI: %v", err), http.StatusBadRequest)
		return false, "", false
	}

	if allowed {
		h.logger.Info("Client registration authorized via trusted scheme",
			"scheme", scheme, "client_ip", clientIP, "strict_matching", !h.server.Config.DisableStrictSchemeMatching)
		return true, scheme, true
	}

	h.logger.Warn("Client registration rejected: missing or invalid authorization",
		"client_ip", clientIP, "has_token", authHeader != "",
		"trusted_schemes_configured", len(h.server.Config.TrustedPublicRegistrationSchemes) > 0)
	h.writeError(w, ErrorCodeInvalidToken,
		"Registration requires authentication. Provide a valid registration token or use a trusted redirect URI scheme.",
		http.StatusUnauthorized)
	return false, "", false
}

// validatePublicClientRegistration validates public client registration is allowed
// Returns true if allowed, false if rejected
func (h *Handler) validatePublicClientRegistration(w http.ResponseWriter, req *clientRegistrationRequest, clientIP string, registeredViaTrustedScheme bool, startTime time.Time, span trace.Span) bool {
	isPublicClientRequest := req.TokenEndpointAuthMethod == TokenEndpointAuthMethodNone || req.ClientType == ClientTypePublic
	if !isPublicClientRequest {
		return true
	}

	if !h.server.Config.AllowPublicClientRegistration && !registeredViaTrustedScheme {
		h.logger.Warn("Public client registration rejected (not allowed by configuration)",
			"token_endpoint_auth_method", req.TokenEndpointAuthMethod,
			"client_type", req.ClientType, "ip", clientIP)
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
		return false
	}

	h.logger.Info("Public client registration authorized",
		"token_endpoint_auth_method", req.TokenEndpointAuthMethod, "client_type", req.ClientType,
		"ip", clientIP, "via_trusted_scheme", registeredViaTrustedScheme)
	return true
}

// Context keys for interstitial page custom handlers.
// These are used to pass the redirect URL and app name to custom handlers
// via the request context.
type interstitialContextKey string

const (
	// interstitialRedirectURLKey is the context key for the OAuth redirect URL
	interstitialRedirectURLKey interstitialContextKey = "interstitial_redirect_url"
	// interstitialAppNameKey is the context key for the application name
	interstitialAppNameKey interstitialContextKey = "interstitial_app_name"
)

// InterstitialRedirectURL extracts the OAuth redirect URL from the request context.
// This is used by custom interstitial handlers to get the redirect URL.
// Returns empty string if not found in context.
func InterstitialRedirectURL(ctx context.Context) string {
	if v, ok := ctx.Value(interstitialRedirectURLKey).(string); ok {
		return v
	}
	return ""
}

// InterstitialAppName extracts the application name from the request context.
// This is used by custom interstitial handlers to get the human-readable app name.
// Returns empty string if not found in context.
func InterstitialAppName(ctx context.Context) string {
	if v, ok := ctx.Value(interstitialAppNameKey).(string); ok {
		return v
	}
	return ""
}

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
// The template supports branding customization through CSS variables and conditional
// rendering of logo/icon, title, message, and button text.
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
    <title>{{if .Title}}{{.Title}}{{else}}Authorization Successful{{end}}</title>
    <style>
        :root {
            --primary-color: {{if .PrimaryColor}}{{.PrimaryColor}}{{else}}#00d26a{{end}};
            --primary-color-dark: {{if .PrimaryColor}}{{.PrimaryColor}}{{else}}#00a855{{end}};
            --bg-gradient: {{if .BackgroundGradient}}{{.BackgroundGradient}}{{else}}linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%){{end}};
        }
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg-gradient);
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
        .logo {
            max-height: 80px;
            max-width: 200px;
            margin: 0 auto 1.5rem;
            display: block;
            animation: scaleIn 0.5s ease-out;
        }
        .success-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 1.5rem;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-color-dark) 100%);
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
            color: var(--primary-color);
            font-weight: 500;
        }
        .button {
            display: inline-block;
            padding: 0.875rem 2rem;
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-color-dark) 100%);
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
        {{.CustomCSS}}
    </style>
</head>
<body>
    <div class="container">
        {{if .LogoURL}}<img src="{{.LogoURL}}" alt="{{.LogoAlt}}" class="logo" crossorigin="anonymous">{{else}}<div class="success-icon">
            <svg viewBox="0 0 24 24">
                <polyline class="checkmark" points="4 12 9 17 20 6"></polyline>
            </svg>
        </div>{{end}}
        <h1>{{if .Title}}{{.Title}}{{else}}Authorization Successful{{end}}</h1>
        <p class="message">
            {{if .Message}}{{.Message}}{{else}}You have been authenticated successfully.
            {{if .AppName}}Return to <span class="app-name">{{.AppName}}</span> to continue.{{else}}You can now return to the application.{{end}}{{end}}
        </p>
        <p class="redirecting" id="redirecting">
            <span class="spinner"></span>Redirecting automatically...
        </p>
        <a href="{{.RedirectURL}}" class="button" id="openApp">
            {{if .ButtonText}}{{.ButtonText}}{{else}}{{if .AppName}}Open {{.AppName}}{{else}}Open Application{{end}}{{end}}
        </a>
        <p class="close-hint">You can close this window after the application opens.</p>
    </div>
    <script>(function(){var btn=document.getElementById("openApp");if(!btn)return;var redirectURL=btn.href;var redirected=false;setTimeout(function(){if(!redirected){redirected=true;window.location.href=redirectURL;}},500);setTimeout(function(){var el=document.getElementById("redirecting");if(el){el.style.display="none";}},3000);})();</script>
</body>
</html>`

// successInterstitialTmpl is the parsed HTML template for OAuth success pages.
// Parsed once at package initialization for efficiency.
var successInterstitialTmpl = template.Must(template.New("success").Parse(successInterstitialTemplate))

// successInterstitialData holds the template data for the success interstitial page.
// All branding fields are optional - unset fields use the default values in the template.
type successInterstitialData struct {
	// Core fields (always set)
	RedirectURL template.URL // template.URL marks URLs as safe for href attributes
	AppName     string       // Human-readable application name (e.g., "Cursor", "Visual Studio Code")

	// Branding fields (optional, from InterstitialBranding config)
	LogoURL            string       // URL to custom logo image (HTTPS required)
	LogoAlt            string       // Alt text for logo (accessibility)
	Title              string       // Custom page title (replaces "Authorization Successful")
	Message            string       // Custom success message
	ButtonText         string       // Custom button text (replaces "Open [AppName]")
	PrimaryColor       template.CSS // CSS color value for primary/accent color (marked safe for CSS context)
	BackgroundGradient template.CSS // CSS background value (marked safe for CSS context)
	CustomCSS          template.CSS // Additional CSS (marked safe for CSS context)
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
//
// The function supports three customization modes (in priority order):
//  1. CustomHandler - if set, delegates to the handler with context values
//  2. CustomTemplate - if set, parses and executes the custom template
//  3. Branding - if set, uses the default template with custom branding
//  4. Default - uses the built-in template with standard styling
func (h *Handler) serveSuccessInterstitial(w http.ResponseWriter, r *http.Request, redirectURL string) {
	// Extract app name from the redirect URL scheme
	appName := getAppNameFromScheme(redirectURL)

	interstitialCfg := h.server.Config.Interstitial

	// Priority 1: Custom handler (full control)
	// The handler is responsible for setting all headers and writing the response
	if interstitialCfg != nil && interstitialCfg.CustomHandler != nil {
		// Store redirect URL and app name in context for the custom handler
		ctx := context.WithValue(r.Context(), interstitialRedirectURLKey, redirectURL)
		ctx = context.WithValue(ctx, interstitialAppNameKey, appName)
		interstitialCfg.CustomHandler(w, r.WithContext(ctx))
		return
	}

	// Priority 2: Custom template
	if interstitialCfg != nil && interstitialCfg.CustomTemplate != "" {
		h.serveCustomInterstitialTemplate(w, interstitialCfg.CustomTemplate, redirectURL, appName, interstitialCfg.Branding)
		return
	}

	// Priority 3 & 4: Default template (with optional branding)
	h.serveDefaultInterstitial(w, redirectURL, appName, interstitialCfg)
}

// serveCustomInterstitialTemplate serves a custom HTML template for the interstitial page.
// The template is parsed each time (not cached) since custom templates may change at runtime.
func (h *Handler) serveCustomInterstitialTemplate(w http.ResponseWriter, templateStr, redirectURL, appName string, branding *server.InterstitialBranding) {
	// Parse the custom template
	tmpl, err := template.New("custom-interstitial").Parse(templateStr)
	if err != nil {
		h.logger.Error("Failed to parse custom interstitial template", "error", err)
		// Fall back to default template on parse error
		h.serveDefaultInterstitial(w, redirectURL, appName, nil)
		return
	}

	// Build template data with branding (if provided)
	data := h.buildInterstitialData(redirectURL, appName, branding)

	// Execute template to buffer first to handle errors cleanly
	// This prevents partial writes to the response if template execution fails
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		h.logger.Error("Failed to execute custom interstitial template", "error", err)
		// Fall back to default template on execution error
		h.serveDefaultInterstitial(w, redirectURL, appName, nil)
		return
	}

	// Set security headers and write the buffered response
	// Note: Custom templates may need different CSP headers for their scripts
	security.SetInterstitialSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// serveDefaultInterstitial serves the default interstitial template with optional branding.
func (h *Handler) serveDefaultInterstitial(w http.ResponseWriter, redirectURL, appName string, interstitialCfg *server.InterstitialConfig) {
	// Get branding config (may be nil)
	var branding *server.InterstitialBranding
	if interstitialCfg != nil {
		branding = interstitialCfg.Branding
	}

	// Build template data
	data := h.buildInterstitialData(redirectURL, appName, branding)

	// Execute template to buffer first to handle errors cleanly
	// This prevents partial writes to the response if template execution fails
	var buf bytes.Buffer
	if err := successInterstitialTmpl.Execute(&buf, data); err != nil {
		h.logger.Error("Failed to execute success interstitial template", "error", err)
		// Fallback to plain text on error (should be rare with pre-parsed template)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Authorization successful. Please return to your application."))
		return
	}

	// Set security headers with CSP hash exception for the inline redirect script
	security.SetInterstitialSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// buildInterstitialData constructs the template data for the interstitial page.
// It applies branding configuration if provided, using defaults for unset values.
func (h *Handler) buildInterstitialData(redirectURL, appName string, branding *server.InterstitialBranding) successInterstitialData {
	// SECURITY: We must use template.URL to allow custom URL schemes in href attributes.
	// Go's html/template filters URLs to only allow http, https, mailto by default.
	// Custom schemes like cursor://, vscode:// are legitimate OAuth redirect URIs
	// per RFC 8252 (OAuth 2.0 for Native Apps) and have already been validated
	// during client registration and authorization flow.
	data := successInterstitialData{
		RedirectURL: template.URL(redirectURL), //nolint:gosec // URL validated during OAuth flow
		AppName:     appName,
	}

	// Apply branding if configured
	if branding != nil {
		data.LogoURL = branding.LogoURL
		data.LogoAlt = branding.LogoAlt
		if data.LogoAlt == "" && data.LogoURL != "" {
			data.LogoAlt = "Logo" // Accessibility fallback
		}
		data.Title = branding.Title
		// Replace {{.AppName}} placeholder in Message and ButtonText
		// This allows users to configure messages like "Return to {{.AppName}}"
		data.Message = strings.ReplaceAll(branding.Message, "{{.AppName}}", appName)
		data.ButtonText = strings.ReplaceAll(branding.ButtonText, "{{.AppName}}", appName)
		// SECURITY: CSS values are marked as template.CSS to prevent escaping
		// These values are validated at config load time to prevent injection
		data.PrimaryColor = template.CSS(branding.PrimaryColor)             //nolint:gosec // Validated in validateInterstitialBranding
		data.BackgroundGradient = template.CSS(branding.BackgroundGradient) //nolint:gosec // Validated in validateInterstitialBranding
		data.CustomCSS = template.CSS(branding.CustomCSS)                   //nolint:gosec // Validated in validateInterstitialBranding
	}

	return data
}

// ValidateToken is middleware that validates OAuth tokens
func (h *Handler) ValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

		if h.checkIPRateLimit(w, r, clientIP) {
			return
		}

		accessToken, ok := h.extractBearerToken(w, r)
		if !ok {
			return
		}

		userInfo, err := h.server.ValidateToken(r.Context(), accessToken)
		if err != nil {
			h.logger.Warn("Token validation failed", "ip", clientIP, "error", err)
			h.writeUnauthorizedError(w, r, ErrorCodeInvalidToken, "Token validation failed")
			return
		}

		if !h.validateTokenScopes(w, r, accessToken, userInfo, clientIP) {
			return
		}

		if h.checkUserRateLimit(w, r, userInfo.ID, clientIP) {
			return
		}

		ctx := ContextWithUserInfo(r.Context(), userInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// checkIPRateLimit checks if the client IP is rate limited. Returns true if limited.
func (h *Handler) checkIPRateLimit(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	if h.server.RateLimiter == nil || h.server.RateLimiter.Allow(clientIP) {
		return false
	}

	h.logger.Warn("Rate limit exceeded", "ip", clientIP)
	h.recordRateLimitExceeded(r.Context(), "ip", clientIP, "", r.URL.Path)
	w.Header().Set("Retry-After", "60")
	h.writeError(w, ErrorCodeRateLimitExceeded, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
	return true
}

// checkUserRateLimit checks if the user is rate limited. Returns true if limited.
func (h *Handler) checkUserRateLimit(w http.ResponseWriter, r *http.Request, userID, clientIP string) bool {
	if h.server.UserRateLimiter == nil || h.server.UserRateLimiter.Allow(userID) {
		return false
	}

	h.logger.Warn("User rate limit exceeded", "user_id", userID, "ip", clientIP)
	h.recordUserRateLimitExceeded(r.Context(), clientIP, userID)
	w.Header().Set("Retry-After", "60")
	h.writeError(w, ErrorCodeRateLimitExceeded, "Rate limit exceeded for user. Please try again later.", http.StatusTooManyRequests)
	return true
}

// recordRateLimitExceeded records rate limit metrics and audit events.
func (h *Handler) recordRateLimitExceeded(ctx context.Context, limitType, clientIP, userID, endpoint string) {
	if h.server.Instrumentation != nil {
		h.server.Instrumentation.Metrics().RecordRateLimitExceeded(ctx, limitType)
	}
	if h.server.Auditor != nil {
		h.server.Auditor.LogEvent(security.Event{
			Type:      security.EventRateLimitExceeded,
			IPAddress: clientIP,
			Details:   map[string]any{"endpoint": endpoint},
		})
		h.server.Auditor.LogRateLimitExceeded(clientIP, userID)
	}
}

// recordUserRateLimitExceeded records user rate limit metrics and audit events.
func (h *Handler) recordUserRateLimitExceeded(ctx context.Context, clientIP, userID string) {
	if h.server.Instrumentation != nil {
		h.server.Instrumentation.Metrics().RecordRateLimitExceeded(ctx, "user")
	}
	if h.server.Auditor != nil {
		h.server.Auditor.LogRateLimitExceeded(clientIP, userID)
	}
}

// extractBearerToken extracts the Bearer token from the Authorization header.
// Returns the token and true if successful, or writes an error and returns false.
func (h *Handler) extractBearerToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.writeUnauthorizedError(w, r, ErrorCodeInvalidToken, "Missing Authorization header")
		return "", false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		h.writeUnauthorizedError(w, r, ErrorCodeInvalidToken, "Invalid Authorization header format")
		return "", false
	}

	return parts[1], true
}

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
	prefix := MetadataPathProtectedResource
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
	mux.HandleFunc(MetadataPathProtectedResource, h.ServeProtectedResourceMetadata)

	// Track registered paths to avoid duplicate registrations
	registeredPaths := make(map[string]bool)
	registeredPaths[MetadataPathProtectedResource] = true

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
	subPath := MetadataPathProtectedResource + cleanPath

	// Skip if already registered
	if registered[subPath] {
		h.logger.Debug("Skipping duplicate metadata path registration",
			"path", subPath)
		return
	}

	h.logger.Info("Registering metadata sub-path endpoint",
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
		h.logger.Info("Registered authorization server metadata endpoints",
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

	h.logger.Info("Registered multi-tenant authorization server metadata endpoints",
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
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)
	if h.checkDiscoveryRateLimit(w, r, clientIP) {
		return
	}

	h.setCORSHeaders(w, r)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)

	metadata := h.buildAuthServerMetadata()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// checkDiscoveryRateLimit checks rate limit for discovery endpoints.
// Returns true if rate limit exceeded and response was written.
func (h *Handler) checkDiscoveryRateLimit(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	if h.server.RateLimiter == nil || h.server.RateLimiter.Allow(clientIP) {
		return false
	}

	h.logger.Warn("Rate limit exceeded on discovery endpoint",
		"ip", clientIP,
		"endpoint", "authorization_server_metadata")

	if h.server.Instrumentation != nil {
		h.server.Instrumentation.Metrics().RecordRateLimitExceeded(r.Context(), "ip")
	}

	if h.server.Auditor != nil {
		h.server.Auditor.LogEvent(security.Event{
			Type:      security.EventRateLimitExceeded,
			IPAddress: clientIP,
			Details:   map[string]any{"endpoint": r.URL.Path},
		})
	}

	w.Header().Set("Retry-After", "60")
	http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
	return true
}

// buildAuthServerMetadata builds the RFC 8414 authorization server metadata.
func (h *Handler) buildAuthServerMetadata() map[string]any {
	metadata := map[string]any{
		"issuer":                                h.server.Config.Issuer,
		"authorization_endpoint":                h.server.Config.AuthorizationEndpoint(),
		"token_endpoint":                        h.server.Config.TokenEndpoint(),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{PKCEMethodS256},
		"token_endpoint_auth_methods_supported": SupportedTokenAuthMethods,
	}

	h.addOptionalMetadata(metadata)
	return metadata
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

	if h.server.Config.EnableClientIDMetadataDocuments {
		metadata["client_id_metadata_document_supported"] = true
	}
}

// isRegistrationAvailable checks if client registration is available.
func (h *Handler) isRegistrationAvailable() bool {
	return h.server.Config.AllowPublicClientRegistration ||
		h.server.Config.RegistrationAccessToken != "" ||
		len(h.server.Config.TrustedPublicRegistrationSchemes) > 0
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
		attribute.String(instrumentation.AttrClientID, clientID),
		attribute.String(instrumentation.AttrPKCEMethod, codeChallengeMethod),
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
	instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, authCode.ClientID))
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
		h.serveSuccessInterstitial(w, r, redirectURL)
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
		// authenticateClient returns Error, extract details
		if oauthErr, ok := err.(*Error); ok {
			h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		} else {
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		}
		return
	}

	// Add span attributes
	instrumentation.SetSpanAttributes(span,
		attribute.String(instrumentation.AttrClientID, client.ClientID),
		attribute.String(instrumentation.AttrClientType, client.ClientType),
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

	instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, clientID))

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

	instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, clientID))

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
	ctx, span := h.startRegistrationSpan(r)
	if span != nil {
		defer span.End()
		r = r.WithContext(ctx)
	}

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics("register", http.MethodPost, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.setCORSHeaders(w, r)
	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	if h.checkClientRegistrationRateLimit(w, clientIP, startTime) {
		return
	}

	req, err := h.parseAndValidateRegistrationRequest(w, r, clientIP)
	if err != nil {
		return
	}

	registeredViaTrustedScheme, trustedScheme, authorized := h.authorizeClientRegistration(w, r, req, clientIP)
	if !authorized {
		return
	}

	if !h.validatePublicClientRegistration(w, req, clientIP, registeredViaTrustedScheme, startTime, span) {
		return
	}

	h.recordTrustedSchemeSpan(span, registeredViaTrustedScheme, trustedScheme)

	maxClients := h.getMaxClientsPerIP()
	client, clientSecret, err := h.server.RegisterClient(ctx, req.ClientName, req.ClientType, req.TokenEndpointAuthMethod, req.RedirectURIs, req.Scopes, clientIP, maxClients)
	if err != nil {
		h.handleRegistrationError(w, err, clientIP, startTime, span)
		return
	}

	h.recordClientRegistered(client.ClientType)
	h.auditTrustedSchemeRegistration(registeredViaTrustedScheme, trustedScheme, client, clientIP)
	h.recordHTTPMetrics("register", http.MethodPost, http.StatusCreated, startTime)
	h.setRegistrationSpanSuccess(span, client)
	h.writeRegistrationResponse(w, client, clientSecret)
}

// startRegistrationSpan creates a tracing span for client registration.
func (h *Handler) startRegistrationSpan(r *http.Request) (context.Context, trace.Span) {
	if h.tracer == nil {
		return r.Context(), nil
	}
	return h.tracer.Start(r.Context(), "oauth.http.client_registration")
}

// parseAndValidateRegistrationRequest parses the request and validates auth method.
func (h *Handler) parseAndValidateRegistrationRequest(w http.ResponseWriter, r *http.Request, clientIP string) (*clientRegistrationRequest, error) {
	var req clientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Invalid JSON", http.StatusBadRequest)
		return nil, err
	}

	if req.TokenEndpointAuthMethod != "" && !isValidAuthMethod(req.TokenEndpointAuthMethod) {
		h.logger.Warn("Unsupported token_endpoint_auth_method requested",
			"method", req.TokenEndpointAuthMethod, "supported_methods", SupportedTokenAuthMethods, "ip", clientIP)
		h.writeError(w, ErrorCodeInvalidRequest,
			fmt.Sprintf("Unsupported token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod),
			http.StatusBadRequest)
		return nil, fmt.Errorf("unsupported auth method")
	}

	return &req, nil
}

// getMaxClientsPerIP returns the max clients per IP with default.
func (h *Handler) getMaxClientsPerIP() int {
	if h.server.Config.MaxClientsPerIP == 0 {
		return 10
	}
	return h.server.Config.MaxClientsPerIP
}

// recordTrustedSchemeSpan records trusted scheme info in span.
func (h *Handler) recordTrustedSchemeSpan(span trace.Span, registeredViaTrustedScheme bool, trustedScheme string) {
	if span != nil && registeredViaTrustedScheme {
		instrumentation.SetSpanAttributes(span,
			attribute.String("oauth.registration_method", "trusted_scheme"),
			attribute.String("oauth.trusted_scheme", trustedScheme),
		)
	}
}

// handleRegistrationError handles client registration errors.
func (h *Handler) handleRegistrationError(w http.ResponseWriter, err error, clientIP string, startTime time.Time, span trace.Span) {
	if strings.Contains(err.Error(), "registration limit") {
		h.logger.Warn("Client registration limit exceeded", "ip", clientIP, "error", err)
		h.recordHTTPMetrics("register", http.MethodPost, http.StatusTooManyRequests, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "registration limit exceeded")
		h.writeError(w, ErrorCodeInvalidRequest, "Client registration limit exceeded", http.StatusTooManyRequests)
		return
	}

	h.logger.Error("Failed to register client", "ip", clientIP, "error", err)
	h.recordHTTPMetrics("register", http.MethodPost, http.StatusInternalServerError, startTime)
	instrumentation.RecordError(span, err)
	instrumentation.SetSpanError(span, "registration failed")
	h.writeError(w, ErrorCodeServerError, "Failed to register client", http.StatusInternalServerError)
}

// auditTrustedSchemeRegistration logs trusted scheme registration for security monitoring.
func (h *Handler) auditTrustedSchemeRegistration(registeredViaTrustedScheme bool, trustedScheme string, client *storage.Client, clientIP string) {
	if !registeredViaTrustedScheme || h.server.Auditor == nil {
		return
	}

	h.server.Auditor.LogEvent(security.Event{
		Type:     security.EventClientRegisteredViaTrustedScheme,
		ClientID: client.ClientID,
		Details: map[string]any{
			"scheme":           trustedScheme,
			"client_type":      client.ClientType,
			"client_ip":        clientIP,
			"redirect_uris":    client.RedirectURIs,
			"strict_matching":  !h.server.Config.DisableStrictSchemeMatching,
			"security_context": "unauthenticated_registration_via_trusted_scheme",
		},
	})
}

// setRegistrationSpanSuccess sets success attributes on the span.
func (h *Handler) setRegistrationSpanSuccess(span trace.Span, client *storage.Client) {
	instrumentation.SetSpanAttributes(span,
		attribute.String(instrumentation.AttrClientID, client.ClientID),
		attribute.String(instrumentation.AttrClientType, client.ClientType),
	)
	instrumentation.SetSpanSuccess(span)
}

// writeRegistrationResponse writes the client registration response.
func (h *Handler) writeRegistrationResponse(w http.ResponseWriter, client *storage.Client, clientSecret string) {
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
	authClientID, authClientSecret := h.parseBasicAuth(r)
	if authClientID != "" {
		clientID = authClientID
	}

	if clientID == "" {
		return nil, ErrInvalidRequest("client_id is required")
	}

	client, err := h.server.GetClient(r.Context(), clientID)
	if err != nil {
		h.logAuthFailure(clientID, clientIP, ErrorCodeInvalidClient, "Unknown client")
		return nil, ErrInvalidClient("Client authentication failed")
	}

	if err := h.validateConfidentialClient(r.Context(), client, authClientSecret, clientIP); err != nil {
		return nil, err
	}

	return client, nil
}

// validateConfidentialClient validates credentials for confidential clients.
func (h *Handler) validateConfidentialClient(ctx context.Context, client *storage.Client, secret, clientIP string) error {
	if client.ClientType != ClientTypeConfidential {
		return nil
	}

	if secret == "" {
		h.logAuthFailure(client.ClientID, clientIP, "confidential_client_auth_required", "Confidential client missing credentials")
		return ErrInvalidClient("Client authentication required")
	}

	if err := h.server.ValidateClientCredentials(ctx, client.ClientID, secret); err != nil {
		h.logAuthFailure(client.ClientID, clientIP, "client_authentication_failed", "Client authentication failed")
		return ErrInvalidClient("Client authentication failed")
	}

	return nil
}

// logAuthFailure logs authentication failures with optional auditing.
func (h *Handler) logAuthFailure(clientID, clientIP, reason, message string) {
	h.logger.Warn(message, "client_id", clientID, "ip", clientIP)
	if h.server.Auditor != nil {
		h.server.Auditor.LogAuthFailure("", clientID, clientIP, reason)
	}
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

// ServeTokenIntrospection handles the RFC 7662 token introspection endpoint
// This allows resource servers to validate access tokens
// Security: Requires client authentication to prevent token scanning attacks
func (h *Handler) ServeTokenIntrospection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.setCORSHeaders(w, r)
	clientIP := security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)

	if err := r.ParseForm(); err != nil {
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		h.writeError(w, ErrorCodeInvalidRequest, "token parameter is required", http.StatusBadRequest)
		return
	}

	clientID, err := h.authenticateIntrospectionClient(r, clientIP)
	if err != nil {
		h.writeError(w, ErrorCodeInvalidClient, err.Error(), http.StatusUnauthorized)
		return
	}

	// Validate the token and build response
	response := h.buildIntrospectionResponse(r.Context(), token, clientID, clientIP)

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// authenticateIntrospectionClient validates client credentials for token introspection.
// Returns the client ID on success, or an error if authentication fails.
func (h *Handler) authenticateIntrospectionClient(r *http.Request, clientIP string) (string, error) {
	ctx := r.Context()
	authClientID, authClientSecret := h.parseBasicAuth(r)

	if authClientID != "" {
		if err := h.server.ValidateClientCredentials(ctx, authClientID, authClientSecret); err != nil {
			h.logger.Warn("Client authentication failed for introspection", "client_id", authClientID, "ip", clientIP)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure("", authClientID, clientIP, "introspection_auth_failed")
			}
			return "", fmt.Errorf("client authentication failed")
		}
		return authClientID, nil
	}

	// No Basic Auth - check for client_id in form (but we still reject without credentials)
	clientID := r.FormValue("client_id")
	if clientID == "" {
		h.logger.Warn("Token introspection rejected: missing client authentication", "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure("", "", clientIP, "introspection_missing_auth")
		}
		return "", fmt.Errorf("client authentication required for token introspection")
	}

	h.logger.Warn("Token introspection rejected: client_id without credentials", "client_id", clientID, "ip", clientIP)
	if h.server.Auditor != nil {
		h.server.Auditor.LogAuthFailure("", clientID, clientIP, "introspection_missing_credentials")
	}
	return "", fmt.Errorf("client authentication required for token introspection")
}

// buildIntrospectionResponse creates the RFC 7662 introspection response.
func (h *Handler) buildIntrospectionResponse(ctx context.Context, token, clientID, clientIP string) map[string]interface{} {
	userInfo, err := h.server.ValidateToken(ctx, token)

	response := map[string]interface{}{
		"active": false,
	}

	if err != nil || userInfo == nil {
		h.logger.Debug("Token introspection failed", "error", err, "ip", clientIP)
		return response
	}

	response["active"] = true
	response["sub"] = userInfo.ID
	response["email"] = userInfo.Email
	response["email_verified"] = userInfo.EmailVerified
	response["token_type"] = "Bearer"

	if userInfo.Name != "" {
		response["name"] = userInfo.Name
	}
	if clientID != "" {
		response["client_id"] = clientID
	}

	return response
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
