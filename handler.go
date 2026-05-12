package oauth

import (
	"bytes"
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
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
	defaultCORSMaxAge        = 3600 // 1 hour default for preflight cache
	tokenTypeBearer          = "Bearer"
	defaultRetryAfterSeconds = 60 // Retry-After fallback for limiters with no defined rate/window
)

// Endpoint labels for `oauth_http_requests_total{endpoint="..."}` etc.
// Future renames are breaking changes for downstream dashboards.
const (
	endpointAuthorize     = "authorize"
	endpointCallback      = "callback"
	endpointToken         = "token"
	endpointRevoke        = "revoke"
	endpointIntrospect    = "introspect"
	endpointRegister      = "register"
	endpointValidateToken = "validate_token"
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
func (h *Handler) checkClientRegistrationRateLimit(ctx context.Context, w http.ResponseWriter, clientIP string, startTime time.Time) bool {
	if h.server.ClientRegistrationRateLimiter == nil {
		return false
	}

	if !h.server.ClientRegistrationRateLimiter.Allow(security.RateLimitBucket(clientIP)) {
		h.logger.Warn("Client registration rate limit exceeded",
			"ip", clientIP,
			"max_per_window", h.server.Config.MaxRegistrationsPerHour,
			"window", time.Duration(h.server.Config.RegistrationRateLimitWindow)*time.Second)
		if h.server.Auditor != nil {
			h.server.Auditor.LogClientRegistrationRateLimitExceeded(ctx, clientIP)
		}
		h.recordHTTPMetrics(ctx, endpointRegister, http.MethodPost, http.StatusTooManyRequests, startTime)
		retryAfter := int(h.server.ClientRegistrationRateLimiter.Window().Seconds())
		if retryAfter < 1 {
			retryAfter = 60
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
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

// Registration auth gate names used in audit, tracing, and logs.
const (
	registrationAuthGateTrustedScheme      = "trusted_scheme"
	registrationAuthGateTrustedRedirectURI = "trusted_redirect_uri"
)

// registrationAuthResult identifies which gate authorized a DCR request.
type registrationAuthResult struct {
	viaTrustedAllowlist bool
	gate                string
	matched             string
}

// authorizeClientRegistration checks whether a DCR request is authorized via the
// public-client flag, a registration access token, the trusted-scheme allowlist,
// or the trusted-redirect-URI allowlist (in that order).
func (h *Handler) authorizeClientRegistration(w http.ResponseWriter, r *http.Request, req *clientRegistrationRequest, clientIP string) (registrationAuthResult, bool) {
	var result registrationAuthResult

	if h.server.Config.AllowPublicClientRegistration {
		h.logger.Warn("Unauthenticated client registration (DoS risk)", "client_ip", clientIP)
		return result, true
	}

	authHeader := r.Header.Get("Authorization")
	if h.validateRegistrationToken(authHeader) {
		h.logger.Debug("Client registration authenticated with valid token")
		return result, true
	}

	if authHeader != "" {
		h.logger.Warn("Invalid registration token provided, falling back to trusted allowlists",
			"client_ip", clientIP,
			"has_trusted_schemes_configured", len(h.server.Config.TrustedPublicRegistrationSchemes) > 0,
			"has_trusted_redirect_uris_configured", len(h.server.Config.TrustedPublicRegistrationRedirectURIs) > 0)
	}

	allowed, scheme, err := h.server.CanRegisterWithTrustedScheme(req.RedirectURIs)
	if err != nil {
		h.logger.Warn("Client registration rejected: invalid redirect URI", "client_ip", clientIP, "error", err)
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("Invalid redirect URI: %v", err), http.StatusBadRequest)
		return result, false
	}
	if allowed {
		h.logger.Debug("Client registration authorized via trusted scheme",
			"scheme", scheme, "client_ip", clientIP, "strict_matching", !h.server.Config.DisableStrictSchemeMatching)
		return registrationAuthResult{viaTrustedAllowlist: true, gate: registrationAuthGateTrustedScheme, matched: scheme}, true
	}

	allowed, uri, err := h.server.CanRegisterWithTrustedRedirectURI(req.RedirectURIs)
	if err != nil {
		h.logger.Warn("Client registration rejected: invalid redirect URI", "client_ip", clientIP, "error", err)
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("Invalid redirect URI: %v", err), http.StatusBadRequest)
		return result, false
	}
	if allowed {
		h.logger.Debug("Client registration authorized via trusted redirect URI",
			"redirect_uri", uri, "client_ip", clientIP)
		return registrationAuthResult{viaTrustedAllowlist: true, gate: registrationAuthGateTrustedRedirectURI, matched: uri}, true
	}

	h.logger.Warn("Client registration rejected: missing or invalid authorization",
		"client_ip", clientIP, "has_token", authHeader != "",
		"has_trusted_schemes_configured", len(h.server.Config.TrustedPublicRegistrationSchemes) > 0,
		"has_trusted_redirect_uris_configured", len(h.server.Config.TrustedPublicRegistrationRedirectURIs) > 0)
	h.writeError(w, ErrorCodeInvalidToken,
		"Registration requires authentication. Provide a valid registration token or use a trusted redirect URI or scheme.",
		http.StatusUnauthorized)
	return result, false
}

// validatePublicClientRegistration validates public client registration is allowed
// Returns true if allowed, false if rejected
func (h *Handler) validatePublicClientRegistration(ctx context.Context, w http.ResponseWriter, req *clientRegistrationRequest, clientIP string, auth registrationAuthResult, startTime time.Time, span trace.Span) bool {
	isPublicClientRequest := req.TokenEndpointAuthMethod == TokenEndpointAuthMethodNone || req.ClientType == ClientTypePublic
	if !isPublicClientRequest {
		return true
	}

	if !h.server.Config.AllowPublicClientRegistration && !auth.viaTrustedAllowlist {
		h.logger.Warn("Public client registration rejected (not allowed by configuration)",
			"token_endpoint_auth_method", req.TokenEndpointAuthMethod,
			"client_type", req.ClientType, "ip", clientIP)
		h.recordHTTPMetrics(ctx, endpointRegister, http.MethodPost, http.StatusBadRequest, startTime)
		if span != nil {
			instrumentation.SetSpanAttributes(
				span,
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

	h.logger.Debug("Public client registration authorized",
		"token_endpoint_auth_method", req.TokenEndpointAuthMethod, "client_type", req.ClientType,
		"ip", clientIP, "via_trusted_allowlist", auth.viaTrustedAllowlist, "auth_gate", auth.gate)
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
// SECURITY: The inline script in success_interstitial.html is static (reads
// redirect URL from the button's href attribute) so it has a stable SHA-256
// hash for CSP allowlisting. If you modify the script, you MUST regenerate
// the hash in security/headers.go:
//
//	echo -n '<script content without tags>' | openssl dgst -sha256 -binary | base64
//
//go:embed success_interstitial.html
var successInterstitialTemplate string

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
			h.writeUnauthorizedError(w, r, ErrorCodeInvalidToken, "Token validation failed")
			return
		}

		// Single metadata lookup: used for both scope validation and session ID
		metadata := h.getTokenMetadata(accessToken)

		if !h.validateTokenScopesFromMetadata(w, r, metadata, userInfo, clientIP) {
			return
		}

		if h.checkUserRateLimit(w, r, userInfo.ID, clientIP) {
			h.recordHTTPMetrics(r.Context(), endpointValidateToken, r.Method, http.StatusTooManyRequests, startTime)
			return
		}

		ctx := ContextWithUserInfo(r.Context(), userInfo)
		if metadata != nil && metadata.FamilyID != "" {
			ctx = ContextWithSessionID(ctx, metadata.FamilyID)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// retryAfterSecondsForRate returns a Retry-After hint in seconds for a token-
// bucket limiter at the given rate (requests/second). Rate 0 (no refill)
// falls back to a constant since the next refill time is unbounded. Any
// positive rate yields 1s — sub-second precision isn't expressible in
// Retry-After (RFC 9110 §10.2.3).
func retryAfterSecondsForRate(rate int) int {
	if rate <= 0 {
		return defaultRetryAfterSeconds
	}
	return 1
}

// clientIP resolves the request's client IP using the server's proxy-trust
// configuration. Threaded into every handler that gates by IP or logs IP.
func (h *Handler) clientIP(r *http.Request) string {
	return security.GetClientIP(r, h.server.Config.TrustProxy, h.server.Config.TrustedProxyCount)
}

// gateIPRateLimit applies the IP rate limit at handler entry. On reject it
// has already written the 429 response, recorded the HTTP counter, and
// annotated the span; the caller just returns. Returns the resolved
// clientIP for the caller to use downstream, and ok=true when the request
// should proceed.
func (h *Handler) gateIPRateLimit(w http.ResponseWriter, r *http.Request, span trace.Span, endpoint, method string, startTime time.Time) (clientIP string, ok bool) {
	clientIP = h.clientIP(r)
	if !h.checkIPRateLimit(w, r, clientIP) {
		return clientIP, true
	}
	h.recordRateLimitReject(r.Context(), span, endpoint, method, startTime)
	return "", false
}

// recordRateLimitReject runs the side-effects common to every rate-limit
// reject path: span annotation + HTTP counter. The check*RateLimit helper
// has already written the 429 response and recorded its own metric/audit.
func (h *Handler) recordRateLimitReject(ctx context.Context, span trace.Span, endpoint, method string, startTime time.Time) {
	instrumentation.SetSpanError(span, "rate limited")
	h.recordHTTPMetrics(ctx, endpoint, method, http.StatusTooManyRequests, startTime)
}

// The four check*RateLimit helpers below share a "true means rejected"
// return convention: on `true`, the helper has already written the 429
// response (and recorded its own metric/audit), and the caller must
// return immediately.

// checkIPRateLimit checks if the client IP is rate limited. Returns true if limited.
func (h *Handler) checkIPRateLimit(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	if h.server.RateLimiter == nil || h.server.RateLimiter.Allow(security.RateLimitBucket(clientIP)) {
		return false
	}

	h.logger.Warn("Rate limit exceeded", "ip", clientIP)
	h.recordRateLimitExceeded(r.Context(), "ip", clientIP, "", r.URL.Path)
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecondsForRate(h.server.RateLimiter.Rate())))
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
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecondsForRate(h.server.UserRateLimiter.Rate())))
	h.writeError(w, ErrorCodeRateLimitExceeded, "Rate limit exceeded for user. Please try again later.", http.StatusTooManyRequests)
	return true
}

// recordRateLimitExceeded records rate limit metrics and audit events.
func (h *Handler) recordRateLimitExceeded(ctx context.Context, limitType, clientIP, userID, endpoint string) {
	h.server.Instrumentation.Metrics().RecordRateLimitExceeded(ctx, limitType)
	if h.server.Auditor != nil {
		h.server.Auditor.LogEvent(ctx, security.Event{
			Type:      security.EventRateLimitExceeded,
			IPAddress: clientIP,
			Details:   map[string]any{"endpoint": endpoint},
		})
		h.server.Auditor.LogRateLimitExceeded(ctx, clientIP, userID)
	}
}

// recordUserRateLimitExceeded records user rate limit metrics and audit events.
func (h *Handler) recordUserRateLimitExceeded(ctx context.Context, clientIP, userID string) {
	h.server.Instrumentation.Metrics().RecordRateLimitExceeded(ctx, "user")
	if h.server.Auditor != nil {
		h.server.Auditor.LogRateLimitExceeded(ctx, clientIP, userID)
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

// OAuthRoutesOptions controls the bundle registered by [Handler.RegisterOAuthRoutes].
type OAuthRoutesOptions struct {
	// MCPPath is forwarded to RegisterProtectedResourceMetadataRoutes for
	// backward compatibility with single-path consumers. Kept because a few
	// examples still pass it, but prefer configuring
	// [Config.ResourceMetadataByPath] instead — when that map is non-empty,
	// MCPPath is ignored (with a single warn log at registration time so the
	// conflict is visible).
	MCPPath string

	// IncludeMetadata controls whether the two discovery bundles
	// (Protected Resource Metadata per RFC 9728 and Authorization Server
	// Metadata per RFC 8414) are registered alongside the OAuth flow
	// endpoints. Default true — this is what every consumer today does by
	// hand.
	IncludeMetadata bool
}

// RegisterOAuthRoutes registers the OAuth flow endpoints on mux and, when
// opts.IncludeMetadata is true (the default), also registers the Protected
// Resource Metadata and Authorization Server Metadata routes via the two
// existing Register*Routes helpers.
//
// Routes registered (all under /oauth, paths fixed by the Config endpoint
// builders):
//
//   - /oauth/authorize, /oauth/callback, /oauth/token,
//     /oauth/revoke, /oauth/register — always registered.
//   - /oauth/introspect — only when Config.EnableIntrospectionEndpoint is
//     true. ServeTokenIntrospection does not self-gate on that flag, so
//     registering it unconditionally would expose an endpoint the operator
//     disabled in config.
//
// A customizable prefix was considered and rejected — [Config.AuthorizationEndpoint],
// [Config.TokenEndpoint], and the other metadata builders hardcode the /oauth
// prefix when constructing the issuer-scoped URLs that appear in metadata.
// A custom prefix would make the routes register at one URL while metadata
// advertised a different one. Consumers needing a custom prefix must wire
// the individual Serve* methods by hand, at which point they also need to
// override metadata advertisement.
//
// Replaces the five-line `mux.HandleFunc("/oauth/...", handler.Serve...)`
// block every consumer writes today:
//
//	handler.RegisterOAuthRoutes(mux, oauth.OAuthRoutesOptions{
//	    MCPPath:         "/mcp",
//	    IncludeMetadata: true,
//	})
func (h *Handler) RegisterOAuthRoutes(mux *http.ServeMux, opts OAuthRoutesOptions) {
	// OAuth flow endpoints — fixed paths (see method godoc for rationale).
	mux.HandleFunc(server.EndpointPathAuthorize, h.ServeAuthorization)
	mux.HandleFunc(oauthCallbackPath, h.ServeCallback)
	mux.HandleFunc(server.EndpointPathToken, h.ServeToken)
	mux.HandleFunc(server.EndpointPathRevoke, h.ServeTokenRevocation)
	mux.HandleFunc(server.EndpointPathRegister, h.ServeClientRegistration)

	// Token introspection (RFC 7662) is opt-in. ServeTokenIntrospection does
	// not self-gate on Config.EnableIntrospectionEndpoint — registering it
	// unconditionally would expose an endpoint the operator disabled in
	// config. Only wire the route when the flag is on.
	if h.server.Config.EnableIntrospectionEndpoint {
		mux.HandleFunc(server.EndpointPathIntrospect, h.ServeTokenIntrospection)
	}

	if !opts.IncludeMetadata {
		return
	}

	// ResourceMetadataByPath is the configuration-driven replacement for the
	// single MCPPath argument. If both are set, the configuration wins —
	// RegisterProtectedResourceMetadataRoutes already registers all the
	// configured paths, so a different MCPPath value would be registered
	// but never preferred over the config entries. Log once so consumers
	// notice the inconsistency instead of silently ignoring the MCPPath.
	if opts.MCPPath != "" && len(h.server.Config.ResourceMetadataByPath) > 0 {
		h.logger.Warn(
			"RegisterOAuthRoutes: MCPPath is set alongside non-empty Config.ResourceMetadataByPath; the configuration map is preferred and MCPPath adds only a back-compat alias route",
			"mcp_path", opts.MCPPath,
			"configured_paths", len(h.server.Config.ResourceMetadataByPath),
		)
	}

	h.RegisterProtectedResourceMetadataRoutes(mux, opts.MCPPath)
	h.RegisterAuthorizationServerMetadataRoutes(mux)

	// JWKS is registered only in JWT mode. AccessTokenFormat is fixed for
	// the server's lifetime; in opaque mode the route falls through to
	// the default-mux 404 and does not consume the discovery rate limit.
	if h.server.Config.IsJWTAccessTokenFormat() {
		mux.HandleFunc(server.EndpointPathJWKS, h.ServeJWKS)
	}
}

// oauthCallbackPath is the provider-callback path. The server's own
// AuthorizationEndpoint / TokenEndpoint / RegistrationEndpoint / RevocationEndpoint
// methods all live under /oauth (see server/config.go); callback follows the
// same convention.
const oauthCallbackPath = "/oauth/callback"

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
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := h.clientIP(r)
	if h.checkDiscoveryRateLimit(w, r, clientIP) {
		return
	}

	h.setCORSHeaders(w, r)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	security.SetDiscoveryCacheHeaders(w, h.server.Config.DiscoveryCacheMaxAge)

	metadata := h.buildAuthServerMetadata()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// checkDiscoveryRateLimit checks rate limit for discovery endpoints.
// Returns true if rate limit exceeded and response was written.
func (h *Handler) checkDiscoveryRateLimit(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	if h.server.RateLimiter == nil || h.server.RateLimiter.Allow(security.RateLimitBucket(clientIP)) {
		return false
	}

	h.logger.Warn("Rate limit exceeded on discovery endpoint",
		"ip", clientIP,
		"endpoint", "authorization_server_metadata")

	h.server.Instrumentation.Metrics().RecordRateLimitExceeded(r.Context(), "ip")

	if h.server.Auditor != nil {
		h.server.Auditor.LogEvent(r.Context(), security.Event{
			Type:      security.EventRateLimitExceeded,
			IPAddress: clientIP,
			Details:   map[string]any{"endpoint": r.URL.Path},
		})
	}

	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecondsForRate(h.server.RateLimiter.Rate())))
	http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
	return true
}

// buildAuthServerMetadata returns the metadata served at both
// /.well-known/oauth-authorization-server (RFC 8414) and
// /.well-known/openid-configuration (OIDC Discovery 1.0 §3).
func (h *Handler) buildAuthServerMetadata() map[string]any {
	metadata := map[string]any{
		"issuer":                                h.server.Config.Issuer,
		"authorization_endpoint":                h.server.Config.AuthorizationEndpoint(),
		"token_endpoint":                        h.server.Config.TokenEndpoint(),
		"response_types_supported":              DefaultResponseTypes,
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{PKCEMethodS256},
		"token_endpoint_auth_methods_supported": SupportedTokenAuthMethods,
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
// The handler reuses the discovery rate limiter so a hot loop against
// /.well-known/jwks.json cannot starve the rest of the server. Cache-Control
// is set to one hour: keys rotate manually (operator changes
// AccessTokenSigningKeyID and restarts), and verifiers caching for an hour
// is the conventional middle ground between churn and freshness.
func (h *Handler) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP := h.clientIP(r)
	if h.checkDiscoveryRateLimit(w, r, clientIP) {
		return
	}

	if !h.server.Config.IsJWTAccessTokenFormat() {
		http.NotFound(w, r)
		return
	}

	jwks, err := h.server.PublicJWKS()
	if err != nil {
		h.logger.Error("Failed to build JWKS for discovery endpoint",
			"error", err,
			"ip", clientIP)
		http.Error(w, "JWKS unavailable", http.StatusInternalServerError)
		return
	}
	if jwks == nil || len(jwks.Keys) == 0 {
		http.NotFound(w, r)
		return
	}

	h.setCORSHeaders(w, r)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		h.logger.Warn("Failed to encode JWKS response", "error", err)
	}
}

// ServeAuthorization handles OAuth authorization requests
func (h *Handler) ServeAuthorization(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.authorization")
	defer endSpan()

	if r.Method != http.MethodGet {
		h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	if _, ok := h.gateIPRateLimit(w, r, span, endpointAuthorize, http.MethodGet, startTime); !ok {
		return
	}

	// Parse query parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	resource := r.URL.Query().Get("resource") // RFC 8707: Target resource server identifier
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	responseType := r.URL.Query().Get("response_type")

	// Extract OIDC parameters for upstream IdP forwarding
	authOpts, err := parseOIDCOptions(r.URL.Query())
	if err != nil {
		h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "invalid OIDC parameter")
		h.writeError(w, ErrorCodeInvalidRequest, err.Error(), http.StatusBadRequest)
		return
	}

	if clientID == "" {
		h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "client_id missing")
		h.writeError(w, ErrorCodeInvalidRequest, "client_id is required", http.StatusBadRequest)
		return
	}

	// RFC 6749 §4.1.2.1 + §3.1.2.4: redirect_uri must be registered for the
	// client before any error branch may redirect to it. The canonical URI
	// returned is the redirect target.
	canonicalRedirectURI, err := h.server.ValidateRedirectURIForAuthorization(r.Context(), clientID, redirectURI)
	if err != nil {
		h.logger.Info("Authorization request rejected: invalid client or redirect_uri", "client_id", clientID, "error", err)
		h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "invalid client or redirect_uri")
		h.writeError(w, ErrorCodeInvalidRequest, err.Error(), http.StatusBadRequest)
		return
	}

	maxStateLength := h.server.Config.MaxStateLength
	if len(state) > maxStateLength {
		h.logger.Warn("Authorization request rejected: state parameter too long", "state_length", len(state), "max_allowed", maxStateLength, "client_id", clientID)
		h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "state too long")
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at most %d characters", maxStateLength), http.StatusBadRequest)
		return
	}

	if rejection := h.checkAuthorizationStateParam(state, clientID); rejection != nil {
		h.respondAuthorizationError(w, r, span, startTime, authorizationError{
			redirectURI: canonicalRedirectURI,
			state:       state,
			code:        ErrorCodeInvalidRequest,
			description: rejection.description,
			spanError:   rejection.spanError,
		})
		return
	}

	if !slices.Contains(DefaultResponseTypes, responseType) {
		h.logger.Info("Authorization request rejected: unsupported response_type", "response_type", responseType, "client_id", clientID)
		h.respondAuthorizationError(w, r, span, startTime, authorizationError{
			redirectURI: canonicalRedirectURI,
			state:       state,
			code:        ErrorCodeUnsupportedResponseType,
			description: fmt.Sprintf("response_type must be one of [%s]", strings.Join(DefaultResponseTypes, ", ")),
			spanError:   "unsupported response_type",
		})
		return
	}

	// Add attributes to span
	instrumentation.SetSpanAttributes(
		span,
		attribute.String(instrumentation.AttrClientID, clientID),
		attribute.String(instrumentation.AttrPKCEMethod, codeChallengeMethod),
		attribute.String(instrumentation.AttrResponseType, responseType),
		attribute.String(instrumentation.AttrScope, scope),
	)

	// Start authorization flow with client state (server also validates for defense in depth)
	authURL, err := h.server.StartAuthorizationFlow(r.Context(), clientID, redirectURI, scope, resource, codeChallenge, codeChallengeMethod, state, authOpts)
	if err != nil {
		h.logger.Error("Failed to start authorization flow", "error", err)
		instrumentation.RecordError(span, err)
		h.respondAuthorizationError(w, r, span, startTime, authorizationError{
			redirectURI: canonicalRedirectURI,
			state:       state,
			code:        ErrorCodeServerError,
			description: "Failed to start authorization flow",
			spanError:   "authorization flow failed",
		})
		return
	}

	// Record authorization started metric
	h.recordAuthorizationStarted(r.Context(), clientID)

	h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusFound, startTime)
	instrumentation.SetSpanSuccess(span)

	// Parse and validate scheme before redirecting. authURL is built by the
	// configured provider's AuthorizationURL(); the parse + scheme check is
	// defense in depth against a misconfigured provider returning a non-HTTP URL.
	parsedAuthURL, err := url.Parse(authURL)
	if err != nil || (parsedAuthURL.Scheme != "https" && parsedAuthURL.Scheme != "http") {
		h.logger.Error("Provider returned invalid authorization URL", "error", err)
		h.respondAuthorizationError(w, r, span, startTime, authorizationError{
			redirectURI: canonicalRedirectURI,
			state:       state,
			code:        ErrorCodeServerError,
			description: "Failed to start authorization flow",
			spanError:   "invalid authorization URL",
		})
		return
	}
	// #nosec G710 -- authURL is built by the configured provider's
	// AuthorizationURL() (server-controlled host) and re-validated above to be
	// http/https. Not user-controllable; not an open redirect.
	http.Redirect(w, r, parsedAuthURL.String(), http.StatusFound)
}

// ServeCallback handles the OAuth provider callback
func (h *Handler) ServeCallback(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.callback")
	defer endSpan()

	if r.Method != http.MethodGet {
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusMethodNotAllowed, startTime)
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
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed(r.Context(), "", false)
		instrumentation.SetSpanError(span, errorParam)
		h.writeError(w, errorParam, errorDesc, http.StatusBadRequest)
		return
	}

	// CRITICAL SECURITY: Validate state and code parameters
	// Input validation at HTTP layer to return proper status codes.
	// The state here is the server-generated provider state (not the client state).
	// It is always generated by generateRandomToken() (43 chars), so both presence
	// and minimum length are enforced unconditionally -- AllowNoStateParameter only
	// controls the client-facing state in the authorization request.
	if state == "" || code == "" {
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed(r.Context(), "", false)
		instrumentation.SetSpanError(span, "missing state or code")
		h.writeError(w, ErrorCodeInvalidRequest, "state and code are required", http.StatusBadRequest)
		return
	}
	minStateLength := h.server.Config.MinStateLength
	maxStateLength := h.server.Config.MaxStateLength
	if len(state) < minStateLength {
		h.logger.Warn("Callback rejected: provider state too short", "state_length", len(state), "min_required", minStateLength)
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed(r.Context(), "", false)
		instrumentation.SetSpanError(span, "state too short")
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at least %d characters for security", minStateLength), http.StatusBadRequest)
		return
	}
	if len(state) > maxStateLength {
		h.logger.Warn("Callback rejected: provider state too long", "state_length", len(state), "max_allowed", maxStateLength)
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed(r.Context(), "", false)
		instrumentation.SetSpanError(span, "state too long")
		h.writeError(w, ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at most %d characters", maxStateLength), http.StatusBadRequest)
		return
	}

	// Handle callback (state here is the provider state, not client state)
	// Server also validates state length for defense in depth
	authCode, clientState, err := h.server.HandleProviderCallback(r.Context(), state, code)
	if err != nil {
		h.logger.Error("Failed to handle callback", "error", err)
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusInternalServerError, startTime)
		h.recordCallbackProcessed(r.Context(), "", false)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "callback handling failed")
		h.writeError(w, ErrorCodeServerError, "Authorization failed", http.StatusInternalServerError)
		return
	}

	// Record successful callback
	h.recordCallbackProcessed(r.Context(), authCode.ClientID, true)
	instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, authCode.ClientID))
	instrumentation.SetSpanSuccess(span)

	// CRITICAL SECURITY: Redirect back to client with their original state parameter
	// for CSRF protection. RFC 9207: include `iss` so clients talking to multiple
	// authorization servers can detect mix-up attacks. authCode.RedirectURI was
	// allowlist-validated against client.RedirectURIs at authorization time and
	// re-validated by ValidateRedirectURIAtAuthorizationTime; we parse it here to
	// build the response URL through url.Values rather than string concatenation.
	parsedRedirect, err := url.Parse(authCode.RedirectURI)
	if err != nil {
		h.logger.Error("Stored redirect URI failed to parse", "error", err, "client_id", authCode.ClientID)
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusInternalServerError, startTime)
		instrumentation.SetSpanError(span, "invalid stored redirect URI")
		h.writeError(w, ErrorCodeServerError, "Authorization failed", http.StatusInternalServerError)
		return
	}
	q := parsedRedirect.Query()
	q.Set("code", authCode.Code)
	q.Set("state", clientState)
	q.Set("iss", h.server.Config.Issuer)
	parsedRedirect.RawQuery = q.Encode()
	redirectURL := parsedRedirect.String()

	// RFC 8252 Section 7.1: Custom URL schemes require special handling
	// Browsers may fail silently on 302 redirects to custom schemes (cursor://, vscode://, etc.)
	// Serve an HTML interstitial page that shows success and attempts JS redirect with manual fallback
	if isCustomURLScheme(authCode.RedirectURI) {
		h.logger.Debug("Serving success interstitial for custom URL scheme",
			"client_id", authCode.ClientID,
			"scheme", parsedRedirect.Scheme)
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusOK, startTime)
		h.serveSuccessInterstitial(w, r, redirectURL)
		return
	}

	// Standard HTTP/HTTPS redirects work reliably
	h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusFound, startTime)
	// #nosec G710 -- redirectURL is built from authCode.RedirectURI, which was
	// allowlist-validated against client.RedirectURIs and re-validated by
	// ValidateRedirectURIAtAuthorizationTime when the authorization state was
	// persisted. Not an open redirect.
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ServeToken handles the OAuth token endpoint
func (h *Handler) ServeToken(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token")
	defer endSpan()

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics(r.Context(), endpointToken, r.Method, http.StatusMethodNotAllowed, startTime)
		instrumentation.SetSpanError(span, "method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointToken, http.MethodPost, startTime)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config.MaxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		if isMaxBytesError(err) {
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusRequestEntityTooLarge, startTime)
			h.writeError(w, ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	grantType := r.Form.Get("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r, clientIP)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r, clientIP)
	default:
		h.recordTokenFailure(r.Context(), grantType, ErrorCodeUnsupportedGrantType)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "unsupported grant_type")
		h.writeError(w, ErrorCodeUnsupportedGrantType, fmt.Sprintf("Grant type %s not supported", grantType), http.StatusBadRequest)
	}
}

// recordTokenFailure records a token-endpoint failure metric labelled by
// grant_type + RFC 6749 error_code. Unknown grant_types are coerced to
// "unknown" to bound label cardinality (a malformed client request with
// grant_type=<random> would otherwise mint a fresh series per probe).
func (h *Handler) recordTokenFailure(ctx context.Context, grantType, errorCode string) {
	switch grantType {
	case "authorization_code", "refresh_token", "client_credentials", "password":
	default:
		grantType = "unknown"
	}
	h.server.Instrumentation.Metrics().RecordTokenEndpointFailure(ctx, grantType, errorCode)
}

func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, clientIP string) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token_exchange")
	defer endSpan()

	// Read from already-parsed form (ParseForm called by ServeToken)
	code := r.Form.Get("code")
	clientID := r.Form.Get("client_id")
	redirectURI := r.Form.Get("redirect_uri")
	resource := r.Form.Get("resource") // RFC 8707: Target resource server identifier
	codeVerifier := r.Form.Get("code_verifier")

	if code == "" {
		h.recordTokenFailure(r.Context(), "authorization_code", ErrorCodeInvalidRequest)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "code missing")
		h.writeError(w, ErrorCodeInvalidRequest, "Required parameter 'code' missing", http.StatusBadRequest)
		return
	}

	// Authenticate client
	client, err := h.authenticateClient(r, clientID, clientIP)
	if err != nil {
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "client authentication failed")
		// authenticateClient returns *Error; read its Status before recording
		// the HTTP metric so a 400 (client_id mismatch) is not mis-labelled as
		// 401 (unauthorized) in dashboards.
		if oauthErr, ok := err.(*Error); ok {
			h.recordTokenFailure(r.Context(), "authorization_code", oauthErr.Code)
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, oauthErr.Status, startTime)
			h.writeError(w, oauthErr.Code, oauthErr.Description, oauthErr.Status)
		} else {
			h.recordTokenFailure(r.Context(), "authorization_code", ErrorCodeInvalidClient)
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusUnauthorized, startTime)
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		}
		return
	}

	// Post-auth rate limit, keyed by client_id. Confidential-only: public
	// clients have no secret to compromise, and rate-limiting by a public
	// client_id is attacker-controllable. Public clients stay bounded by
	// the IP limit.
	if client.ClientType == ClientTypeConfidential && h.checkUserRateLimit(w, r, client.ClientID, clientIP) {
		h.recordRateLimitReject(r.Context(), span, endpointToken, http.MethodPost, startTime)
		return
	}

	// Add span attributes
	instrumentation.SetSpanAttributes(
		span,
		attribute.String(instrumentation.AttrClientID, client.ClientID),
		attribute.String(instrumentation.AttrClientType, client.ClientType),
		attribute.String(instrumentation.AttrGrantType, "authorization_code"),
	)

	// Exchange authorization code for tokens
	tokenResponse, scope, err := h.server.ExchangeAuthorizationCode(r.Context(), code, client.ClientID, redirectURI, resource, codeVerifier)
	if err != nil {
		h.logger.Error("Failed to exchange authorization code", "client_id", client.ClientID, "ip", clientIP, "error", err)
		h.recordTokenFailure(r.Context(), "authorization_code", ErrorCodeInvalidGrant)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "code exchange failed")
		// SECURITY: Don't leak internal error details to client
		// Audit logging is done in ExchangeAuthorizationCode
		h.writeError(w, ErrorCodeInvalidGrant, "Authorization code is invalid or expired", http.StatusBadRequest)
		return
	}

	h.logger.Debug("Token exchange successful", "client_id", client.ClientID, "ip", clientIP)

	// Record code exchanged metric
	pkceMethod := ""
	if codeVerifier != "" {
		pkceMethod = PKCEMethodS256
	}
	h.recordCodeExchanged(r.Context(), client.ClientID, pkceMethod)

	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, scope)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, clientIP string) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token_refresh")
	defer endSpan()

	// Read from already-parsed form (ParseForm called by ServeToken)
	refreshToken := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")

	if refreshToken == "" {
		h.recordTokenFailure(r.Context(), "refresh_token", ErrorCodeInvalidRequest)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "refresh_token missing")
		h.writeError(w, ErrorCodeInvalidRequest, "refresh_token is required", http.StatusBadRequest)
		return
	}

	// OAUTH 2.1 SECURITY: Authenticate client for refresh token grant
	// Confidential clients MUST authenticate; public clients may use client_id only
	clientID, clientAuthenticated, err := h.authenticateRefreshTokenClient(r.Context(), w, r, clientID, clientIP, startTime, span)
	if err != nil {
		// Error already written to response by authenticateRefreshTokenClient
		return
	}

	instrumentation.SetSpanAttributes(
		span,
		attribute.String(instrumentation.AttrClientID, clientID),
		attribute.String(instrumentation.AttrGrantType, "refresh_token"),
	)
	if clientAuthenticated {
		instrumentation.SetSpanAttributes(span, attribute.Bool("oauth.client_authenticated", true))

		// Post-auth rate limit for confidential clients, keyed by client_id.
		// Public clients have no authentication step, only an IP-rate bound.
		if h.checkUserRateLimit(w, r, clientID, clientIP) {
			h.recordRateLimitReject(r.Context(), span, endpointToken, http.MethodPost, startTime)
			return
		}
	}

	// Refresh token
	tokenResponse, err := h.server.RefreshAccessToken(r.Context(), refreshToken, clientID)
	if err != nil {
		h.logger.Error("Failed to refresh token", "client_id", clientID, "ip", clientIP, "error", err)
		h.recordTokenFailure(r.Context(), "refresh_token", ErrorCodeInvalidGrant)
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "token refresh failed")
		// SECURITY: Don't leak internal error details to client
		// Audit logging is already done in RefreshAccessToken
		h.writeError(w, ErrorCodeInvalidGrant, "Refresh token is invalid or expired", http.StatusBadRequest)
		return
	}

	// Record token refreshed metric (check if it was rotated)
	rotated := h.server.Config.AllowRefreshTokenRotation
	h.recordTokenRefreshed(r.Context(), clientID, rotated)

	h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return tokens
	h.writeTokenResponse(w, tokenResponse, "")
}

// authenticateRefreshTokenClient authenticates the client for refresh token grant.
// Per OAuth 2.1 Section 6, confidential clients MUST authenticate on refresh.
// Returns (clientID, clientAuthenticated, error).
// If error is returned, the HTTP response has already been written.
func (h *Handler) authenticateRefreshTokenClient(ctx context.Context, w http.ResponseWriter, r *http.Request, clientID, clientIP string, startTime time.Time, span trace.Span) (string, bool, error) {
	basicClientID, basicClientSecret := h.parseBasicAuth(r)

	if h.rejectBasicFormClientIDMismatch(w, r, basicClientID, clientID, clientIP, endpointToken, "refresh_token", span, startTime) {
		return "", false, fmt.Errorf("client_id mismatch between Basic Authorization header and form parameter")
	}

	// Case 1: Basic Auth credentials provided - validate them
	if basicClientID != "" {
		clientID = basicClientID
		if err := h.server.ValidateClientCredentials(ctx, clientID, basicClientSecret); err != nil {
			h.logger.Warn("Client authentication failed", "client_id", clientID, "ip", clientIP, "error", err)
			if h.server.Auditor != nil {
				h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, "refresh_client_authentication_failed")
			}
			h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusUnauthorized, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "client authentication failed")
			h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
			return "", false, err
		}
		return clientID, true, nil
	}

	// Case 2: No Basic Auth - check if client_id was provided
	if clientID == "" {
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "client_id missing")
		h.writeError(w, ErrorCodeInvalidRequest, "client_id is required", http.StatusBadRequest)
		return "", false, fmt.Errorf("client_id required")
	}

	// Case 3: client_id provided but no credentials - check if client is confidential
	client, err := h.server.GetClient(ctx, clientID)
	if err != nil {
		h.logger.Warn("Unknown client for refresh", "client_id", clientID, "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, "refresh_unknown_client")
		}
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusUnauthorized, startTime)
		instrumentation.SetSpanError(span, "unknown client")
		h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		return "", false, err
	}

	// OAUTH 2.1 SECURITY: Confidential clients MUST authenticate
	if client.ClientType == ClientTypeConfidential {
		h.logger.Warn("Confidential client attempted refresh without authentication",
			"client_id", clientID, "ip", clientIP,
			"security_event", "confidential_client_missing_auth",
			"oauth_spec", "OAuth 2.1 Section 6")
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, "confidential_client_refresh_missing_auth")
			h.server.Auditor.LogEvent(ctx, security.Event{
				Type:     security.EventAuthFailure,
				ClientID: clientID,
				Details: map[string]any{
					"severity":     "high",
					"client_type":  "confidential",
					"auth_missing": true,
					"endpoint":     "refresh_token",
					"ip":           clientIP,
					"oauth_spec":   "OAuth 2.1 Section 6",
				},
			})
		}
		h.recordHTTPMetrics(r.Context(), endpointToken, http.MethodPost, http.StatusUnauthorized, startTime)
		instrumentation.SetSpanError(span, "confidential client requires authentication")
		h.writeError(w, ErrorCodeInvalidClient, "Client authentication required", http.StatusUnauthorized)
		return "", false, fmt.Errorf("confidential client requires authentication")
	}

	// Public client - authentication not required but client_id validated
	return clientID, false, nil
}

// authenticateRevocationClient resolves the client for /revoke. It enforces
// the RFC 6749 §2.3.1 Basic / form client_id agreement, validates Basic-Auth
// credentials when supplied, and returns (resolvedClientID, authenticated, ok).
// ok=false means the HTTP response has already been written; the caller must
// return immediately. RFC 7009 allows unauthenticated revocation for public
// clients, so a missing Basic header is not itself an error.
func (h *Handler) authenticateRevocationClient(w http.ResponseWriter, r *http.Request, formClientID, clientIP string, startTime time.Time, span trace.Span) (string, bool, bool) {
	basicClientID, basicClientSecret := h.parseBasicAuth(r)

	if h.rejectBasicFormClientIDMismatch(w, r, basicClientID, formClientID, clientIP, endpointRevoke, "", span, startTime) {
		return "", false, false
	}

	if basicClientID == "" {
		return formClientID, false, true
	}

	if err := h.server.ValidateClientCredentials(r.Context(), basicClientID, basicClientSecret); err != nil {
		h.logger.Warn("Client authentication failed for revocation", "client_id", basicClientID, "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure(r.Context(), "", basicClientID, clientIP, "revocation_auth_failed")
		}
		h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusUnauthorized, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "client authentication failed")
		h.writeError(w, ErrorCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)
		return "", false, false
	}
	return basicClientID, true, true
}

// ServeTokenRevocation handles the RFC 7009 token revocation endpoint
func (h *Handler) ServeTokenRevocation(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.token_revocation")
	defer endSpan()

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers for browser-based clients
	h.setCORSHeaders(w, r)

	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointRevoke, http.MethodPost, startTime)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config.MaxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		if isMaxBytesError(err) {
			h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusRequestEntityTooLarge, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "request body too large")
			h.writeError(w, ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "parse form failed")
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.Form.Get("token")
	clientID := r.Form.Get("client_id")

	if token == "" {
		h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "token missing")
		h.writeError(w, ErrorCodeInvalidRequest, "token is required", http.StatusBadRequest)
		return
	}

	resolvedClientID, clientAuthenticated, ok := h.authenticateRevocationClient(w, r, clientID, clientIP, startTime, span)
	if !ok {
		return
	}
	clientID = resolvedClientID

	instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, clientID))

	// Post-auth rate limit for authenticated clients, keyed by client_id.
	if clientAuthenticated && h.checkUserRateLimit(w, r, clientID, clientIP) {
		h.recordRateLimitReject(r.Context(), span, endpointRevoke, http.MethodPost, startTime)
		return
	}

	// Revoke token
	if err := h.server.RevokeToken(r.Context(), token, clientID, clientIP); err != nil {
		h.logger.Error("Failed to revoke token", "client_id", clientID, "ip", clientIP, "error", err)
		instrumentation.RecordError(span, err)
		// Per RFC 7009, don't fail the request even if revocation failed
	}
	// Per RFC 7009, return 200 even if revocation fails

	// Record token revoked metric
	h.recordTokenRevoked(r.Context(), clientID)

	h.recordHTTPMetrics(r.Context(), endpointRevoke, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)

	// Return success (per RFC 7009)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.WriteHeader(http.StatusOK)
}

// ServeClientRegistration handles dynamic client registration (RFC 7591)
func (h *Handler) ServeClientRegistration(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.client_registration")
	defer endSpan()

	if r.Method != http.MethodPost {
		h.recordHTTPMetrics(r.Context(), endpointRegister, http.MethodPost, http.StatusMethodNotAllowed, startTime)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.setCORSHeaders(w, r)
	clientIP := h.clientIP(r)

	if h.checkClientRegistrationRateLimit(r.Context(), w, clientIP, startTime) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config.MaxRequestBodySize)

	req, err := h.parseAndValidateRegistrationRequest(w, r, clientIP)
	if err != nil {
		if isMaxBytesError(err) {
			h.recordHTTPMetrics(r.Context(), endpointRegister, http.MethodPost, http.StatusRequestEntityTooLarge, startTime)
			instrumentation.RecordError(span, err)
			instrumentation.SetSpanError(span, "request body too large")
		}
		return
	}

	auth, authorized := h.authorizeClientRegistration(w, r, req, clientIP)
	if !authorized {
		return
	}

	if !h.validatePublicClientRegistration(r.Context(), w, req, clientIP, auth, startTime, span) {
		return
	}

	h.recordTrustedAllowlistSpan(span, auth)

	maxClients := h.getMaxClientsPerIP()
	client, clientSecret, err := h.server.RegisterClient(r.Context(), req.ClientName, req.ClientType, req.TokenEndpointAuthMethod, req.RedirectURIs, req.Scopes, clientIP, maxClients)
	if err != nil {
		h.handleRegistrationError(r.Context(), w, err, clientIP, startTime, span)
		return
	}

	h.recordClientRegistered(r.Context(), client.ClientType)
	h.auditTrustedAllowlistRegistration(r.Context(), auth, client, clientIP)
	h.recordHTTPMetrics(r.Context(), endpointRegister, http.MethodPost, http.StatusCreated, startTime)
	h.setRegistrationSpanSuccess(span, client)
	h.writeRegistrationResponse(w, client, clientSecret)
}

// startHandlerSpan opens a span for the request, attaches it to r.Context()
// (so downstream code reading r.Context() picks up the span), and returns
// the updated request, the span (nil when tracing is disabled), and a
// cleanup func that is always safe to defer.
func (h *Handler) startHandlerSpan(r *http.Request, name string) (*http.Request, trace.Span, func()) {
	if h.tracer == nil {
		return r, nil, func() {}
	}
	ctx, span := h.tracer.Start(r.Context(), name)
	return r.WithContext(ctx), span, func() { span.End() }
}

// parseAndValidateRegistrationRequest parses the request and validates auth method.
func (h *Handler) parseAndValidateRegistrationRequest(w http.ResponseWriter, r *http.Request, clientIP string) (*clientRegistrationRequest, error) {
	var req clientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if isMaxBytesError(err) {
			h.writeError(w, ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return nil, err
		}
		h.writeError(w, ErrorCodeInvalidRequest, "Invalid JSON", http.StatusBadRequest)
		return nil, err
	}

	// Validate client_name to prevent potential stored XSS and log injection (defense-in-depth)
	if err := helpers.ValidateClientName(req.ClientName); err != nil {
		h.logger.Warn("Invalid client_name in registration request",
			"client_name_length", len(req.ClientName), "error", err, "ip", clientIP)
		h.writeError(w, ErrorCodeInvalidRequest, err.Error(), http.StatusBadRequest)
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

// recordTrustedAllowlistSpan records the allowlist gate used in the span, if any.
func (h *Handler) recordTrustedAllowlistSpan(span trace.Span, auth registrationAuthResult) {
	if span == nil || !auth.viaTrustedAllowlist {
		return
	}
	switch auth.gate {
	case registrationAuthGateTrustedScheme:
		instrumentation.SetSpanAttributes(
			span,
			attribute.String("oauth.registration_method", auth.gate),
			attribute.String("oauth.trusted_scheme", auth.matched),
		)
	case registrationAuthGateTrustedRedirectURI:
		instrumentation.SetSpanAttributes(
			span,
			attribute.String("oauth.registration_method", auth.gate),
			attribute.String("oauth.trusted_redirect_uri", auth.matched),
		)
	default:
		h.logger.Warn("Skipping span attrs for unknown registration auth gate", "gate", auth.gate)
	}
}

// handleRegistrationError handles client registration errors.
func (h *Handler) handleRegistrationError(ctx context.Context, w http.ResponseWriter, err error, clientIP string, startTime time.Time, span trace.Span) {
	if strings.Contains(err.Error(), "registration limit") {
		h.logger.Warn("Client registration limit exceeded", "ip", clientIP, "error", err)
		h.recordHTTPMetrics(ctx, endpointRegister, http.MethodPost, http.StatusTooManyRequests, startTime)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "registration limit exceeded")
		h.writeError(w, ErrorCodeInvalidRequest, "Client registration limit exceeded", http.StatusTooManyRequests)
		return
	}

	h.logger.Error("Failed to register client", "ip", clientIP, "error", err)
	h.recordHTTPMetrics(ctx, endpointRegister, http.MethodPost, http.StatusInternalServerError, startTime)
	instrumentation.RecordError(span, err)
	instrumentation.SetSpanError(span, "registration failed")
	h.writeError(w, ErrorCodeServerError, "Failed to register client", http.StatusInternalServerError)
}

// auditTrustedAllowlistRegistration logs unauthenticated DCR via either trusted
// allowlist (scheme or HTTPS redirect URI) for security monitoring.
func (h *Handler) auditTrustedAllowlistRegistration(ctx context.Context, auth registrationAuthResult, client *storage.Client, clientIP string) {
	if !auth.viaTrustedAllowlist || h.server.Auditor == nil {
		return
	}

	details := map[string]any{
		"client_type":   client.ClientType,
		"client_ip":     clientIP,
		"redirect_uris": client.RedirectURIs,
	}

	var eventType string
	switch auth.gate {
	case registrationAuthGateTrustedScheme:
		eventType = security.EventClientRegisteredViaTrustedScheme
		details["scheme"] = auth.matched
		details["strict_matching"] = !h.server.Config.DisableStrictSchemeMatching
		details["security_context"] = "unauthenticated_registration_via_trusted_scheme"
	case registrationAuthGateTrustedRedirectURI:
		eventType = security.EventClientRegisteredViaTrustedRedirectURI
		details["redirect_uri"] = auth.matched
		details["security_context"] = "unauthenticated_registration_via_trusted_redirect_uri"
	default:
		h.logger.Warn("Skipping audit for unknown registration auth gate",
			"gate", auth.gate, "client_id", client.ClientID, "client_ip", clientIP)
		return
	}

	h.server.Auditor.LogEvent(ctx, security.Event{
		Type:     eventType,
		ClientID: client.ClientID,
		Details:  details,
	})
}

// setRegistrationSpanSuccess sets success attributes on the span.
func (h *Handler) setRegistrationSpanSuccess(span trace.Span, client *storage.Client) {
	instrumentation.SetSpanAttributes(
		span,
		attribute.String(instrumentation.AttrClientID, client.ClientID),
		attribute.String(instrumentation.AttrClientType, client.ClientType),
	)
	instrumentation.SetSpanSuccess(span)
}

// writeRegistrationResponse writes the client registration response per
// RFC 7591 §3.2.1. `client_id_issued_at` is always present; for confidential
// clients the response also carries `client_secret` plus
// `client_secret_expires_at: 0` (the spec sentinel for "never expires").
func (h *Handler) writeRegistrationResponse(w http.ResponseWriter, client *storage.Client, clientSecret string) {
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	response := map[string]any{
		"client_id":                  client.ClientID,
		"client_id_issued_at":        client.CreatedAt.Unix(),
		"client_name":                client.ClientName,
		"client_type":                client.ClientType,
		"redirect_uris":              client.RedirectURIs,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
	}

	if clientSecret != "" {
		response["client_secret"] = clientSecret
		response["client_secret_expires_at"] = 0
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(response)
}

// Helper methods

// parseBasicAuth returns the Basic Authorization credentials when the header
// is well-formed. A malformed Basic header (missing `Basic ` prefix, undecodable
// payload, missing colon) returns empty strings so the caller routes the
// request to the unauthenticated path rather than treating garbage as a
// silent client_id.
func (h *Handler) parseBasicAuth(r *http.Request) (username, password string) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", ""
	}
	return username, password
}

// rejectBasicFormClientIDMismatch enforces RFC 6749 §2.3.1: when both a Basic
// Authorization header and a form `client_id` are supplied they MUST identify
// the same client. On mismatch the response is written (400 invalid_client),
// the audit event is emitted, and the HTTP metric / span are recorded — the
// caller returns immediately on a true result. tokenFailureGrant is non-empty
// for /token-grant sites so the per-grant failure counter increments alongside
// the HTTP counter; /revoke and /introspect pass "".
func (h *Handler) rejectBasicFormClientIDMismatch(
	w http.ResponseWriter,
	r *http.Request,
	basicClientID, formClientID, clientIP, endpoint, tokenFailureGrant string,
	span trace.Span,
	startTime time.Time,
) bool {
	if basicClientID == "" || formClientID == "" || basicClientID == formClientID {
		return false
	}
	h.logger.Warn("client_id mismatch between Basic Authorization header and form parameter",
		"basic_client_id", basicClientID, "form_client_id", formClientID, "ip", clientIP, "endpoint", endpoint)
	if h.server.Auditor != nil {
		// Audit pins the Basic-Auth value: that is the authenticated identity
		// the request claimed, and forensics care about who tried to authenticate
		// rather than the form value the attacker may have synthesised.
		h.server.Auditor.LogAuthFailure(r.Context(), "", basicClientID, clientIP, "client_id_mismatch_basic_vs_form")
	}
	if tokenFailureGrant != "" {
		h.recordTokenFailure(r.Context(), tokenFailureGrant, ErrorCodeInvalidClient)
	}
	h.recordHTTPMetrics(r.Context(), endpoint, http.MethodPost, http.StatusBadRequest, startTime)
	instrumentation.SetSpanError(span, "client_id mismatch basic vs form")
	h.writeError(w, ErrorCodeInvalidClient, "client_id in Basic Authorization header does not match form parameter", http.StatusBadRequest)
	return true
}

// authenticateClient validates client credentials from either Basic Auth or form parameters
// Returns the validated client or an error with the OAuth error code
func (h *Handler) authenticateClient(r *http.Request, clientID, clientIP string) (*storage.Client, error) {
	basicClientID, basicClientSecret := h.parseBasicAuth(r)
	formClientID := clientID

	// RFC 6749 §2.3.1: if both Basic Auth and form client_id are supplied,
	// they MUST identify the same client.
	if basicClientID != "" && formClientID != "" && basicClientID != formClientID {
		h.logAuthFailure(r.Context(), basicClientID, clientIP, "client_id_mismatch_basic_vs_form", "client_id in Basic Authorization header does not match form parameter")
		return nil, NewError(ErrorCodeInvalidClient, "client_id in Basic Authorization header does not match form parameter", http.StatusBadRequest)
	}

	authClientSecret := basicClientSecret
	if basicClientID != "" {
		clientID = basicClientID
	}

	if clientID == "" {
		return nil, ErrInvalidRequest("client_id is required")
	}

	client, err := h.server.GetClient(r.Context(), clientID)
	if err != nil {
		h.logAuthFailure(r.Context(), clientID, clientIP, ErrorCodeInvalidClient, "Unknown client")
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
		h.logAuthFailure(ctx, client.ClientID, clientIP, "confidential_client_auth_required", "Confidential client missing credentials")
		return ErrInvalidClient("Client authentication required")
	}

	if err := h.server.ValidateClientCredentials(ctx, client.ClientID, secret); err != nil {
		h.logAuthFailure(ctx, client.ClientID, clientIP, "client_authentication_failed", "Client authentication failed")
		return ErrInvalidClient("Client authentication failed")
	}

	return nil
}

// logAuthFailure logs authentication failures with optional auditing.
func (h *Handler) logAuthFailure(ctx context.Context, clientID, clientIP, reason, message string) {
	h.logger.Warn(message, "client_id", clientID, "ip", clientIP)
	if h.server.Auditor != nil {
		h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, reason)
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

	// OIDC Compliance: Include id_token in response if present
	// Per OpenID Connect Core 1.0 Section 3.1.3.3, the id_token is REQUIRED
	// in token responses for OIDC flows. This enables clients to use
	// id_token_hint and login_hint for silent re-authentication.
	if idToken := server.ExtractIDToken(token); idToken != "" {
		response["id_token"] = idToken
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

// authorizationError carries the OAuth error fields for an RFC 6749 §4.1.2.1
// error returned by the /authorize endpoint. redirectURI is the canonical
// allowlisted target from ValidateRedirectURIForAuthorization. spanError is
// the short reason recorded on the tracing span.
type authorizationError struct {
	redirectURI *url.URL
	state       string
	code        string
	description string
	spanError   string
}

// respondAuthorizationError redirects (302) to redirectURI with
// error / error_description / state per RFC 6749 §4.1.2.1. When redirectURI
// is nil or uses a custom scheme admitted by Config.AllowedCustomSchemes
// (RFC 8252 native apps), it falls back to JSON 400 because the spec only
// requires redirect for http(s) targets.
func (h *Handler) respondAuthorizationError(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, e authorizationError) {
	instrumentation.SetSpanError(span, e.spanError)
	instrumentation.SetSpanAttributes(
		span,
		attribute.String(instrumentation.AttrError, e.code),
		attribute.String(instrumentation.AttrErrorDescription, e.description),
	)

	if e.redirectURI == nil || (e.redirectURI.Scheme != "https" && e.redirectURI.Scheme != "http") {
		h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusBadRequest, startTime)
		h.writeError(w, e.code, e.description, http.StatusBadRequest)
		return
	}

	redirect := *e.redirectURI
	q := redirect.Query()
	q.Set("error", e.code)
	q.Set("error_description", e.description)
	if e.state != "" {
		q.Set("state", e.state)
	}
	redirect.RawQuery = q.Encode()

	h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusFound, startTime)
	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// authorizationStateRejection describes a state-parameter failure suitable
// for the /authorize redirect error response.
type authorizationStateRejection struct {
	description string
	spanError   string
}

// checkAuthorizationStateParam enforces the CSRF state-parameter rule at the
// HTTP layer. Returns nil when state is acceptable (or when
// AllowNoStateParameter is set for clients that cannot send state).
func (h *Handler) checkAuthorizationStateParam(state, clientID string) *authorizationStateRejection {
	if h.server.Config.AllowNoStateParameter {
		return nil
	}
	if state == "" {
		h.logger.Info("Authorization request rejected: state parameter missing", "client_id", clientID)
		return &authorizationStateRejection{
			description: "state parameter is required for CSRF protection",
			spanError:   "state missing",
		}
	}
	minStateLength := h.server.Config.MinStateLength
	if len(state) < minStateLength {
		h.logger.Warn("Authorization request rejected: state parameter too short", "state_length", len(state), "min_required", minStateLength, "client_id", clientID)
		return &authorizationStateRejection{
			description: fmt.Sprintf("state parameter must be at least %d characters for security", minStateLength),
			spanError:   "state too short",
		}
	}
	return nil
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
	startTime := time.Now()

	r, span, endSpan := h.startHandlerSpan(r, "oauth.http.introspection")
	defer endSpan()

	if r.Method != http.MethodPost {
		instrumentation.SetSpanError(span, "method not allowed")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.setCORSHeaders(w, r)
	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointIntrospect, http.MethodPost, startTime)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.server.Config.MaxRequestBodySize)
	if err := r.ParseForm(); err != nil {
		if isMaxBytesError(err) {
			instrumentation.SetSpanError(span, "request body too large")
			h.recordHTTPMetrics(r.Context(), endpointIntrospect, http.MethodPost, http.StatusRequestEntityTooLarge, startTime)
			h.writeError(w, ErrorCodeInvalidRequest, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		instrumentation.SetSpanError(span, "failed to parse request")
		h.recordHTTPMetrics(r.Context(), endpointIntrospect, http.MethodPost, http.StatusBadRequest, startTime)
		h.writeError(w, ErrorCodeInvalidRequest, "Failed to parse request", http.StatusBadRequest)
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		instrumentation.SetSpanError(span, "token parameter missing")
		h.writeError(w, ErrorCodeInvalidRequest, "token parameter is required", http.StatusBadRequest)
		return
	}

	tokenType := r.Form.Get("token_type_hint")
	if tokenType != "" && span != nil {
		instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrTokenType, tokenType))
	}

	// RFC 6749 §2.3.1: enforce Basic / form client_id agreement before the
	// per-endpoint authenticate function runs, so /introspect cannot become a
	// silent-override bypass for the same rule the token / refresh / revoke
	// paths enforce.
	basicClientID, _ := h.parseBasicAuth(r)
	if h.rejectBasicFormClientIDMismatch(w, r, basicClientID, r.Form.Get("client_id"), clientIP, endpointIntrospect, "", span, startTime) {
		return
	}

	clientID, err := h.authenticateIntrospectionClient(r, clientIP)
	if err != nil {
		instrumentation.SetSpanError(span, "client authentication failed")
		h.writeError(w, ErrorCodeInvalidClient, err.Error(), http.StatusUnauthorized)
		return
	}

	if span != nil {
		instrumentation.SetSpanAttributes(span, attribute.String(instrumentation.AttrClientID, clientID))
	}

	response := h.server.IntrospectToken(r.Context(), token, clientID)
	if active, _ := response["active"].(bool); !active {
		h.logger.Debug("Token introspection inactive", "ip", clientIP, "client_id", clientID)
	}

	security.SetSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
	h.recordHTTPMetrics(r.Context(), endpointIntrospect, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
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
				h.server.Auditor.LogAuthFailure(ctx, "", authClientID, clientIP, "introspection_auth_failed")
			}
			return "", fmt.Errorf("client authentication failed")
		}
		return authClientID, nil
	}

	// No Basic Auth - check for client_id in form (but we still reject without credentials)
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		h.logger.Warn("Token introspection rejected: missing client authentication", "ip", clientIP)
		if h.server.Auditor != nil {
			h.server.Auditor.LogAuthFailure(ctx, "", "", clientIP, "introspection_missing_auth")
		}
		return "", fmt.Errorf("client authentication required for token introspection")
	}

	h.logger.Warn("Token introspection rejected: client_id without credentials", "client_id", clientID, "ip", clientIP)
	if h.server.Auditor != nil {
		h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, "introspection_missing_credentials")
	}
	return "", fmt.Errorf("client authentication required for token introspection")
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

	if h.server.Auditor != nil {
		h.server.Auditor.LogAuthFailure(r.Context(), userInfo.ID, "", clientIP, "insufficient_scope")
	}

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

// recordHTTPMetrics records an HTTP request metric.
func (h *Handler) recordHTTPMetrics(ctx context.Context, endpoint, method string, status int, startTime time.Time) {
	duration := time.Since(startTime).Seconds() * 1000
	h.server.Instrumentation.Metrics().RecordHTTPRequest(ctx, method, endpoint, status, duration)
}

// recordAuthorizationStarted records when an authorization flow is started.
func (h *Handler) recordAuthorizationStarted(ctx context.Context, clientID string) {
	h.server.Instrumentation.Metrics().RecordAuthorizationStarted(ctx, clientID)
}

// recordCallbackProcessed records when a callback is processed.
func (h *Handler) recordCallbackProcessed(ctx context.Context, clientID string, success bool) {
	h.server.Instrumentation.Metrics().RecordCallbackProcessed(ctx, clientID, success)
}

// recordCodeExchanged records when an authorization code is exchanged.
func (h *Handler) recordCodeExchanged(ctx context.Context, clientID, pkceMethod string) {
	h.server.Instrumentation.Metrics().RecordCodeExchange(ctx, clientID, pkceMethod)
}

// recordTokenRefreshed records when a token is refreshed.
func (h *Handler) recordTokenRefreshed(ctx context.Context, clientID string, rotated bool) {
	h.server.Instrumentation.Metrics().RecordTokenRefresh(ctx, clientID, rotated)
}

// recordTokenRevoked records when a token is revoked.
func (h *Handler) recordTokenRevoked(ctx context.Context, clientID string) {
	h.server.Instrumentation.Metrics().RecordTokenRevocation(ctx, clientID)
}

// recordClientRegistered records when a client is registered.
func (h *Handler) recordClientRegistered(ctx context.Context, clientType string) {
	h.server.Instrumentation.Metrics().RecordClientRegistration(ctx, clientType)
}

// validPromptValues defines the allowed values for the OIDC prompt parameter.
// Per OpenID Connect Core 1.0 Section 3.1.2.1, valid values are:
// - "none": No UI displayed (silent auth)
// - "login": Force re-authentication
// - "consent": Force consent screen
// - "select_account": Force account selection
//
// Multiple values can be space-separated (e.g., "login consent").
// Empty string is valid (no prompt parameter).
var validPromptValues = map[string]bool{
	"none":           true,
	"login":          true,
	"consent":        true,
	"select_account": true,
}

// validatePrompt validates the prompt parameter value.
// Returns the validated prompt string (may be truncated) or empty string if invalid.
// Multiple space-separated values are supported per OIDC spec.
func validatePrompt(prompt string) string {
	if prompt == "" {
		return ""
	}

	// Enforce length limit first (defense against DoS)
	if len(prompt) > MaxPromptLength {
		return "" // Reject oversized prompt values
	}

	// Validate each space-separated value
	parts := strings.Fields(prompt)
	if len(parts) == 0 {
		return ""
	}
	for _, part := range parts {
		if !validPromptValues[part] {
			// Unknown prompt value - reject entire prompt for security
			// (could be injection attempt or typo; let IdP handle defaults)
			return ""
		}
	}

	normalized := strings.Join(parts, " ")
	if len(normalized) > MaxPromptLength {
		return ""
	}

	return normalized
}

// parseOIDCOptions extracts and validates OIDC parameters from the query string
// for upstream IdP forwarding. Returns nil when no valid parameters are present.
// Oversized values for non-nonce params are silently dropped. Oversized nonce
// is a hard rejection because the parameter is a security primitive — silent
// truncation would either skip enforcement or persist a value the client did
// not actually send.
func parseOIDCOptions(query url.Values) (*providers.AuthorizationURLOptions, error) {
	prompt := validatePrompt(query.Get("prompt"))
	loginHint := dropIfOversize(query.Get("login_hint"), MaxLoginHintLength)
	idTokenHint := dropIfOversize(query.Get("id_token_hint"), MaxIDTokenHintLength)
	acrValues := dropIfOversize(query.Get("acr_values"), MaxACRValuesLength)
	maxAge := parseMaxAgeQueryValue(query.Get("max_age"))
	nonce := query.Get("nonce")

	if len(nonce) > MaxNonceLength {
		return nil, fmt.Errorf("nonce parameter exceeds %d characters", MaxNonceLength)
	}

	if prompt == "" && loginHint == "" && idTokenHint == "" && maxAge == nil && acrValues == "" && nonce == "" {
		return nil, nil
	}

	return &providers.AuthorizationURLOptions{
		Prompt:      prompt,
		LoginHint:   loginHint,
		IDTokenHint: idTokenHint,
		MaxAge:      maxAge,
		ACRValues:   acrValues,
		Nonce:       nonce,
	}, nil
}

// dropIfOversize returns the empty string when v exceeds maxLen — used for
// OIDC parameters whose silent omission is preferable to truncation.
func dropIfOversize(v string, maxLen int) string {
	if len(v) > maxLen {
		return ""
	}
	return v
}

// parseMaxAgeQueryValue parses the OIDC max_age parameter to *int. Returns nil
// for missing, oversized, non-numeric, negative, or out-of-range values.
func parseMaxAgeQueryValue(raw string) *int {
	if raw == "" || len(raw) > MaxMaxAgeLength {
		return nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 || v > MaxMaxAgeSeconds {
		return nil
	}
	return &v
}

// isMaxBytesError reports whether err was caused by the request body
// exceeding the http.MaxBytesReader limit.
func isMaxBytesError(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}
