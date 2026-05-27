package handler

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

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
	if scheme == oauth.SchemeHTTP || scheme == oauth.SchemeHTTPS {
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
		h.writeError(w, oauth.ErrorCodeInvalidRequest, err.Error(), http.StatusBadRequest)
		return
	}

	if clientID == "" {
		h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "client_id missing")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, "client_id is required", http.StatusBadRequest)
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
		h.writeError(w, oauth.ErrorCodeInvalidRequest, err.Error(), http.StatusBadRequest)
		return
	}

	// State-too-long is handled inline rather than via checkAuthorizationStateParam:
	// an oversized state cannot be safely echoed back in a redirect URL, so the
	// response stays a direct 400 instead of a redirect with `error=invalid_request`.
	maxStateLength := h.server.Config.MaxStateLength
	if len(state) > maxStateLength {
		h.logger.Warn("Authorization request rejected: state parameter too long", "state_length", len(state), "max_allowed", maxStateLength, "client_id", clientID)
		h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusBadRequest, startTime)
		instrumentation.SetSpanError(span, "state too long")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at most %d characters", maxStateLength), http.StatusBadRequest)
		return
	}

	if rejection := h.checkAuthorizationStateParam(state, clientID); rejection != nil {
		h.respondAuthorizationError(w, r, span, startTime, authorizationError{
			redirectURI: canonicalRedirectURI,
			state:       state,
			code:        oauth.ErrorCodeInvalidRequest,
			description: rejection.description,
			spanError:   rejection.spanError,
		})
		return
	}

	if !slices.Contains(oauth.DefaultResponseTypes, responseType) {
		h.logger.Info("Authorization request rejected: unsupported response_type", "response_type", responseType, "client_id", clientID)
		h.respondAuthorizationError(w, r, span, startTime, authorizationError{
			redirectURI: canonicalRedirectURI,
			state:       state,
			code:        oauth.ErrorCodeUnsupportedResponseType,
			description: fmt.Sprintf("response_type must be one of [%s]", strings.Join(oauth.DefaultResponseTypes, ", ")),
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

	authURL, err := h.server.StartAuthorizationFlow(r.Context(), clientID, canonicalRedirectURI, scope, resource, codeChallenge, codeChallengeMethod, state, authOpts)
	if err != nil {
		h.logger.Error("Failed to start authorization flow", "error", err)
		instrumentation.RecordError(span, err)
		h.respondAuthorizationError(w, r, span, startTime, authorizationError{
			redirectURI: canonicalRedirectURI,
			state:       state,
			code:        oauth.ErrorCodeServerError,
			description: "Failed to start authorization flow",
			spanError:   "authorization flow failed",
		})
		return
	}

	// Record authorization started metric
	h.recordAuthorizationStarted(r.Context(), clientID)

	// Parse and validate scheme before redirecting. authURL is built by the
	// configured provider's AuthorizationURL(); the parse + scheme check is
	// defense in depth against a misconfigured provider returning a non-HTTP URL.
	parsedAuthURL, err := url.Parse(authURL)
	if err != nil || (parsedAuthURL.Scheme != oauth.SchemeHTTPS && parsedAuthURL.Scheme != oauth.SchemeHTTP) {
		h.logger.Error("Provider returned invalid authorization URL", "error", err)
		h.respondAuthorizationError(w, r, span, startTime, authorizationError{
			redirectURI: canonicalRedirectURI,
			state:       state,
			code:        oauth.ErrorCodeServerError,
			description: "Failed to start authorization flow",
			spanError:   "invalid authorization URL",
		})
		return
	}

	h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusFound, startTime)
	instrumentation.SetSpanSuccess(span)

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

	clientIP, ok := h.gateIPRateLimit(w, r, span, endpointCallback, http.MethodGet, startTime)
	if !ok {
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
		h.logger.Warn("Provider returned error", "ip", clientIP, "error", errorParam, "description", errorDesc)
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
		h.writeError(w, oauth.ErrorCodeInvalidRequest, "state and code are required", http.StatusBadRequest)
		return
	}
	minStateLength := h.server.Config.MinStateLength
	maxStateLength := h.server.Config.MaxStateLength
	if len(state) < minStateLength {
		h.logger.Warn("Callback rejected: provider state too short", "ip", clientIP, "state_length", len(state), "min_required", minStateLength)
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed(r.Context(), "", false)
		instrumentation.SetSpanError(span, "state too short")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at least %d characters for security", minStateLength), http.StatusBadRequest)
		return
	}
	if len(state) > maxStateLength {
		h.logger.Warn("Callback rejected: provider state too long", "ip", clientIP, "state_length", len(state), "max_allowed", maxStateLength)
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusBadRequest, startTime)
		h.recordCallbackProcessed(r.Context(), "", false)
		instrumentation.SetSpanError(span, "state too long")
		h.writeError(w, oauth.ErrorCodeInvalidRequest, fmt.Sprintf("state parameter must be at most %d characters", maxStateLength), http.StatusBadRequest)
		return
	}

	// Handle callback (state here is the provider state, not client state)
	// Server also validates state length for defense in depth
	authCode, clientState, err := h.server.HandleProviderCallback(r.Context(), state, code)
	if err != nil {
		h.logger.Error("Failed to handle callback", "ip", clientIP, "error", err)
		h.recordHTTPMetrics(r.Context(), endpointCallback, http.MethodGet, http.StatusInternalServerError, startTime)
		h.recordCallbackProcessed(r.Context(), "", false)
		instrumentation.RecordError(span, err)
		instrumentation.SetSpanError(span, "callback handling failed")
		h.writeError(w, oauth.ErrorCodeServerError, "Authorization failed", http.StatusInternalServerError)
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
		h.logger.Error("Stored redirect URI failed to parse", "ip", clientIP, "error", err, "client_id", authCode.ClientID)
		h.failRequest(w, r, span, endpointCallback, http.MethodGet, http.StatusInternalServerError, oauth.ErrorCodeServerError, "Authorization failed", startTime)
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

	if e.redirectURI == nil || (e.redirectURI.Scheme != oauth.SchemeHTTPS && e.redirectURI.Scheme != oauth.SchemeHTTP) {
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

// recordAuthorizationStarted records when an authorization flow is started.
func (h *Handler) recordAuthorizationStarted(ctx context.Context, clientID string) {
	h.server.Instrumentation.Metrics().RecordAuthorizationStarted(ctx, clientID)
}

// recordCallbackProcessed records when a callback is processed.
func (h *Handler) recordCallbackProcessed(ctx context.Context, clientID string, success bool) {
	h.server.Instrumentation.Metrics().RecordCallbackProcessed(ctx, clientID, success)
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
	if len(prompt) > oauth.MaxPromptLength {
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
	if len(normalized) > oauth.MaxPromptLength {
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
	loginHint := dropIfOversize(query.Get("login_hint"), oauth.MaxLoginHintLength)
	idTokenHint := dropIfOversize(query.Get("id_token_hint"), oauth.MaxIDTokenHintLength)
	acrValues := dropIfOversize(query.Get("acr_values"), oauth.MaxACRValuesLength)
	maxAge := parseMaxAgeQueryValue(query.Get("max_age"))
	nonce := query.Get("nonce")

	if len(nonce) > oauth.MaxNonceLength {
		return nil, fmt.Errorf("nonce parameter exceeds %d characters", oauth.MaxNonceLength)
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

// parseMaxAgeQueryValue parses the OIDC max_age parameter to *int. Returns nil
// for missing, oversized, non-numeric, negative, or out-of-range values.
func parseMaxAgeQueryValue(raw string) *int {
	if raw == "" || len(raw) > oauth.MaxMaxAgeLength {
		return nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 0 || v > oauth.MaxMaxAgeSeconds {
		return nil
	}
	return &v
}
