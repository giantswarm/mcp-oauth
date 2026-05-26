package handler

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

const (
	defaultCORSMaxAge        = 3600 // 1 hour default for preflight cache
	tokenTypeBearer          = "Bearer"
	defaultRetryAfterSeconds = 60 // Retry-After fallback for limiters with no defined rate/window
)

// Endpoint labels for `oauth_http_requests_total{endpoint="..."}` etc.
// Future renames are breaking changes for downstream dashboards.
const (
	endpointAuthorize        = "authorize"
	endpointCallback         = "callback"
	endpointToken            = "token"
	endpointRevoke           = "revoke"
	endpointIntrospect       = "introspect"
	endpointRegister         = "register"
	endpointValidateToken    = "validate_token"
	endpointUserInfo         = "userinfo"
	endpointDiscovery        = "discovery"
	endpointJWKS             = "jwks"
	endpointClientManagement = "client_management"
)

// Handler is a thin HTTP adapter for the OAuth Server.
// It handles HTTP requests and delegates to the Server for business logic.
type Handler struct {
	server *server.Server
	logger *slog.Logger
	tracer trace.Tracer // OpenTelemetry tracer for HTTP layer
}

// NewHandler creates a new HTTP handler
func New(server *server.Server, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}

	h := &Handler{
		server: server,
		logger: logger,
	}

	h.tracer = server.Instrumentation.Tracer("http")

	return h
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

	// OIDC UserInfo (OIDC Core 1.0 §5.3) is opt-in. The handler runs behind
	// ValidateToken so bearer authentication, scope/audience checks, and
	// rate limiting all apply.
	if h.server.Config.EnableUserInfoEndpoint {
		mux.Handle(server.EndpointPathUserInfo, h.ValidateToken(http.HandlerFunc(h.ServeUserInfo)))
	}

	// RFC 7592 client management is opt-in. The trailing slash registers all
	// /oauth/register/{client_id} sub-paths via net/http prefix matching.
	if h.server.Config.EnableClientManagementEndpoint {
		mux.HandleFunc(server.EndpointPathClientManagement, h.ServeClientManagement)
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

func (h *Handler) failRequest(w http.ResponseWriter, r *http.Request, span trace.Span, endpoint, method string, status int, code, description string, startTime time.Time) {
	instrumentation.SetSpanError(span, description)
	h.recordHTTPMetrics(r.Context(), endpoint, method, status, startTime)
	h.writeError(w, code, description, status)
}

// logAuthFailure logs authentication failures with optional auditing.
func (h *Handler) logAuthFailure(ctx context.Context, clientID, clientIP, reason, message string) {
	h.logger.Warn(message, "client_id", clientID, "ip", clientIP)
	h.server.Auditor.LogAuthFailure(ctx, "", clientID, clientIP, reason)
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

// dropIfOversize returns the empty string when v exceeds maxLen — used for
// OIDC parameters whose silent omission is preferable to truncation.
func dropIfOversize(v string, maxLen int) string {
	if len(v) > maxLen {
		return ""
	}
	return v
}

// isMaxBytesError reports whether err was caused by the request body
// exceeding the http.MaxBytesReader limit.
func isMaxBytesError(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}
