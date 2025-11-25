package instrumentation

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Common span attribute keys
//
// SECURITY WARNING: Never log actual sensitive values (access tokens, refresh tokens,
// authorization codes, client secrets, etc.) in traces or metrics. Only log metadata
// such as token types, expiry times, family IDs, and validation results.
//
// These constants define attribute key names for observability, not for logging
// sensitive credential values. Logging actual credentials would create critical
// security vulnerabilities as traces are often:
//   - Persisted for extended periods
//   - Accessible to wider audiences than production systems
//   - Replicated across monitoring infrastructure
//   - Subject to compliance requirements (GDPR, PCI-DSS, etc.)
const (
	// OAuth flow attributes - SAFE to use for metadata only
	AttrClientID         = "oauth.client_id"         // Client identifier (non-secret)
	AttrUserID           = "oauth.user_id"           // User identifier (non-secret)
	AttrScope            = "oauth.scope"             // Requested scopes
	AttrPKCEMethod       = "oauth.pkce.method"       // PKCE method used (S256, plain)
	AttrTokenFamilyID    = "oauth.token.family_id"   //nolint:gosec // Token family identifier for rotation tracking
	AttrTokenGeneration  = "oauth.token.generation"  //nolint:gosec // Token generation number
	AttrCodeReuse        = "oauth.code.reuse"        // Whether code reuse was detected (boolean)
	AttrTokenReuse       = "oauth.token.reuse"       //nolint:gosec // Whether token reuse was detected (boolean)
	AttrTokenRotated     = "oauth.token.rotated"     //nolint:gosec // Whether token was rotated (boolean)
	AttrGrantType        = "oauth.grant_type"        // OAuth grant type
	AttrResponseType     = "oauth.response_type"     // OAuth response type
	AttrClientType       = "oauth.client_type"       // Client type (public/confidential)
	AttrRedirectURI      = "oauth.redirect_uri"      // Redirect URI (may contain sensitive data)
	AttrState            = "oauth.state"             // OAuth state parameter
	AttrProviderState    = "oauth.provider_state"    // Provider-specific state
	AttrTokenType        = "oauth.token_type"        //nolint:gosec // Token type (Bearer, etc.) - NOT the actual token
	AttrExpiresIn        = "oauth.expires_in"        // Token expiry duration
	AttrError            = "oauth.error"             // Error code
	AttrErrorDescription = "oauth.error_description" // Error description

	// RESERVED - DO NOT USE: These are reserved for potential future metadata use only.
	// NEVER set these attributes to actual credential values.
	// Instead, use boolean flags like "token_present" or "code_validated".
	AttrAuthorizationCode = "oauth.authorization_code" // RESERVED - use "code_present" or "code_length" instead
	AttrAccessToken       = "oauth.access_token"       //nolint:gosec // RESERVED - use "token_type" or "token_present" instead
	AttrRefreshToken      = "oauth.refresh_token"      //nolint:gosec // RESERVED - use "refresh_present" or "refresh_rotated" instead

	// Storage attributes
	AttrStorageOperation = "storage.operation"
	AttrStorageResult    = "storage.result"
	AttrStorageType      = "storage.type"
	AttrStorageKey       = "storage.key"

	// Provider attributes
	AttrProviderName      = "provider.name"
	AttrProviderOperation = "provider.operation"
	AttrProviderStatus    = "provider.status"
	AttrProviderErrorType = "provider.error_type"

	// Security attributes
	AttrRateLimiterType     = "security.rate_limiter.type"
	AttrClientIP            = "security.client_ip"
	AttrAuditEventType      = "security.audit.event_type"
	AttrEncryptionOperation = "security.encryption.operation"

	// HTTP attributes (in addition to standard semantic conventions)
	AttrHTTPEndpoint     = "http.endpoint"
	AttrHTTPMethod       = "http.method"
	AttrHTTPStatusCode   = "http.status_code"
	AttrHTTPRequestSize  = "http.request.size"
	AttrHTTPResponseSize = "http.response.size"
)

// RecordError records an error on a span with proper status codes
func RecordError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// SetSpanSuccess marks a span as successful
func SetSpanSuccess(span trace.Span) {
	span.SetStatus(codes.Ok, "")
}

// AddOAuthFlowAttributes adds common OAuth flow attributes to a span
func AddOAuthFlowAttributes(span trace.Span, clientID, userID, scope string) {
	if clientID != "" {
		span.SetAttributes(attribute.String(AttrClientID, clientID))
	}
	if userID != "" {
		span.SetAttributes(attribute.String(AttrUserID, userID))
	}
	if scope != "" {
		span.SetAttributes(attribute.String(AttrScope, scope))
	}
}

// AddPKCEAttributes adds PKCE-related attributes to a span
func AddPKCEAttributes(span trace.Span, method string) {
	if method != "" {
		span.SetAttributes(attribute.String(AttrPKCEMethod, method))
	}
}

// AddTokenFamilyAttributes adds token family tracking attributes to a span
func AddTokenFamilyAttributes(span trace.Span, familyID string, generation int) {
	if familyID != "" {
		span.SetAttributes(
			attribute.String(AttrTokenFamilyID, familyID),
			attribute.Int(AttrTokenGeneration, generation),
		)
	}
}

// AddStorageAttributes adds storage operation attributes to a span
func AddStorageAttributes(span trace.Span, operation, storageType string) {
	span.SetAttributes(
		attribute.String(AttrStorageOperation, operation),
		attribute.String(AttrStorageType, storageType),
	)
}

// AddProviderAttributes adds provider attributes to a span
func AddProviderAttributes(span trace.Span, providerName, operation string) {
	span.SetAttributes(
		attribute.String(AttrProviderName, providerName),
		attribute.String(AttrProviderOperation, operation),
	)
}

// AddHTTPAttributes adds HTTP request attributes to a span
func AddHTTPAttributes(span trace.Span, method, endpoint string, statusCode int) {
	span.SetAttributes(
		attribute.String(AttrHTTPMethod, method),
		attribute.String(AttrHTTPEndpoint, endpoint),
		attribute.Int(AttrHTTPStatusCode, statusCode),
	)
}

// AddSecurityAttributes adds security-related attributes to a span
func AddSecurityAttributes(span trace.Span, clientIP string) {
	if clientIP != "" {
		span.SetAttributes(attribute.String(AttrClientIP, clientIP))
	}
}
