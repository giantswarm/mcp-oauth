package instrumentation

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Common span attribute keys
const (
	// OAuth flow attributes
	AttrClientID          = "oauth.client_id"
	AttrUserID            = "oauth.user_id"
	AttrScope             = "oauth.scope"
	AttrPKCEMethod        = "oauth.pkce.method"
	AttrTokenFamilyID     = "oauth.token.family_id"   //nolint:gosec // False positive: not a hardcoded credential
	AttrTokenGeneration   = "oauth.token.generation"  //nolint:gosec // False positive: not a hardcoded credential
	AttrCodeReuse         = "oauth.code.reuse"
	AttrTokenReuse        = "oauth.token.reuse"           //nolint:gosec // False positive: not a hardcoded credential
	AttrTokenRotated      = "oauth.token.rotated"         //nolint:gosec // False positive: not a hardcoded credential
	AttrGrantType         = "oauth.grant_type"
	AttrResponseType      = "oauth.response_type"
	AttrClientType        = "oauth.client_type"
	AttrRedirectURI       = "oauth.redirect_uri"
	AttrState             = "oauth.state"
	AttrProviderState     = "oauth.provider_state"
	AttrAuthorizationCode = "oauth.authorization_code"
	AttrAccessToken       = "oauth.access_token"          //nolint:gosec // False positive: not a hardcoded credential
	AttrRefreshToken      = "oauth.refresh_token"         //nolint:gosec // False positive: not a hardcoded credential
	AttrTokenType         = "oauth.token_type"            //nolint:gosec // False positive: not a hardcoded credential
	AttrExpiresIn         = "oauth.expires_in"
	AttrError             = "oauth.error"
	AttrErrorDescription  = "oauth.error_description"

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

// StartSpan is a helper for starting spans with common attributes
type StartSpan struct {
	tracer trace.Tracer
}

// NewStartSpan creates a new span starter
func NewStartSpan(tracer trace.Tracer) *StartSpan {
	return &StartSpan{tracer: tracer}
}

// Start starts a new span with the given name and attributes
func (s *StartSpan) Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return s.tracer.Start(ctx, spanName, opts...)
}

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
