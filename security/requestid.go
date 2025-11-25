package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
)

// requestIDContextKey is the context key for storing request IDs
type requestIDContextKey struct{}

// RequestIDHeader is the HTTP header for request IDs
const RequestIDHeader = "X-Request-ID"

// requestIDPattern validates request IDs to prevent header injection attacks.
// Allows: alphanumeric, hyphens, underscores (1-128 chars).
// This prevents malicious payloads while accepting common request ID formats
// from upstream proxies (AWS, GCP, Cloudflare, etc.).
var requestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// GenerateRequestID generates a cryptographically secure random request ID.
// It uses crypto/rand to generate 16 bytes (128 bits) of entropy and
// encodes them as a 22-character base64url string without padding.
//
// Request IDs are used for audit trails, security correlation, and debugging.
// The function panics if the system's random number generator fails,
// which indicates a critical system-level security failure.
func GenerateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// CRITICAL: System RNG failure - cannot generate secure request IDs
		// This should never happen in normal operation
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		return requestID
	}
	return ""
}

// isValidRequestID validates a request ID to prevent header injection attacks.
// Returns true if the request ID contains only safe characters (alphanumeric, hyphens, underscores)
// and is within acceptable length limits (1-128 characters).
//
// Security considerations:
//   - Prevents newline injection (CRLF) attacks in HTTP headers
//   - Prevents excessively long IDs that could cause DoS via memory exhaustion
//   - Accepts standard formats from common proxies (AWS ALB, GCP Load Balancer, Cloudflare, etc.)
func isValidRequestID(requestID string) bool {
	return requestIDPattern.MatchString(requestID)
}

// RequestIDMiddleware is HTTP middleware that generates and propagates request IDs.
//
// Security behavior:
//   - Preserves valid request IDs from upstream proxies for audit trail continuity
//   - Validates upstream IDs to prevent header injection attacks (CRLF, DoS)
//   - Generates new cryptographically secure ID if upstream ID is missing or invalid
//   - Adds request ID to response headers for end-to-end correlation
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request already has an ID from upstream proxy
		requestID := r.Header.Get(RequestIDHeader)

		// Validate upstream request ID for security
		if requestID == "" || !isValidRequestID(requestID) {
			// Generate new request ID if missing or invalid
			requestID = GenerateRequestID()
		}

		// Add to response headers for correlation
		w.Header().Set(RequestIDHeader, requestID)

		// Add to context for use by handlers
		ctx := WithRequestID(r.Context(), requestID)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
