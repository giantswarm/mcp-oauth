package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// requestIDContextKey is the context key for storing request IDs
type requestIDContextKey struct{}

// RequestIDHeader is the HTTP header for request IDs
const RequestIDHeader = "X-Request-ID"

// GenerateRequestID generates a unique request ID
func GenerateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to empty string if crypto/rand fails
		return ""
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

// RequestIDMiddleware is HTTP middleware that generates and propagates request IDs
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request already has an ID from upstream proxy
		requestID := r.Header.Get(RequestIDHeader)
		if requestID == "" {
			// Generate new request ID
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
