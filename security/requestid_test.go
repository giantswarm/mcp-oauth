package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateRequestID(t *testing.T) {
	// Test generation
	id1 := GenerateRequestID()
	if id1 == "" {
		t.Error("Expected non-empty request ID")
	}

	// Test uniqueness
	id2 := GenerateRequestID()
	if id1 == id2 {
		t.Error("Expected unique request IDs")
	}

	// Test length (16 bytes = 22 chars in base64url)
	if len(id1) != 22 {
		t.Errorf("Expected request ID length 22, got %d", len(id1))
	}
}

func TestRequestIDContext(t *testing.T) {
	ctx := context.Background()
	requestID := "test-request-id-123"

	// Test adding to context
	ctx = WithRequestID(ctx, requestID)

	// Test retrieving from context
	retrieved := GetRequestID(ctx)
	if retrieved != requestID {
		t.Errorf("Expected %s, got %s", requestID, retrieved)
	}

	// Test missing request ID
	emptyCtx := context.Background()
	empty := GetRequestID(emptyCtx)
	if empty != "" {
		t.Errorf("Expected empty string, got %s", empty)
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	tests := []struct {
		name           string
		existingHeader string
		expectNew      bool
	}{
		{
			name:           "generates new ID when not present",
			existingHeader: "",
			expectNew:      true,
		},
		{
			name:           "preserves existing ID from upstream",
			existingHeader: "upstream-request-id-xyz",
			expectNew:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedRequestID string
			var capturedContext context.Context

			// Create test handler that captures request ID
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedRequestID = GetRequestID(r.Context())
				capturedContext = r.Context()
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with middleware
			handler := RequestIDMiddleware(testHandler)

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.existingHeader != "" {
				req.Header.Set(RequestIDHeader, tt.existingHeader)
			}
			rec := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rec, req)

			// Verify response header is set
			responseID := rec.Header().Get(RequestIDHeader)
			if responseID == "" {
				t.Error("Expected X-Request-ID header in response")
			}

			// Verify context contains request ID
			if capturedRequestID == "" {
				t.Error("Expected request ID in context")
			}

			// Verify context was updated
			if capturedContext == nil {
				t.Error("Expected context to be set")
			}

			// Verify behavior based on test case
			if tt.expectNew {
				// Should generate new ID
				if capturedRequestID == tt.existingHeader {
					t.Error("Expected new request ID to be generated")
				}
				if len(capturedRequestID) != 22 {
					t.Errorf("Expected generated ID length 22, got %d", len(capturedRequestID))
				}
			} else {
				// Should preserve existing ID
				if capturedRequestID != tt.existingHeader {
					t.Errorf("Expected %s, got %s", tt.existingHeader, capturedRequestID)
				}
				if responseID != tt.existingHeader {
					t.Errorf("Expected response header %s, got %s", tt.existingHeader, responseID)
				}
			}
		})
	}
}

func TestRequestIDMiddlewareIntegration(t *testing.T) {
	// Test that request ID flows through multiple handlers
	var requestIDs []string

	handler1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestIDs = append(requestIDs, GetRequestID(r.Context()))
	})

	handler2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestIDs = append(requestIDs, GetRequestID(r.Context()))
	})

	// Wrap handlers
	wrappedHandler := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler1.ServeHTTP(w, r)
		handler2.ServeHTTP(w, r)
	}))

	// Execute request
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(rec, req)

	// Verify both handlers saw the same request ID
	if len(requestIDs) != 2 {
		t.Fatalf("Expected 2 request IDs, got %d", len(requestIDs))
	}
	if requestIDs[0] != requestIDs[1] {
		t.Errorf("Expected same request ID in both handlers: %s vs %s", requestIDs[0], requestIDs[1])
	}
	if requestIDs[0] == "" {
		t.Error("Expected non-empty request ID")
	}
}
