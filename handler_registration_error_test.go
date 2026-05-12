package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestHandleRegistrationError pins the two response shapes that
// handleRegistrationError emits: 429 for registration-limit errors,
// 500 for everything else. Coverage gap noted on the umbrella.
func TestHandleRegistrationError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "registration limit triggers 429 invalid_request",
			err:        errors.New("client registration limit exceeded for IP 192.0.2.1"),
			wantStatus: http.StatusTooManyRequests,
			wantCode:   ErrorCodeInvalidRequest,
		},
		{
			name:       "generic error triggers 500 server_error",
			err:        errors.New("backend storage unavailable"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   ErrorCodeServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()

			w := httptest.NewRecorder()
			span := noop.Span{}

			handler.handleRegistrationError(context.Background(), w, tt.err, "192.0.2.1", time.Now(), span)

			require.Equal(t, tt.wantStatus, w.Code)
			var body map[string]string
			require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
			require.Equal(t, tt.wantCode, body["error"])
		})
	}
}
