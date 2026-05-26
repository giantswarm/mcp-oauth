package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/storage"
)

// TestHandleRegistrationError pins the two response shapes that
// handleRegistrationError emits: 429 for registration-limit errors,
// 500 for everything else.
func TestHandleRegistrationError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "registration limit triggers 429 invalid_request",
			err:        fmt.Errorf("%w: 192.0.2.1 (5/5)", storage.ErrClientIPLimitExceeded),
			wantStatus: http.StatusTooManyRequests,
			wantCode:   oauth.ErrorCodeInvalidRequest,
		},
		{
			name:       "generic error triggers 500 server_error",
			err:        errors.New("backend storage unavailable"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   oauth.ErrorCodeServerError,
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
