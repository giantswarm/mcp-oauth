package oauth

import (
	"net/http"
	"testing"
)

func TestOAuthError_Error(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		description string
		want        string
	}{
		{
			name:        "simple error",
			code:        "invalid_request",
			description: "Missing required parameter",
			want:        "invalid_request: Missing required parameter",
		},
		{
			name:        "error with empty description",
			code:        "server_error",
			description: "",
			want:        "server_error: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &OAuthError{
				Code:        tt.code,
				Description: tt.description,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("OAuthError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewOAuthError(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		description string
		status      int
	}{
		{
			name:        "bad request",
			code:        ErrorCodeInvalidRequest,
			description: "Test error",
			status:      http.StatusBadRequest,
		},
		{
			name:        "unauthorized",
			code:        ErrorCodeInvalidClient,
			description: "Client authentication failed",
			status:      http.StatusUnauthorized,
		},
		{
			name:        "internal server error",
			code:        ErrorCodeServerError,
			description: "Something went wrong",
			status:      http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewOAuthError(tt.code, tt.description, tt.status)
			if err.Code != tt.code {
				t.Errorf("Code = %q, want %q", err.Code, tt.code)
			}
			if err.Description != tt.description {
				t.Errorf("Description = %q, want %q", err.Description, tt.description)
			}
			if err.Status != tt.status {
				t.Errorf("Status = %d, want %d", err.Status, tt.status)
			}
		})
	}
}

func TestErrorConstants(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected string
	}{
		{"invalid_request", ErrorCodeInvalidRequest, "invalid_request"},
		{"invalid_grant", ErrorCodeInvalidGrant, "invalid_grant"},
		{"invalid_client", ErrorCodeInvalidClient, "invalid_client"},
		{"invalid_scope", ErrorCodeInvalidScope, "invalid_scope"},
		{"invalid_token", ErrorCodeInvalidToken, "invalid_token"},
		{"unauthorized_client", ErrorCodeUnauthorizedClient, "unauthorized_client"},
		{"unsupported_grant_type", ErrorCodeUnsupportedGrantType, "unsupported_grant_type"},
		{"server_error", ErrorCodeServerError, "server_error"},
		{"access_denied", ErrorCodeAccessDenied, "access_denied"},
		{"invalid_redirect_uri", ErrorCodeInvalidRedirectURI, "invalid_redirect_uri"},
		{"rate_limit_exceeded", ErrorCodeRateLimitExceeded, "rate_limit_exceeded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.expected {
				t.Errorf("constant %s = %q, want %q", tt.name, tt.code, tt.expected)
			}
		})
	}
}

func TestErrorConstructors(t *testing.T) {
	tests := []struct {
		name           string
		constructor    func(string) *OAuthError
		expectedCode   string
		expectedStatus int
	}{
		{
			name:           "ErrInvalidRequest",
			constructor:    ErrInvalidRequest,
			expectedCode:   ErrorCodeInvalidRequest,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrInvalidGrant",
			constructor:    ErrInvalidGrant,
			expectedCode:   ErrorCodeInvalidGrant,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrInvalidClient",
			constructor:    ErrInvalidClient,
			expectedCode:   ErrorCodeInvalidClient,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "ErrInvalidScope",
			constructor:    ErrInvalidScope,
			expectedCode:   ErrorCodeInvalidScope,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrInvalidToken",
			constructor:    ErrInvalidToken,
			expectedCode:   ErrorCodeInvalidToken,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "ErrUnauthorizedClient",
			constructor:    ErrUnauthorizedClient,
			expectedCode:   ErrorCodeUnauthorizedClient,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrUnsupportedGrantType",
			constructor:    ErrUnsupportedGrantType,
			expectedCode:   ErrorCodeUnsupportedGrantType,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrServerError",
			constructor:    ErrServerError,
			expectedCode:   ErrorCodeServerError,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "ErrAccessDenied",
			constructor:    ErrAccessDenied,
			expectedCode:   ErrorCodeAccessDenied,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "ErrInvalidRedirectURI",
			constructor:    ErrInvalidRedirectURI,
			expectedCode:   ErrorCodeInvalidRedirectURI,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc := "test description"
			err := tt.constructor(desc)
			if err.Code != tt.expectedCode {
				t.Errorf("Code = %q, want %q", err.Code, tt.expectedCode)
			}
			if err.Description != desc {
				t.Errorf("Description = %q, want %q", err.Description, desc)
			}
			if err.Status != tt.expectedStatus {
				t.Errorf("Status = %d, want %d", err.Status, tt.expectedStatus)
			}
		})
	}
}
