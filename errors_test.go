package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestError_Error(t *testing.T) {
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
			e := &Error{
				Code:        tt.code,
				Description: tt.description,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("Error.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewError(t *testing.T) {
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
			err := NewError(tt.code, tt.description, tt.status)
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
		constructor    func(string) *Error
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

func TestSilentAuthError_Error(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		description string
		want        string
	}{
		{
			name:        "login_required with description",
			code:        ErrorCodeLoginRequired,
			description: "User must authenticate",
			want:        "silent authentication failed: login_required - User must authenticate",
		},
		{
			name:        "consent_required without description",
			code:        ErrorCodeConsentRequired,
			description: "",
			want:        "silent authentication failed: consent_required",
		},
		{
			name:        "interaction_required with description",
			code:        ErrorCodeInteractionRequired,
			description: "UI required",
			want:        "silent authentication failed: interaction_required - UI required",
		},
		{
			name:        "account_selection_required without description",
			code:        ErrorCodeAccountSelectionRequired,
			description: "",
			want:        "silent authentication failed: account_selection_required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &SilentAuthError{
				Code:        tt.code,
				Description: tt.description,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("SilentAuthError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsSilentAuthError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "login_required SilentAuthError",
			err:      &SilentAuthError{Code: ErrorCodeLoginRequired},
			expected: true,
		},
		{
			name:     "consent_required SilentAuthError",
			err:      &SilentAuthError{Code: ErrorCodeConsentRequired},
			expected: true,
		},
		{
			name:     "interaction_required SilentAuthError",
			err:      &SilentAuthError{Code: ErrorCodeInteractionRequired},
			expected: true,
		},
		{
			name:     "account_selection_required SilentAuthError",
			err:      &SilentAuthError{Code: ErrorCodeAccountSelectionRequired},
			expected: true,
		},
		{
			name:     "wrapped SilentAuthError",
			err:      fmt.Errorf("wrapped: %w", &SilentAuthError{Code: ErrorCodeLoginRequired}),
			expected: true,
		},
		{
			name:     "ErrSilentAuthFailed sentinel",
			err:      ErrSilentAuthFailed,
			expected: true,
		},
		{
			name:     "wrapped ErrSilentAuthFailed",
			err:      fmt.Errorf("wrapped: %w", ErrSilentAuthFailed),
			expected: true,
		},
		{
			name:     "other OAuth error - invalid_grant",
			err:      fmt.Errorf("oauth error: invalid_grant"),
			expected: false,
		},
		{
			name:     "generic error",
			err:      fmt.Errorf("something went wrong"),
			expected: false,
		},
		{
			name:     "error string containing login_required",
			err:      fmt.Errorf("error: login_required"),
			expected: true,
		},
		{
			name:     "error string containing consent_required",
			err:      fmt.Errorf("error: consent_required"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSilentAuthError(tt.err); got != tt.expected {
				t.Errorf("IsSilentAuthError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseOAuthError(t *testing.T) {
	tests := []struct {
		name             string
		errorCode        string
		errorDescription string
		wantNil          bool
		wantSilentAuth   bool
		wantMessage      string
	}{
		{
			name:             "empty error code returns nil",
			errorCode:        "",
			errorDescription: "",
			wantNil:          true,
		},
		{
			name:             "login_required returns SilentAuthError",
			errorCode:        ErrorCodeLoginRequired,
			errorDescription: "User must authenticate",
			wantSilentAuth:   true,
			wantMessage:      "silent authentication failed: login_required - User must authenticate",
		},
		{
			name:             "consent_required returns SilentAuthError",
			errorCode:        ErrorCodeConsentRequired,
			errorDescription: "",
			wantSilentAuth:   true,
			wantMessage:      "silent authentication failed: consent_required",
		},
		{
			name:             "interaction_required returns SilentAuthError",
			errorCode:        ErrorCodeInteractionRequired,
			errorDescription: "UI required",
			wantSilentAuth:   true,
			wantMessage:      "silent authentication failed: interaction_required - UI required",
		},
		{
			name:             "account_selection_required returns SilentAuthError",
			errorCode:        ErrorCodeAccountSelectionRequired,
			errorDescription: "",
			wantSilentAuth:   true,
			wantMessage:      "silent authentication failed: account_selection_required",
		},
		{
			name:             "invalid_grant returns generic error",
			errorCode:        ErrorCodeInvalidGrant,
			errorDescription: "Token expired",
			wantSilentAuth:   false,
			wantMessage:      "oauth error: invalid_grant - Token expired",
		},
		{
			name:             "access_denied returns generic error",
			errorCode:        ErrorCodeAccessDenied,
			errorDescription: "",
			wantSilentAuth:   false,
			wantMessage:      "oauth error: access_denied",
		},
		{
			name:             "unknown error code returns generic error",
			errorCode:        "unknown_error",
			errorDescription: "Something happened",
			wantSilentAuth:   false,
			wantMessage:      "oauth error: unknown_error - Something happened",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ParseOAuthError(tt.errorCode, tt.errorDescription)

			if tt.wantNil {
				if err != nil {
					t.Errorf("ParseOAuthError() = %v, want nil", err)
				}
				return
			}

			if err == nil {
				t.Fatal("ParseOAuthError() = nil, want error")
			}

			if err.Error() != tt.wantMessage {
				t.Errorf("ParseOAuthError().Error() = %q, want %q", err.Error(), tt.wantMessage)
			}

			if tt.wantSilentAuth {
				var silentErr *SilentAuthError
				if !errors.As(err, &silentErr) {
					t.Errorf("ParseOAuthError() should return *SilentAuthError")
				}
				if silentErr.Code != tt.errorCode {
					t.Errorf("SilentAuthError.Code = %q, want %q", silentErr.Code, tt.errorCode)
				}
				if !IsSilentAuthError(err) {
					t.Errorf("IsSilentAuthError() should return true for parsed error")
				}
			} else {
				var silentErr *SilentAuthError
				if errors.As(err, &silentErr) {
					t.Errorf("ParseOAuthError() should not return *SilentAuthError for %q", tt.errorCode)
				}
			}
		})
	}
}

func TestSilentAuthErrorConstants(t *testing.T) {
	// Verify the constants are correctly defined
	tests := []struct {
		name     string
		code     string
		expected string
	}{
		{"login_required", ErrorCodeLoginRequired, "login_required"},
		{"consent_required", ErrorCodeConsentRequired, "consent_required"},
		{"interaction_required", ErrorCodeInteractionRequired, "interaction_required"},
		{"account_selection_required", ErrorCodeAccountSelectionRequired, "account_selection_required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.expected {
				t.Errorf("constant %s = %q, want %q", tt.name, tt.code, tt.expected)
			}
		})
	}
}

func TestErrSilentAuthFailed(t *testing.T) {
	// Verify the sentinel error message
	expectedMsg := "silent authentication failed: user interaction required"
	if ErrSilentAuthFailed.Error() != expectedMsg {
		t.Errorf("ErrSilentAuthFailed.Error() = %q, want %q", ErrSilentAuthFailed.Error(), expectedMsg)
	}

	// Verify it's detected by IsSilentAuthError
	if !IsSilentAuthError(ErrSilentAuthFailed) {
		t.Error("IsSilentAuthError(ErrSilentAuthFailed) should return true")
	}

	// Verify wrapped sentinel is also detected
	wrapped := fmt.Errorf("auth failed: %w", ErrSilentAuthFailed)
	if !IsSilentAuthError(wrapped) {
		t.Error("IsSilentAuthError(wrapped ErrSilentAuthFailed) should return true")
	}

	// Verify errors.Is works
	if !errors.Is(wrapped, ErrSilentAuthFailed) {
		t.Error("errors.Is should find wrapped ErrSilentAuthFailed")
	}
}
