package oauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/giantswarm/mcp-oauth/internal/constants"
)

// Error represents an OAuth 2.0 error response.
// This type implements the standard error interface and provides
// structured information about OAuth protocol errors.
type Error struct {
	Code        string // OAuth error code (e.g., "invalid_request", "invalid_grant")
	Description string // Human-readable error description
	Status      int    // HTTP status code
}

// Error implements the error interface
func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// NewError creates a new OAuth error with the specified code, description, and HTTP status.
func NewError(code, description string, status int) *Error {
	return &Error{
		Code:        code,
		Description: description,
		Status:      status,
	}
}

// OAuthError is an alias for Error, provided for backward compatibility.
//
// Deprecated: Use Error instead. This alias will be removed in a future major version.
//
//revive:disable:exported // Backward-compatible API aliases use stuttering names intentionally.
type OAuthError = Error

// NewOAuthError is an alias for NewError, provided for backward compatibility.
//
// Deprecated: Use NewError instead. This alias will be removed in a future major version.
var NewOAuthError = NewError

//revive:enable:exported

// Common OAuth errors as reusable instances
var (
	// ErrInvalidRequest indicates the request is malformed or missing required parameters
	ErrInvalidRequest = func(desc string) *Error {
		return NewError(constants.ErrorCodeInvalidRequest, desc, http.StatusBadRequest)
	}

	// ErrInvalidGrant indicates the authorization code or refresh token is invalid or expired
	ErrInvalidGrant = func(desc string) *Error {
		return NewError(constants.ErrorCodeInvalidGrant, desc, http.StatusBadRequest)
	}

	// ErrInvalidClient indicates client authentication failed
	ErrInvalidClient = func(desc string) *Error {
		return NewError(constants.ErrorCodeInvalidClient, desc, http.StatusUnauthorized)
	}

	// ErrInvalidScope indicates the requested scope is invalid or unsupported
	ErrInvalidScope = func(desc string) *Error {
		return NewError(constants.ErrorCodeInvalidScope, desc, http.StatusBadRequest)
	}

	// ErrInvalidToken indicates the access token is invalid or expired
	ErrInvalidToken = func(desc string) *Error {
		return NewError(constants.ErrorCodeInvalidToken, desc, http.StatusUnauthorized)
	}

	// ErrInsufficientScope indicates the access token lacks required scopes
	ErrInsufficientScope = func(desc string) *Error {
		return NewError(constants.ErrorCodeInsufficientScope, desc, http.StatusForbidden)
	}

	// ErrUnauthorizedClient indicates the client is not authorized for the requested grant type
	ErrUnauthorizedClient = func(desc string) *Error {
		return NewError(constants.ErrorCodeUnauthorizedClient, desc, http.StatusBadRequest)
	}

	// ErrUnsupportedGrantType indicates the grant type is not supported
	ErrUnsupportedGrantType = func(desc string) *Error {
		return NewError(constants.ErrorCodeUnsupportedGrantType, desc, http.StatusBadRequest)
	}

	// ErrServerError indicates an internal server error occurred
	ErrServerError = func(desc string) *Error {
		return NewError(constants.ErrorCodeServerError, desc, http.StatusInternalServerError)
	}

	// ErrAccessDenied indicates the user or authorization server denied the request
	ErrAccessDenied = func(desc string) *Error {
		return NewError(constants.ErrorCodeAccessDenied, desc, http.StatusForbidden)
	}

	// ErrInvalidRedirectURI indicates the redirect URI is invalid or not registered
	ErrInvalidRedirectURI = func(desc string) *Error {
		return NewError(constants.ErrorCodeInvalidRedirectURI, desc, http.StatusBadRequest)
	}
)

// ErrSilentAuthFailed is a sentinel error for when silent authentication is not possible.
// This occurs when the IdP requires user interaction (login or consent) but the
// authorization request used prompt=none for silent authentication.
//
// Use IsSilentAuthError to check if an error indicates silent auth failure.
var ErrSilentAuthFailed = errors.New("silent authentication failed: user interaction required")

// SilentAuthError represents an error from a silent authentication attempt.
// These errors indicate the IdP requires user interaction and the client
// should fall back to interactive login.
//
// Silent authentication fails when:
//   - No active session at the IdP (login_required)
//   - User hasn't granted required scopes (consent_required)
//   - IdP needs user interaction for other reasons (interaction_required)
//   - Multiple accounts and none selected (account_selection_required)
//
// See: https://openid.net/specs/openid-connect-core-1_0.html#AuthError
type SilentAuthError struct {
	// Code is the OAuth/OIDC error code.
	// Common values: "login_required", "consent_required", "interaction_required"
	Code string

	// Description is the optional error description from the IdP
	Description string
}

// Error implements the error interface.
func (e *SilentAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("silent authentication failed: %s - %s", e.Code, e.Description)
	}
	return fmt.Sprintf("silent authentication failed: %s", e.Code)
}

// IsSilentAuthError returns true if the error indicates silent authentication failed
// and interactive login is required. This checks for:
//   - *SilentAuthError type (including wrapped errors)
//   - Error strings containing known silent auth error codes
//
// Example usage:
//
//	result := handleCallback(r)
//	if err := result.Err(); err != nil {
//	    if oauth.IsSilentAuthError(err) {
//	        // Fall back to interactive login
//	        return startInteractiveLogin(w, r)
//	    }
//	    // Handle other errors
//	    return handleError(w, err)
//	}
func IsSilentAuthError(err error) bool {
	if err == nil {
		return false
	}

	// Check if error is or wraps a SilentAuthError
	var silentErr *SilentAuthError
	if errors.As(err, &silentErr) {
		return true
	}

	// Check if error is or wraps ErrSilentAuthFailed sentinel
	if errors.Is(err, ErrSilentAuthFailed) {
		return true
	}

	return false
}

// ParseOAuthError parses an OAuth error response and returns the appropriate error type.
// For silent auth failure codes (login_required, consent_required, interaction_required,
// account_selection_required), returns a *SilentAuthError.
// For other errors, returns a generic *Error with the code and description.
// Returns nil if errorCode is empty.
//
// Example usage:
//
//	err := oauth.ParseOAuthError(r.URL.Query().Get("error"), r.URL.Query().Get("error_description"))
//	if err != nil {
//	    if oauth.IsSilentAuthError(err) {
//	        // Handle silent auth failure
//	    }
//	}
func ParseOAuthError(errorCode, errorDescription string) error {
	if errorCode == "" {
		return nil
	}

	switch errorCode {
	case constants.ErrorCodeLoginRequired, constants.ErrorCodeConsentRequired, constants.ErrorCodeInteractionRequired, constants.ErrorCodeAccountSelectionRequired:
		return &SilentAuthError{Code: errorCode, Description: errorDescription}
	default:
		if errorDescription != "" {
			return fmt.Errorf("oauth error: %s - %s", errorCode, errorDescription)
		}
		return fmt.Errorf("oauth error: %s", errorCode)
	}
}
