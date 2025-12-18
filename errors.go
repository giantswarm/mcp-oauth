package oauth

import (
	"fmt"
	"net/http"
)

// OAuth error codes as constants
const (
	ErrorCodeInvalidRequest       = "invalid_request"
	ErrorCodeInvalidGrant         = "invalid_grant"
	ErrorCodeInvalidClient        = "invalid_client"
	ErrorCodeInvalidScope         = "invalid_scope"
	ErrorCodeInvalidToken         = "invalid_token"
	ErrorCodeInsufficientScope    = "insufficient_scope"
	ErrorCodeUnauthorizedClient   = "unauthorized_client"
	ErrorCodeUnsupportedGrantType = "unsupported_grant_type"
	ErrorCodeServerError          = "server_error"
	ErrorCodeAccessDenied         = "access_denied"
	ErrorCodeInvalidRedirectURI   = "invalid_redirect_uri"
	ErrorCodeRateLimitExceeded    = "rate_limit_exceeded"
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
type OAuthError = Error

// NewOAuthError is an alias for NewError, provided for backward compatibility.
//
// Deprecated: Use NewError instead. This alias will be removed in a future major version.
var NewOAuthError = NewError

// Common OAuth errors as reusable instances
var (
	// ErrInvalidRequest indicates the request is malformed or missing required parameters
	ErrInvalidRequest = func(desc string) *Error {
		return NewError(ErrorCodeInvalidRequest, desc, http.StatusBadRequest)
	}

	// ErrInvalidGrant indicates the authorization code or refresh token is invalid or expired
	ErrInvalidGrant = func(desc string) *Error {
		return NewError(ErrorCodeInvalidGrant, desc, http.StatusBadRequest)
	}

	// ErrInvalidClient indicates client authentication failed
	ErrInvalidClient = func(desc string) *Error {
		return NewError(ErrorCodeInvalidClient, desc, http.StatusUnauthorized)
	}

	// ErrInvalidScope indicates the requested scope is invalid or unsupported
	ErrInvalidScope = func(desc string) *Error {
		return NewError(ErrorCodeInvalidScope, desc, http.StatusBadRequest)
	}

	// ErrInvalidToken indicates the access token is invalid or expired
	ErrInvalidToken = func(desc string) *Error {
		return NewError(ErrorCodeInvalidToken, desc, http.StatusUnauthorized)
	}

	// ErrInsufficientScope indicates the access token lacks required scopes
	ErrInsufficientScope = func(desc string) *Error {
		return NewError(ErrorCodeInsufficientScope, desc, http.StatusForbidden)
	}

	// ErrUnauthorizedClient indicates the client is not authorized for the requested grant type
	ErrUnauthorizedClient = func(desc string) *Error {
		return NewError(ErrorCodeUnauthorizedClient, desc, http.StatusBadRequest)
	}

	// ErrUnsupportedGrantType indicates the grant type is not supported
	ErrUnsupportedGrantType = func(desc string) *Error {
		return NewError(ErrorCodeUnsupportedGrantType, desc, http.StatusBadRequest)
	}

	// ErrServerError indicates an internal server error occurred
	ErrServerError = func(desc string) *Error {
		return NewError(ErrorCodeServerError, desc, http.StatusInternalServerError)
	}

	// ErrAccessDenied indicates the user or authorization server denied the request
	ErrAccessDenied = func(desc string) *Error {
		return NewError(ErrorCodeAccessDenied, desc, http.StatusForbidden)
	}

	// ErrInvalidRedirectURI indicates the redirect URI is invalid or not registered
	ErrInvalidRedirectURI = func(desc string) *Error {
		return NewError(ErrorCodeInvalidRedirectURI, desc, http.StatusBadRequest)
	}
)
