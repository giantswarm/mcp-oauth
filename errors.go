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
	ErrorCodeUnauthorizedClient   = "unauthorized_client"
	ErrorCodeUnsupportedGrantType = "unsupported_grant_type"
	ErrorCodeServerError          = "server_error"
	ErrorCodeAccessDenied         = "access_denied"
	ErrorCodeInvalidRedirectURI   = "invalid_redirect_uri"
	ErrorCodeRateLimitExceeded    = "rate_limit_exceeded"
)

// OAuthError represents an OAuth 2.0 error response
type OAuthError struct {
	Code        string // OAuth error code (e.g., "invalid_request", "invalid_grant")
	Description string // Human-readable error description
	Status      int    // HTTP status code
}

// Error implements the error interface
func (e *OAuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// NewOAuthError creates a new OAuth error
func NewOAuthError(code, description string, status int) *OAuthError {
	return &OAuthError{
		Code:        code,
		Description: description,
		Status:      status,
	}
}

// Common OAuth errors as reusable instances
var (
	// ErrInvalidRequest indicates the request is malformed or missing required parameters
	ErrInvalidRequest = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeInvalidRequest, desc, http.StatusBadRequest)
	}

	// ErrInvalidGrant indicates the authorization code or refresh token is invalid or expired
	ErrInvalidGrant = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeInvalidGrant, desc, http.StatusBadRequest)
	}

	// ErrInvalidClient indicates client authentication failed
	ErrInvalidClient = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeInvalidClient, desc, http.StatusUnauthorized)
	}

	// ErrInvalidScope indicates the requested scope is invalid or unsupported
	ErrInvalidScope = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeInvalidScope, desc, http.StatusBadRequest)
	}

	// ErrInvalidToken indicates the access token is invalid or expired
	ErrInvalidToken = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeInvalidToken, desc, http.StatusUnauthorized)
	}

	// ErrUnauthorizedClient indicates the client is not authorized for the requested grant type
	ErrUnauthorizedClient = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeUnauthorizedClient, desc, http.StatusBadRequest)
	}

	// ErrUnsupportedGrantType indicates the grant type is not supported
	ErrUnsupportedGrantType = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeUnsupportedGrantType, desc, http.StatusBadRequest)
	}

	// ErrServerError indicates an internal server error occurred
	ErrServerError = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeServerError, desc, http.StatusInternalServerError)
	}

	// ErrAccessDenied indicates the user or authorization server denied the request
	ErrAccessDenied = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeAccessDenied, desc, http.StatusForbidden)
	}

	// ErrInvalidRedirectURI indicates the redirect URI is invalid or not registered
	ErrInvalidRedirectURI = func(desc string) *OAuthError {
		return NewOAuthError(ErrorCodeInvalidRedirectURI, desc, http.StatusBadRequest)
	}
)
