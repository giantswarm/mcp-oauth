package oauth

import (
	"fmt"
	"net/http"
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
		return NewOAuthError("invalid_request", desc, http.StatusBadRequest)
	}

	// ErrInvalidGrant indicates the authorization code or refresh token is invalid or expired
	ErrInvalidGrant = func(desc string) *OAuthError {
		return NewOAuthError("invalid_grant", desc, http.StatusBadRequest)
	}

	// ErrInvalidClient indicates client authentication failed
	ErrInvalidClient = func(desc string) *OAuthError {
		return NewOAuthError("invalid_client", desc, http.StatusUnauthorized)
	}

	// ErrInvalidScope indicates the requested scope is invalid or unsupported
	ErrInvalidScope = func(desc string) *OAuthError {
		return NewOAuthError("invalid_scope", desc, http.StatusBadRequest)
	}

	// ErrInvalidToken indicates the access token is invalid or expired
	ErrInvalidToken = func(desc string) *OAuthError {
		return NewOAuthError("invalid_token", desc, http.StatusUnauthorized)
	}

	// ErrUnauthorizedClient indicates the client is not authorized for the requested grant type
	ErrUnauthorizedClient = func(desc string) *OAuthError {
		return NewOAuthError("unauthorized_client", desc, http.StatusBadRequest)
	}

	// ErrUnsupportedGrantType indicates the grant type is not supported
	ErrUnsupportedGrantType = func(desc string) *OAuthError {
		return NewOAuthError("unsupported_grant_type", desc, http.StatusBadRequest)
	}

	// ErrServerError indicates an internal server error occurred
	ErrServerError = func(desc string) *OAuthError {
		return NewOAuthError("server_error", desc, http.StatusInternalServerError)
	}

	// ErrAccessDenied indicates the user or authorization server denied the request
	ErrAccessDenied = func(desc string) *OAuthError {
		return NewOAuthError("access_denied", desc, http.StatusForbidden)
	}

	// ErrInvalidRedirectURI indicates the redirect URI is invalid or not registered
	ErrInvalidRedirectURI = func(desc string) *OAuthError {
		return NewOAuthError("invalid_redirect_uri", desc, http.StatusBadRequest)
	}
)
