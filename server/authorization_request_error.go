package server

import "errors"

// ErrRedirectURIRejected marks a redirect_uri the server refuses: in an
// authorization request, one not registered for its client or failing the
// authorization-time security check (RFC 6749 §4.1.2.1: the error is shown to
// the person and never redirected to that URI); in a client registration, one
// failing the security check (RFC 7591 §3.2.2 invalid_redirect_uri).
var ErrRedirectURIRejected = errors.New("redirect_uri rejected")

// AuthorizationRequestError is an authorization request refused because a
// parameter is missing or not acceptable, as [Server.PrepareAuthorization]
// returns it. Code is the OAuth error code of the refusal (RFC 6749 §4.1.2.1,
// RFC 8707 §2) and Description a fixed text that is safe to return to the
// client in error_description. The detailed reason is in the wrapped error and
// belongs in logs only.
//
// Match it with errors.As. A refusal of redirect_uri also matches
// [ErrRedirectURIRejected]. Outside this type, an unknown client is
// [ErrClientNotVerified], a store that did not answer [ErrStorageUnavailable],
// and any other error a server failure.
type AuthorizationRequestError struct {
	Code        string
	Description string
	cause       error
}

func newAuthorizationRequestError(code, description string, cause error) *AuthorizationRequestError {
	return &AuthorizationRequestError{Code: code, Description: description, cause: cause}
}

func (e *AuthorizationRequestError) Error() string {
	if e.cause == nil {
		return e.Code + ": " + e.Description
	}
	return e.Code + ": " + e.cause.Error()
}

func (e *AuthorizationRequestError) Unwrap() error {
	return e.cause
}
