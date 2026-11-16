package server

// AuthorizationRequestError is an authorization request refused because a
// parameter is missing or not acceptable, as [Server.PrepareAuthorization]
// returns it. Code is the OAuth error code of the refusal (RFC 6749 §4.1.2.1,
// RFC 8707 §2) and Description a fixed text that is safe to return to the
// client in error_description. The detailed reason is in the wrapped error and
// belongs in logs only.
//
// Match it with errors.As. Any other error is a server failure, not a refusal
// of the request.
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
