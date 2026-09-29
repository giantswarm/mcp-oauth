package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/security"
)

// ErrProviderUnavailable marks a refresh grant that failed because the upstream
// identity provider did not answer the provider-token refresh: it returned a
// 5xx or 429, the call timed out, or the connection failed. The provider did
// not reject the grant and the refresh token was not consumed, so the client
// must retry the same request. HTTP handlers answer it as 503
// temporarily_unavailable with a Retry-After header, never as invalid_grant,
// which clients read as "the token is dead" and answer by discarding the token
// and forcing a new sign-in.
//
// Match it with errors.Is; it wraps the provider's error.
var ErrProviderUnavailable = errors.New("identity provider temporarily unavailable")

// isTransientProviderError reports whether a provider refresh error means the
// provider did not answer rather than rejected the grant: an OAuth error
// response with status 5xx or 429, a timeout or cancellation, or a network
// error. An OAuth error response with any other status (invalid_grant and the
// other 4xx rejections) is permanent.
func isTransientProviderError(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		if retrieveErr.Response == nil {
			return false
		}
		code := retrieveErr.Response.StatusCode
		return code >= http.StatusInternalServerError || code == http.StatusTooManyRequests
	}
	if isContextError(err) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// providerUnavailable classifies a transient provider refresh failure met on
// the refresh grant: it logs the failure, audits it under the reason
// provider_unavailable and returns err wrapped in ErrProviderUnavailable.
func (s *Server) providerUnavailable(ctx context.Context, userID, clientID string, err error) error {
	s.Logger.Warn("Identity provider temporarily unavailable during refresh",
		logKeyError, err.Error(), paramClientID, clientID, "user_id", userID)

	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventAuthFailure, UserID: userID, ClientID: clientID,
		Details: map[string]any{logKeyReason: "provider_unavailable"},
	})
	return fmt.Errorf("%w: refresh token with provider: %w", ErrProviderUnavailable, err)
}
