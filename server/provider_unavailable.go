package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
)

// ErrProviderUnavailable marks a refresh grant or a token validation that
// failed because the upstream identity provider did not answer the
// provider-token refresh or its discovery, userinfo or JWKS endpoint: it
// returned a 5xx or 429, the call timed out (Config.TokenValidationTimeout
// bounds a whole bearer validation), or the connection failed. The provider did
// not reject the grant or the bearer and the refresh token was not consumed,
// so the client must retry the same request. HTTP handlers answer it as 503
// temporarily_unavailable with a Retry-After header, never as invalid_grant
// or 401 invalid_token, which clients read as "the token is dead" and answer
// by discarding the token and forcing a new sign-in.
//
// Match it with errors.Is; it wraps the provider's error.
var ErrProviderUnavailable = errors.New("identity provider temporarily unavailable")

// isTransientProviderError reports whether a provider error means the
// provider did not answer rather than rejected the grant or the bearer: an
// OAuth error response, a discovery, userinfo or JWKS answer with status 5xx
// or 429, a timeout or cancellation, or a network error. Any other status
// (invalid_grant, a userinfo 401 and the other 4xx rejections) is permanent.
func isTransientProviderError(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) {
		return retrieveErr.Response != nil && isTransientStatus(retrieveErr.Response.StatusCode)
	}
	var userInfoErr *providers.UserInfoStatusError
	if errors.As(err, &userInfoErr) {
		return isTransientStatus(userInfoErr.StatusCode)
	}
	var discoveryErr *oidc.DiscoveryStatusError
	if errors.As(err, &discoveryErr) {
		return isTransientStatus(discoveryErr.StatusCode)
	}
	var jwksErr *oidc.JWKSStatusError
	if errors.As(err, &jwksErr) {
		return isTransientStatus(jwksErr.StatusCode)
	}
	if isContextError(err) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// isTransientStatus reports whether an IdP answer with this status means the
// IdP did not serve the request (5xx, 429) rather than rejected it.
func isTransientStatus(code int) bool {
	return code >= http.StatusInternalServerError || code == http.StatusTooManyRequests
}

// providerUnavailable classifies a transient provider failure met during op
// (the refresh grant's provider-token refresh, a bearer's validation): it
// logs the failure, audits it under the reason provider_unavailable and
// returns err wrapped in ErrProviderUnavailable.
func (s *Server) providerUnavailable(ctx context.Context, op, userID, clientID string, err error) error {
	s.Logger.Warn("Identity provider temporarily unavailable during "+op,
		logKeyError, err.Error(), paramClientID, clientID, "user_id", userID)

	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventAuthFailure, UserID: userID, ClientID: clientID,
		Details: map[string]any{logKeyReason: "provider_unavailable"},
	})
	return fmt.Errorf("%w: %s: %w", ErrProviderUnavailable, op, err)
}
