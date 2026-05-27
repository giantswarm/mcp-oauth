package server

import (
	"context"
	"errors"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/constants"
)

// OAuth 2.0 / 2.1 error codes and spec version re-exported from internal/constants
// so that server-package code can reference them without a circular import.
const (
	ErrorCodeInvalidClient      = constants.ErrorCodeInvalidClient
	ErrorCodeInvalidRequest     = constants.ErrorCodeInvalidRequest
	ErrorCodeInvalidRedirectURI = constants.ErrorCodeInvalidRedirectURI
	ErrorCodeInvalidScope       = constants.ErrorCodeInvalidScope
	ErrorCodeInvalidGrant       = constants.ErrorCodeInvalidGrant
	OAuthSpecVersion            = constants.OAuthSpecVersion
)

var errInvalidGrant = errors.New(ErrorCodeInvalidGrant + ": invalid grant")

// registerTokenPair records the AT -> RT pairing so that provider token refreshes
// triggered by one key can also update the other.
func (s *Server) registerTokenPair(accessToken, refreshToken string) {
	s.tokenPairs.Store(accessToken, refreshToken)
	s.tokenPairsByRefresh.Store(refreshToken, accessToken)
}

// capTokenExpiry returns the earlier of the configured AccessTokenTTL-based expiry
// and the provider token's expiry, ensuring expires_in never promises more than
// the underlying provider token can deliver. Provider tokens with zero or past
// expiry are ignored. now is the caller's issuance instant.
func (s *Server) capTokenExpiry(now, providerExpiry time.Time) time.Time {
	expiry := now.Add(time.Duration(s.Config.AccessTokenTTL) * time.Second)
	if !providerExpiry.IsZero() && providerExpiry.After(now) && providerExpiry.Before(expiry) {
		expiry = providerExpiry
	}
	return expiry
}

// refreshTokenExpiry returns the expiry instant for a newly-issued refresh
// token, derived from now and Config.RefreshTokenTTL.
func (s *Server) refreshTokenExpiry(now time.Time) time.Time {
	return now.Add(time.Duration(s.Config.RefreshTokenTTL) * time.Second)
}

func (s *Server) logAuthFailure(ctx context.Context, userID, clientID, reason string) {
	s.Auditor.LogAuthFailure(ctx, userID, clientID, "", reason)
}
