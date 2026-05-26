package server

import (
	"context"
	"time"
)

// OAuth 2.0 error codes from RFC 6749.
// Note: These are intentionally duplicated from errors.go to avoid circular imports
// (root package imports server for type aliases, server can't import root).
// Keep these in sync with errors.go.
const (
	ErrorCodeInvalidClient      = "invalid_client"
	ErrorCodeInvalidRequest     = "invalid_request"
	ErrorCodeInvalidRedirectURI = "invalid_redirect_uri"
	ErrorCodeInvalidScope       = "invalid_scope"
	ErrorCodeInvalidGrant       = "invalid_grant"
)

// OAuthSpecVersion is the OAuth specification version this library implements.
// Note: This is intentionally duplicated from constants.go to avoid circular imports.
// Keep in sync with constants.go.
const OAuthSpecVersion = "OAuth 2.1"

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
