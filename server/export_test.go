package server

import (
	"context"

	"golang.org/x/oauth2"
)

// RefreshUserProviderTokenForTest exposes the unexported single-flight
// provider-refresh coordinator to package server_test. The external test
// package exists because the valkey storage backend imports this package
// (DPoP replay cache), so cross-pod tests over real valkey.Store instances
// cannot live in an in-package test file without an import cycle.
func (s *Server) RefreshUserProviderTokenForTest(ctx context.Context, userID string, observed *oauth2.Token) (*oauth2.Token, error) {
	return s.refreshUserProviderToken(ctx, userID, observed)
}
