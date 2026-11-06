package server

import (
	"context"
	"crypto/sha256"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
)

type legacyProviderTokenEntry struct {
	store   storage.TokenStore
	tokenID string
}

func (entry legacyProviderTokenEntry) GetUserProviderToken(ctx context.Context, _ string) (*oauth2.Token, error) {
	return entry.store.GetToken(ctx, entry.tokenID)
}

func (entry legacyProviderTokenEntry) SaveUserProviderToken(ctx context.Context, _ string, providerToken *oauth2.Token) error {
	return entry.store.SaveToken(ctx, entry.tokenID, providerToken)
}

func (entry legacyProviderTokenEntry) key() string {
	return fmt.Sprintf("legacy:%x", sha256.Sum256([]byte(entry.tokenID)))
}

// discardTokenPair removes staged credentials without revoking the shared
// provider grant or the session's existing token family.
func (s *Server) discardTokenPair(ctx context.Context, accessToken, refreshToken string) {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), storage.DefaultOperationTimeout)
	defer cancel()
	for _, tokenID := range []string{accessToken, refreshToken} {
		if tokenID == "" {
			continue
		}
		if store, unified := s.userProviderTokenStore(); unified {
			if err := store.DeleteProviderTokenRef(cleanupContext, tokenID); err != nil {
				s.Logger.Warn("Failed to discard provider token reference", logKeyError, err)
			}
		}
		if err := s.tokenStore.DeleteToken(cleanupContext, tokenID); err != nil {
			s.Logger.Warn("Failed to discard token mapping", logKeyError, err)
		}
	}
	if refreshToken != "" {
		if err := s.tokenStore.DeleteRefreshToken(cleanupContext, refreshToken); err != nil {
			s.Logger.Warn("Failed to discard refresh token", logKeyError, err)
		}
	}
}
