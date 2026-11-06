package handler

import (
	"context"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func saveTestAccessToken(ctx context.Context, store *memory.Store, accessToken string, providerToken *oauth2.Token, audiences ...string) error {
	const userID = "mock-user-123"
	if err := store.SaveUserProviderToken(ctx, userID, providerToken); err != nil {
		return err
	}
	expiresAt := time.Now().Add(time.Hour)
	audience := testIssuer
	if len(audiences) > 0 {
		audience = audiences[0]
	}
	if err := store.SaveProviderTokenRef(ctx, accessToken, userID, expiresAt); err != nil {
		return err
	}
	return store.SaveTokenMetadata(ctx, accessToken, storage.TokenMetadata{
		UserID: userID, ClientID: "test-client", TokenType: "access", ExpiresAt: expiresAt, Audience: audience,
	})
}
