package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

func (s *Server) validateForwardedIDToken(ctx context.Context, token string) (*providers.UserInfo, error) {
	acceptance, err := s.AcceptForwardedIDToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return acceptance.UserInfo, nil
}

// seedProviderToken stores a provider token for an issued token the way the
// unified layout does (storage.UserProviderTokenStore): the token is written
// once as userID's shared entry and tokenID holds a reference to it. Tests
// that need per-token isolation should use distinct user IDs.
func seedProviderToken(t testing.TB, store storage.UserProviderTokenStore, tokenID, userID string, token *oauth2.Token, audiences ...string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.SaveUserProviderToken(ctx, userID, token))
	require.NoError(t, store.SaveProviderTokenRef(ctx, tokenID, userID, time.Now().Add(time.Hour)))
	if metadataStore, ok := store.(storage.TokenMetadataStore); ok {
		audience := "https://auth.example.com"
		if len(audiences) > 0 {
			audience = audiences[0]
		}
		require.NoError(t, metadataStore.SaveTokenMetadata(ctx, tokenID, storage.TokenMetadata{
			UserID: userID, ClientID: "test-client", TokenType: "access", ExpiresAt: time.Now().Add(time.Hour), Audience: audience,
		}))
	}
}

func testInstrumentation(t testing.TB) *instrumentation.Instrumentation {
	t.Helper()
	inst, err := instrumentation.New(instrumentation.Config{})
	require.NoError(t, err)
	return inst
}

func testAuditor() *security.Auditor {
	return security.NewAuditor(nil, false)
}
