package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// seedProviderToken stores a provider token for an issued token the way the
// unified layout does (storage.UserProviderTokenStore): the token is written
// once as userID's shared entry and tokenID holds a reference to it. Tests
// that need per-token isolation should use distinct user IDs.
func seedProviderToken(t testing.TB, store storage.UserProviderTokenStore, tokenID, userID string, token *oauth2.Token) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.SaveUserProviderToken(ctx, userID, token))
	require.NoError(t, store.SaveProviderTokenRef(ctx, tokenID, userID, time.Now().Add(time.Hour)))
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
