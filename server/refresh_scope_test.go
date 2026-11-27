package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestServer_RefreshAccessTokenWithOptions_Scope(t *testing.T) {
	tests := []struct {
		name          string
		requested     []string
		wantAccess    []string
		wantDeprecate bool
	}{
		{name: "omitted keeps the grant", requested: nil, wantAccess: []string{"openid", "email", "profile"}},
		{name: "subset narrows the access token", requested: []string{"email"}, wantAccess: []string{"email"}},
		{name: "same scope in another order", requested: []string{"profile", "openid", "email"}, wantAccess: []string{"openid", "email", "profile"}},
		{name: "beyond the grant keeps the grant and warns", requested: []string{"email", "admin"}, wantAccess: []string{"openid", "email", "profile"}, wantDeprecate: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, store, client, refreshToken := refreshScopeGrant(t, "openid email profile")
			var logs bytes.Buffer
			srv.Logger = slog.New(slog.NewTextHandler(&logs, nil))

			token, scope, err := srv.RefreshAccessTokenWithOptions(t.Context(), refreshToken, client, RefreshOptions{Scope: tt.requested})
			require.NoError(t, err)

			access, err := store.GetTokenMetadata(token.AccessToken)
			require.NoError(t, err)
			require.Equal(t, tt.wantAccess, access.Scopes)
			require.Equal(t, strings.Join(tt.wantAccess, " "), scope)

			refresh, err := store.GetTokenMetadata(token.RefreshToken)
			require.NoError(t, err)
			require.Equal(t, []string{"openid", "email", "profile"}, refresh.Scopes, "RFC 6749 §6: the new refresh token keeps the original scope")

			if tt.wantDeprecate {
				require.Contains(t, logs.String(), "DEPRECATED")
				require.Contains(t, logs.String(), "admin")
			} else {
				require.NotContains(t, logs.String(), "DEPRECATED")
			}
		})
	}
}

func refreshScopeGrant(t *testing.T, scope string) (*Server, *memory.Store, *storage.Client, string) {
	t.Helper()
	ctx := t.Context()
	srv, store, provider := setupFlowTestServer(t)
	srv.Config.AllowRefreshTokenRotation = true
	srv.Config.RefreshTokenTTL = 86400

	client, _, err := srv.RegisterClient(ctx, "Scope Test Client", ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"openid", "email", "profile"}, "192.168.1.100", 10)
	require.NoError(t, err)

	verifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(verifier))
	flowURL, err := srv.StartAuthorizationFlow(ctx, client.ClientID, mustParseURL(t, "https://example.com/callback"), scope, "",
		base64.RawURLEncoding.EncodeToString(hash[:]), PKCEMethodS256, testutil.GenerateRandomString(43), nil)
	require.NoError(t, err)
	authState, err := store.GetAuthorizationStateByProviderState(ctx, providerStateOf(t, flowURL))
	require.NoError(t, err)
	code, _, err := srv.HandleProviderCallback(ctx, authState.ProviderState, "code-"+testutil.GenerateRandomString(10))
	require.NoError(t, err)
	token, _, err := srv.ExchangeAuthorizationCode(ctx, code.Code, client.ClientID, "https://example.com/callback", "", verifier, "")
	require.NoError(t, err)

	provider.RefreshTokenFunc = func(context.Context, string) (*oauth2.Token, error) {
		return &oauth2.Token{AccessToken: "provider-" + testutil.GenerateRandomString(10), RefreshToken: "provider-refresh", Expiry: time.Now().Add(time.Hour)}, nil
	}
	return srv, store, client, token.RefreshToken
}
