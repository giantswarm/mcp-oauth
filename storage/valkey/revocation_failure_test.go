package valkey

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	vk "github.com/valkey-io/valkey-go"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

type failingFamilyCommandClient struct {
	vk.Client
	operation string
	key       string
	sentinel  string
	enabled   atomic.Bool
	failures  atomic.Int32
}

func (c *failingFamilyCommandClient) Do(ctx context.Context, command vk.Completed) vk.ValkeyResult {
	arguments := command.Commands()
	if c.enabled.Load() && strings.EqualFold(arguments[0], c.operation) && slices.Contains(arguments[1:], c.key) {
		c.failures.Add(1)
		return c.Client.Do(ctx, c.Client.B().Incr().Key(c.sentinel).Build())
	}
	return c.Client.Do(ctx, command)
}

func TestFamilyRevocationPropagatesMemberFailuresAndRetries(t *testing.T) {
	for _, failure := range []string{"metadata read", "metadata write", "legacy metadata read", "member deletion", "index retention"} {
		t.Run(failure, func(t *testing.T) {
			store := testStore(t)
			for _, token := range []string{"presented", "sibling"} {
				require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), token, "person", "client", "family", 1, time.Now().Add(time.Hour)))
			}
			sentinel := store.prefix + "failure-sentinel"
			require.NoError(t, store.client.Do(t.Context(), store.client.B().Set().Key(sentinel).Value("not-an-integer").Build()).Error())
			wrapped := &failingFamilyCommandClient{Client: store.client, sentinel: sentinel, operation: "GET", key: store.refreshTokenMetaKey("sibling")}
			switch failure {
			case "metadata write":
				wrapped.operation = "SET"
			case "legacy metadata read":
				metadata, err := store.client.Do(t.Context(), store.client.B().Get().Key(wrapped.key).Build()).ToString()
				require.NoError(t, err)
				require.NoError(t, store.client.Do(t.Context(), store.client.B().Set().Key(store.legacyRefreshTokenMetaKey("sibling")).Value(metadata).Build()).Error())
				require.NoError(t, store.client.Do(t.Context(), store.client.B().Del().Key(wrapped.key).Build()).Error())
				wrapped.key = store.legacyRefreshTokenMetaKey("sibling")
			case "member deletion":
				wrapped.operation, wrapped.key = "DEL", store.refreshTokenKey("sibling")
			case "index retention":
				wrapped.operation, wrapped.key = "EVAL", store.familyKey("family")
			}
			store.client = wrapped
			wrapped.enabled.Store(true)
			oauthServer, err := server.New(mock.NewProvider(), store, store, store, &server.Config{Issuer: "https://auth.example.com"}, nil)
			require.NoError(t, err)
			require.ErrorIs(t, oauthServer.RevokeToken(t.Context(), "presented", "client", "192.0.2.1"), server.ErrStorageUnavailable)
			require.Positive(t, wrapped.failures.Load())
			presented, err := store.GetRefreshTokenFamily(t.Context(), "presented")
			require.NoError(t, err)
			require.True(t, presented.Revoked)
			wrapped.enabled.Store(false)
			require.NoError(t, oauthServer.RevokeToken(t.Context(), "presented", "client", "192.0.2.1"))
			if failure == "legacy metadata read" {
				payload, err := store.client.Do(t.Context(), store.client.B().Get().Key(wrapped.key).Build()).ToString()
				require.NoError(t, err)
				var sibling refreshTokenFamilyJSON
				require.NoError(t, json.Unmarshal([]byte(payload), &sibling))
				require.True(t, sibling.Revoked)
			} else {
				sibling, err := store.GetRefreshTokenFamily(t.Context(), "sibling")
				require.NoError(t, err)
				require.True(t, sibling.Revoked)
			}
			_, err = store.GetRefreshTokenInfo(t.Context(), "sibling")
			require.ErrorIs(t, err, storage.ErrTokenNotFound)
		})
	}
}

func TestJTIRevocationRetainsFullFractionalLifetime(t *testing.T) {
	store := testStore(t)
	expiresAt := time.Now().Add(2500 * time.Millisecond)
	require.NoError(t, store.RevokeJTI(t.Context(), "fractional-jti", expiresAt))
	remaining, err := store.client.Do(t.Context(), store.client.B().Pttl().Key(store.revokedJTIKey("fractional-jti")).Build()).AsInt64()
	require.NoError(t, err)
	require.GreaterOrEqual(t, time.Duration(remaining)*time.Millisecond, time.Until(expiresAt))
}
