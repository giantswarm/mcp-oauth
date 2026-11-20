package handler

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type failingRevocationStore struct {
	*memory.Store
	unavailable bool
}

func (s *failingRevocationStore) DeleteRefreshToken(ctx context.Context, token string) error {
	if s.unavailable {
		return errors.New("refresh deletion unavailable")
	}
	return s.Store.DeleteRefreshToken(ctx, token)
}

func TestRevocationWriteOutageReturns503AndCanRetry(t *testing.T) {
	store := memory.New()
	t.Cleanup(store.Stop)
	failingStore := &failingRevocationStore{Store: store, unavailable: true}
	var audit bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&audit, nil))
	oauthServer, err := server.New(mock.NewProvider(), failingStore, store, store, &server.Config{Issuer: testIssuer}, logger,
		server.WithAuditor(security.NewAuditor(logger, true)))
	require.NoError(t, err)
	handler := New(oauthServer, logger)
	client := newMatrixClient(t, handler, "none")
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "refresh", "person", client.client.ClientID, "family", 1, time.Now().Add(time.Hour)))
	response := matrixClientRequest(t, handler, server.EndpointPathRevoke, client, "none", url.Values{"token": {"refresh"}})
	require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
	require.NotEmpty(t, response.Header().Get("Retry-After"))
	require.Empty(t, response.Header().Get("WWW-Authenticate"))
	require.Contains(t, response.Body.String(), "retry the same request")
	require.NotContains(t, response.Body.String(), "refresh deletion unavailable")
	require.True(t, auditAuthFailureWithReason(t, &audit, "transient_storage_error"))
	require.False(t, auditEventLogged(t, &audit, security.EventTokenRevoked))
	retry := matrixClientRequest(t, handler, server.EndpointPathRevoke, client, "none", url.Values{"token": {"refresh"}})
	require.Equal(t, http.StatusServiceUnavailable, retry.Code)
	require.Equal(t, response.Body.String(), retry.Body.String())
	failingStore.unavailable = false
	response = matrixClientRequest(t, handler, server.EndpointPathRevoke, client, "none", url.Values{"token": {"refresh"}})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	_, err = store.GetRefreshTokenInfo(t.Context(), "refresh")
	require.Error(t, err)
}
