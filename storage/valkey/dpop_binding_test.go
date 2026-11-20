package valkey

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/handler"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestTokenMetadataPreservesDPoPBindingAndExtraClaims(t *testing.T) {
	store := testStore(t)
	metadata := storage.TokenMetadata{
		UserID: "person", ClientID: "client", TokenType: "access", Audience: "https://auth.example.com",
		ExpiresAt: time.Now().Add(time.Hour), JKT: "public-key-thumbprint",
		ExtraClaims: map[string]any{"tenant": "test", "approved": true},
	}
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "opaque-dpop-access", metadata))
	stored, err := store.GetTokenMetadata("opaque-dpop-access")
	require.NoError(t, err)
	require.Equal(t, metadata.JKT, stored.JKT)
	require.Equal(t, metadata.ExtraClaims, stored.ExtraClaims)
}

func TestOpaqueDPoPBindingRejectsBearerAfterValkeyRoundTrip(t *testing.T) {
	store := testStore(t)
	var audit bytes.Buffer
	auditor := security.NewAuditor(slog.New(slog.NewJSONHandler(&audit, nil)), true)
	oauthServer, err := server.New(mock.NewProvider(), store, store, store, &server.Config{Issuer: "https://auth.example.com"}, nil, server.WithAuditor(auditor))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, oauthServer.Shutdown(context.WithoutCancel(t.Context()))) })
	expiresAt := time.Now().Add(time.Hour)
	require.NoError(t, store.SaveUserProviderToken(t.Context(), "person", &oauth2.Token{
		AccessToken: "upstream-access", RefreshToken: "upstream-refresh", Expiry: expiresAt,
	}))
	require.NoError(t, store.SaveProviderTokenRef(t.Context(), "opaque-dpop-access", "person", expiresAt))
	metadata := storage.TokenMetadata{
		UserID: "person", ClientID: "client", TokenType: "access",
		Audience: oauthServer.Config.GetResourceIdentifier(), ExpiresAt: expiresAt,
	}
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "opaque-dpop-access", metadata))
	protected := handler.New(oauthServer, nil).ValidateToken(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	requestBearer := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "https://auth.example.com/mcp", nil)
		request.Header.Set("Authorization", "Bearer opaque-dpop-access")
		response := httptest.NewRecorder()
		protected.ServeHTTP(response, request)
		return response
	}
	require.Equal(t, http.StatusNoContent, requestBearer().Code)
	metadata.JKT = "public-key-thumbprint"
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "opaque-dpop-access", metadata))
	response := requestBearer()
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Contains(t, response.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	require.Contains(t, audit.String(), "dpop_bound_token_bearer_bypass")
}
