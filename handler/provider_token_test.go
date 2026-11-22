package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type providerTokenStore struct {
	*memory.Store
	unavailable bool
}

func (s *providerTokenStore) GetToken(ctx context.Context, bearer string) (*oauth2.Token, error) {
	if s.unavailable {
		return nil, errors.New("storage unavailable")
	}
	return s.Store.GetToken(ctx, bearer)
}

func TestProviderIDTokenRequiresValidatedContext(t *testing.T) {
	ctx := ContextWithUserInfo(t.Context(), &providers.UserInfo{ID: "user", TokenSource: providers.TokenSourceSSO})
	_, err := ProviderIDTokenFromContext(ctx)
	require.ErrorIs(t, err, ErrProviderIDTokenUnavailable)
}

func TestProviderIDTokenFromValidatedBearer(t *testing.T) {
	for _, name := range []string{"stored ID token", "missing ID token", "storage unavailable"} {
		t.Run(name, func(t *testing.T) {
			store := memory.New()
			backingStore := &providerTokenStore{Store: store}
			authorizationServer, err := server.New(mock.NewProvider(), backingStore, store, store, &server.Config{Issuer: testIssuer}, nil)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, authorizationServer.Shutdown(context.WithoutCancel(t.Context()))) })
			providerToken := &oauth2.Token{AccessToken: "provider-access", Expiry: time.Now().Add(time.Hour)}
			if name != "missing ID token" {
				providerToken = providerToken.WithExtra(map[string]any{"id_token": "provider-id-token"})
			}
			require.NoError(t, saveTestAccessToken(t.Context(), store, "local-access", providerToken))
			handler := New(authorizationServer, nil)
			called := false
			next := handler.RequireProviderIDToken(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				called = true
				identity, ok := UserInfoFromContext(request.Context())
				require.True(t, ok)
				require.Equal(t, testIssuer, identity.Issuer)
				token, err := ProviderIDTokenFromContext(request.Context())
				require.NoError(t, err)
				require.Equal(t, "provider-id-token", token)
				w.WriteHeader(http.StatusNoContent)
			}))
			chain := handler.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				backingStore.unavailable = name == "storage unavailable"
				next.ServeHTTP(w, request)
			}))
			request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
			request.Header.Set("Authorization", "bEaReR local-access")
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			switch name {
			case "stored ID token":
				require.Equal(t, http.StatusNoContent, response.Code, response.Body.String())
				require.True(t, called)
			case "missing ID token":
				require.Equal(t, http.StatusUnauthorized, response.Code, response.Body.String())
				require.Contains(t, response.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
				require.False(t, called)
			case "storage unavailable":
				require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
				require.False(t, called)
			}
		})
	}
}

func TestForwardedProviderIDTokenIsTheValidatedBearer(t *testing.T) {
	handler, bearer, _ := newForwardedTokenHandler(t, 0)
	request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	request.Header.Set("Authorization", "bEaReR "+bearer)
	response := httptest.NewRecorder()
	handler.ValidateToken(handler.RequireProviderIDToken(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		token, err := ProviderIDTokenFromContext(request.Context())
		require.NoError(t, err)
		require.Equal(t, bearer, token)
		identity, ok := UserInfoFromContext(request.Context())
		require.True(t, ok)
		require.NotEmpty(t, identity.Issuer)
		w.WriteHeader(http.StatusNoContent)
	}))).ServeHTTP(response, request)
	require.Equal(t, http.StatusNoContent, response.Code, response.Body.String())
}
