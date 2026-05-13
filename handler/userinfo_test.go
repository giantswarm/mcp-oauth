package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/server"
)

func TestHandler_ServeUserInfo(t *testing.T) {
	t.Run("rejects when openid scope missing", func(t *testing.T) {
		handler, store, token := setupUserInfoTest(t, []string{"profile", "email"})
		defer store.Stop()

		req := httptest.NewRequest(http.MethodGet, server.EndpointPathUserInfo, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ValidateToken(http.HandlerFunc(handler.ServeUserInfo)).ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Code)
		require.Contains(t, w.Header().Get("WWW-Authenticate"), oauth.ErrorCodeInsufficientScope)
	})

	t.Run("openid only returns sub", func(t *testing.T) {
		handler, store, token := setupUserInfoTest(t, []string{"openid"})
		defer store.Stop()

		req := httptest.NewRequest(http.MethodGet, server.EndpointPathUserInfo, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ValidateToken(http.HandlerFunc(handler.ServeUserInfo)).ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		claims := decodeUserInfoResponse(t, w)
		require.Equal(t, "mock-user-123", claims["sub"])
		require.NotContains(t, claims, "name")
		require.NotContains(t, claims, "email")
	})

	t.Run("profile scope unlocks profile claims", func(t *testing.T) {
		handler, store, token := setupUserInfoTest(t, []string{"openid", "profile"})
		defer store.Stop()

		req := httptest.NewRequest(http.MethodPost, server.EndpointPathUserInfo, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ValidateToken(http.HandlerFunc(handler.ServeUserInfo)).ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		claims := decodeUserInfoResponse(t, w)
		require.Equal(t, "mock-user-123", claims["sub"])
		require.Equal(t, "Mock User", claims["name"])
		require.Equal(t, "Mock", claims["given_name"])
		require.Equal(t, "User", claims["family_name"])
		require.NotContains(t, claims, "email")
	})

	t.Run("email scope unlocks email claims", func(t *testing.T) {
		handler, store, token := setupUserInfoTest(t, []string{"openid", "email"})
		defer store.Stop()

		req := httptest.NewRequest(http.MethodGet, server.EndpointPathUserInfo, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ValidateToken(http.HandlerFunc(handler.ServeUserInfo)).ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		claims := decodeUserInfoResponse(t, w)
		require.Equal(t, "mock-user-123", claims["sub"])
		require.Equal(t, "mock@example.com", claims["email"])
		require.Equal(t, true, claims["email_verified"])
		require.NotContains(t, claims, "name")
	})

	t.Run("metadata advertises endpoint when enabled", func(t *testing.T) {
		handler, store, _ := setupUserInfoTest(t, []string{"openid"})
		defer store.Stop()

		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		w := httptest.NewRecorder()
		handler.ServeAuthorizationServerMetadata(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		var meta map[string]any
		require.NoError(t, json.NewDecoder(w.Body).Decode(&meta))
		require.Equal(t, "https://auth.example.com"+server.EndpointPathUserInfo, meta["userinfo_endpoint"])
	})

	t.Run("metadata omits endpoint when disabled", func(t *testing.T) {
		handler, store := setupTestHandler(t)
		defer store.Stop()

		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		w := httptest.NewRecorder()
		handler.ServeAuthorizationServerMetadata(w, req)
		var meta map[string]any
		require.NoError(t, json.NewDecoder(w.Body).Decode(&meta))
		require.NotContains(t, meta, "userinfo_endpoint")
	})

	t.Run("rejects unsupported methods", func(t *testing.T) {
		handler, store, token := setupUserInfoTest(t, []string{"openid"})
		defer store.Stop()

		req := httptest.NewRequest(http.MethodDelete, server.EndpointPathUserInfo, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ValidateToken(http.HandlerFunc(handler.ServeUserInfo)).ServeHTTP(w, req)

		require.Equal(t, http.StatusMethodNotAllowed, w.Code)
		require.Equal(t, "GET, POST", w.Header().Get("Allow"))
	})
}
