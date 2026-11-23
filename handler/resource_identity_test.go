package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// serveBearerAt sends a bearer to target through the ValidateToken middleware
// and returns the status and the validated user's username.
func serveBearerAt(t *testing.T, h *Handler, target, bearer string) (int, string) {
	t.Helper()
	var username string
	protected := h.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, ok := UserInfoFromContext(r.Context())
		require.True(t, ok)
		username = userInfo.Username
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil)
	request.Header.Set("Authorization", "Bearer "+bearer)
	recorder := httptest.NewRecorder()
	protected.ServeHTTP(recorder, request)
	return recorder.Code, username
}

func TestValidateToken_TrustedIssuerSubjectClaim(t *testing.T) {
	dex := newOffIssuer(t)
	dex.entry.SubjectClaim = "email"
	h := newOffHandler(t, nil, dex.entry)

	verified := dex.claims()
	verified.EmailVerified = true
	status, username := serveBearerAt(t, h, "/mcp", dex.signClaims(t, verified))
	require.Equal(t, http.StatusNoContent, status)
	require.Equal(t, "user@test.example", username)

	status, _ = serveBearerAt(t, h, "/mcp", dex.sign(t))
	require.Equal(t, http.StatusUnauthorized, status)
}

func TestValidateToken_PathResourceTrustedIssuer(t *testing.T) {
	const extraResource = "https://mcp.test.example/other"
	dex := newOffIssuer(t)
	dex.entry.AllowedAudiences = []string{offResource, extraResource}
	h := newOffHandler(t, func(c *server.Config) {
		c.RequireResourceAccessTokens = true
		c.ResourceMetadataByPath["/other"] = server.ProtectedResourceConfig{ResourceIdentifier: extraResource, AuthorizationServers: []string{offDexIssuer}}
	}, dex.entry)
	tokenFor := func(resource string) string {
		claims := dex.claims()
		claims.Audience = josejwt.Audience{resource}
		return dex.signClaims(t, claims)
	}

	for name, tc := range map[string]struct {
		resource, target string
		status           int
	}{
		"extra resource at its path":  {resource: extraResource, target: "/other", status: http.StatusNoContent},
		"extra resource at main path": {resource: extraResource, target: "/mcp", status: http.StatusUnauthorized},
		"main resource at main path":  {resource: offResource, target: "/mcp", status: http.StatusNoContent},
		"main resource at extra path": {resource: offResource, target: "/other", status: http.StatusNoContent},
	} {
		t.Run(name, func(t *testing.T) {
			status, _ := serveBearerAt(t, h, tc.target, tokenFor(tc.resource))
			require.Equal(t, tc.status, status)
		})
	}
}

func TestValidateToken_PathResourceIssuedToken(t *testing.T) {
	const extraResource = testIssuer + "/other"
	store := memory.New()
	srv, err := server.New(mock.NewProvider(), store, store, store, &server.Config{
		Issuer: testIssuer,
		ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
			"/other": {ScopesSupported: []string{"other:read"}},
		},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Shutdown(context.WithoutCancel(t.Context())) })
	h := New(srv, nil)
	providerToken := &oauth2.Token{AccessToken: "provider-token", Expiry: time.Now().Add(time.Hour)}
	require.NoError(t, saveTestAccessToken(t.Context(), store, "extra-token", providerToken, extraResource))
	require.NoError(t, saveTestAccessToken(t.Context(), store, "main-token", providerToken))

	for name, tc := range map[string]struct {
		bearer, target string
		status         int
	}{
		"extra resource at its path":  {bearer: "extra-token", target: "/other", status: http.StatusNoContent},
		"extra resource at main path": {bearer: "extra-token", target: "/mcp", status: http.StatusUnauthorized},
		"main resource at main path":  {bearer: "main-token", target: "/mcp", status: http.StatusNoContent},
		"main resource at extra path": {bearer: "main-token", target: "/other", status: http.StatusNoContent},
	} {
		t.Run(name, func(t *testing.T) {
			status, _ := serveBearerAt(t, h, tc.target, tc.bearer)
			require.Equal(t, tc.status, status)
		})
	}
}
