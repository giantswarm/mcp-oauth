package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const (
	offDexIssuer = "https://dex.test.example"
	offAudience  = "platform"
	offResource  = "https://mcp.test.example/mcp"
)

// offIssuer is a trusted issuer served by a TLS JWKS endpoint, signing ID
// tokens with typ JWT.
type offIssuer struct {
	entry server.TrustedIssuer
	sign  func(t *testing.T) string
}

func newOffIssuer(t *testing.T) offIssuer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	const keyID = "dex-key"
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: privateKey.Public(), KeyID: keyID, Algorithm: "RS256", Use: "sig"}}}
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksServer.Close)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(jwksServer.Certificate())

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: privateKey, KeyID: keyID, Algorithm: "RS256", Use: "sig"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	return offIssuer{
		entry: server.TrustedIssuer{
			Issuer:             offDexIssuer,
			JwksURL:            jwksServer.URL,
			AllowedAudiences:   []string{offAudience},
			AcceptedTypHeaders: []string{"JWT"},
			AllowPrivateIPJWKS: true, //nolint:staticcheck // the JWKS server is on loopback, which a host list does not lift
			RootCAs:            rootCAs,
			OpenIDProvider:     true,
		},
		sign: func(t *testing.T) string {
			t.Helper()
			now := time.Now()
			token, err := josejwt.Signed(signer).Claims(oidc.IDTokenClaims{
				Claims: josejwt.Claims{
					Subject:  "user-subject-123",
					Issuer:   offDexIssuer,
					Audience: josejwt.Audience{offAudience},
					IssuedAt: josejwt.NewNumericDate(now),
					Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
				},
				Email: "user@test.example",
			}).Serialize()
			require.NoError(t, err)
			return token
		},
	}
}

func newOffHandler(t *testing.T, configure func(*server.Config), issuers ...server.TrustedIssuer) *Handler {
	t.Helper()
	store := memory.New()
	configuration := &server.Config{
		Issuer:                     "https://mcp.test.example",
		ResourceIdentifier:         offResource,
		DisableAuthorizationServer: true,
		ResourceMetadataByPath: map[string]server.ProtectedResourceConfig{
			"/mcp": {ResourceIdentifier: offResource, AuthorizationServers: []string{offDexIssuer}},
		},
	}
	if configure != nil {
		configure(configuration)
	}
	srv, err := server.New(nil, store, store, store, configuration, nil, server.WithTrustedIssuers(issuers))
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Shutdown(context.WithoutCancel(t.Context())) })
	return New(srv, nil)
}

func serveStatus(t *testing.T, mux http.Handler, method, target string) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), method, target, nil))
	return recorder.Code
}

func TestRegisterOAuthRoutes_AuthorizationServerOff(t *testing.T) {
	h := newOffHandler(t, nil, newOffIssuer(t).entry)
	mux := http.NewServeMux()
	h.RegisterOAuthRoutes(mux, OAuthRoutesOptions{IncludeMetadata: true})

	for _, target := range []string{
		"/oauth/authorize", "/oauth/callback", "/oauth/token", "/oauth/revoke", "/oauth/register",
		"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration",
	} {
		require.Equal(t, http.StatusNotFound, serveStatus(t, mux, http.MethodGet, target), target)
	}

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource/mcp", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &metadata))
	require.Equal(t, offResource, metadata["resource"])
	require.Equal(t, []any{offDexIssuer}, metadata["authorization_servers"])
}

func TestServeAuthorizationServerEndpoints_NotFoundWhenOff(t *testing.T) {
	h := newOffHandler(t, nil, newOffIssuer(t).entry)

	for name, serve := range map[string]http.HandlerFunc{
		"authorization": h.ServeAuthorization,
		"callback":      h.ServeCallback,
		"token":         h.ServeToken,
		"revocation":    h.ServeTokenRevocation,
		"registration":  h.ServeClientRegistration,
		"metadata":      h.ServeAuthorizationServerMetadata,
		"openid":        h.ServeOpenIDConfiguration,
	} {
		require.Equal(t, http.StatusNotFound, serveStatus(t, serve, http.MethodPost, "/"), name)
	}
}

func TestProtectedResourceMetadata_AuthorizationServerOffWithoutAdvertisedServer(t *testing.T) {
	h := newOffHandler(t, func(c *server.Config) { c.ResourceMetadataByPath = nil }, newOffIssuer(t).entry)
	mux := http.NewServeMux()
	h.RegisterOAuthRoutes(mux, OAuthRoutesOptions{IncludeMetadata: true})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-protected-resource", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &metadata))
	require.NotContains(t, metadata, "authorization_servers")
}

func TestValidateToken_AuthorizationServerOff(t *testing.T) {
	dex := newOffIssuer(t)
	h := newOffHandler(t, nil, dex.entry)
	var idToken string
	protected := h.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		idToken, err = ProviderIDTokenFromContext(r.Context())
		require.NoError(t, err)
		w.WriteHeader(http.StatusNoContent)
	}))

	for name, tc := range map[string]struct {
		bearer string
		status int
	}{
		"Dex ID token": {bearer: dex.sign(t), status: http.StatusNoContent},
		"opaque token": {bearer: "opaque-token", status: http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
			request.Header.Set("Authorization", "Bearer "+tc.bearer)
			recorder := httptest.NewRecorder()

			protected.ServeHTTP(recorder, request)

			require.Equal(t, tc.status, recorder.Code)
			if tc.status == http.StatusUnauthorized {
				require.Contains(t, recorder.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
			} else {
				require.Equal(t, tc.bearer, idToken)
			}
		})
	}
}

func TestProviderIDTokenFromContext_TrustedIssuerNotOpenIDProvider(t *testing.T) {
	dex := newOffIssuer(t)
	dex.entry.OpenIDProvider = false
	h := newOffHandler(t, nil, dex.entry)
	var err error
	protected := h.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err = ProviderIDTokenFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer "+dex.sign(t))

	protected.ServeHTTP(httptest.NewRecorder(), request)

	require.ErrorIs(t, err, ErrProviderIDTokenUnavailable)
}

func TestDynamicClientRegistrationOff(t *testing.T) {
	store := memory.New()
	srv, err := server.New(mock.NewProvider(), store, store, store, &server.Config{
		Issuer:                           "https://mcp.test.example",
		AllowPublicClientRegistration:    true,
		DisableDynamicClientRegistration: true,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Shutdown(context.WithoutCancel(t.Context())) })
	h := New(srv, nil)
	mux := http.NewServeMux()
	h.RegisterOAuthRoutes(mux, OAuthRoutesOptions{IncludeMetadata: true})

	require.Equal(t, http.StatusNotFound, serveStatus(t, mux, http.MethodPost, "/oauth/register"))
	require.Equal(t, http.StatusNotFound, serveStatus(t, http.HandlerFunc(h.ServeClientRegistration), http.MethodPost, "/oauth/register"))

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	require.Equal(t, http.StatusOK, recorder.Code)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &metadata))
	require.NotContains(t, metadata, "registration_endpoint")
	require.Contains(t, metadata, "token_endpoint")
}
