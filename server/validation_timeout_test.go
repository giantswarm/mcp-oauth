package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// newValidationTimeoutServer builds a Server on mem (as tokenStore, or wrapped
// by it) whose provider blocks every userinfo and refresh call until the
// caller's context ends, the way an identity provider that accepted the
// connection but never answers does.
func newValidationTimeoutServer(t *testing.T, mem *memory.Store, tokenStore storage.TokenStore, timeout time.Duration) *Server {
	t.Helper()
	provider := mock.NewProvider()
	provider.ValidateTokenFunc = func(ctx context.Context, _ string) (*providers.UserInfo, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	provider.RefreshTokenFunc = func(ctx context.Context, _ string) (*oauth2.Token, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(mem.Stop)
	srv, err := New(provider, tokenStore, mem, mem, &Config{
		Issuer:                 "https://auth.example.com",
		TokenValidationTimeout: timeout,
	}, nil)
	require.NoError(t, err)
	return srv
}

// TestValidateToken_ProviderTimeout: a provider that does not answer turns
// into ErrProviderUnavailable once Config.TokenValidationTimeout has passed,
// not after the provider's own request timeout.
func TestValidateToken_ProviderTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{"configured", 2 * time.Second, 2 * time.Second},
		{"default", 0, DefaultTokenValidationTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				mem := memory.New()
				srv := newValidationTimeoutServer(t, mem, mem, tt.timeout)

				start := time.Now()
				_, err := srv.ValidateToken(t.Context(), "opaque-access-token")
				require.ErrorIs(t, err, ErrProviderUnavailable)
				require.Equal(t, tt.want, time.Since(start))
			})
		})
	}
}

// TestValidateToken_ExpiredTokenRefreshTimeout: a stored provider token past
// expiry needs a refresh before validation can proceed; a provider that does
// not answer it is ErrProviderUnavailable within the validation timeout, in
// both storage layouts.
func TestValidateToken_ExpiredTokenRefreshTimeout(t *testing.T) {
	expired := &oauth2.Token{
		AccessToken:  "dex-at",
		RefreshToken: "dex-rt",
		Expiry:       time.Now().Add(-time.Hour),
	}
	tests := []struct {
		name string
		seed func(t *testing.T, mem *memory.Store) storage.TokenStore
	}{
		{"unified layout", func(t *testing.T, mem *memory.Store) storage.TokenStore {
			seedProviderToken(t, mem, "issued-access-token", "user-1", expired)
			return mem
		}},
		{"legacy layout", func(t *testing.T, mem *memory.Store) storage.TokenStore {
			require.NoError(t, mem.SaveToken(t.Context(), "issued-access-token", expired))
			return legacyLayoutStore{
				Combined: mem, RefreshTokenFamilyStore: mem, TokenRevocationStore: mem,
				TokenFamilyRevocationStore: mem, TokenMetadataStore: mem, TokenMetadataGetter: mem,
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				expired.Expiry = time.Now().Add(-time.Hour)
				mem := memory.New()
				srv := newValidationTimeoutServer(t, mem, tt.seed(t, mem), 2*time.Second)

				start := time.Now()
				_, err := srv.ValidateToken(t.Context(), "issued-access-token")
				require.ErrorIs(t, err, ErrProviderUnavailable)
				require.Equal(t, 2*time.Second, time.Since(start))

				// The detached refresh keeps running past the caller's
				// deadline; let it end before the bubble closes.
				time.Sleep(providerRefreshWaitTimeout)
				synctest.Wait()
			})
		})
	}
}

// TestValidateToken_ExpiredTokenRefreshClassification: a refresh the
// provider did not serve is ErrProviderUnavailable; a refresh it rejected
// keeps the bearer rejected.
func TestValidateToken_ExpiredTokenRefreshClassification(t *testing.T) {
	tests := []struct {
		name            string
		status          int
		wantUnavailable bool
	}{
		{"provider 503", http.StatusServiceUnavailable, true},
		{"provider invalid_grant", http.StatusBadRequest, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mem := memory.New()
			t.Cleanup(mem.Stop)
			seedProviderToken(t, mem, "issued-access-token", "user-1", &oauth2.Token{
				AccessToken: "dex-at", RefreshToken: "dex-rt", Expiry: time.Now().Add(-time.Hour),
			})
			srv := newRefreshTestServer(t, mem, func(context.Context, string) (*oauth2.Token, error) {
				return nil, &oauth2.RetrieveError{Response: &http.Response{StatusCode: tt.status}}
			})

			_, err := srv.ValidateToken(t.Context(), "issued-access-token")
			require.Error(t, err)
			require.Equal(t, tt.wantUnavailable, errors.Is(err, ErrProviderUnavailable), "error: %v", err)
		})
	}
}

// unavailableJWKS serves 503 on every request and returns its URL and a JWKS
// client that trusts it.
func unavailableJWKS(t *testing.T) (string, *oidc.JWKSClient) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{
		HTTPClient:     srv.Client(),
		AllowPrivateIP: true,
	})
}

// TestValidateToken_TrustedIssuerJWKSUnavailable: a trusted issuer whose
// JWKS endpoint does not answer rejected nothing.
func TestValidateToken_TrustedIssuerJWKSUnavailable(t *testing.T) {
	const issuer = "https://kubernetes.default.svc.cluster.local"
	jwksURL, jwksClient := unavailableJWKS(t)

	srv, _, _ := setupFlowTestServer(t)
	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:             issuer,
		JwksURL:            jwksURL,
		AllowPrivateIPJWKS: true,
		AcceptedTypHeaders: []string{""},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v

	token := signSubjectTokenWithType(t, newTestECKey(t), "sa-key", "",
		saTokenClaims(issuer, "system:serviceaccount:ns:svc", srv.Config.GetResourceIdentifier()))

	_, err = srv.ValidateToken(t.Context(), token)
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

// TestValidateToken_ForwardedIDTokenJWKSUnavailable: a forwarded ID token
// whose provider JWKS endpoint does not answer is ErrProviderUnavailable,
// without a userinfo fallback that cannot validate an ID token.
func TestValidateToken_ForwardedIDTokenJWKSUnavailable(t *testing.T) {
	h := newForwardedTokenHarness(t)
	jwksURL, jwksClient := unavailableJWKS(t)
	h.provider.JWKSURIFunc = func(context.Context) (string, error) { return jwksURL, nil }
	h.srv.jwksClient = jwksClient

	var userinfoCalls atomic.Int32
	h.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
		userinfoCalls.Add(1)
		return nil, errors.New("userinfo must not be called")
	}

	now := time.Now()
	token := h.signToken(t, josejwt.Claims{
		Issuer:   h.issuer,
		Subject:  "user-1",
		Audience: josejwt.Audience{h.audience},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
	})

	_, err := h.srv.ValidateToken(t.Context(), token)
	require.ErrorIs(t, err, ErrProviderUnavailable)
	require.Zero(t, userinfoCalls.Load())
}

// TestIntrospectToken_ProviderUnavailable: introspecting an opaque token whose
// userinfo check the provider did not serve is ErrProviderUnavailable, not
// {"active": false}; a provider rejection stays inactive.
func TestIntrospectToken_ProviderUnavailable(t *testing.T) {
	tests := []struct {
		name            string
		status          int
		wantUnavailable bool
	}{
		{"userinfo 503", http.StatusServiceUnavailable, true},
		{"userinfo 401", http.StatusUnauthorized, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFaultyFixture(t, AccessTokenFormatOpaque)
			at := f.login(t).AccessToken
			f.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
				return nil, &providers.UserInfoStatusError{StatusCode: tt.status}
			}

			response, err := f.srv.IntrospectToken(t.Context(), at, f.clientID)
			if tt.wantUnavailable {
				require.ErrorIs(t, err, ErrProviderUnavailable)
				require.Nil(t, response)
				return
			}
			require.NoError(t, err)
			require.Equal(t, false, response[fieldActive])
		})
	}
}
