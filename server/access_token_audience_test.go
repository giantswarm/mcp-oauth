package server

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// newJWTModeServer builds a server in JWT access token mode with the given
// resource identifier (empty string leaves it unset so GetResourceIdentifier
// falls back to the issuer).
func newJWTModeServer(t *testing.T, resourceIdentifier string) *Server {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          resourceIdentifier,
		SupportedScopes:             []string{"openid"},
		AccessTokenTTL:              600,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       generateRSAKey(t),
		AccessTokenSigningKeyID:     "test-kid-1",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}

	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)
	return srv
}

func parseAudience(t *testing.T, srv *Server, tokenString string) josejwt.Audience {
	t.Helper()

	parsed, err := josejwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)

	var claims josejwt.Claims
	require.NoError(t, parsed.Claims(srv.Config.AccessTokenSigningKey.Public(), &claims))
	return claims.Audience
}

// TestIssueAccessToken_DefaultsAudienceToResourceIdentifier verifies that
// access tokens issued for grants without an RFC 8707 resource parameter
// still carry an aud claim (required by RFC 9068 §2.2), defaulting to the
// server's own resource identifier. Clients using generic OAuth libraries
// that never send a resource parameter would otherwise receive tokens that
// downstream JWT validators (e.g. gateways fronting the resource server)
// reject with an audience mismatch.
func TestIssueAccessToken_DefaultsAudienceToResourceIdentifier(t *testing.T) {
	now := time.Now().UTC()

	t.Run("empty audience defaults to ResourceIdentifier", func(t *testing.T) {
		srv := newJWTModeServer(t, "https://api.example.com/mcp")

		tokenString, err := srv.issueAccessToken(t.Context(), accessTokenIssueParams{
			UserID:    "user-42",
			ClientID:  "client-abc",
			Audience:  "",
			ExpiresAt: now.Add(10 * time.Minute),
		})
		require.NoError(t, err)
		require.Equal(t, josejwt.Audience{"https://api.example.com/mcp"}, parseAudience(t, srv, tokenString))
	})

	t.Run("empty audience falls back to issuer without ResourceIdentifier", func(t *testing.T) {
		srv := newJWTModeServer(t, "")

		tokenString, err := srv.issueAccessToken(t.Context(), accessTokenIssueParams{
			UserID:    "user-42",
			ClientID:  "client-abc",
			Audience:  "",
			ExpiresAt: now.Add(10 * time.Minute),
		})
		require.NoError(t, err)
		require.Equal(t, josejwt.Audience{"https://auth.example.com"}, parseAudience(t, srv, tokenString))
	})

	t.Run("explicit audience is preserved", func(t *testing.T) {
		srv := newJWTModeServer(t, "https://api.example.com/mcp")

		tokenString, err := srv.issueAccessToken(t.Context(), accessTokenIssueParams{
			UserID:    "user-42",
			ClientID:  "client-abc",
			Audience:  "https://other.example.com",
			ExpiresAt: now.Add(10 * time.Minute),
		})
		require.NoError(t, err)
		require.Equal(t, josejwt.Audience{"https://other.example.com"}, parseAudience(t, srv, tokenString))
	})
}
