package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// newJWTIntrospectionServer wires a JWT-mode server, an opaque-mode mock
// provider, and three registered clients (token owner, probing client,
// allowlisted resource server). It returns the server and the issued JWT
// access token.
func newJWTIntrospectionServer(t *testing.T) (srv *Server, accessToken, ownerClientID, probingClientID, resourceServerID string) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       generateRSAKey(t),
		AccessTokenSigningKeyID:     "kid-introspect",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		AccessTokenTTL:              3600,
		ClockSkewGracePeriod:        5,
	}
	require.NoError(t, cfg.Validate())

	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)

	owner, _, err := srv.RegisterClient(context.Background(), "Owner", ClientTypeConfidential, "", []string{"https://example.com/cb-owner"}, []string{"openid"}, "192.168.1.1", 10)
	require.NoError(t, err)
	probe, _, err := srv.RegisterClient(context.Background(), "Probe", ClientTypeConfidential, "", []string{"https://example.com/cb-probe"}, []string{"openid"}, "192.168.1.2", 10)
	require.NoError(t, err)
	rs, _, err := srv.RegisterClient(context.Background(), "Resource Server", ClientTypeConfidential, "", []string{"https://example.com/cb-rs"}, []string{"openid"}, "192.168.1.3", 10)
	require.NoError(t, err)

	now := time.Now().UTC()
	issuer, err := newJWTIssuer(cfg)
	require.NoError(t, err)
	token, err := issuer.Issue(context.Background(), AccessTokenClaims{
		Subject:   "user-42",
		ClientID:  owner.ClientID,
		Audience:  cfg.GetResourceIdentifier(),
		Scopes:    []string{"openid", "email"},
		Email:     "user@example.com",
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	})
	require.NoError(t, err)

	return srv, token, owner.ClientID, probe.ClientID, rs.ClientID
}

func TestServer_IntrospectToken_JWTPath_OwnerSeesProjection(t *testing.T) {
	srv, token, owner, _, _ := newJWTIntrospectionServer(t)

	response := srv.IntrospectToken(context.Background(), token, owner)

	require.Equal(t, true, response["active"])
	require.Equal(t, "Bearer", response["token_type"])
	require.Equal(t, owner, response["client_id"])
	require.Equal(t, "user-42", response["sub"])
	require.Equal(t, "https://auth.example.com", response["iss"])
	require.Equal(t, "openid email", response["scope"])
	require.Equal(t, "user@example.com", response["email"])
	require.Equal(t, srv.Config.GetResourceIdentifier(), response["aud"])
	require.Contains(t, response, "exp")
	require.Contains(t, response, "iat")
	// exp / iat must be int64 — copyClaimUnixTime converts the float64 claim.
	_, expIsInt := response["exp"].(int64)
	require.True(t, expIsInt, "exp should be int64 after projection (got %T)", response["exp"])
}

func TestServer_IntrospectToken_JWTPath_CrossClientDenied(t *testing.T) {
	srv, token, _, probe, _ := newJWTIntrospectionServer(t)

	response := srv.IntrospectToken(context.Background(), token, probe)

	require.Equal(t, false, response["active"])
	for _, leaked := range []string{"sub", "email", "client_id", "scope", "aud", "iss", "exp", "iat", "token_type"} {
		require.NotContains(t, response, leaked, "cross-client JWT probe leaked %q", leaked)
	}
}

func TestServer_IntrospectToken_JWTPath_AllowlistedResourceServer(t *testing.T) {
	srv, token, owner, _, rs := newJWTIntrospectionServer(t)
	srv.Config.IntrospectionResourceServers = []string{rs}

	response := srv.IntrospectToken(context.Background(), token, rs)

	require.Equal(t, true, response["active"])
	require.Equal(t, owner, response["client_id"], "client_id must reflect the token's owner, not the introspecting RS")
}

func TestServer_Config_Validate_EmptyIntrospectionResourceServerEntryFailsClosed(t *testing.T) {
	cfg := &Config{
		Issuer:                       "https://auth.example.com",
		IntrospectionResourceServers: []string{"valid-client", ""},
	}
	err := cfg.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "IntrospectionResourceServers[1] is empty")
}
