package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

func TestTrustedIssuerBearer_ActorProfile(t *testing.T) {
	const actorIssuer = "https://actors.example"
	chain := func(depth int) *oidc.ActorClaim {
		var actor *oidc.ActorClaim
		for range depth {
			actor = &oidc.ActorClaim{Issuer: actorIssuer, Subject: "workload", Act: actor}
		}
		return actor
	}
	actors := []struct {
		name              string
		actor             *oidc.ActorClaim
		refusedWithPolicy bool
		tooDeep           bool
	}{
		{name: "no actor"},
		{name: "subject only", actor: &oidc.ActorClaim{Subject: "workload"}, refusedWithPolicy: true},
		{name: "issuer only", actor: &oidc.ActorClaim{Issuer: actorIssuer}, refusedWithPolicy: true},
		{name: "prior subject only", actor: &oidc.ActorClaim{Issuer: actorIssuer, Subject: "workload", Act: &oidc.ActorClaim{Subject: "prior"}}},
		{name: "prior issuer only", actor: &oidc.ActorClaim{Issuer: actorIssuer, Subject: "workload", Act: &oidc.ActorClaim{Issuer: "https://prior.example"}}},
		{name: "maximum depth", actor: chain(maxActorChainDepth)},
		{name: "excessive depth", actor: chain(maxActorChainDepth + 1), tooDeep: true},
	}
	paths := []struct {
		name     string
		validate func(*testing.T, *forwardedTokenHarness, string) (*providers.UserInfo, error)
	}{
		{name: "ValidateToken", validate: func(t *testing.T, harness *forwardedTokenHarness, token string) (*providers.UserInfo, error) {
			return harness.srv.ValidateToken(t.Context(), token)
		}},
		{name: "AcceptTrustedIssuerToken", validate: func(t *testing.T, harness *forwardedTokenHarness, token string) (*providers.UserInfo, error) {
			accepted, err := harness.srv.AcceptTrustedIssuerToken(t.Context(), token)
			if err != nil {
				return nil, err
			}
			return accepted.UserInfo, nil
		}},
		{name: "AcceptForwardedIDToken", validate: func(t *testing.T, harness *forwardedTokenHarness, token string) (*providers.UserInfo, error) {
			accepted, err := harness.srv.AcceptForwardedIDToken(t.Context(), token)
			if err != nil {
				return nil, err
			}
			return accepted.UserInfo, nil
		}},
	}
	for _, path := range paths {
		for _, policy := range []*ActorPolicy{nil, {Issuers: []string{actorIssuer}}} {
			for _, actor := range actors {
				name := path.name + "/no policy/" + actor.name
				if policy != nil {
					name = path.name + "/policy/" + actor.name
				}
				t.Run(name, func(t *testing.T) {
					harness := newForwardedTokenHarness(t)
					validator, err := newOIDCValidatorWithClient([]TrustedIssuer{{
						Issuer: harness.issuer, JwksURL: harness.jwksServer.URL,
						AllowedAudiences: []string{harness.audience}, AcceptedTypHeaders: []string{"JWT"}, Actors: policy,
					}}, harness.srv.jwksClient)
					require.NoError(t, err)
					harness.srv.trustedIssuerValidator = validator
					harness.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
						t.Error("provider userinfo reached")
						return nil, errors.New("unexpected userinfo call")
					}
					info, err := path.validate(t, harness, harness.signDelegatedToken(t, actor.actor, nil))
					if actor.tooDeep || policy != nil && actor.refusedWithPolicy {
						require.ErrorIs(t, err, ErrActorNotTrusted)
						require.Nil(t, info)
						return
					}
					require.NoError(t, err)
					require.Equal(t, "user-subject-123", info.ID)
					require.Equal(t, actor.actor != nil, info.IsOBO())
					if actor.actor != nil {
						require.Equal(t, actor.actor.Issuer, info.ActorIssuer)
						require.Equal(t, actor.actor.Subject, info.ActorSubject)
						if actor.actor.Act != nil {
							require.Equal(t, actor.actor.Act.Issuer, info.ActorChain[1].Issuer)
							require.Equal(t, actor.actor.Act.Subject, info.ActorChain[1].Subject)
						}
					}
				})
			}
		}
	}
}

func TestAcceptForwardedIDToken_ActorWithoutTrustedIssuerEntry(t *testing.T) {
	harness := newForwardedTokenHarness(t)
	harness.srv.trustedIssuerValidator = nil
	accepted, err := harness.srv.AcceptForwardedIDToken(t.Context(), harness.signDelegatedToken(t, &oidc.ActorClaim{Subject: "workload"}, nil))
	require.NoError(t, err)
	require.Equal(t, "workload", accepted.UserInfo.ActorSubject)
	require.Empty(t, accepted.UserInfo.ActorIssuer)
}

func TestActorFromJWTClaim_DepthAndShape(t *testing.T) {
	for _, invalid := range []any{nil, "actor", []any{}, map[string]any{"sub": 42}} {
		_, err := actorFromJWTClaim(invalid)
		require.Error(t, err)
	}
	var actor *oidc.ActorClaim
	for depth := 1; depth <= maxActorChainDepth+1; depth++ {
		actor = &oidc.ActorClaim{Subject: "workload", Act: actor}
		_, err := actorFromJWTClaim(actor)
		if depth > maxActorChainDepth {
			require.ErrorIs(t, err, errInvalidActorClaim)
		} else {
			require.NoError(t, err)
		}
	}
}
