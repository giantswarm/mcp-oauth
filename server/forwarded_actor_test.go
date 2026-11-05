package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
)

// withProviderActorPolicy makes the harness provider's issuer a trusted issuer
// carrying policy.
func (h *forwardedTokenHarness) withProviderActorPolicy(t *testing.T, policy *ActorPolicy) {
	t.Helper()
	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           h.issuer,
		JwksURL:          h.jwksServer.URL,
		AllowedAudiences: []string{"another-audience"},
		Actors:           policy,
	}}, h.srv.jwksClient)
	require.NoError(t, err)
	h.srv.trustedIssuerValidator = v
}

func (h *forwardedTokenHarness) signDelegatedToken(t *testing.T, act *oidc.ActorClaim, scope oidc.ScopeClaim) string {
	t.Helper()
	return signTestRS256Token(t, h.privateKey, h.keyID, oidc.IDTokenClaims{
		Claims: h.validClaims(),
		Act:    act,
		Scope:  scope,
	})
}

func TestAcceptForwardedIDToken_ActorPolicy(t *testing.T) {
	listed := &oidc.ActorClaim{Issuer: "https://actors.example", Subject: "workload-1"}
	unlisted := &oidc.ActorClaim{Issuer: "https://other.example", Subject: "x"}

	tests := []struct {
		name    string
		noEntry bool
		policy  *ActorPolicy
		act     *oidc.ActorClaim
		wantErr bool
	}{
		{name: "no trusted issuer entry", noEntry: true, act: unlisted},
		{name: "entry without policy", policy: nil, act: unlisted},
		{name: "listed current actor", policy: &ActorPolicy{Issuers: []string{"https://actors.example"}}, act: listed},
		{name: "unlisted current actor", policy: &ActorPolicy{Issuers: []string{"https://actors.example"}}, act: unlisted, wantErr: true},
		{name: "empty list refuses act", policy: &ActorPolicy{}, act: listed, wantErr: true},
		{name: "empty list accepts a token without act", policy: &ActorPolicy{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newForwardedTokenHarness(t)
			if !tc.noEntry {
				h.withProviderActorPolicy(t, tc.policy)
			}

			acc, err := h.srv.AcceptForwardedIDToken(t.Context(), h.signDelegatedToken(t, tc.act, nil))
			if tc.wantErr {
				require.ErrorIs(t, err, ErrActorNotTrusted)
				require.Equal(t, instrumentation.ForwardedIDTokenResultActorNotTrusted, classifyForwardedTokenError(err))
				return
			}
			require.NoError(t, err)
			require.Equal(t, "user-subject-123", acc.Subject)
		})
	}
}

// A forwarded token refused by the actor policy is rejected outright, never
// handed to the provider's userinfo endpoint, which would accept it without
// its act claim.
func TestValidateForwardedIDTokenBranch_ActorRefusalIsFinal(t *testing.T) {
	h := newForwardedTokenHarness(t)
	h.withProviderActorPolicy(t, &ActorPolicy{Issuers: []string{"https://actors.example"}})
	logger, logBuf := captureLogger()
	h.srv.Auditor = security.NewAuditor(logger, true)

	userInfo, err := h.srv.validateForwardedIDTokenBranch(t.Context(),
		h.signDelegatedToken(t, &oidc.ActorClaim{Issuer: "https://other.example", Subject: "x"}, nil))
	require.ErrorIs(t, err, ErrActorNotTrusted)
	require.Nil(t, userInfo)
	require.True(t, containsAuthFailure(logBuf.String(), "forwarded_id_token_actor_not_trusted"), "audit log: %s", logBuf.String())
}

func TestAcceptForwardedIDToken_Scopes(t *testing.T) {
	h := newForwardedTokenHarness(t)

	acc, err := h.srv.AcceptForwardedIDToken(t.Context(), h.signDelegatedToken(t, nil, oidc.ScopeClaim{"tools:read", "tools:write"}))
	require.NoError(t, err)
	require.Equal(t, []string{"tools:read", "tools:write"}, acc.UserInfo.Scopes)
}

func TestUserInfoFromJWTClaims_Scopes(t *testing.T) {
	info := userInfoFromJWTClaims(map[string]any{claimSub: "user", "scope": "openid tools:read"})
	require.Equal(t, []string{"openid", "tools:read"}, info.Scopes)

	info = userInfoFromJWTClaims(map[string]any{claimSub: "user", "scope": []any{"openid", "tools:read"}})
	require.Equal(t, []string{"openid", "tools:read"}, info.Scopes)

	info = userInfoFromJWTClaims(map[string]any{claimSub: "user"})
	require.Empty(t, info.Scopes)
}
