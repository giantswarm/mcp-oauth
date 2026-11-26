package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
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

// A token from an issuer that is both the provider and a trusted issuer, with
// an act the policy refuses, is rejected with its own audit reason and never
// reaches the provider's userinfo endpoint, which would accept it without its
// act claim.
func TestTrustedIssuerBearer_ActorRefusal(t *testing.T) {
	unlisted := &oidc.ActorClaim{Issuer: "https://other.example", Subject: "x"}

	tests := []struct {
		name     string
		validate func(h *forwardedTokenHarness, token string) error
	}{
		{name: "ValidateToken", validate: func(h *forwardedTokenHarness, token string) error {
			_, err := h.srv.ValidateToken(t.Context(), token)
			return err
		}},
		{name: "AcceptTrustedIssuerToken", validate: func(h *forwardedTokenHarness, token string) error {
			_, err := h.srv.AcceptTrustedIssuerToken(t.Context(), token)
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newForwardedTokenHarness(t)
			v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
				Issuer:           h.issuer,
				JwksURL:          h.jwksServer.URL,
				AllowedAudiences: []string{h.audience},
				Actors:           &ActorPolicy{Issuers: []string{"https://actors.example"}},
			}}, h.srv.jwksClient)
			require.NoError(t, err)
			h.srv.trustedIssuerValidator = v
			h.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
				t.Error("provider userinfo reached")
				return nil, errors.New("unexpected userinfo call")
			}
			logger, logBuf := captureLogger()
			h.srv.Auditor = security.NewAuditor(logger, true)

			err = tc.validate(h, h.signDelegatedToken(t, unlisted, nil))
			require.ErrorIs(t, err, ErrActorNotTrusted)
			require.True(t, containsAuthFailure(logBuf.String(), auditReasonTrustedIssuerActorNotTrusted), "audit log: %s", logBuf.String())
		})
	}
}

func TestAcceptForwardedIDToken_Scopes(t *testing.T) {
	h := newForwardedTokenHarness(t)

	acc, err := h.srv.AcceptForwardedIDToken(t.Context(), h.signDelegatedToken(t, nil, oidc.ScopeClaim{"tools:read", "tools:write"}))
	require.NoError(t, err)
	require.Equal(t, []string{"tools:read", "tools:write"}, acc.UserInfo.Scopes)
}

func TestUserInfoFromJWTClaims_Scopes(t *testing.T) {
	tests := []struct {
		name    string
		scope   any
		want    []string
		wantErr bool
	}{
		{name: "space-delimited string", scope: "openid tools:read", want: []string{"openid", "tools:read"}},
		{name: "absent"},
		{name: "number refused", scope: 42.0, wantErr: true},
		{name: "array of strings refused", scope: []any{"openid", "tools:read"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{claimSub: "user"}
			if tc.scope != nil {
				claims["scope"] = tc.scope
			}
			info, err := userInfoFromJWTClaims(claims)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, info.Scopes)
		})
	}
}
