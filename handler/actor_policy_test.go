package handler

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

func TestActorPolicyHTTP(t *testing.T) {
	const issuer = "https://actors.example"
	var excessiveHistory *oidc.ActorClaim
	for range 11 {
		excessiveHistory = &oidc.ActorClaim{Subject: "prior", Act: excessiveHistory}
	}
	policy := &server.ActorPolicy{Issuers: []string{issuer}}
	var rejectedBody, rejectedChallenge string
	for _, test := range []struct {
		name   string
		actor  *oidc.ActorClaim
		policy *server.ActorPolicy
		allow  bool
	}{
		{name: "subject-only actor without policy", actor: &oidc.ActorClaim{Subject: "workload"}, allow: true},
		{name: "prior actor without issuer", actor: &oidc.ActorClaim{Issuer: issuer, Subject: "workload", Act: &oidc.ActorClaim{Subject: "prior"}}, policy: policy, allow: true},
		{name: "policy requires current subject", actor: &oidc.ActorClaim{Issuer: issuer}, policy: policy},
		{name: "policy requires current issuer", actor: &oidc.ActorClaim{Subject: "workload"}, policy: policy},
		{name: "policy refuses unlisted actor", actor: &oidc.ActorClaim{Issuer: "https://other.example", Subject: "workload"}, policy: policy},
		{name: "excessive history without policy", actor: excessiveHistory},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, bearer, logs := newExternalTokenHandler(t, slog.LevelInfo, true, test.actor, test.policy)
			handler.server.Auditor = security.NewAuditor(handler.logger, true)
			response, called := serveBearer(t, handler, bearer)
			if test.allow {
				require.Equal(t, http.StatusOK, response.Code)
				require.True(t, called)
				return
			}
			require.Equal(t, http.StatusUnauthorized, response.Code)
			require.False(t, called)
			require.Contains(t, response.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
			require.True(t, auditAuthFailureWithReason(t, logs, "trusted_issuer_actor_not_trusted"))
			if rejectedBody == "" {
				rejectedBody = response.Body.String()
				rejectedChallenge = response.Header().Get("WWW-Authenticate")
			}
			require.Equal(t, rejectedBody, response.Body.String())
			require.Equal(t, rejectedChallenge, response.Header().Get("WWW-Authenticate"))
		})
	}
}
