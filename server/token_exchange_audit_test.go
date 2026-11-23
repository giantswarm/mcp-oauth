package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
)

func TestLocalExchangeFailureAuditContext(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		prepare      func(*Server, *SelfIssuedExchangeRequest, *stubTokenValidator)
	}{
		{name: "JWT mode", reason: "token_exchange_jwt_mode_required", prepare: func(service *Server, _ *SelfIssuedExchangeRequest, _ *stubTokenValidator) {
			service.Config.AccessTokenFormat = AccessTokenFormatOpaque
		}},
		{name: "unknown subject type", reason: "unsupported_subject_token_type", prepare: func(_ *Server, request *SelfIssuedExchangeRequest, _ *stubTokenValidator) {
			request.Subject.Type = "urn:example:unsupported"
		}},
		{name: "missing subject validator", reason: "unsupported_subject_token_type", prepare: func(service *Server, _ *SelfIssuedExchangeRequest, _ *stubTokenValidator) {
			delete(service.subjectValidators, SubjectTokenTypeIDToken)
		}},
		{name: "subject rejection", reason: "subject_token_validation_failed", prepare: func(_ *Server, _ *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			validator.byErr = map[string]error{"sub-tok": fmt.Errorf("subject rejected")}
		}},
		{name: "subject provider unavailable", reason: auditReasonProviderUnavailable, prepare: func(_ *Server, _ *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			validator.byErr = map[string]error{"sub-tok": ErrProviderUnavailable}
		}},
		{name: "subject provider timeout", reason: auditReasonProviderUnavailable, prepare: func(_ *Server, _ *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			validator.byErr = map[string]error{"sub-tok": context.DeadlineExceeded}
		}},
		{name: "actor rejection", reason: "actor_token_validation_failed", prepare: func(_ *Server, request *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			request.Actor = TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken}
			validator.byErr = map[string]error{"act-tok": fmt.Errorf("actor rejected")}
		}},
		{name: "actor provider unavailable", reason: auditReasonProviderUnavailable, prepare: func(_ *Server, request *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			request.Actor = TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken}
			validator.byErr = map[string]error{"act-tok": ErrProviderUnavailable}
		}},
		{name: "actor provider timeout", reason: auditReasonProviderUnavailable, prepare: func(_ *Server, request *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			request.Actor = TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken}
			validator.byErr = map[string]error{"act-tok": context.DeadlineExceeded}
		}},
		{name: "missing client", reason: "token_exchange_client_required", prepare: func(_ *Server, request *SelfIssuedExchangeRequest, _ *stubTokenValidator) {
			request.ClientID = ""
		}},
		{name: "unknown client", reason: "token_exchange_client_unknown", prepare: func(_ *Server, request *SelfIssuedExchangeRequest, _ *stubTokenValidator) {
			request.ClientID = "unknown"
		}},
		{name: "unknown actor type", reason: "unsupported_actor_token_type", prepare: func(_ *Server, request *SelfIssuedExchangeRequest, _ *stubTokenValidator) {
			request.Actor = TypedToken{Token: "act-tok", Type: "urn:example:unsupported"}
		}},
		{name: "key binding", reason: "token_exchange_subject_key_mismatch", prepare: func(_ *Server, _ *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			validator.byToken["sub-tok"].ConfirmationJKT = "subject-key"
		}},
		{name: "self renewal", reason: "token_exchange_self_renewal_denied", prepare: func(service *Server, _ *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			validator.byToken["sub-tok"].Issuer = service.Config.Issuer
		}},
		{name: "unverified email", reason: "token_exchange_unverified_subject_email", prepare: func(_ *Server, _ *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			validator.byToken["sub-tok"].Claims = &oidc.IDTokenClaims{Email: "person@example.com"}
		}},
		{name: "actor depth", reason: "token_exchange_actor_chain_invalid", prepare: func(_ *Server, _ *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			var chain *oidc.ActorClaim
			for range maxActorChainDepth + 1 {
				chain = &oidc.ActorClaim{Subject: "actor", Issuer: "https://issuer.example.com", Act: chain}
			}
			validator.byToken["sub-tok"].Claims = &oidc.IDTokenClaims{Act: chain}
		}},
		{name: "scope", reason: "token_exchange_scope_not_granted", prepare: func(_ *Server, request *SelfIssuedExchangeRequest, validator *stubTokenValidator) {
			validator.byToken["sub-tok"].AllowedScopes = []string{"read"}
			request.Scope = "admin"
		}},
		{name: "rate limit", reason: "token_exchange_rate_limited", prepare: func(service *Server, request *SelfIssuedExchangeRequest, _ *stubTokenValidator) {
			service.UserRateLimiter = security.NewRateLimiter(0, 1, nil)
			service.UserRateLimiter.Allow(service.bearerSessionID(request.Subject.Token))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, _ := newActorExchangeServer(t)
			request := SelfIssuedExchangeRequest{
				ClientID:        registerExchangeClient(t, service),
				SubjectExchange: SubjectExchange{Subject: TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken}},
			}
			validator := service.subjectValidators[SubjectTokenTypeIDToken].(*stubTokenValidator)
			test.prepare(service, &request, validator)
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			service.Auditor = security.NewAuditor(logger, true)
			if service.UserRateLimiter != nil {
				t.Cleanup(service.UserRateLimiter.Stop)
			}
			result, err := service.SelfIssuedExchange(t.Context(), request)
			require.Error(t, err)
			require.Nil(t, result)
			if test.reason == auditReasonProviderUnavailable {
				require.ErrorIs(t, err, ErrProviderUnavailable)
			}
			details := auditDetails(t, &logs, security.EventAuthFailure)
			require.Equal(t, request.ClientID, details["__client_id"])
			require.Equal(t, service.bearerSessionID(request.Subject.Token), details["session_id"])
			require.Equal(t, test.reason, details["reason"])
			require.Equal(t, "warning", details["severity"])
			require.Equal(t, GrantTypeTokenExchange, details["grant_type"])
			require.NotContains(t, logs.String(), security.EventTokenIssued)
		})
	}
}
