package server

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

type retiredExchangeClientStore struct {
	storage.ClientStore
}

func (retiredExchangeClientStore) IsClientRevoked(context.Context, string) (bool, error) {
	return true, nil
}

func TestSelfIssuedExchangeRetiredClientAudit(t *testing.T) {
	service, _ := newActorExchangeServer(t)
	clientID := registerExchangeClient(t, service)
	logger, logs := captureLogger()
	service.Auditor = security.NewAuditor(logger, true)
	service.clientStore = retiredExchangeClientStore{ClientStore: service.clientStore}
	result, err := service.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		ClientID: clientID,
		SubjectExchange: SubjectExchange{
			Subject: TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
			Scope:   "read",
		},
	})
	require.ErrorIs(t, err, ErrExchangeClientRequired)
	require.Nil(t, result)
	require.True(t, containsAuthFailure(logs.String(), "token_exchange_client_revoked"))
	require.Contains(t, logs.String(), "severity:warning")
	require.Contains(t, logs.String(), clientID)
	require.Contains(t, logs.String(), GrantTypeTokenExchange)
	require.Contains(t, logs.String(), service.bearerSessionID("sub-tok"))
}

func TestSelfIssuedExchangeClientStorageUnavailable(t *testing.T) {
	for _, fault := range storageFaults {
		for _, operation := range []string{"get_client", "is_client_revoked"} {
			t.Run(fault.name+"/"+operation, func(t *testing.T) {
				fixture := newFaultyGrantFixture(t)
				var logs bytes.Buffer
				fixture.srv.Auditor = security.NewAuditor(slog.New(slog.NewJSONHandler(&logs, nil)), true)
				fixture.srv.subjectValidators[SubjectTokenTypeIDToken] = &stubTokenValidator{byToken: map[string]*SubjectIdentity{
					"subject": {Subject: "person", Issuer: "https://issuer.example.com"},
				}}
				request := SelfIssuedExchangeRequest{
					ClientID: fixture.clientID,
					SubjectExchange: SubjectExchange{
						Subject: TypedToken{Token: "subject", Type: SubjectTokenTypeIDToken},
						Scope:   "openid",
					},
				}
				fixture.faulty.Fail(storagemock.OnOperation(operation, fault.fault))
				started := time.Now()
				result, err := fixture.srv.SelfIssuedExchange(t.Context(), request)
				requireUnavailable(t, err)
				require.Nil(t, result)
				details := auditDetails(t, &logs, security.EventAuthFailure)
				require.Equal(t, request.ClientID, details["__client_id"])
				require.Equal(t, fixture.srv.bearerSessionID("subject"), details["session_id"])
				require.Equal(t, GrantTypeTokenExchange, details["grant_type"])
				require.Equal(t, "warning", details["severity"])
				requireWithinDeadline(t, time.Since(started))
				fixture.faulty.Heal()
				result, err = fixture.srv.SelfIssuedExchange(t.Context(), request)
				require.NoError(t, err)
				require.NotEmpty(t, result.AccessToken)
			})
		}
	}
}

func TestSelfIssuedExchangeRequiresRegisteredExchangeGrant(t *testing.T) {
	service, _ := newActorExchangeServer(t)
	logger, logs := captureLogger()
	service.Auditor = security.NewAuditor(logger, true)
	registered, _, err := service.RegisterClient(t.Context(), "dynamic", ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"read"}, "192.0.2.1", 10)
	require.NoError(t, err)

	result, err := service.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		ClientID: registered.ClientID,
		SubjectExchange: SubjectExchange{
			Subject: TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
			Scope:   "read",
		},
	})
	require.ErrorIs(t, err, ErrExchangeGrantNotRegistered)
	require.Nil(t, result)
	require.True(t, containsAuthFailure(logs.String(), "token_exchange_grant_not_registered"))
	require.Contains(t, logs.String(), registered.ClientID)
}
