package server

import (
	"context"
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
}

func TestSelfIssuedExchangeClientStorageUnavailable(t *testing.T) {
	for _, fault := range storageFaults {
		for _, operation := range []string{"get_client", "is_client_revoked"} {
			t.Run(fault.name+"/"+operation, func(t *testing.T) {
				fixture := newFaultyGrantFixture(t)
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
				requireWithinDeadline(t, time.Since(started))
				fixture.faulty.Heal()
				result, err = fixture.srv.SelfIssuedExchange(t.Context(), request)
				require.NoError(t, err)
				require.NotEmpty(t, result.AccessToken)
			})
		}
	}
}
