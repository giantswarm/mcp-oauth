package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func TestUpdateClientRegistrationAuditsChangedFieldNames(t *testing.T) {
	logger, logs := captureLogger()
	store := memory.New()
	t.Cleanup(store.Stop)
	srv, err := New(mock.NewProvider(), store, store, store, &Config{
		Issuer:                      "https://auth.example.com",
		DisableNonceEchoRequirement: true,
	}, logger)
	require.NoError(t, err)
	srv.Auditor = security.NewAuditor(logger, true)

	previous, _, err := srv.RegisterClient(t.Context(), "before", ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"mcp"}, "192.0.2.1", 10)
	require.NoError(t, err)
	previous.RegistrationAccessTokenHash = "previous-registration-hash"
	require.NoError(t, store.SaveClient(t.Context(), previous))

	updated := *previous
	updated.ClientName = "after"
	updated.JWKS = json.RawMessage(`{"keys":[]}`)
	updated.RegistrationAccessTokenHash = "rotated-registration-hash"
	logs.Reset()
	require.NoError(t, srv.UpdateClientRegistration(t.Context(), &updated, previous))

	var event string
	for line := range strings.Lines(logs.String()) {
		if strings.Contains(line, "event_type="+security.EventClientUpdated) {
			event = line
		}
	}
	require.NotEmpty(t, event, logs.String())
	require.Contains(t, event, "audit.client_id="+previous.ClientID)
	require.Contains(t, event, "client_name")
	require.Contains(t, event, "jwks")
	require.Contains(t, event, "registration_access_token")
	require.NotContains(t, event, "redirect_uris")
	require.NotContains(t, event, "rotated-registration-hash")
	require.NotContains(t, event, "after")
}
