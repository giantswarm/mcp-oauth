package handler

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
)

func TestAuthenticationRejectionsRetainAuditReasons(t *testing.T) {
	for _, test := range []struct {
		name, endpoint, reason string
		publicClient           bool
		duplicateCredentials   bool
	}{
		{name: "missing introspection authentication", endpoint: server.EndpointPathIntrospect, reason: "introspection_missing_auth"},
		{name: "public introspection client", endpoint: server.EndpointPathIntrospect, reason: "introspection_missing_credentials", publicClient: true},
		{name: "missing revocation identification", endpoint: server.EndpointPathRevoke, reason: "revocation_missing_auth"},
		{name: "ambiguous revocation credentials", endpoint: server.EndpointPathRevoke, reason: "revocation_invalid_credentials", duplicateCredentials: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			t.Cleanup(store.Stop)
			form := url.Values{"token": {"unknown"}}
			if test.publicClient {
				client, _, err := handler.server.RegisterClient(t.Context(), "audit", "public", "none", []string{"testapp://callback"}, nil, "192.0.2.1", 100)
				require.NoError(t, err)
				form.Set("client_id", client.ClientID)
			}
			var audit bytes.Buffer
			handler.server.Auditor = security.NewAuditor(slog.New(slog.NewJSONHandler(&audit, nil)), true)
			request := httptest.NewRequest(http.MethodPost, test.endpoint, strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if test.duplicateCredentials {
				request.Header.Add("Authorization", "Basic invalid")
				request.Header.Add("Authorization", "Basic invalid")
			}
			response := httptest.NewRecorder()
			if test.endpoint == server.EndpointPathIntrospect {
				handler.ServeTokenIntrospection(response, request)
			} else {
				handler.ServeTokenRevocation(response, request)
			}
			require.Contains(t, []int{http.StatusUnauthorized, http.StatusBadRequest}, response.Code)
			events := auditEvents(t, &audit)
			require.Len(t, events, 1)
			require.Equal(t, security.EventAuthFailure, events[0]["event_type"])
			require.Equal(t, test.reason, events[0]["details"].(map[string]any)["reason"])
		})
	}
}

func TestRefreshMissingCredentialsRetainsHighSeverityAudit(t *testing.T) {
	handler, store := setupTestHandler(t)
	t.Cleanup(store.Stop)
	client, _, err := handler.server.RegisterClient(t.Context(), "audit", "confidential", "client_secret_post", []string{"testapp://callback"}, nil, "192.0.2.1", 100)
	require.NoError(t, err)
	var audit bytes.Buffer
	handler.server.Auditor = security.NewAuditor(slog.New(slog.NewJSONHandler(&audit, nil)), true)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"unconsumed"}, "client_id": {client.ClientID}}
	request := httptest.NewRequest(http.MethodPost, server.EndpointPathToken, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeToken(response, request)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	events := auditEvents(t, &audit)
	require.Len(t, events, 2)
	details := events[0]["details"].(map[string]any)
	require.Equal(t, "high", details["severity"])
	require.Equal(t, "refresh_token", details["endpoint"])
	require.Equal(t, true, details["auth_missing"])
	require.Equal(t, "confidential", details["client_type"])
	require.Equal(t, "confidential_client_refresh_missing_auth", events[1]["details"].(map[string]any)["reason"])
}

func TestManagementInvalidMetadataErrorCategory(t *testing.T) {
	for _, field := range []string{"client_name", "token_endpoint_auth_method"} {
		t.Run(field, func(t *testing.T) {
			handler := setupManagementHandler(t)
			registered, err := handler.server.RegisterClientV2(t.Context(), "managed", "confidential", "client_secret_basic", []string{"testapp://callback"}, nil, "192.0.2.1", 100)
			require.NoError(t, err)
			metadata := map[string]any{"client_id": registered.Client.ClientID, "client_name": "valid", "redirect_uris": []string{"testapp://callback"}, "token_endpoint_auth_method": "client_secret_basic"}
			metadata[field] = "unsupported"
			if field == "client_name" {
				metadata[field] = "invalid\x00name"
			}
			response := managementCredentialRequest(t, handler, http.MethodPut, registered.Client.ClientID, registered.RegistrationToken, metadata)
			require.Equal(t, http.StatusBadRequest, response.Code)
			var body map[string]any
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			require.Equal(t, "invalid_client_metadata", body["error"])
			currentCredentialResponse(t, managementCredentialRequest(t, handler, http.MethodGet, registered.Client.ClientID, registered.RegistrationToken, nil), registered.ClientSecret)
		})
	}
}

func auditEvents(t *testing.T, output *bytes.Buffer) []map[string]any {
	t.Helper()
	var events []map[string]any
	decoder := json.NewDecoder(output)
	for decoder.More() {
		var line map[string]any
		require.NoError(t, decoder.Decode(&line))
		events = append(events, line["audit"].(map[string]any))
	}
	return events
}
