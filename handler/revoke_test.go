package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
)

func TestHandler_ServeTokenRevocation_InvalidMethod(t *testing.T) {
	handler, store := setupTestHandler(t)
	defer store.Stop()

	req := httptest.NewRequest(http.MethodGet, "/revoke", nil)
	w := httptest.NewRecorder()

	handler.ServeTokenRevocation(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandler_ServeTokenRevocation_Success(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, secret, err := handler.server.RegisterClient(
		ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Create a refresh token
	refreshToken := testutil.GenerateRandomString(32)
	err = store.SaveRefreshToken(ctx, refreshToken, "test-user-123", time.Now().Add(90*24*time.Hour))
	if err != nil {
		t.Fatalf("SaveRefreshToken() error = %v", err)
	}

	// Revoke the token
	formData := url.Values{}
	formData.Set("token", refreshToken)
	formData.Set("token_type_hint", "refresh_token")

	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, secret)
	w := httptest.NewRecorder()

	handler.ServeTokenRevocation(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandler_ServeTokenIntrospection(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	// Register a client
	client, secret, err := handler.server.RegisterClient(
		ctx,
		"Test Client",
		"confidential",
		"", // tokenEndpointAuthMethod
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	// Test introspection with invalid method
	req := httptest.NewRequest(http.MethodGet, "/introspect", nil)
	w := httptest.NewRecorder()

	handler.ServeTokenIntrospection(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}

	// Test introspection with POST but missing token - should return error
	formData := url.Values{}

	req = httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, secret)
	w = httptest.NewRecorder()

	handler.ServeTokenIntrospection(w, req)

	// Missing token parameter returns 400
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	// Test introspection with missing client auth
	formData = url.Values{}
	formData.Set("token", "some-token")

	req = httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()

	handler.ServeTokenIntrospection(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandler_ServeTokenIntrospection_BasicFormClientIDMismatchRejected(t *testing.T) {
	ctx := context.Background()

	handler, store := setupTestHandler(t)
	defer store.Stop()

	client, secret, err := handler.server.RegisterClient(ctx, "Introspect Client", "confidential", "", []string{"https://example.com/cb"}, []string{"openid"}, "192.168.1.5", 10)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("token", "any-opaque-token")
	form.Set("client_id", "form-value-does-not-match")

	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ClientID, secret)
	w := httptest.NewRecorder()

	handler.ServeTokenIntrospection(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	var response map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	require.Equal(t, constants.ErrorCodeInvalidClient, response["error"])
	require.Contains(t, response["error_description"], "does not match")
}

func TestHandler_ServeTokenIntrospection_OpaquePath(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                  string
		requester             string // "owner", "probe", "rs" — picks which client makes the request
		allowlistResourceSrv  bool   // wire IntrospectionResourceServers with the rs client
		wantActive            bool
		wantFieldsPresent     []string // beyond "active"
		wantFieldsAbsent      []string
		wantClientIDIsTokenRS bool // when active, assert client_id is the token's owner not requester
	}{
		{
			name:              "token owner sees full RFC 7662 §2.2 projection",
			requester:         "owner",
			wantActive:        true,
			wantFieldsPresent: []string{"client_id", "sub", "token_type", "scope", "aud", "iss", "exp", "iat"},
		},
		{
			name:             "cross-client probe denied — no field leakage",
			requester:        "probe",
			wantActive:       false,
			wantFieldsAbsent: []string{"sub", "email", "email_verified", "name", "client_id", "scope", "aud", "iss", "exp", "iat", "token_type"},
		},
		{
			name:                  "allowlisted resource server sees token-owner client_id",
			requester:             "rs",
			allowlistResourceSrv:  true,
			wantActive:            true,
			wantFieldsPresent:     []string{"client_id", "sub"},
			wantClientIDIsTokenRS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, store := setupTestHandler(t)
			defer store.Stop()

			tokenOwner, ownerSecret, err := handler.server.RegisterClient(ctx, "Owner Client", "confidential", "", []string{"https://example.com/cb-owner"}, []string{"openid"}, "192.168.1.1", 10)
			require.NoError(t, err)
			probingClient, probingSecret, err := handler.server.RegisterClient(ctx, "Probing Client", "confidential", "", []string{"https://example.com/cb-probe"}, []string{"openid"}, "192.168.1.2", 10)
			require.NoError(t, err)
			resourceServer, resourceSecret, err := handler.server.RegisterClient(ctx, "Resource Server", "confidential", "", []string{"https://example.com/cb-rs"}, []string{"openid"}, "192.168.1.3", 10)
			require.NoError(t, err)

			if tt.allowlistResourceSrv {
				handler.config.IntrospectionResourceServers = []string{resourceServer.ClientID}
			}

			const accessToken = "opaque-access-token"
			expiry := time.Now().Add(45 * time.Minute).Truncate(time.Second)
			audience := testIssuer
			scopes := []string{"openid", "email", "profile"}
			issuedAt := seedOpaqueIntrospectionToken(t, store, accessToken, "user-1", tokenOwner.ClientID, audience, scopes, expiry)

			form := url.Values{}
			form.Set("token", accessToken)
			req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			switch tt.requester {
			case "owner":
				req.SetBasicAuth(tokenOwner.ClientID, ownerSecret)
			case "probe":
				req.SetBasicAuth(probingClient.ClientID, probingSecret)
			case "rs":
				req.SetBasicAuth(resourceServer.ClientID, resourceSecret)
			}

			w := httptest.NewRecorder()
			handler.ServeTokenIntrospection(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			require.Contains(t, w.Header().Get("Cache-Control"), "no-store",
				"RFC 7662 §2.2 requires Cache-Control: no-store on introspection responses")
			require.Equal(t, "no-cache", w.Header().Get("Pragma"),
				"HTTP/1.0 intermediaries honour Pragma: no-cache")

			var response map[string]any
			require.NoError(t, json.NewDecoder(w.Body).Decode(&response))

			active, _ := response["active"].(bool)
			require.Equal(t, tt.wantActive, active, "response: %v", response)

			for _, key := range tt.wantFieldsPresent {
				require.Contains(t, response, key, "expected %q present (response=%v)", key, response)
			}
			for _, key := range tt.wantFieldsAbsent {
				require.NotContains(t, response, key, "denied probe leaked %q (response=%v)", key, response)
			}

			if tt.wantActive {
				require.Equal(t, "Bearer", response["token_type"])
				if tt.wantClientIDIsTokenRS {
					require.Equal(t, tokenOwner.ClientID, response["client_id"],
						"client_id must reflect the token's owner, not the introspecting RS")
				}
				if scope, ok := response["scope"].(string); ok {
					require.Equal(t, helpers.JoinScopes(scopes), scope)
				}
				if exp, ok := response["exp"].(float64); ok {
					require.Equal(t, expiry.Unix(), int64(exp))
				}
				if iat, ok := response["iat"].(float64); ok {
					require.Equal(t, issuedAt.Unix(), int64(iat))
				}
				require.Equal(t, audience, response["aud"])
				require.Equal(t, testIssuer, response["iss"])
			}
		})
	}
}

// CORS Tests
