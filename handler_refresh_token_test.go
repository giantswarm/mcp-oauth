package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type refreshTestEnv struct {
	handler  *Handler
	store    *memory.Store
	auditBuf *bytes.Buffer
}

func newRefreshTestEnv(t *testing.T) *refreshTestEnv {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	auditBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(auditBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := &server.Config{
		Issuer:                    testIssuer,
		AllowRefreshTokenRotation: true,
	}

	auditor := security.NewAuditor(logger, true)

	srv, err := server.New(provider, store, store, store, config, logger, server.WithAuditor(auditor))
	require.NoError(t, err)

	return &refreshTestEnv{
		handler:  NewHandler(srv, logger),
		store:    store,
		auditBuf: auditBuf,
	}
}

func (e *refreshTestEnv) registerClient(t *testing.T, clientType string) (string, string) {
	t.Helper()
	client, secret, err := e.handler.server.RegisterClient(
		context.Background(),
		"refresh-grant-test-client",
		clientType,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.0.2.10",
		10,
	)
	require.NoError(t, err)
	return client.ClientID, secret
}

func (e *refreshTestEnv) seedRefreshToken(t *testing.T, clientID, userID, familyID string, expiresAt time.Time) string {
	t.Helper()
	refreshToken := "rt-" + clientID + "-" + familyID
	err := e.store.SaveRefreshTokenWithFamily(
		context.Background(),
		refreshToken,
		userID,
		clientID,
		familyID,
		0,
		expiresAt,
	)
	require.NoError(t, err)
	err = e.store.SaveToken(context.Background(), refreshToken, &oauth2.Token{
		AccessToken:  "provider-access-" + refreshToken,
		RefreshToken: "provider-refresh-" + refreshToken,
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	})
	require.NoError(t, err)
	return refreshToken
}

// seedLegacyRefreshToken stores a refresh token without family metadata so the
// stored client_id is empty.
func (e *refreshTestEnv) seedLegacyRefreshToken(t *testing.T, userID string, expiresAt time.Time) string {
	t.Helper()
	refreshToken := "legacy-rt-" + userID
	err := e.store.SaveRefreshToken(context.Background(), refreshToken, userID, expiresAt)
	require.NoError(t, err)
	err = e.store.SaveToken(context.Background(), refreshToken, &oauth2.Token{
		AccessToken:  "provider-access-" + refreshToken,
		RefreshToken: "provider-refresh-" + refreshToken,
		Expiry:       time.Now().Add(time.Hour),
		TokenType:    "Bearer",
	})
	require.NoError(t, err)
	return refreshToken
}

func doRefreshRequest(handler *Handler, form url.Values, basicAuth [2]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicAuth[0] != "" {
		request.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	recorder := httptest.NewRecorder()
	handler.ServeToken(recorder, request)
	return recorder
}

func decodeTokenResponse(t *testing.T, recorder *httptest.ResponseRecorder) TokenResponse {
	t.Helper()
	var response TokenResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	return response
}

func decodeErrorResponse(t *testing.T, recorder *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var response ErrorResponse
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&response))
	return response
}

// scanAuditRecords decodes one JSON record per non-empty line in auditBuf.
// Unparseable non-empty lines fail the test so a log-format regression
// surfaces loudly instead of producing a silent false-negative from the
// downstream auditEventLogged / auditAuthFailureWithReason helpers.
func scanAuditRecords(t *testing.T, auditBuf *bytes.Buffer) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0)
	for i, line := range strings.Split(strings.TrimRight(auditBuf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("audit log line %d is not JSON: %v\nline: %s", i, err, line)
		}
		out = append(out, record)
	}
	return out
}

func auditEventLogged(t *testing.T, auditBuf *bytes.Buffer, eventType string) bool {
	t.Helper()
	for _, record := range scanAuditRecords(t, auditBuf) {
		audit, ok := record["audit"].(map[string]any)
		if !ok {
			continue
		}
		if audit["event_type"] == eventType {
			return true
		}
	}
	return false
}

func auditAuthFailureWithReason(t *testing.T, auditBuf *bytes.Buffer, reason string) bool {
	t.Helper()
	for _, record := range scanAuditRecords(t, auditBuf) {
		audit, ok := record["audit"].(map[string]any)
		if !ok {
			continue
		}
		if audit["event_type"] != security.EventAuthFailure {
			continue
		}
		details, ok := audit["details"].(map[string]any)
		if !ok {
			continue
		}
		if details["reason"] == reason {
			return true
		}
	}
	return false
}

// refreshGrantInputs is what the per-case setup closure returns to the table
// runner: the form body, the Basic Auth pair, and whether to issue a prior
// successful refresh first (covers the reuse-detection case where the second
// request must run after the token has already rotated).
type refreshGrantInputs struct {
	form               url.Values
	basicAuth          [2]string
	preRefreshFirstHit bool
}

func TestHandler_ServeToken_RefreshGrant(t *testing.T) {
	tests := []struct {
		name             string
		setup            func(t *testing.T, env *refreshTestEnv) refreshGrantInputs
		wantStatus       int
		wantErrorCode    string // empty on success
		wantErrorContain string // optional substring of error_description
		wantAuditEvents  []string
		wantAuditReasons []string
		assertRotation   bool // happy path only: response.RefreshToken != seeded
	}{
		{
			name: "happy path / confidential client / Basic Auth",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, secret := env.registerClient(t, ClientTypeConfidential)
				rt := env.seedRefreshToken(t, clientID, "user-c", "family-c", time.Now().Add(time.Hour))
				return refreshGrantInputs{
					form:      formWith("grant_type", "refresh_token", "refresh_token", rt),
					basicAuth: [2]string{clientID, secret},
				}
			},
			wantStatus:      http.StatusOK,
			wantAuditEvents: []string{security.EventTokenRefreshed},
			assertRotation:  true,
		},
		{
			name: "happy path / public client / client_id only",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, _ := env.registerClient(t, ClientTypePublic)
				rt := env.seedRefreshToken(t, clientID, "user-p", "family-p", time.Now().Add(time.Hour))
				return refreshGrantInputs{
					form: formWith("grant_type", "refresh_token", "refresh_token", rt, "client_id", clientID),
				}
			},
			wantStatus:      http.StatusOK,
			wantAuditEvents: []string{security.EventTokenRefreshed},
			assertRotation:  true,
		},
		{
			name: "confidential client without authentication is rejected",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, _ := env.registerClient(t, ClientTypeConfidential)
				rt := env.seedRefreshToken(t, clientID, "user-noauth", "family-noauth", time.Now().Add(time.Hour))
				return refreshGrantInputs{
					form: formWith("grant_type", "refresh_token", "refresh_token", rt, "client_id", clientID),
				}
			},
			wantStatus:       http.StatusUnauthorized,
			wantErrorCode:    ErrorCodeInvalidClient,
			wantAuditReasons: []string{"confidential_client_refresh_missing_auth"},
		},
		{
			name: "basic / form client_id mismatch is rejected (RFC 6749 §2.3.1)",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, secret := env.registerClient(t, ClientTypeConfidential)
				rt := env.seedRefreshToken(t, clientID, "user-mm", "family-mm", time.Now().Add(time.Hour))
				return refreshGrantInputs{
					form:      formWith("grant_type", "refresh_token", "refresh_token", rt, "client_id", "form-value-does-not-match"),
					basicAuth: [2]string{clientID, secret},
				}
			},
			wantStatus:       http.StatusBadRequest,
			wantErrorCode:    ErrorCodeInvalidClient,
			wantErrorContain: "does not match",
			wantAuditReasons: []string{"client_id_mismatch_basic_vs_form"},
		},
		{
			name: "basic + matching form client_id succeeds",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, secret := env.registerClient(t, ClientTypeConfidential)
				rt := env.seedRefreshToken(t, clientID, "user-match", "family-match", time.Now().Add(time.Hour))
				return refreshGrantInputs{
					form:      formWith("grant_type", "refresh_token", "refresh_token", rt, "client_id", clientID),
					basicAuth: [2]string{clientID, secret},
				}
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "cross-client refresh token binding is rejected",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientA, _ := env.registerClient(t, ClientTypeConfidential)
				clientB, secretB := env.registerClient(t, ClientTypeConfidential)
				rt := env.seedRefreshToken(t, clientA, "user-x", "family-x", time.Now().Add(time.Hour))
				return refreshGrantInputs{
					form:      formWith("grant_type", "refresh_token", "refresh_token", rt),
					basicAuth: [2]string{clientB, secretB},
				}
			},
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   ErrorCodeInvalidGrant,
			wantAuditEvents: []string{security.EventRefreshTokenClientBindingMismatch},
		},
		{
			name: "reused refresh token is rejected on the second hit",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, secret := env.registerClient(t, ClientTypeConfidential)
				rt := env.seedRefreshToken(t, clientID, "user-r", "family-r", time.Now().Add(time.Hour))
				return refreshGrantInputs{
					form:               formWith("grant_type", "refresh_token", "refresh_token", rt),
					basicAuth:          [2]string{clientID, secret},
					preRefreshFirstHit: true,
				}
			},
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   ErrorCodeInvalidGrant,
			wantAuditEvents: []string{security.EventRefreshTokenReuseDetected},
		},
		{
			name: "expired refresh token is rejected",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, secret := env.registerClient(t, ClientTypeConfidential)
				rt := env.seedRefreshToken(t, clientID, "user-e", "family-e", time.Now().Add(-time.Hour))
				return refreshGrantInputs{
					form:      formWith("grant_type", "refresh_token", "refresh_token", rt),
					basicAuth: [2]string{clientID, secret},
				}
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: ErrorCodeInvalidGrant,
		},
		{
			name: "legacy refresh token without client binding is rejected",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, secret := env.registerClient(t, ClientTypeConfidential)
				rt := env.seedLegacyRefreshToken(t, "user-l", time.Now().Add(time.Hour))
				return refreshGrantInputs{
					form:      formWith("grant_type", "refresh_token", "refresh_token", rt),
					basicAuth: [2]string{clientID, secret},
				}
			},
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   ErrorCodeInvalidGrant,
			wantAuditEvents: []string{security.EventRefreshTokenMissingClientBinding},
		},
		{
			name: "missing refresh_token parameter is rejected",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, secret := env.registerClient(t, ClientTypeConfidential)
				return refreshGrantInputs{
					form:      formWith("grant_type", "refresh_token"),
					basicAuth: [2]string{clientID, secret},
				}
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: ErrorCodeInvalidRequest,
		},
		{
			name: "missing client_id on a public-client refresh is rejected",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				return refreshGrantInputs{
					form: formWith("grant_type", "refresh_token", "refresh_token", "any-refresh-token"),
				}
			},
			wantStatus:    http.StatusBadRequest,
			wantErrorCode: ErrorCodeInvalidRequest,
		},
		{
			name: "unknown client is rejected",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				return refreshGrantInputs{
					form: formWith("grant_type", "refresh_token", "refresh_token", "any-refresh-token", "client_id", "client-that-was-never-registered"),
				}
			},
			wantStatus:    http.StatusUnauthorized,
			wantErrorCode: ErrorCodeInvalidClient,
		},
		{
			name: "bad client secret is rejected",
			setup: func(t *testing.T, env *refreshTestEnv) refreshGrantInputs {
				clientID, _ := env.registerClient(t, ClientTypeConfidential)
				return refreshGrantInputs{
					form:      formWith("grant_type", "refresh_token", "refresh_token", "any-refresh-token"),
					basicAuth: [2]string{clientID, "wrong-secret"},
				}
			},
			wantStatus:    http.StatusUnauthorized,
			wantErrorCode: ErrorCodeInvalidClient,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newRefreshTestEnv(t)
			inputs := tc.setup(t, env)

			if inputs.preRefreshFirstHit {
				first := doRefreshRequest(env.handler, inputs.form, inputs.basicAuth)
				require.Equal(t, http.StatusOK, first.Code, "first hit body: %s", first.Body.String())
			}

			seededRefreshToken := inputs.form.Get("refresh_token")
			recorder := doRefreshRequest(env.handler, inputs.form, inputs.basicAuth)
			require.Equal(t, tc.wantStatus, recorder.Code, "body: %s", recorder.Body.String())

			if tc.wantErrorCode != "" {
				response := decodeErrorResponse(t, recorder)
				require.Equal(t, tc.wantErrorCode, response.Error)
				if tc.wantErrorContain != "" {
					require.Contains(t, response.ErrorDescription, tc.wantErrorContain)
				}
			} else {
				response := decodeTokenResponse(t, recorder)
				require.NotEmpty(t, response.AccessToken)
				require.NotEmpty(t, response.RefreshToken)
				if tc.assertRotation && seededRefreshToken != "" {
					require.NotEqual(t, seededRefreshToken, response.RefreshToken, "rotation must mint a new refresh token")
				}
				require.Equal(t, tokenTypeBearer, response.TokenType)
			}

			for _, event := range tc.wantAuditEvents {
				require.True(t, auditEventLogged(t, env.auditBuf, event), "audit event %q not emitted", event)
			}
			for _, reason := range tc.wantAuditReasons {
				require.True(t, auditAuthFailureWithReason(t, env.auditBuf, reason), "auth_failure with reason %q not emitted", reason)
			}
		})
	}
}

// formWith builds a url.Values from a flat key,value,key,value,... slice. Panics
// on an odd argument count — the test author controls the call site.
func formWith(kv ...string) url.Values {
	if len(kv)%2 != 0 {
		panic("formWith: odd number of arguments")
	}
	form := url.Values{}
	for i := 0; i < len(kv); i += 2 {
		form.Set(kv[i], kv[i+1])
	}
	return form
}
