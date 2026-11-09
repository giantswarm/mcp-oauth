package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
)

func requireResourceAccessTokens(configuration *Config) {
	configuration.RequireResourceAccessTokens = true
}

func userinfoMustNotBeCalled(t *testing.T, h *forwardedTokenHarness) {
	h.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
		t.Error("a forwarded JWT must not reach userinfo")
		return nil, ErrUnknownJWTBearer
	}
}

// collectForwardedIDTokenResults replaces the server's instrumentation with
// one backed by a manual reader and returns a function collecting the result
// labels recorded on oauth.forwarded_id_token.accepted_total.
func collectForwardedIDTokenResults(t *testing.T, srv *Server) func() []string {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	inst, err := instrumentation.New(instrumentation.Config{Enabled: true, MeterProvider: provider})
	require.NoError(t, err)
	srv.Instrumentation = inst

	return func() []string {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(t.Context(), &rm))
		var results []string
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != "oauth.forwarded_id_token.accepted_total" {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok, "unexpected data type %T", m.Data)
				for _, dp := range sum.DataPoints {
					result, _ := dp.Attributes.Value(attribute.Key("result"))
					results = append(results, result.AsString())
				}
			}
		}
		return results
	}
}

type senderConstrainedClaims struct {
	oidc.IDTokenClaims
	Cnf map[string]string `json:"cnf"`
}

func TestValidateToken_ForwardedIDTokenAccepted(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoMustNotBeCalled(t, h)
	audit := captureAudit(h.srv)
	results := collectForwardedIDTokenResults(t, h.srv)
	bearer := h.signToken(t, h.validClaims())

	userInfo, err := h.srv.ValidateToken(t.Context(), bearer)

	require.NoError(t, err)
	require.Equal(t, "user-subject-123", userInfo.ID)
	require.Equal(t, "user@test.example", userInfo.Email)
	require.Equal(t, providers.TokenSourceSSO, userInfo.TokenSource)
	line := onlyAuditLine(t, audit, security.EventForwardedIDTokenAccepted)
	require.Equal(t, h.audience, line.Details["matched_audience"])
	require.Equal(t, h.srv.SessionIDForBearer(bearer), line.Details["session_id"])
	require.Equal(t, []string{string(instrumentation.ForwardedIDTokenResultOK)}, results())
}

func TestValidateToken_ForwardedIDTokenRefused(t *testing.T) {
	tests := []struct {
		name        string
		bearer      func(t *testing.T, h *forwardedTokenHarness) string
		wantErr     error
		wantAudit   string
		wantResults []string
	}{
		{
			name:        "expired",
			bearer:      expiredForwardedToken,
			wantErr:     oidc.ErrTokenExpired,
			wantAudit:   auditReasonForwardedIDTokenInvalid,
			wantResults: []string{string(instrumentation.ForwardedIDTokenResultExpired)},
		},
		{
			name: "carries act",
			bearer: func(t *testing.T, h *forwardedTokenHarness) string {
				return h.signDelegatedToken(t, &oidc.ActorClaim{Issuer: "https://actors.example", Subject: "workload-1"}, nil)
			},
			wantErr:   ErrUnknownJWTBearer,
			wantAudit: auditReasonUnknownJWTBearer,
		},
		{
			name: "carries cnf",
			bearer: func(t *testing.T, h *forwardedTokenHarness) string {
				return signTestRS256Token(t, h.privateKey, h.keyID, senderConstrainedClaims{
					IDTokenClaims: oidc.IDTokenClaims{Claims: h.validClaims()},
					Cnf:           map[string]string{"jkt": "bound-key"},
				})
			},
			wantErr:   ErrUnknownJWTBearer,
			wantAudit: auditReasonUnknownJWTBearer,
		},
		{
			name:      "audience not trusted",
			bearer:    tokenForAnotherClient,
			wantErr:   ErrUnknownJWTBearer,
			wantAudit: auditReasonUnknownJWTBearer,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newForwardedTokenHarness(t)
			userinfoMustNotBeCalled(t, h)
			audit := captureAudit(h.srv)
			results := collectForwardedIDTokenResults(t, h.srv)

			userInfo, err := h.srv.ValidateToken(t.Context(), tc.bearer(t, h))

			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, userInfo)
			line := onlyAuditLine(t, audit, string(security.EventAuthFailure))
			require.Equal(t, tc.wantAudit, line.Details["reason"])
			require.Equal(t, tc.wantResults, results())
		})
	}
}

func TestValidateToken_ForwardedIDTokenJWKSOutage(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoMustNotBeCalled(t, h)
	unreachable := httptest.NewTLSServer(http.NotFoundHandler())
	unreachable.Close()
	h.provider.JWKSURIFunc = func(context.Context) (string, error) { return unreachable.URL, nil }

	userInfo, err := h.srv.ValidateToken(t.Context(), h.signToken(t, h.validClaims()))

	require.ErrorIs(t, err, ErrProviderUnavailable)
	require.Nil(t, userInfo)
}

// trustProviderIssuer configures the provider's issuer as a trusted issuer
// whose entry accepts the provider's ID tokens: their aud and their JWT typ.
func trustProviderIssuer(t *testing.T, h *forwardedTokenHarness) {
	t.Helper()
	validator, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:             h.issuer,
		JwksURL:            h.jwksServer.URL,
		AllowedAudiences:   []string{h.audience},
		AcceptedTypHeaders: []string{"JWT"},
	}}, h.srv.jwksClient)
	require.NoError(t, err)
	h.srv.trustedIssuerValidator = validator
}

func TestValidateToken_TrustedIssuer_IDTokenWithTrustedAudienceIsForwarded(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoMustNotBeCalled(t, h)
	trustProviderIssuer(t, h)
	results := collectForwardedIDTokenResults(t, h.srv)

	userInfo, err := h.srv.ValidateToken(t.Context(), h.signToken(t, h.validClaims()))

	require.NoError(t, err)
	require.Equal(t, providers.TokenSourceSSO, userInfo.TokenSource)
	require.Equal(t, []string{string(instrumentation.ForwardedIDTokenResultOK)}, results())
}

func TestValidateToken_TrustedIssuer_DelegatedIDTokenGoesToTrustedIssuer(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoMustNotBeCalled(t, h)
	trustProviderIssuer(t, h)
	results := collectForwardedIDTokenResults(t, h.srv)
	bearer := h.signDelegatedToken(t, &oidc.ActorClaim{Issuer: "https://actors.example", Subject: "workload-1"}, nil)

	userInfo, err := h.srv.ValidateToken(t.Context(), bearer)

	require.NoError(t, err)
	require.Equal(t, providers.TokenSourceTrustedIssuer, userInfo.TokenSource)
	require.Equal(t, "workload-1", userInfo.ActorSubject)
	require.Empty(t, results())
}

func TestValidateToken_TrustedIssuer_AllowedAudienceAuthorizes(t *testing.T) {
	key := newTestECKey(t)
	const keyID = "allowed-audience-key"
	jwksURL, jwksClient := serveStaticJWKS(t, key, keyID)
	srv, _, _ := setupFlowTestServer(t)
	const allowedAudience = "aggregator-client"
	validator, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer: testIssuer, JwksURL: jwksURL, AllowedAudiences: []string{allowedAudience},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = validator
	bearer := signSubjectTokenWithType(t, key, keyID, rfc9068TokenType, josejwt.Claims{
		Issuer: testIssuer, Subject: testSubject, Audience: josejwt.Audience{allowedAudience},
		Expiry: josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	userInfo, err := srv.ValidateToken(t.Context(), bearer)

	require.NoError(t, err)
	require.Equal(t, testSubject, userInfo.ID)
	require.Equal(t, providers.TokenSourceTrustedIssuer, userInfo.TokenSource)
}

// captureWarnings routes the server's logger to a buffer and returns the
// buffer and a function decoding the WARN records with the given message.
func captureWarnings(t *testing.T, srv *Server) (*bytes.Buffer, func(msg string) []map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	srv.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return &buf, func(msg string) []map[string]any {
		var records []map[string]any
		for line := range bytes.SplitSeq(buf.Bytes(), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var record map[string]any
			require.NoError(t, json.Unmarshal(line, &record))
			if record["msg"] == msg {
				records = append(records, record)
			}
		}
		return records
	}
}

// requireNoTokenMaterial fails when the log holds any eight-byte fragment of
// the bearer's signature.
func requireNoTokenMaterial(t *testing.T, logs *bytes.Buffer, bearer string) {
	t.Helper()
	signature := bearer[strings.LastIndex(bearer, ".")+1:]
	for i := 0; i+8 <= len(signature); i++ {
		require.NotContains(t, logs.String(), signature[i:i+8])
	}
}

func TestValidateToken_UnknownJWTBearerLogsItsAudience(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoMustNotBeCalled(t, h)
	logs, warnings := captureWarnings(t, h.srv)
	bearer := tokenForAnotherClient(t, h)

	_, err := h.srv.ValidateToken(t.Context(), bearer)

	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	records := warnings("JWT bearer refused: not issued by this server, a trusted issuer, or for a trusted audience")
	require.Len(t, records, 1)
	require.Equal(t, h.issuer, records[0]["token_issuer"])
	require.Equal(t, []any{"another-client"}, records[0]["token_audience"])
	require.Equal(t, []any{h.audience}, records[0]["trusted_audiences"])
	requireNoTokenMaterial(t, logs, bearer)
}

func TestValidateToken_ForwardedIDTokenRefusalLogsTheCause(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoMustNotBeCalled(t, h)
	logs, warnings := captureWarnings(t, h.srv)
	bearer := expiredForwardedToken(t, h)

	_, err := h.srv.ValidateToken(t.Context(), bearer)

	require.ErrorIs(t, err, oidc.ErrTokenExpired)
	records := warnings("Forwarded ID token refused")
	require.Len(t, records, 1)
	require.Contains(t, records[0]["error"], oidc.ErrTokenExpired.Error())
	requireNoTokenMaterial(t, logs, bearer)
}
