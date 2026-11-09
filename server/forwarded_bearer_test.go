package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

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

type senderConstrainedClaims struct {
	oidc.IDTokenClaims
	Cnf map[string]string `json:"cnf"`
}

func TestValidateToken_ForwardedIDTokenAccepted(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoMustNotBeCalled(t, h)
	audit := captureAudit(h.srv)
	bearer := h.signToken(t, h.validClaims())

	userInfo, err := h.srv.ValidateToken(t.Context(), bearer)

	require.NoError(t, err)
	require.Equal(t, "user-subject-123", userInfo.ID)
	require.Equal(t, "user@test.example", userInfo.Email)
	require.Equal(t, providers.TokenSourceSSO, userInfo.TokenSource)
	line := onlyAuditLine(t, audit, security.EventForwardedIDTokenAccepted)
	require.Equal(t, h.audience, line.Details["matched_audience"])
	require.Equal(t, h.srv.SessionIDForBearer(bearer), line.Details["session_id"])
}

func TestValidateToken_ForwardedIDTokenRefused(t *testing.T) {
	tests := []struct {
		name      string
		bearer    func(t *testing.T, h *forwardedTokenHarness) string
		wantErr   error
		wantAudit string
	}{
		{
			name:      "expired",
			bearer:    expiredForwardedToken,
			wantErr:   oidc.ErrTokenExpired,
			wantAudit: auditReasonForwardedIDTokenInvalid,
		},
		{
			name: "carries act",
			bearer: func(t *testing.T, h *forwardedTokenHarness) string {
				return h.signDelegatedToken(t, &oidc.ActorClaim{Issuer: "https://actors.example", Subject: "workload-1"}, nil)
			},
			wantErr:   ErrActorNotTrusted,
			wantAudit: auditReasonForwardedIDTokenInvalid,
		},
		{
			name: "carries cnf",
			bearer: func(t *testing.T, h *forwardedTokenHarness) string {
				return signTestRS256Token(t, h.privateKey, h.keyID, senderConstrainedClaims{
					IDTokenClaims: oidc.IDTokenClaims{Claims: h.validClaims()},
					Cnf:           map[string]string{"jkt": "bound-key"},
				})
			},
			wantErr:   errForwardedTokenSenderConstrained,
			wantAudit: auditReasonForwardedIDTokenInvalid,
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

			userInfo, err := h.srv.ValidateToken(t.Context(), tc.bearer(t, h))

			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, userInfo)
			line := onlyAuditLine(t, audit, string(security.EventAuthFailure))
			require.Equal(t, tc.wantAudit, line.Details["reason"])
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

// The provider's issuer is also a trusted issuer (for RFC 8693 subject
// tokens); its ID token fails the at+jwt check and is accepted as a
// forwarded identity.
func TestValidateToken_TrustedIssuer_IDTokenWithTrustedAudienceIsForwarded(t *testing.T) {
	h := newForwardedTokenHarness(t)
	userinfoMustNotBeCalled(t, h)
	validator, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           h.issuer,
		JwksURL:          h.jwksServer.URL,
		AllowedAudiences: []string{h.audience},
	}}, h.srv.jwksClient)
	require.NoError(t, err)
	h.srv.trustedIssuerValidator = validator

	userInfo, err := h.srv.ValidateToken(t.Context(), h.signToken(t, h.validClaims()))

	require.NoError(t, err)
	require.Equal(t, providers.TokenSourceSSO, userInfo.TokenSource)
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
