package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestValidateToken_RejectsProviderJWTAudienceMismatch(t *testing.T) {
	harness := newForwardedTokenHarness(t)
	claims := harness.validClaims()
	claims.Audience = josejwt.Audience{"another-backend"}
	accessToken := harness.signToken(t, claims)
	var logs bytes.Buffer
	harness.srv.Auditor = security.NewAuditor(slog.New(slog.NewJSONHandler(&logs, nil)), true)
	userinfoCalls := 0
	harness.provider.ValidateTokenFunc = func(_ context.Context, bearer string) (*providers.UserInfo, error) {
		userinfoCalls++
		parsed, err := josejwt.ParseSigned(bearer, []jose.SignatureAlgorithm{jose.RS256})
		require.NoError(t, err)
		var verified josejwt.Claims
		require.NoError(t, parsed.Claims(harness.privateKey.Public(), &verified))
		require.NoError(t, verified.Validate(josejwt.Expected{Issuer: harness.issuer, Time: time.Now()}))
		return &providers.UserInfo{ID: verified.Subject}, nil
	}

	userInfo, err := harness.srv.ValidateToken(t.Context(), accessToken)
	require.ErrorIs(t, err, ErrUnknownJWTBearer)
	require.Nil(t, userInfo)
	require.Zero(t, userinfoCalls, "a foreign-audience bearer must not be sent to userinfo")
	require.Contains(t, logs.String(), `"reason":"unknown_jwt_bearer"`)
	require.NotContains(t, logs.String(), accessToken)
}

func TestValidateToken_ProviderJWTAudienceRequired(t *testing.T) {
	for _, test := range []struct {
		name             string
		audiences        josejwt.Audience
		trustedAudiences []string
	}{
		{"no trusted audiences", josejwt.Audience{"another-backend"}, nil},
		{"missing audience", nil, []string{"forwarded-audience"}},
		{"empty audience", josejwt.Audience{""}, []string{"forwarded-audience"}},
		{"several foreign audiences", josejwt.Audience{"backend-a", "backend-b"}, []string{"forwarded-audience"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newForwardedTokenHarness(t, func(configuration *Config) {
				configuration.TrustedAudiences = test.trustedAudiences
			})
			claims := harness.validClaims()
			claims.Audience = test.audiences
			harness.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
				t.Error("audience-mismatched bearer reached userinfo")
				return &providers.UserInfo{ID: "user-subject-123"}, nil
			}

			userInfo, err := harness.srv.ValidateToken(t.Context(), harness.signToken(t, claims))
			require.ErrorIs(t, err, ErrUnknownJWTBearer)
			require.Nil(t, userInfo)
		})
	}
}

func TestValidateToken_AcceptsTrustedProviderJWT(t *testing.T) {
	harness := newForwardedTokenHarness(t)
	claims := harness.validClaims()
	claims.Audience = josejwt.Audience{"another-backend", harness.audience}
	harness.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
		t.Error("trusted JWT must be validated through JWKS")
		return nil, errors.New("userinfo unavailable")
	}

	userInfo, err := harness.srv.ValidateToken(t.Context(), harness.signToken(t, claims))
	require.NoError(t, err)
	require.Equal(t, "user-subject-123", userInfo.ID)
	require.Equal(t, providers.TokenSourceSSO, userInfo.TokenSource)
}

func TestValidateToken_ProviderAudiencePreservesStoredTokens(t *testing.T) {
	for _, tokenFormat := range []string{"opaque", "provider JWT"} {
		t.Run(tokenFormat, func(t *testing.T) {
			harness := newForwardedTokenHarness(t)
			accessToken := "issued-opaque-token"
			if tokenFormat == "provider JWT" {
				claims := harness.validClaims()
				claims.Audience = josejwt.Audience{"another-backend"}
				accessToken = harness.signToken(t, claims)
			}
			seedProviderToken(t, harness.srv.tokenStore.(storage.UserProviderTokenStore), accessToken, "user-subject-123", &oauth2.Token{
				AccessToken: "stored-provider-token",
				Expiry:      time.Now().Add(time.Hour),
			})
			harness.provider.ValidateTokenFunc = func(_ context.Context, bearer string) (*providers.UserInfo, error) {
				require.Equal(t, "stored-provider-token", bearer)
				return &providers.UserInfo{ID: "user-subject-123"}, nil
			}

			userInfo, err := harness.srv.ValidateToken(t.Context(), accessToken)
			require.NoError(t, err)
			require.Equal(t, "user-subject-123", userInfo.ID)
			require.Equal(t, providers.TokenSourceOAuth, userInfo.TokenSource)
		})
	}
}

func TestValidateToken_ProviderIssuerDoesNotControlBearerRejection(t *testing.T) {
	for _, test := range []struct {
		name           string
		issuer         string
		providerIssuer string
	}{
		{"non-provider issuer", "https://other.example.com", "https://auth.test.example"},
		{"unknown provider issuer", "https://auth.test.example", ""},
		{"opaque bearer", "", "https://auth.test.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newForwardedTokenHarness(t)
			harness.provider.IssuerURLFunc = func() string { return test.providerIssuer }
			accessToken := "upstream-opaque-token"
			if test.issuer != "" {
				claims := harness.validClaims()
				claims.Issuer = test.issuer
				claims.Audience = josejwt.Audience{"another-backend"}
				accessToken = harness.signToken(t, claims)
			}
			harness.provider.ValidateTokenFunc = func(_ context.Context, bearer string) (*providers.UserInfo, error) {
				require.Equal(t, accessToken, bearer)
				return &providers.UserInfo{ID: "user-subject-123"}, nil
			}

			userInfo, err := harness.srv.ValidateToken(t.Context(), accessToken)
			if test.issuer != "" {
				require.ErrorIs(t, err, ErrUnknownJWTBearer)
				require.Nil(t, userInfo)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "user-subject-123", userInfo.ID)
			require.Equal(t, providers.TokenSourceOAuth, userInfo.TokenSource)
		})
	}
}
