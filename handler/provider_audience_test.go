package handler

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/server"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

func TestValidateToken_ProviderAudienceMismatchHTTP(t *testing.T) {
	environment := newOutageEnvWithFormat(t, server.AccessTokenFormatOpaque)
	const issuer = "https://dex.example.com"
	environment.provider.IssuerURLFunc = func() string { return issuer }
	environment.handler.server.Config.TrustedAudiences = []string{"this-backend"}
	environment.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
		return nil, &providers.UserInfoStatusError{StatusCode: http.StatusUnauthorized}
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	require.NoError(t, err)
	accessToken, err := josejwt.Signed(signer).Claims(josejwt.Claims{
		Issuer:   issuer,
		Subject:  "user-subject-123",
		Audience: josejwt.Audience{"another-backend"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).Serialize()
	require.NoError(t, err)
	protected := environment.handler.ValidateToken(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unauthenticated request reached the protected handler")
	}))
	request := func(bearer string) *httptest.ResponseRecorder {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mcp", nil)
		request.Header.Set("Authorization", "Bearer "+bearer)
		response := httptest.NewRecorder()
		protected.ServeHTTP(response, request)
		return response
	}

	unknown := request("unknown-opaque-token")
	refused := request(accessToken)
	require.Equal(t, http.StatusUnauthorized, refused.Code)
	require.Equal(t, unknown.Body.String(), refused.Body.String())
	require.Equal(t, unknown.Header().Get("WWW-Authenticate"), refused.Header().Get("WWW-Authenticate"))
	require.Contains(t, environment.logs.String(), "unknown_jwt_bearer")

	environment.faulty.Fail(storagemock.OnOperation("get_provider_token_ref", storagemock.ConnectionRefused))
	unavailable := request(accessToken)
	requireUnavailableResponse(t, unavailable)

	environment.faulty.Heal()
	require.Equal(t, http.StatusUnauthorized, request(accessToken).Code)
}
