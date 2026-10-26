package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const testIdentityReturnURL = "https://auth.example.com/oauth/proxy/start"

type identityFlow struct {
	returnURL   *url.URL
	verifier    string
	clientState string
	scopes      []string
	options     *providers.AuthorizationURLOptions
}

func newIdentityFlow(t *testing.T) *identityFlow {
	t.Helper()
	verifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	return &identityFlow{
		returnURL:   mustParseURL(t, testIdentityReturnURL),
		verifier:    verifier,
		clientState: testutil.GenerateRandomString(43),
	}
}

func (f *identityFlow) challenge() string {
	hash := sha256.Sum256([]byte(f.verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// signIn runs an identity flow up to the code the return URL receives.
func (f *identityFlow) signIn(t *testing.T, srv *Server, store *memory.Store) string {
	t.Helper()
	_, err := srv.StartIdentityFlow(t.Context(), f.returnURL, f.challenge(), f.clientState)
	require.NoError(t, err)

	authState, err := store.GetAuthorizationState(t.Context(), f.clientState)
	require.NoError(t, err)
	require.True(t, authState.IdentityOnly)

	code, clientState, err := srv.HandleProviderCallback(t.Context(), authState.ProviderState, "provider-code")
	require.NoError(t, err)
	require.Equal(t, f.clientState, clientState)
	require.Equal(t, testIdentityReturnURL, code.RedirectURI)
	return code.Code
}

func setupIdentityTestServer(t *testing.T) (*Server, *memory.Store, *identityFlow) {
	t.Helper()
	srv, store, provider := setupFlowTestServer(t)
	flow := newIdentityFlow(t)
	authorizationURL := provider.AuthorizationURLFunc
	provider.AuthorizationURLFunc = func(state, codeChallenge, method string, scopes []string, opts *providers.AuthorizationURLOptions) string {
		flow.scopes = scopes
		flow.options = opts
		return authorizationURL(state, codeChallenge, method, scopes, opts)
	}
	return srv, store, flow
}

func TestIdentityFlow_ReturnsTheSubjectAndGrantsNothing(t *testing.T) {
	srv, store, flow := setupIdentityTestServer(t)
	sessions := 0
	srv.sessionCreationHandler = func(_ context.Context, _, _ string, _ *oauth2.Token) { sessions++ }

	code := flow.signIn(t, srv, store)
	subject, err := srv.RedeemIdentityCode(t.Context(), code, flow.returnURL, flow.verifier)

	require.NoError(t, err)
	require.Equal(t, testMockUserID, subject)
	require.Equal(t, []string{identityScope}, flow.scopes)
	require.True(t, flow.options.IdentityOnly, "no offline_access: the provider issues no refresh token")
	require.NotEmpty(t, flow.options.Nonce)
	_, err = store.GetUserInfo(t.Context(), testMockUserID)
	require.Error(t, err, "the person's stored user info and provider token are untouched")
	_, err = store.GetToken(t.Context(), testMockUserID)
	require.Error(t, err)
	require.Zero(t, sessions)
}

func TestIdentityFlow_CodeIsRedeemedOnce(t *testing.T) {
	srv, store, flow := setupIdentityTestServer(t)
	code := flow.signIn(t, srv, store)

	_, err := srv.RedeemIdentityCode(t.Context(), code, flow.returnURL, flow.verifier)
	require.NoError(t, err)
	_, err = srv.RedeemIdentityCode(t.Context(), code, flow.returnURL, flow.verifier)
	require.ErrorIs(t, err, ErrInvalidIdentityCode)
}

func TestIdentityFlow_RedeemRefusals(t *testing.T) {
	for name, redeem := range map[string]func(*identityFlow) (*url.URL, string){
		"wrong PKCE verifier": func(f *identityFlow) (*url.URL, string) {
			return f.returnURL, testutil.GenerateRandomString(testPKCEVerifierLength)
		},
		"another return URL": func(f *identityFlow) (*url.URL, string) {
			return &url.URL{Scheme: "https", Host: "auth.example.com", Path: "/elsewhere"}, f.verifier
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv, store, flow := setupIdentityTestServer(t)
			code := flow.signIn(t, srv, store)
			returnURL, verifier := redeem(flow)

			_, err := srv.RedeemIdentityCode(t.Context(), code, returnURL, verifier)

			require.ErrorIs(t, err, ErrInvalidIdentityCode)
		})
	}
}

// SECURITY: an identity code must never become tokens, whoever presents it.
func TestIdentityFlow_CodeIsNotExchangeable(t *testing.T) {
	srv, store, flow := setupIdentityTestServer(t)
	logger, logs := captureLogger()
	srv.Auditor = security.NewAuditor(logger, true)
	code := flow.signIn(t, srv, store)

	_, _, err := srv.ExchangeAuthorizationCode(t.Context(), code, "", testIdentityReturnURL, "", flow.verifier, "")

	require.Error(t, err)
	require.True(t, containsAuthFailure(logs.String(), "identity_code_not_exchangeable"), logs.String())
}

// SECURITY: a reused identity code grants nothing, so it revokes nothing.
// Its holder must not be able to end the person's sessions at a client.
func TestIdentityFlow_ReusedCodeRevokesNothing(t *testing.T) {
	const clientRedirect = "https://example.com/callback"
	srv, store, flow := setupIdentityTestServer(t)
	logger, logs := captureLogger()
	srv.Auditor = security.NewAuditor(logger, true)
	client, _, err := srv.RegisterClient(t.Context(), "Test Client", ClientTypePublic, "",
		[]string{clientRedirect}, []string{"openid"}, "192.168.1.100", 10)
	require.NoError(t, err)
	const accessToken = "seeded-access-token"
	require.NoError(t, store.SaveToken(t.Context(), accessToken, &oauth2.Token{
		AccessToken: accessToken, TokenType: "Bearer", Expiry: time.Now().Add(time.Hour),
	}))
	require.NoError(t, store.SaveTokenMetadata(t.Context(), accessToken, storage.TokenMetadata{
		UserID: testMockUserID, ClientID: client.ClientID, TokenType: "access",
	}))
	code := flow.signIn(t, srv, store)
	_, _, err = srv.ExchangeAuthorizationCode(t.Context(), code, client.ClientID, clientRedirect, "", flow.verifier, "")
	require.Error(t, err)

	_, _, err = srv.ExchangeAuthorizationCode(t.Context(), code, client.ClientID, clientRedirect, "", flow.verifier, "")

	require.Error(t, err)
	_, err = store.GetToken(t.Context(), accessToken)
	require.NoError(t, err, "the person's token at the client is not revoked")
	require.True(t, containsAuthFailure(logs.String(), "identity_code_not_exchangeable"), logs.String())
	require.NotContains(t, logs.String(), "authorization_code_reuse")
}

func TestIdentityFlow_IssueAndRedeemAreAudited(t *testing.T) {
	srv, store, flow := setupIdentityTestServer(t)
	logger, logs := captureLogger()
	srv.Auditor = security.NewAuditor(logger, true)

	code := flow.signIn(t, srv, store)
	require.True(t, containsAuditEvent(logs.String(), security.EventIdentityCodeIssued), logs.String())

	_, err := srv.RedeemIdentityCode(t.Context(), code, flow.returnURL, flow.verifier)

	require.NoError(t, err)
	require.True(t, containsAuditEvent(logs.String(), security.EventIdentityCodeRedeemed), logs.String())
	require.Contains(t, logs.String(), helpers.HashForLogging(testMockUserID))
	require.Equal(t, 2, strings.Count(logs.String(), "return_url:"+testIdentityReturnURL), logs.String())
}

func TestIdentityFlow_CodeLifetime(t *testing.T) {
	tests := []struct {
		name                 string
		authorizationCodeTTL int64
		want                 time.Duration
	}{
		{name: "identity code TTL", authorizationCodeTTL: 600, want: identityCodeTTL},
		{name: "capped by AuthorizationCodeTTL", authorizationCodeTTL: 30, want: 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, store, flow := setupIdentityTestServer(t)
			srv.Config.AuthorizationCodeTTL = tt.authorizationCodeTTL
			code := flow.signIn(t, srv, store)

			authCode, err := store.GetAuthorizationCode(t.Context(), code)

			require.NoError(t, err)
			require.Equal(t, tt.want, authCode.ExpiresAt.Sub(authCode.CreatedAt))
		})
	}
}

// A client's authorization code is not an identity code.
func TestIdentityFlow_RedeemRefusesAnAuthorizationCode(t *testing.T) {
	const clientRedirect = "https://example.com/callback"
	srv, store, _ := setupFlowTestServer(t)
	client, _, err := srv.RegisterClient(t.Context(), "Test Client", ClientTypePublic, "",
		[]string{clientRedirect}, []string{"openid"}, "192.168.1.100", 10)
	require.NoError(t, err)
	flow := newIdentityFlow(t)
	_, err = srv.StartAuthorizationFlow(t.Context(), client.ClientID, mustParseURL(t, clientRedirect), "openid", "",
		flow.challenge(), PKCEMethodS256, flow.clientState, nil)
	require.NoError(t, err)
	authState, err := store.GetAuthorizationState(t.Context(), flow.clientState)
	require.NoError(t, err)
	code, _, err := srv.HandleProviderCallback(t.Context(), authState.ProviderState, "provider-code")
	require.NoError(t, err)

	_, err = srv.RedeemIdentityCode(t.Context(), code.Code, mustParseURL(t, clientRedirect), flow.verifier)

	require.ErrorIs(t, err, ErrInvalidIdentityCode)
}

func TestStartIdentityFlow_Refusals(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)
	flow := newIdentityFlow(t)

	for name, start := range map[string]func() error{
		"return URL on another origin": func() error {
			_, err := srv.StartIdentityFlow(t.Context(), mustParseURL(t, "https://evil.example.com/collect"), flow.challenge(), flow.clientState)
			return err
		},
		"return URL on another scheme": func() error {
			_, err := srv.StartIdentityFlow(t.Context(), mustParseURL(t, "http://auth.example.com/oauth/proxy/start"), flow.challenge(), flow.clientState)
			return err
		},
		"relative return URL": func() error {
			_, err := srv.StartIdentityFlow(t.Context(), &url.URL{Path: "/oauth/proxy/start"}, flow.challenge(), flow.clientState)
			return err
		},
		"no code challenge": func() error {
			_, err := srv.StartIdentityFlow(t.Context(), flow.returnURL, "", flow.clientState)
			return err
		},
		"no state": func() error {
			_, err := srv.StartIdentityFlow(t.Context(), flow.returnURL, flow.challenge(), "")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, start())
		})
	}
}
