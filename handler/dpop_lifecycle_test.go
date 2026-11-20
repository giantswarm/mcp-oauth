package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type dpopLifecycleEnvironment struct {
	handler       *Handler
	store         *memory.Store
	client        *storage.Client
	secret        string
	key           *ecdsa.PrivateKey
	thumbprint    string
	providerToken *oauth2.Token
	audit         *bytes.Buffer
}

func newDPoPLifecycleEnvironment(t *testing.T, clientType string, options ...server.Option) dpopLifecycleEnvironment {
	t.Helper()
	store := memory.New()
	var audit bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&audit, nil))
	options = append(options, server.WithAuditor(security.NewAuditor(logger, true)))
	oauthServer, err := server.New(mock.NewProvider(), store, store, store, &server.Config{
		Issuer: testIssuer, AllowRefreshTokenRotation: true, RequirePKCE: true,
	}, logger, options...)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, oauthServer.Shutdown(context.WithoutCancel(t.Context()))) })
	client, secret, err := oauthServer.RegisterClient(t.Context(), "dpop client", clientType, "", []string{"http://127.0.0.1:54321/callback"}, []string{"mcp"}, "192.0.2.1", 10)
	require.NoError(t, err)
	key := newTestDPoPKey(t)
	public := jose.JSONWebKey{Key: key.Public()}
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	providerToken := &oauth2.Token{AccessToken: "upstream-access", RefreshToken: "upstream-refresh", Expiry: time.Now().Add(time.Hour)}
	require.NoError(t, store.SaveUserProviderToken(t.Context(), "person", providerToken))
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "bound-refresh", "person", client.ClientID, "bound-family", 0, time.Now().Add(time.Hour)))
	require.NoError(t, store.SaveProviderTokenRef(t.Context(), "bound-refresh", "person", time.Now().Add(time.Hour)))
	encodedThumbprint := base64.RawURLEncoding.EncodeToString(thumbprint)
	require.NoError(t, store.SaveTokenMetadata(t.Context(), "bound-refresh", storage.TokenMetadata{
		UserID: "person", ClientID: client.ClientID, TokenType: "refresh", FamilyID: "bound-family",
		Audience: testIssuer, Scopes: []string{"mcp"}, ExpiresAt: time.Now().Add(time.Hour), JKT: encodedThumbprint,
	}))
	return dpopLifecycleEnvironment{handler: New(oauthServer, logger), store: store, client: client, secret: secret, key: key, thumbprint: encodedThumbprint, providerToken: providerToken, audit: &audit}
}

func (environment dpopLifecycleEnvironment) request(t *testing.T, form url.Values, proof string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("client_id", environment.client.ClientID)
	request := httptest.NewRequest(http.MethodPost, testIssuer+server.EndpointPathToken, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if environment.client.IsConfidential() {
		request.SetBasicAuth(environment.client.ClientID, environment.secret)
	}
	if proof != "" {
		request.Header.Set("DPoP", proof)
	}
	if mutate != nil {
		mutate(request)
	}
	response := httptest.NewRecorder()
	environment.handler.ServeToken(response, request)
	return response
}

func dpopRefreshForm() url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"bound-refresh"}, "resource": {testIssuer}}
}

func TestPublicDPoPRefreshRequiresOriginalProofKey(t *testing.T) {
	for _, shape := range []string{"missing", "malformed", "wrong key", "duplicate", "empty", "correct"} {
		t.Run(shape, func(t *testing.T) {
			environment := newDPoPLifecycleEnvironment(t, server.ClientTypePublic)
			proof := buildDPoPProofWithATH(t, environment.key, http.MethodPost, testIssuer+server.EndpointPathToken, "first-proof", "")
			var mutate func(*http.Request)
			switch shape {
			case "missing":
				proof = ""
			case "malformed":
				proof = "invalid-proof"
			case "wrong key":
				proof = buildDPoPProofWithATH(t, newTestDPoPKey(t), http.MethodPost, testIssuer+server.EndpointPathToken, "wrong-key-proof", "")
			case "duplicate":
				mutate = func(request *http.Request) { request.Header.Add("DPoP", proof) }
			case "empty":
				proof = ""
				mutate = func(request *http.Request) { request.Header.Set("DPoP", "") }
			}
			response := environment.request(t, dpopRefreshForm(), proof, mutate)
			if shape != "correct" {
				require.Equal(t, http.StatusBadRequest, response.Code)
				errorCode := "invalid_dpop_proof"
				if shape == "missing" || shape == "wrong key" {
					errorCode = "invalid_grant"
				}
				require.Equal(t, errorCode, decodeErrorResponse(t, response).Error)
				_, err := environment.store.GetRefreshTokenInfo(t.Context(), "bound-refresh")
				require.NoError(t, err)
				family, err := environment.store.GetRefreshTokenFamily(t.Context(), "bound-refresh")
				require.NoError(t, err)
				require.False(t, family.Revoked)
				if shape == "missing" || shape == "wrong key" {
					require.True(t, auditAuthFailureWithReason(t, environment.audit, "refresh_dpop_key_mismatch"))
				}
				response = environment.request(t, dpopRefreshForm(), buildDPoPProofWithATH(t, environment.key, http.MethodPost, testIssuer+server.EndpointPathToken, "retry-proof", ""), nil)
			}
			require.Equal(t, http.StatusOK, response.Code)
			tokens := decodeTokenResponse(t, response)
			require.Equal(t, "DPoP", tokens.TokenType)
			metadata, err := environment.store.GetTokenMetadata(tokens.AccessToken)
			require.NoError(t, err)
			require.Equal(t, environment.thumbprint, metadata.JKT)
		})
	}
}

func TestConfidentialRefreshSelectsCurrentRequestDPoPBinding(t *testing.T) {
	for _, proofPresent := range []bool{false, true} {
		t.Run(map[bool]string{false: "bearer", true: "fresh key"}[proofPresent], func(t *testing.T) {
			environment := newDPoPLifecycleEnvironment(t, server.ClientTypeConfidential)
			proof, expectedThumbprint, expectedType := "", "", "Bearer"
			if proofPresent {
				key := newTestDPoPKey(t)
				proof = buildDPoPProofWithATH(t, key, http.MethodPost, testIssuer+server.EndpointPathToken, "fresh-key-proof", "")
				public := jose.JSONWebKey{Key: key.Public()}
				thumbprint, err := public.Thumbprint(crypto.SHA256)
				require.NoError(t, err)
				expectedThumbprint, expectedType = base64.RawURLEncoding.EncodeToString(thumbprint), "DPoP"
			}
			response := environment.request(t, dpopRefreshForm(), proof, nil)
			require.Equal(t, http.StatusOK, response.Code)
			tokens := decodeTokenResponse(t, response)
			require.Equal(t, expectedType, tokens.TokenType)
			metadata, err := environment.store.GetTokenMetadata(tokens.AccessToken)
			require.NoError(t, err)
			require.Equal(t, expectedThumbprint, metadata.JKT)
			introspection, err := environment.handler.server.IntrospectToken(t.Context(), tokens.AccessToken, environment.client.ClientID)
			require.NoError(t, err)
			require.Equal(t, true, introspection["active"])
			if proofPresent {
				require.Equal(t, map[string]any{"jkt": expectedThumbprint}, introspection["cnf"])
			} else {
				require.NotContains(t, introspection, "cnf")
			}
		})
	}
}

func TestTokenDPoPNonceBootstrapPreservesGrant(t *testing.T) {
	for _, grant := range []string{"authorization_code", "refresh_token"} {
		t.Run(grant, func(t *testing.T) {
			nonces := server.NewHMACNonceProvider([]byte("fixture-nonce-key"), time.Minute, nil)
			environment := newDPoPLifecycleEnvironment(t, server.ClientTypePublic, server.WithDPoPNonceProvider(nonces))
			form := dpopRefreshForm()
			if grant == "authorization_code" {
				verifier := strings.Repeat("v", 43)
				challenge := sha256.Sum256([]byte(verifier))
				require.NoError(t, environment.store.SaveAuthorizationCode(t.Context(), &storage.AuthorizationCode{
					Code: "dpop-code", ClientID: environment.client.ClientID, RedirectURI: environment.client.RedirectURIs[0],
					Scope: "mcp", Audience: testIssuer, Resource: testIssuer, UserID: "person", ProviderToken: environment.providerToken,
					CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), CodeChallengeMethod: "S256", ExpiresAt: time.Now().Add(time.Minute),
				}))
				form = url.Values{"grant_type": {grant}, "code": {"dpop-code"}, "redirect_uri": {environment.client.RedirectURIs[0]}, "resource": {testIssuer}, "code_verifier": {verifier}}
			}
			proof := buildDPoPProofWithATH(t, environment.key, http.MethodPost, testIssuer+server.EndpointPathToken, "without-nonce", "")
			response := environment.request(t, form, proof, nil)
			require.Equal(t, http.StatusBadRequest, response.Code)
			require.Equal(t, "use_dpop_nonce", decodeErrorResponse(t, response).Error)
			nonce := response.Header().Get("DPoP-Nonce")
			require.NotEmpty(t, nonce)
			require.True(t, nonces.Valid(t.Context(), nonce))
			if grant == "authorization_code" {
				code, err := environment.store.GetAuthorizationCode(t.Context(), "dpop-code")
				require.NoError(t, err)
				require.False(t, code.Used)
			} else {
				_, err := environment.store.GetRefreshTokenInfo(t.Context(), "bound-refresh")
				require.NoError(t, err)
			}
			require.True(t, auditAuthFailureWithReason(t, environment.audit, "dpop_nonce_required"))
			proof = buildDPoPProofWithNonce(t, environment.key, http.MethodPost, testIssuer+server.EndpointPathToken, "with-nonce", nonce, "")
			response = environment.request(t, form, proof, nil)
			require.Equal(t, http.StatusOK, response.Code)
			require.Equal(t, "DPoP", decodeTokenResponse(t, response).TokenType)
		})
	}
}

type unavailableDPoPReplayCache struct {
	server.DPoPReplayCache
	unavailable atomic.Bool
}

func (cache *unavailableDPoPReplayCache) Seen(ctx context.Context, identifier string, ttl time.Duration) (bool, error) {
	if cache.unavailable.Load() {
		return false, errors.New("replay store unavailable")
	}
	return cache.DPoPReplayCache.Seen(ctx, identifier, ttl)
}

func TestDPoPReplayStorageFailurePreservesRefreshForRetry(t *testing.T) {
	cache := &unavailableDPoPReplayCache{DPoPReplayCache: server.NewMemoryDPoPReplayCache()}
	cache.unavailable.Store(true)
	environment := newDPoPLifecycleEnvironment(t, server.ClientTypePublic, server.WithDPoPReplayCache(cache))
	proof := buildDPoPProofWithATH(t, environment.key, http.MethodPost, testIssuer+server.EndpointPathToken, "retryable-proof", "")
	response := environment.request(t, dpopRefreshForm(), proof, nil)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.NotEmpty(t, response.Header().Get("Retry-After"))
	_, err := environment.store.GetRefreshTokenInfo(t.Context(), "bound-refresh")
	require.NoError(t, err)
	require.True(t, auditAuthFailureWithReason(t, environment.audit, "dpop_replay_store_unavailable"))
	cache.unavailable.Store(false)
	response = environment.request(t, dpopRefreshForm(), proof, nil)
	require.Equal(t, http.StatusOK, response.Code)
	response = environment.request(t, dpopRefreshForm(), proof, nil)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Equal(t, "invalid_dpop_proof", decodeErrorResponse(t, response).Error)
}

func TestDPoPResourceRejectsDuplicateCredentialsAndRetriesStorageOutage(t *testing.T) {
	key := newTestDPoPKey(t)
	for _, header := range []string{"Authorization", "DPoP"} {
		t.Run(header, func(t *testing.T) {
			called := false
			protected := DPoPMiddleware(server.NewMemoryDPoPReplayCache(), nil, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			request := httptest.NewRequest(http.MethodGet, "https://resource.example.com/mcp", nil)
			request.Header.Set("Authorization", "DPoP fixture-access")
			request.Header.Set("DPoP", buildDPoPProofWithATH(t, key, http.MethodGet, "https://resource.example.com/mcp", "duplicate-proof", "fixture-access"))
			request.Header.Add(header, request.Header.Get(header))
			response := httptest.NewRecorder()
			protected.ServeHTTP(response, request)
			require.Equal(t, http.StatusUnauthorized, response.Code)
			require.False(t, called)
		})
	}
	cache := &unavailableDPoPReplayCache{DPoPReplayCache: server.NewMemoryDPoPReplayCache()}
	cache.unavailable.Store(true)
	called := false
	protected := DPoPMiddleware(cache, nil, nil)(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		called = true
		response.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "https://resource.example.com/mcp", nil)
	request.Header.Set("Authorization", "DPoP fixture-access")
	request.Header.Set("DPoP", buildDPoPProofWithATH(t, key, http.MethodGet, "https://resource.example.com/mcp", "retryable-resource-proof", "fixture-access"))
	response := httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.NotEmpty(t, response.Header().Get("Retry-After"))
	require.False(t, called)
	cache.unavailable.Store(false)
	response = httptest.NewRecorder()
	protected.ServeHTTP(response, request)
	require.Equal(t, http.StatusNoContent, response.Code)
	require.True(t, called)
}

func TestTokenExchangeDPoPReplayStorageOutageIsRetryable(t *testing.T) {
	cache := &unavailableDPoPReplayCache{DPoPReplayCache: server.NewMemoryDPoPReplayCache()}
	cache.unavailable.Store(true)
	handler, audit := setupTokenExchangeHandler(t,
		withSubjectValidator(&fakeSubjectValidator{identity: server.SubjectIdentity{
			Subject: "person", Issuer: "https://oidc.example.com", AllowedScopes: []string{"read"},
		}}),
		func(configuration *tokenExchangeHarnessConfig) { configuration.replayCache = cache },
	)
	request := newTokenExchangeRequest(happyExchangeForm())
	request.Header.Set("DPoP", buildDPoPProofWithATH(t, newTestDPoPKey(t), http.MethodPost, "http://example.com/token", "retryable-exchange-proof", ""))
	response := httptest.NewRecorder()
	handler.ServeToken(response, request)
	requireUnavailableResponse(t, response)
	require.True(t, auditAuthFailureWithReason(t, audit, "token_exchange_dpop_replay_store_unavailable"))
	cache.unavailable.Store(false)
	response = httptest.NewRecorder()
	proof := request.Header.Get("DPoP")
	request = newTokenExchangeRequest(happyExchangeForm())
	request.Header.Set("DPoP", proof)
	handler.ServeToken(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "DPoP", decodeTokenResponse(t, response).TokenType)
}
