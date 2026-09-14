package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

// outageOpTimeout is the per-operation deadline of the faulty store; a
// hanging store is cut off after exactly this long.
const outageOpTimeout = 150 * time.Millisecond

// outageEnv is a JWT-mode token endpoint on a fault-injecting store with one
// confidential client — the shape of the Slack gateway refreshing against
// muster with Basic client authentication.
type outageEnv struct {
	handler      *Handler
	store        *memory.Store
	faulty       *storagemock.FaultyStore
	logs         *bytes.Buffer
	clientID     string
	clientSecret string
}

func newOutageEnv(t *testing.T) *outageEnv {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })
	faulty := storagemock.NewFaultyStore(store, outageOpTimeout)

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	cfg := &server.Config{
		Issuer:                      testIssuer,
		ResourceIdentifier:          "https://api.example.com",
		SupportedScopes:             []string{"openid", "email", "profile"},
		AccessTokenTTL:              600,
		RefreshTokenTTL:             86400,
		AllowRefreshTokenRotation:   true,
		AccessTokenFormat:           server.AccessTokenFormatJWT,
		AccessTokenSigningKey:       signingKey,
		AccessTokenSigningKeyID:     "outage-kid",
		AccessTokenSigningAlgorithm: server.SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}
	// The actor token of the exchange tests is not a JWT: the self-issued
	// validator the server chains ahead of this one hands it over.
	actorValidator := &fakeSubjectValidator{byToken: map[string]*server.SubjectIdentity{
		"act-tok": {Subject: "agent-a", Issuer: "https://k8s.example.com"},
	}}
	srv, err := server.New(mock.NewProvider(), faulty, faulty, faulty, cfg, logger,
		server.WithAuditor(security.NewAuditor(logger, true)),
		server.WithSubjectTokenValidator(server.SubjectTokenTypeIDToken, actorValidator))
	require.NoError(t, err)

	client, secret, err := srv.RegisterClient(context.Background(), "gateway", server.ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"openid", "email"}, testClientRemoteAddr, 10)
	require.NoError(t, err)

	return &outageEnv{
		handler: New(srv, logger), store: store, faulty: faulty, logs: logs,
		clientID: client.ClientID, clientSecret: secret,
	}
}

// issueCode runs the authorization flow up to the code the client presents.
func (e *outageEnv) issueCode(t *testing.T) (code, verifier string) {
	t.Helper()
	ctx := context.Background()
	verifier = strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := strings.Repeat("s", 43)

	_, err := e.handler.server.StartAuthorizationFlow(ctx, e.clientID, mustParse(t, "https://example.com/callback"),
		"openid email", "", challenge, server.PKCEMethodS256, clientState, nil)
	require.NoError(t, err)
	authState, err := e.store.GetAuthorizationState(ctx, clientState)
	require.NoError(t, err)
	authCode, _, err := e.handler.server.HandleProviderCallback(ctx, authState.ProviderState, "provider-code")
	require.NoError(t, err)
	return authCode.Code, verifier
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func (e *outageEnv) login(t *testing.T) *oauth2.Token {
	t.Helper()
	code, verifier := e.issueCode(t)
	tok, _, err := e.handler.server.ExchangeAuthorizationCode(context.Background(), code, e.clientID, "https://example.com/callback", "", verifier, "")
	require.NoError(t, err)
	return tok
}

// postToken sends form to the token endpoint with Basic client authentication.
func (e *outageEnv) postToken(form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(e.clientID, e.clientSecret)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	e.handler.ServeToken(w, req)
	return w
}

func (e *outageEnv) refreshForm(rt string) url.Values {
	return url.Values{"grant_type": {grantTypeRefreshToken}, "refresh_token": {rt}}
}

func (e *outageEnv) codeForm(code, verifier string) url.Values {
	return url.Values{
		"grant_type": {grantTypeAuthorizationCode}, "code": {code}, "code_verifier": {verifier},
		"redirect_uri": {"https://example.com/callback"}, "client_id": {e.clientID},
	}
}

func (e *outageEnv) exchangeForm(subject string) url.Values {
	return url.Values{
		"grant_type":         {server.GrantTypeTokenExchange},
		"subject_token":      {subject},
		"subject_token_type": {server.SubjectTokenTypeAccessToken},
		"actor_token":        {"act-tok"},
		"actor_token_type":   {server.SubjectTokenTypeIDToken},
		"resource":           {"https://api.example.com"},
		"scope":              {"openid"},
	}
}

// requireTemporarilyUnavailable asserts the 503 contract: the error code, the
// Retry-After hint, no trace of invalid_grant, and the audit reason.
func requireTemporarilyUnavailable(t *testing.T, e *outageEnv, w *httptest.ResponseRecorder, elapsed time.Duration) {
	t.Helper()
	require.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, constants.ErrorCodeTemporarilyUnavailable, body["error"])
	require.NotContains(t, w.Body.String(), constants.ErrorCodeInvalidGrant)
	require.Equal(t, "5", w.Header().Get("Retry-After"))
	require.Less(t, elapsed, outageOpTimeout+time.Second, "the request must end at the operation deadline, took %v", elapsed)
	require.Contains(t, e.logs.String(), "transient_storage_error", "the outage is audited")
}

// TestServeToken_RefreshGrant_StorageUnavailable: a refresh grant met by a
// store that hangs or refuses connections — on the client-secret check or on
// the token lookup — answers 503 temporarily_unavailable within the deadline;
// the refresh token stays valid and refreshes once the store is back.
func TestServeToken_RefreshGrant_StorageUnavailable(t *testing.T) {
	faults := map[string]storagemock.Fault{"hanging store": storagemock.Hang, "connection refused": storagemock.ConnectionRefused}
	for name, fault := range faults {
		for _, op := range []string{"validate_client_secret", "get_refresh_token_info"} {
			t.Run(name+"/"+op, func(t *testing.T) {
				e := newOutageEnv(t)
				rt := e.login(t).RefreshToken
				familyBefore, err := e.store.GetRefreshTokenFamily(context.Background(), rt)
				require.NoError(t, err)

				e.faulty.Fail(storagemock.OnOperation(op, fault))
				start := time.Now()
				w := e.postToken(e.refreshForm(rt))
				requireTemporarilyUnavailable(t, e, w, time.Since(start))

				familyAfter, err := e.store.GetRefreshTokenFamily(context.Background(), rt)
				require.NoError(t, err, "the refresh token must survive the outage")
				require.Equal(t, familyBefore.Generation, familyAfter.Generation)
				require.False(t, familyAfter.Revoked)

				e.faulty.Heal()
				w = e.postToken(e.refreshForm(rt))
				require.Equal(t, http.StatusOK, w.Code, "the same refresh token must work after the outage: %s", w.Body.String())
			})
		}
	}
}

// TestServeToken_AuthorizationCodeGrant_StorageUnavailable: the code grant
// answers 503 within the deadline and the code is still exchangeable after
// the outage.
func TestServeToken_AuthorizationCodeGrant_StorageUnavailable(t *testing.T) {
	faults := map[string]storagemock.Fault{"hanging store": storagemock.Hang, "connection refused": storagemock.ConnectionRefused}
	for name, fault := range faults {
		for _, op := range []string{"get_client", "atomic_check_and_mark_auth_code_used"} {
			t.Run(name+"/"+op, func(t *testing.T) {
				e := newOutageEnv(t)
				code, verifier := e.issueCode(t)

				e.faulty.Fail(storagemock.OnOperation(op, fault))
				start := time.Now()
				w := e.postToken(e.codeForm(code, verifier))
				requireTemporarilyUnavailable(t, e, w, time.Since(start))

				e.faulty.Heal()
				w = e.postToken(e.codeForm(code, verifier))
				require.Equal(t, http.StatusOK, w.Code, "the code must still be exchangeable after the outage: %s", w.Body.String())
			})
		}
	}
}

// TestServeToken_TokenExchangeGrant_StorageUnavailable: an exchange whose
// self-issued subject token cannot be checked against the revocation list
// answers 503 within the deadline and succeeds after the outage.
func TestServeToken_TokenExchangeGrant_StorageUnavailable(t *testing.T) {
	faults := map[string]storagemock.Fault{"hanging store": storagemock.Hang, "connection refused": storagemock.ConnectionRefused}
	for name, fault := range faults {
		t.Run(name, func(t *testing.T) {
			e := newOutageEnv(t)
			subject := e.login(t).AccessToken

			e.faulty.Fail(storagemock.OnOperation("is_jti_revoked", fault))
			start := time.Now()
			w := e.postToken(e.exchangeForm(subject))
			requireTemporarilyUnavailable(t, e, w, time.Since(start))

			e.faulty.Heal()
			w = e.postToken(e.exchangeForm(subject))
			require.Equal(t, http.StatusOK, w.Code, "the exchange must succeed after the outage: %s", w.Body.String())
		})
	}
}
