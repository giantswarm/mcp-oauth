package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

// outageOpTimeout is the per-operation deadline of the faulty store; a
// hanging store is cut off after exactly this long.
const outageOpTimeout = 150 * time.Millisecond

// outageSlack is the time a request may spend outside the store call while
// still proving it ended at the operation deadline rather than lasting the
// outage (the old behaviour was a hang for as long as the client waited). The
// bcrypt client-secret check dominates and runs several times slower under
// the race detector on a loaded machine.
const outageSlack = 3 * time.Second

// outageEnv is a handler on a fault-injecting store with one confidential
// client — the shape of the Slack gateway against muster, refreshing with
// Basic client authentication and presenting bearers on the MCP path. The
// grant tests run it in JWT mode; the validation tests in both formats.
type outageEnv struct {
	handler      *Handler
	provider     *mock.Provider
	store        *memory.Store
	faulty       *storagemock.FaultyStore
	logs         *bytes.Buffer
	clientID     string
	clientSecret string
}

func newOutageEnv(t *testing.T) *outageEnv {
	t.Helper()
	return newOutageEnvWithFormat(t, server.AccessTokenFormatJWT)
}

func newOutageEnvWithFormat(t *testing.T, format server.AccessTokenFormat) *outageEnv {
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
		AccessTokenFormat:           format,
		DisableNonceEchoRequirement: true,
	}
	if format == server.AccessTokenFormatJWT {
		cfg.AccessTokenSigningKey = signingKey
		cfg.AccessTokenSigningKeyID = "outage-kid"
		cfg.AccessTokenSigningAlgorithm = server.SigningAlgorithmRS256
	}
	// The actor token of the exchange tests is not a JWT: the self-issued
	// validator the server chains ahead of this one hands it over.
	actorValidator := &fakeSubjectValidator{byToken: map[string]*server.SubjectIdentity{
		"act-tok": {Subject: "agent-a", Issuer: "https://k8s.example.com"},
	}}
	provider := mock.NewProvider()
	srv, err := server.New(provider, faulty, faulty, faulty, cfg, logger,
		server.WithAuditor(security.NewAuditor(logger, true)),
		server.WithSubjectTokenValidator(server.SubjectTokenTypeIDToken, actorValidator))
	require.NoError(t, err)

	client, secret, err := srv.RegisterClient(context.Background(), "gateway", server.ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"openid", "email"}, testClientRemoteAddr, 10)
	require.NoError(t, err)

	return &outageEnv{
		handler: New(srv, logger), provider: provider, store: store, faulty: faulty, logs: logs,
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

// outageFaults are the two shapes of a store outage every test drives: a
// backend that accepts the connection and never answers, and one that
// refuses it at once.
var outageFaults = []struct {
	name  string
	fault storagemock.Fault
}{
	{"hanging store", storagemock.Hang},
	{"connection refused", storagemock.ConnectionRefused},
}

// requireTemporarilyUnavailable asserts the 503 contract: the error code, the
// Retry-After hint, no trace of invalid_grant or invalid_token, no
// WWW-Authenticate challenge, and the audit reason.
func requireTemporarilyUnavailable(t *testing.T, e *outageEnv, w *httptest.ResponseRecorder, elapsed time.Duration) {
	t.Helper()
	require.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, constants.ErrorCodeTemporarilyUnavailable, body["error"])
	require.NotContains(t, w.Body.String(), constants.ErrorCodeInvalidGrant)
	require.NotContains(t, w.Body.String(), constants.ErrorCodeInvalidToken)
	require.Empty(t, w.Header().Get("WWW-Authenticate"), "a 503 is not a challenge")
	require.Equal(t, "5", w.Header().Get("Retry-After"))
	require.Less(t, elapsed, outageOpTimeout+outageSlack, "the request must end at the operation deadline, took %v", elapsed)
	require.Contains(t, e.logs.String(), "transient_storage_error", "the outage is audited")
}

// TestServeToken_RefreshGrant_StorageUnavailable: a refresh grant met by a
// store that hangs or refuses connections — on the client-secret check or on
// the token lookup — answers 503 temporarily_unavailable within the deadline;
// the refresh token stays valid and refreshes once the store is back.
func TestServeToken_RefreshGrant_StorageUnavailable(t *testing.T) {
	for _, fault := range outageFaults {
		for _, op := range []string{"validate_client_secret", "get_refresh_token_info"} {
			t.Run(fault.name+"/"+op, func(t *testing.T) {
				e := newOutageEnv(t)
				rt := e.login(t).RefreshToken
				familyBefore, err := e.store.GetRefreshTokenFamily(context.Background(), rt)
				require.NoError(t, err)

				e.faulty.Fail(storagemock.OnOperation(op, fault.fault))
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
	for _, fault := range outageFaults {
		for _, op := range []string{"get_client", "atomic_check_and_mark_auth_code_used"} {
			t.Run(fault.name+"/"+op, func(t *testing.T) {
				e := newOutageEnv(t)
				code, verifier := e.issueCode(t)

				e.faulty.Fail(storagemock.OnOperation(op, fault.fault))
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
	for _, fault := range outageFaults {
		t.Run(fault.name, func(t *testing.T) {
			e := newOutageEnv(t)
			subject := e.login(t).AccessToken

			e.faulty.Fail(storagemock.OnOperation("is_jti_revoked", fault.fault))
			start := time.Now()
			w := e.postToken(e.exchangeForm(subject))
			requireTemporarilyUnavailable(t, e, w, time.Since(start))

			e.faulty.Heal()
			w = e.postToken(e.exchangeForm(subject))
			require.Equal(t, http.StatusOK, w.Code, "the exchange must succeed after the outage: %s", w.Body.String())
		})
	}
}

// protectedResult is what the handler behind the ValidateToken middleware
// saw on the request context.
type protectedResult struct {
	userID, sessionID string
}

// callProtected sends a bearer request through the ValidateToken middleware
// to a handler that records the validated identity and session; the result
// is nil when the middleware did not let the request through.
func (e *outageEnv) callProtected(accessToken string) (*httptest.ResponseRecorder, *protectedResult) {
	var got *protectedResult
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, _ := UserInfoFromContext(r.Context())
		sessionID, _ := SessionIDFromContext(r.Context())
		got = &protectedResult{userID: userInfo.ID, sessionID: sessionID}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	e.handler.ValidateToken(next).ServeHTTP(w, req)
	return w, got
}

// postIntrospect sends token to the introspection endpoint with Basic client
// authentication.
func (e *outageEnv) postIntrospect(token string) *httptest.ResponseRecorder {
	form := url.Values{"token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(e.clientID, e.clientSecret)
	req.RemoteAddr = testClientRemoteAddr
	w := httptest.NewRecorder()
	e.handler.ServeTokenIntrospection(w, req)
	return w
}

// TestValidateTokenMiddleware_StorageUnavailable: a bearer request met by a
// store that hangs or refuses connections on any read validation depends on
// — the JWT's revocation-list and family checks, the opaque token's
// provider-token and audience reads, and the middleware's own metadata read
// — answers 503 temporarily_unavailable with Retry-After within the
// deadline, carries no invalid_token challenge, never reaches the protected
// handler, and lets the same bearer through with the same identity and
// session once the store is back.
func TestValidateTokenMiddleware_StorageUnavailable(t *testing.T) {
	cases := []struct {
		format     server.AccessTokenFormat
		operations []string
	}{
		{server.AccessTokenFormatJWT, []string{"is_jti_revoked", "get_refresh_token_family_by_id", "get_token_metadata"}},
		{server.AccessTokenFormatOpaque, []string{"get_provider_token_ref", "get_user_provider_token", "get_token_metadata"}},
	}
	for _, tc := range cases {
		for _, fault := range outageFaults {
			for _, op := range tc.operations {
				t.Run(string(tc.format)+"/"+fault.name+"/"+op, func(t *testing.T) {
					e := newOutageEnvWithFormat(t, tc.format)
					at := e.login(t).AccessToken
					w, before := e.callProtected(at)
					require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
					require.NotNil(t, before)
					require.NotEmpty(t, before.sessionID)

					e.faulty.Fail(storagemock.OnOperation(op, fault.fault))
					start := time.Now()
					w, during := e.callProtected(at)
					requireTemporarilyUnavailable(t, e, w, time.Since(start))
					require.Nil(t, during, "the protected handler must not run during the outage")

					e.faulty.Heal()
					w, after := e.callProtected(at)
					require.Equal(t, http.StatusOK, w.Code, "the same bearer must pass once the store is back: %s", w.Body.String())
					require.Equal(t, before, after, "identity and session must be the ones from before the outage")
				})
			}
		}
	}
}

// TestValidateTokenMiddleware_RejectionsStay401: with the store answering,
// a bearer the store has no record of and the provider rejects stays 401
// invalid_token — the 503 is reserved for a store that did not answer.
func TestValidateTokenMiddleware_RejectionsStay401(t *testing.T) {
	e := newOutageEnv(t)
	e.provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
		return nil, errors.New("unknown token")
	}
	w, got := e.callProtected("not-a-token")
	require.Equal(t, http.StatusUnauthorized, w.Code, "body: %s", w.Body.String())
	require.Nil(t, got)
	require.Contains(t, w.Header().Get("WWW-Authenticate"), constants.ErrorCodeInvalidToken)
	require.Empty(t, w.Header().Get("Retry-After"))
}

// TestServeTokenIntrospection_StorageUnavailable: introspection met by a
// store that does not answer is 503 temporarily_unavailable, not
// {"active": false}; the same token introspects active once the store is
// back.
func TestServeTokenIntrospection_StorageUnavailable(t *testing.T) {
	cases := []struct {
		format server.AccessTokenFormat
		op     string
	}{
		{server.AccessTokenFormatJWT, "is_jti_revoked"},
		{server.AccessTokenFormatOpaque, "get_token_metadata"},
	}
	for _, tc := range cases {
		for _, fault := range outageFaults {
			t.Run(string(tc.format)+"/"+fault.name+"/"+tc.op, func(t *testing.T) {
				e := newOutageEnvWithFormat(t, tc.format)
				at := e.login(t).AccessToken

				e.faulty.Fail(storagemock.OnOperation(tc.op, fault.fault))
				start := time.Now()
				w := e.postIntrospect(at)
				requireTemporarilyUnavailable(t, e, w, time.Since(start))
				require.NotContains(t, w.Body.String(), `"active"`, "an outage is not an inactive token")

				e.faulty.Heal()
				w = e.postIntrospect(at)
				require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
				var body map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				require.Equal(t, true, body["active"], "the token must introspect active once the store is back")
			})
		}
	}
}
