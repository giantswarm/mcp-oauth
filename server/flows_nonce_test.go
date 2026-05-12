package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// makeIDTokenWithNonce builds a JWS carrying the requested `nonce` claim, or
// omits the claim when nonce is "". Signature is a placeholder.
func makeIDTokenWithNonce(t *testing.T, nonce string) string {
	t.Helper()
	if nonce == "" {
		return makeIDTokenWithRawNonceClaim(t, nil)
	}
	return makeIDTokenWithRawNonceClaim(t, nonce)
}

// makeIDTokenWithRawNonceClaim builds a JWS whose `nonce` claim takes an
// arbitrary JSON value (string, number, array, ...). Pass nil to omit the
// claim entirely. Signature is a placeholder.
func makeIDTokenWithRawNonceClaim(t *testing.T, nonceValue any) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"}
	headerBytes, err := json.Marshal(header)
	require.NoError(t, err)

	payload := map[string]any{
		"sub":   "user-123",
		"iss":   "https://upstream.example.com",
		"aud":   "test-client",
		"email": "test@example.com",
	}
	if nonceValue != nil {
		payload["nonce"] = nonceValue
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	encode := base64.RawURLEncoding.EncodeToString
	return encode(headerBytes) + "." + encode(payloadBytes) + ".sig"
}

type nonceFlowFixture struct {
	srv      *Server
	store    *memory.Store
	provider *mock.Provider
	clientID string
	auditBuf *bytes.Buffer
}

func setupNonceFlow(t *testing.T, requireNonce bool) *nonceFlowFixture {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	provider := mock.NewProvider()

	logger, auditBuf := captureLogger()

	config := &Config{
		Issuer:                      "https://auth.example.com",
		SupportedScopes:             []string{"openid", "email", "profile"},
		AuthorizationCodeTTL:        600,
		AccessTokenTTL:              3600,
		RequirePKCE:                 true,
		AllowPKCEPlain:              false,
		ClockSkewGracePeriod:        5,
		DisableNonceEchoRequirement: !requireNonce,
	}

	srv, err := New(provider, store, store, store, config, logger)
	require.NoError(t, err)
	srv.Auditor = security.NewAuditor(logger, true)

	client, _, err := srv.RegisterClient(
		context.Background(),
		"Nonce Test Client",
		ClientTypeConfidential,
		"",
		[]string{"https://example.com/callback"},
		[]string{"openid", "email"},
		"192.168.1.100",
		10,
	)
	require.NoError(t, err)

	return &nonceFlowFixture{
		srv:      srv,
		store:    store,
		provider: provider,
		clientID: client.ClientID,
		auditBuf: auditBuf,
	}
}

func (f *nonceFlowFixture) startOIDCFlow(t *testing.T) (providerState, expectedNonce string) {
	t.Helper()

	verifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	ctx := context.Background()
	_, err := f.srv.StartAuthorizationFlow(
		ctx,
		f.clientID,
		"https://example.com/callback",
		"openid email",
		"",
		challenge,
		PKCEMethodS256,
		clientState,
		nil,
	)
	require.NoError(t, err)

	authState, err := f.store.GetAuthorizationState(ctx, clientState)
	require.NoError(t, err)
	require.NotEmpty(t, authState.Nonce, "OIDC flow must persist a nonce")

	return authState.ProviderState, authState.Nonce
}

func (f *nonceFlowFixture) startNonOIDCFlow(t *testing.T) string {
	t.Helper()

	verifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	ctx := context.Background()
	_, err := f.srv.StartAuthorizationFlow(
		ctx,
		f.clientID,
		"https://example.com/callback",
		"email",
		"",
		challenge,
		PKCEMethodS256,
		clientState,
		nil,
	)
	require.NoError(t, err)

	authState, err := f.store.GetAuthorizationState(ctx, clientState)
	require.NoError(t, err)
	require.Empty(t, authState.Nonce, "non-OIDC flow must not bind a nonce")

	return authState.ProviderState
}

func (f *nonceFlowFixture) echoIDToken(idToken string) {
	f.provider.ExchangeCodeFunc = func(_ context.Context, _, _ string) (*oauth2.Token, error) {
		token := &oauth2.Token{
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
		}
		if idToken != "" {
			token = token.WithExtra(map[string]any{"id_token": idToken})
		}
		return token, nil
	}
}

func TestNonce_HappyPath(t *testing.T) {
	fix := setupNonceFlow(t, true)
	providerState, expected := fix.startOIDCFlow(t)
	fix.echoIDToken(makeIDTokenWithNonce(t, expected))

	authCode, _, err := fix.srv.HandleProviderCallback(context.Background(), providerState, "code")
	require.NoError(t, err)
	require.NotNil(t, authCode)
	require.NotEmpty(t, authCode.Code)
}

func TestNonce_Mismatch_Rejected(t *testing.T) {
	fix := setupNonceFlow(t, true)
	providerState, _ := fix.startOIDCFlow(t)
	fix.echoIDToken(makeIDTokenWithNonce(t, "attacker-supplied-nonce-with-enough-length-1234"))

	authCode, _, err := fix.srv.HandleProviderCallback(context.Background(), providerState, "code")
	require.Error(t, err)
	require.Nil(t, authCode)
	require.True(t, errors.Is(err, oidc.ErrNonceMismatch),
		"expected ErrNonceMismatch, got %v", err)

	logOutput := fix.auditBuf.String()
	require.True(t, containsAuditEvent(logOutput, security.EventProviderNonceMismatch),
		"audit event %q not emitted on mismatch; log: %s", security.EventProviderNonceMismatch, logOutput)
	require.Contains(t, logOutput, "mismatch",
		"audit reason should record %q", "mismatch")
	require.Contains(t, logOutput, "high",
		"audit severity should be %q for replay-attack indicator", "high")
}

func TestNonce_MissingInIDToken_Rejected(t *testing.T) {
	fix := setupNonceFlow(t, true)
	providerState, _ := fix.startOIDCFlow(t)
	fix.echoIDToken(makeIDTokenWithNonce(t, ""))

	authCode, _, err := fix.srv.HandleProviderCallback(context.Background(), providerState, "code")
	require.Error(t, err)
	require.Nil(t, authCode)
	require.True(t, errors.Is(err, oidc.ErrNonceMismatch),
		"expected ErrNonceMismatch (claim absent), got %v", err)
	require.Contains(t, err.Error(), "absent")

	logOutput := fix.auditBuf.String()
	require.True(t, containsAuditEvent(logOutput, security.EventProviderNonceMismatch),
		"audit event %q not emitted on absent claim; log: %s", security.EventProviderNonceMismatch, logOutput)
	require.Contains(t, logOutput, "absent",
		"audit reason should record %q", "absent")
}

func TestNonce_WrongTypeClaim_AuditedAsWrongType(t *testing.T) {
	fix := setupNonceFlow(t, true)
	providerState, _ := fix.startOIDCFlow(t)
	fix.echoIDToken(makeIDTokenWithRawNonceClaim(t, 42))

	authCode, _, err := fix.srv.HandleProviderCallback(context.Background(), providerState, "code")
	require.Error(t, err)
	require.Nil(t, authCode)
	require.True(t, errors.Is(err, oidc.ErrNonceMismatch),
		"wrong-type claim must be rejected as nonce mismatch, got %v", err)
	require.Contains(t, err.Error(), "wrong_type")

	logOutput := fix.auditBuf.String()
	require.True(t, containsAuditEvent(logOutput, security.EventProviderNonceMismatch),
		"audit event %q not emitted on wrong-type claim; log: %s", security.EventProviderNonceMismatch, logOutput)
	require.Contains(t, logOutput, "wrong_type",
		"audit reason should distinguish wrong_type from absent/mismatch")
}

func TestNonce_Replay_ProviderStateOneTime(t *testing.T) {
	fix := setupNonceFlow(t, true)
	providerState, expected := fix.startOIDCFlow(t)
	fix.echoIDToken(makeIDTokenWithNonce(t, expected))

	authCode, _, err := fix.srv.HandleProviderCallback(context.Background(), providerState, "code")
	require.NoError(t, err)
	require.NotNil(t, authCode, "first callback must succeed")

	// Replaying the same providerState must fail. The state is deleted after the
	// first consumption — the second call cannot retrieve authState.Nonce and
	// the entire callback is rejected before the echo check fires.
	authCode2, _, err := fix.srv.HandleProviderCallback(context.Background(), providerState, "code")
	require.Error(t, err, "replayed providerState must be rejected")
	require.Nil(t, authCode2)
}

func TestNonce_NotOIDCFlow_NotEnforced(t *testing.T) {
	fix := setupNonceFlow(t, true)
	providerState := fix.startNonOIDCFlow(t)

	fix.echoIDToken(makeIDTokenWithNonce(t, "some-other-nonce-that-would-mismatch-1234"))

	authCode, _, err := fix.srv.HandleProviderCallback(context.Background(), providerState, "code")
	require.NoError(t, err)
	require.NotNil(t, authCode)
}

func TestNonce_DisableNonceEchoRequirement_Bypasses(t *testing.T) {
	fix := setupNonceFlow(t, false)
	providerState, _ := fix.startOIDCFlow(t)
	fix.echoIDToken(makeIDTokenWithNonce(t, ""))

	authCode, _, err := fix.srv.HandleProviderCallback(context.Background(), providerState, "code")
	require.NoError(t, err, "DisableNonceEchoRequirement must bypass the echo check")
	require.NotNil(t, authCode)
}

func TestValidateNonceClaim_ConstantTimeAndSentinel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		claim    string
		expected string
		wantErr  error
	}{
		{"skip when expected empty", "anything", "", nil},
		{"skip when both empty", "", "", nil},
		{"absent claim is rejected", "", "expected-nonce", oidc.ErrNonceMismatch},
		{"mismatch is rejected", "wrong", "expected-nonce", oidc.ErrNonceMismatch},
		{"equal passes", "expected-nonce", "expected-nonce", nil},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := oidc.ValidateNonceClaim(tc.claim, tc.expected)
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.True(t, errors.Is(err, tc.wantErr), "got %v", err)
		})
	}
}

func TestNonce_ForwardedToProviderURL(t *testing.T) {
	fix := setupNonceFlow(t, true)

	verifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	authURL, err := fix.srv.StartAuthorizationFlow(
		context.Background(),
		fix.clientID,
		"https://example.com/callback",
		"openid email",
		"",
		challenge,
		PKCEMethodS256,
		clientState,
		nil,
	)
	require.NoError(t, err)
	require.True(t, strings.Contains(authURL, "nonce="),
		"upstream authorization URL must carry a nonce parameter: %s", authURL)

	authState, err := fix.store.GetAuthorizationState(context.Background(), clientState)
	require.NoError(t, err)
	require.NotEmpty(t, authState.Nonce)
	require.Contains(t, authURL, "nonce="+authState.Nonce)
}

func TestNonce_ClientSuppliedPassesThrough(t *testing.T) {
	fix := setupNonceFlow(t, true)

	clientNonce := "client-supplied-nonce-of-sufficient-length-1234567890"
	require.GreaterOrEqual(t, len(clientNonce), minClientNonceLength)

	verifier := testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	_, err := fix.srv.StartAuthorizationFlow(
		context.Background(),
		fix.clientID,
		"https://example.com/callback",
		"openid email",
		"",
		challenge,
		PKCEMethodS256,
		clientState,
		&providers.AuthorizationURLOptions{Nonce: clientNonce},
	)
	require.NoError(t, err)

	authState, err := fix.store.GetAuthorizationState(context.Background(), clientState)
	require.NoError(t, err)
	require.Equal(t, clientNonce, authState.Nonce)
}
