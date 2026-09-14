package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

// faultyOpTimeout is the per-operation deadline the faulty store applies; the
// hanging fault blocks exactly this long.
const faultyOpTimeout = 150 * time.Millisecond

// faultyGrantFixture is a JWT-mode server on a fault-injecting store with one
// confidential client, the shape of the Slack gateway against muster.
type faultyGrantFixture struct {
	srv          *Server
	store        *memory.Store
	faulty       *storagemock.FaultyStore
	clientID     string
	clientSecret string
}

func newFaultyGrantFixture(t *testing.T) *faultyGrantFixture {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })
	faulty := storagemock.NewFaultyStore(store, faultyOpTimeout)

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          "https://api.example.com",
		SupportedScopes:             []string{"openid", "email", "profile"},
		AccessTokenTTL:              600,
		RefreshTokenTTL:             86400,
		AllowRefreshTokenRotation:   true,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       generateRSAKey(t),
		AccessTokenSigningKeyID:     "faulty-kid",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
	}
	srv, err := New(mock.NewProvider(), faulty, faulty, faulty, cfg, nil)
	require.NoError(t, err)

	client, secret, err := srv.RegisterClient(context.Background(), "gateway", ClientTypeConfidential, "",
		[]string{"https://example.com/callback"}, []string{"openid", "email"}, "192.168.1.100", 10)
	require.NoError(t, err)

	return &faultyGrantFixture{srv: srv, store: store, faulty: faulty, clientID: client.ClientID, clientSecret: secret}
}

// issueCode runs the authorization flow up to the code the client would
// present at the token endpoint. The second value is the PKCE verifier.
func (f *faultyGrantFixture) issueCode(t *testing.T) (code, verifier string) {
	t.Helper()
	ctx := context.Background()
	verifier = testutil.GenerateRandomString(testPKCEVerifierLength)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	clientState := testutil.GenerateRandomString(43)

	_, err := f.srv.StartAuthorizationFlow(ctx, f.clientID, mustParseURL(t, "https://example.com/callback"),
		"openid email", "", challenge, PKCEMethodS256, clientState, nil)
	require.NoError(t, err)
	authState, err := f.store.GetAuthorizationState(ctx, clientState)
	require.NoError(t, err)
	authCode, _, err := f.srv.HandleProviderCallback(ctx, authState.ProviderState, "provider-code-"+testutil.GenerateRandomString(8))
	require.NoError(t, err)
	return authCode.Code, verifier
}

// login completes a session and returns its tokens.
func (f *faultyGrantFixture) login(t *testing.T) *oauth2.Token {
	t.Helper()
	code, verifier := f.issueCode(t)
	tok, _, err := f.srv.ExchangeAuthorizationCode(context.Background(), code, f.clientID, "https://example.com/callback", "", verifier, "")
	require.NoError(t, err)
	require.NotEmpty(t, tok.RefreshToken)
	return tok
}

// requireUnavailable asserts err is the storage-outage classification and
// nothing a client would read as a dead grant.
func requireUnavailable(t *testing.T, err error) {
	t.Helper()
	require.ErrorIs(t, err, ErrStorageUnavailable)
	require.NotErrorIs(t, err, errInvalidGrant)
	require.NotContains(t, err.Error(), ErrorCodeInvalidGrant)
}

// requireWithinDeadline asserts a hanging store was cut off by its
// per-operation deadline rather than the request lasting for the outage.
func requireWithinDeadline(t *testing.T, elapsed time.Duration) {
	t.Helper()
	require.Less(t, elapsed, faultyOpTimeout+time.Second, "must give up at the operation deadline, took %v", elapsed)
}

var storageFaults = []struct {
	name  string
	fault storagemock.Fault
}{
	{"hanging store", storagemock.Hang},
	{"connection refused", storagemock.ConnectionRefused},
}

// TestRefreshAccessToken_StorageUnavailable: with the store unreachable on
// any read the refresh grant depends on, the grant fails as
// ErrStorageUnavailable within the operation deadline, the refresh token and
// its family are untouched, and the same token refreshes once the store is
// back.
func TestRefreshAccessToken_StorageUnavailable(t *testing.T) {
	operations := []string{
		"get_token_metadata",
		"get_refresh_token_info",
		"get_user_provider_token",
		"acquire_provider_refresh_lock",
		"atomic_consume_refresh_token",
	}
	for _, fault := range storageFaults {
		for _, op := range operations {
			t.Run(fault.name+"/"+op, func(t *testing.T) {
				f := newFaultyGrantFixture(t)
				ctx := context.Background()
				rt := f.login(t).RefreshToken
				familyBefore, err := f.store.GetRefreshTokenFamily(ctx, rt)
				require.NoError(t, err)

				callsBefore := f.faulty.Calls(op)
				f.faulty.Fail(storagemock.OnOperation(op, fault.fault))
				start := time.Now()
				_, err = f.srv.RefreshAccessToken(ctx, rt, f.clientID)
				elapsed := time.Since(start)
				requireUnavailable(t, err)
				requireWithinDeadline(t, elapsed)
				require.Equal(t, callsBefore+1, f.faulty.Calls(op), "the failing operation is not retried inside the grant")

				// Family and token untouched: same family, same generation, not revoked.
				familyAfter, err := f.store.GetRefreshTokenFamily(ctx, rt)
				require.NoError(t, err, "refresh token must survive a storage outage")
				require.Equal(t, familyBefore.FamilyID, familyAfter.FamilyID)
				require.Equal(t, familyBefore.Generation, familyAfter.Generation)
				require.False(t, familyAfter.Revoked)
				_, err = f.store.GetRefreshTokenInfo(ctx, rt)
				require.NoError(t, err, "refresh token must not be consumed on a storage outage")

				// Store back: the same token refreshes and rotates within its family.
				f.faulty.Heal()
				tok, err := f.srv.RefreshAccessToken(ctx, rt, f.clientID)
				require.NoError(t, err, "retry after the outage must succeed")
				require.NotEqual(t, rt, tok.RefreshToken)
				familyNext, err := f.store.GetRefreshTokenFamily(ctx, tok.RefreshToken)
				require.NoError(t, err)
				require.Equal(t, familyBefore.FamilyID, familyNext.FamilyID)
				require.Equal(t, familyBefore.Generation+1, familyNext.Generation)
			})
		}
	}
}

// TestExchangeAuthorizationCode_StorageUnavailable: the code grant fails as
// ErrStorageUnavailable within the deadline and the code stays exchangeable
// once the store is back — the client lookup runs before the code is marked
// used, so neither failure burns it.
func TestExchangeAuthorizationCode_StorageUnavailable(t *testing.T) {
	operations := []string{"get_client", "atomic_check_and_mark_auth_code_used"}
	for _, fault := range storageFaults {
		for _, op := range operations {
			t.Run(fault.name+"/"+op, func(t *testing.T) {
				f := newFaultyGrantFixture(t)
				ctx := context.Background()
				code, verifier := f.issueCode(t)

				f.faulty.Fail(storagemock.OnOperation(op, fault.fault))
				start := time.Now()
				_, _, err := f.srv.ExchangeAuthorizationCode(ctx, code, f.clientID, "https://example.com/callback", "", verifier, "")
				requireUnavailable(t, err)
				requireWithinDeadline(t, time.Since(start))

				f.faulty.Heal()
				tok, _, err := f.srv.ExchangeAuthorizationCode(ctx, code, f.clientID, "https://example.com/callback", "", verifier, "")
				require.NoError(t, err, "the code must still be exchangeable after the outage")
				require.NotEmpty(t, tok.AccessToken)
			})
		}
	}
}

// TestTokenExchange_StorageUnavailable: a self-issued subject token whose
// revocation list or family record cannot be read fails the exchange as
// ErrStorageUnavailable (self-issued and brokered), never as an invalid
// subject, and the exchange succeeds once the store is back.
func TestTokenExchange_StorageUnavailable(t *testing.T) {
	operations := []string{"is_jti_revoked", "get_refresh_token_family_by_id"}
	for _, fault := range storageFaults {
		for _, op := range operations {
			t.Run(fault.name+"/"+op, func(t *testing.T) {
				f := newFaultyGrantFixture(t)
				ctx := context.Background()
				subject := f.login(t).AccessToken // a self-issued JWT carrying jti and family_id

				// The actor token is not a JWT; the self-issued validator hands
				// it to the next validator in the chain.
				f.srv.subjectValidators[SubjectTokenTypeIDToken] = &selfIssuedSubjectValidator{
					srv: f.srv,
					next: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
						"act-tok": {Subject: "agent-a", Issuer: "https://k8s.example.com"},
					}},
				}
				req := SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
					Subject:  TypedToken{Token: subject, Type: SubjectTokenTypeAccessToken},
					Actor:    TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken},
					Resource: "https://api.example.com",
					Scope:    "openid",
				}}

				f.faulty.Fail(storagemock.OnOperation(op, fault.fault))
				start := time.Now()
				_, err := f.srv.SelfIssuedExchange(ctx, req)
				requireUnavailable(t, err)
				requireWithinDeadline(t, time.Since(start))

				f.srv.exchanger = &stubExchanger{result: &ExchangerResult{AccessToken: "downstream", ExpiresAt: time.Now().Add(time.Minute)}}
				f.srv.Config.TokenExchangeClientAudiences = map[string][]string{f.clientID: {"downstream-api"}}
				_, err = f.srv.BrokeredExchange(ctx, BrokeredExchangeRequest{
					SubjectExchange: req.SubjectExchange, ClientID: f.clientID, Audience: "downstream-api",
				})
				requireUnavailable(t, err)

				f.faulty.Heal()
				result, err := f.srv.SelfIssuedExchange(ctx, req)
				require.NoError(t, err, "the exchange must succeed once the store is back")
				require.NotEmpty(t, result.AccessToken)
			})
		}
	}
}

// TestClientAuthentication_StorageUnavailable: a client store that does not
// answer is ErrStorageUnavailable on both lookup and secret validation, while
// an unknown client or a wrong secret keep their rejections.
func TestClientAuthentication_StorageUnavailable(t *testing.T) {
	for _, fault := range storageFaults {
		t.Run(fault.name, func(t *testing.T) {
			f := newFaultyGrantFixture(t)
			ctx := context.Background()

			f.faulty.Fail(storagemock.OnOperation("validate_client_secret", fault.fault))
			start := time.Now()
			err := f.srv.ValidateClientCredentials(ctx, f.clientID, f.clientSecret)
			requireUnavailable(t, err)
			requireWithinDeadline(t, time.Since(start))

			f.faulty.Fail(storagemock.OnOperation("get_client", fault.fault))
			_, err = f.srv.GetClient(ctx, f.clientID)
			requireUnavailable(t, err)

			f.faulty.Heal()
			require.NoError(t, f.srv.ValidateClientCredentials(ctx, f.clientID, f.clientSecret))
			err = f.srv.ValidateClientCredentials(ctx, f.clientID, "wrong-secret")
			require.ErrorIs(t, err, storage.ErrInvalidClientCredentials)
			require.NotErrorIs(t, err, ErrStorageUnavailable)
			_, err = f.srv.GetClient(ctx, "no-such-client")
			require.ErrorIs(t, err, storage.ErrClientNotFound)
			require.NotErrorIs(t, err, ErrStorageUnavailable)
		})
	}
}
