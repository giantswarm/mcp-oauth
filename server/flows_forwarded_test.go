package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// ---- helpers ----------------------------------------------------------------

// forwardedTokenHarness is the fixture shared by the AcceptForwardedIDToken tests.
// It spins up a TLS JWKS server, constructs a mock JWKSProvider pointing at it,
// and returns a Server wired to issue signed ID tokens that validate against it.
type forwardedTokenHarness struct {
	srv        *Server
	privateKey *rsa.PrivateKey
	keyID      string
	jwksServer *httptest.Server
	issuer     string
	audience   string
	provider   *mock.Provider
}

func newForwardedTokenHarness(t *testing.T, opts ...func(*Config)) *forwardedTokenHarness {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	const keyID = "test-key-1"
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       privateKey.Public(),
			KeyID:     keyID,
			Algorithm: "RS256",
			Use:       "sig",
		}},
	}

	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksServer.Close)

	const (
		issuer   = "https://auth.test.example"
		audience = "forwarded-audience"
	)

	mockProvider := mock.NewProvider()
	mockProvider.JWKSURIFunc = func(ctx context.Context) (string, error) {
		return jwksServer.URL, nil
	}
	mockProvider.IssuerURLFunc = func() string {
		return issuer
	}

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:             issuer,
		TrustedAudiences:   []string{audience},
		AllowPrivateIPJWKS: true,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	srv := &Server{
		Config:     cfg,
		Logger:     slog.Default(),
		provider:   mockProvider,
		tokenStore: store,
	}

	// Inject a JWKS client that trusts the test TLS server and permits loopback
	// addresses. srv.getJWKSClient() uses sync.Once, so populate it first and
	// consume the Once to prevent a real construction from replacing ours.
	srv.jwksClient = oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{
		HTTPClient:     jwksServer.Client(),
		AllowPrivateIP: true,
		Logger:         slog.Default(),
	})
	srv.jwksClientOnce.Do(func() {})

	return &forwardedTokenHarness{
		srv:        srv,
		privateKey: privateKey,
		keyID:      keyID,
		jwksServer: jwksServer,
		issuer:     issuer,
		audience:   audience,
		provider:   mockProvider,
	}
}

// signToken creates a valid RS256-signed JWT with the given registered claims.
func (h *forwardedTokenHarness) signToken(t *testing.T, claims josejwt.Claims) string {
	t.Helper()
	return signTestRS256Token(t, h.privateKey, h.keyID, oidc.IDTokenClaims{
		Claims: claims,
		Email:  "user@test.example",
		Name:   "Test User",
	})
}

// signTestRS256Token signs a token using go-jose with the given private RSA
// key, kid, and full claim payload. Used by both the harness and the
// invalid-signature test which signs with a deliberately wrong key.
func signTestRS256Token(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims any) string {
	t.Helper()
	signingKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:       privateKey,
			KeyID:     kid,
			Algorithm: "RS256",
			Use:       "sig",
		},
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	signed, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// validClaims returns a claims set that should pass all checks.
func (h *forwardedTokenHarness) validClaims() josejwt.Claims {
	now := time.Now()
	return josejwt.Claims{
		Subject:  "user-subject-123",
		Issuer:   h.issuer,
		Audience: josejwt.Audience{h.audience},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
	}
}

// ---- tests ------------------------------------------------------------------

func TestAcceptForwardedIDToken_HappyPath(t *testing.T) {
	h := newForwardedTokenHarness(t)
	tok := h.signToken(t, h.validClaims())

	acc, err := h.srv.AcceptForwardedIDToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("AcceptForwardedIDToken: %v", err)
	}
	if acc == nil {
		t.Fatal("nil acceptance")
	}
	if acc.Subject != "user-subject-123" {
		t.Errorf("Subject = %q, want user-subject-123", acc.Subject)
	}
	if acc.UserInfo == nil || acc.UserInfo.ID != "user-subject-123" {
		t.Errorf("UserInfo.ID unexpected: %+v", acc.UserInfo)
	}
	if acc.UserInfo.TokenSource != providers.TokenSourceSSO {
		t.Errorf("UserInfo.TokenSource = %q, want sso", acc.UserInfo.TokenSource)
	}
	if acc.Issuer != h.issuer {
		t.Errorf("Issuer = %q, want %q", acc.Issuer, h.issuer)
	}
	if acc.Audience != h.audience {
		t.Errorf("Audience = %q, want %q", acc.Audience, h.audience)
	}
	if !strings.HasPrefix(acc.SessionID, "ext-") || len(acc.SessionID) != len("ext-")+16 {
		t.Errorf("SessionID = %q, want ext-<16 hex>", acc.SessionID)
	}
	if acc.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be populated from JWT exp")
	}
}

func TestAcceptForwardedIDToken_Determinism(t *testing.T) {
	h := newForwardedTokenHarness(t)
	tok := h.signToken(t, h.validClaims())

	ctx := context.Background()
	a1, err := h.srv.AcceptForwardedIDToken(ctx, tok)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	a2, err := h.srv.AcceptForwardedIDToken(ctx, tok)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if a1.SessionID != a2.SessionID {
		t.Errorf("SessionID not deterministic: %q vs %q", a1.SessionID, a2.SessionID)
	}
}

func TestAcceptForwardedIDToken_AudienceMismatch(t *testing.T) {
	h := newForwardedTokenHarness(t)
	claims := h.validClaims()
	claims.Audience = []string{"some-other-audience"}
	tok := h.signToken(t, claims)

	_, err := h.srv.AcceptForwardedIDToken(context.Background(), tok)
	if !errors.Is(err, ErrTrustedAudienceMismatch) {
		t.Fatalf("err = %v, want ErrTrustedAudienceMismatch", err)
	}
}

func TestAcceptForwardedIDToken_IssuerMismatch(t *testing.T) {
	h := newForwardedTokenHarness(t)
	claims := h.validClaims()
	claims.Issuer = "https://wrong.issuer.example"
	tok := h.signToken(t, claims)

	_, err := h.srv.AcceptForwardedIDToken(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for issuer mismatch, got nil")
	}
	if !errors.Is(err, oidc.ErrIssuerMismatch) {
		t.Errorf("err = %v, want wrapped oidc.ErrIssuerMismatch", err)
	}
}

func TestAcceptForwardedIDToken_InvalidSignature(t *testing.T) {
	h := newForwardedTokenHarness(t)
	// Sign with a completely different key so the signature fails verification.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	bad := signTestRS256Token(t, otherKey, h.keyID, oidc.IDTokenClaims{Claims: h.validClaims()})

	_, err = h.srv.AcceptForwardedIDToken(context.Background(), bad)
	if err == nil {
		t.Fatal("expected signature error")
	}
	if errors.Is(err, ErrTrustedAudienceMismatch) {
		t.Errorf("got audience-mismatch sentinel for signature failure: %v", err)
	}
}

func TestAcceptForwardedIDToken_ExpiredJWT(t *testing.T) {
	h := newForwardedTokenHarness(t)
	claims := h.validClaims()
	past := time.Now().Add(-2 * time.Hour)
	claims.IssuedAt = josejwt.NewNumericDate(past)
	claims.Expiry = josejwt.NewNumericDate(past.Add(time.Minute))
	tok := h.signToken(t, claims)

	_, err := h.srv.AcceptForwardedIDToken(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for expired JWT")
	}
}

func TestAcceptForwardedIDToken_NoJWKSProvider(t *testing.T) {
	h := newForwardedTokenHarness(t)
	// Replace the JWKSProvider-capable mock with a bare Provider implementation.
	// Safe because the no-JWKS precondition runs BEFORE validateAndParseForwardedIDToken
	// (which would dereference the JWKS client) — see AcceptForwardedIDToken for the
	// check order.
	h.srv.provider = &oauthOnlyProvider{name: "oauth-only"}

	tok := h.signToken(t, h.validClaims())
	_, err := h.srv.AcceptForwardedIDToken(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for non-JWKS provider")
	}
	if !strings.Contains(err.Error(), "does not support JWKS") {
		t.Errorf("err = %v, want 'does not support JWKS' message", err)
	}
}

// TestAcceptForwardedIDToken_HMACKeyChangesSessionID feeds the SAME bearer token
// to two servers — one unkeyed, one with SessionIDHMACKey set — and asserts the
// derived session IDs differ. Earlier iteration of this test signed two
// different tokens (one per harness) and compared their session IDs, which
// trivially differed because the bearer-token bytes differed; it would have
// passed even if the HMAC branch were deleted. Sharing the same provider
// keypair across both servers isolates the HMAC key as the only variable.
func TestAcceptForwardedIDToken_HMACKeyChangesSessionID(t *testing.T) {
	h := newForwardedTokenHarness(t)
	tok := h.signToken(t, h.validClaims())

	// a1: unkeyed SHA-256 derivation.
	a1, err := h.srv.AcceptForwardedIDToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("unkeyed: %v", err)
	}

	// Build a second Server sharing the SAME provider/JWKS and validator
	// state, differing ONLY in Config.SessionIDHMACKey. This exercises the
	// HMAC branch of deriveForwardedSessionID. Can't shallow-copy *h.srv
	// because the Server embeds sync primitives (singleflight.Group) that
	// copylocks would flag; construct a sibling and wire only the fields
	// AcceptForwardedIDToken reads.
	cfg2 := *h.srv.Config
	cfg2.SessionIDHMACKey = []byte("per-deployment-secret-key-32-byte")
	srv2 := &Server{
		Config:     &cfg2,
		Logger:     h.srv.Logger,
		provider:   h.srv.provider,
		tokenStore: h.srv.tokenStore,
		jwksClient: h.srv.jwksClient,
	}
	srv2.jwksClientOnce.Do(func() {}) // prevent re-init of jwksClient

	a2, err := srv2.AcceptForwardedIDToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("hmac-keyed: %v", err)
	}

	if a1.SessionID == a2.SessionID {
		t.Errorf("SessionID should differ when HMAC key set (same token, only key changed): both = %q", a1.SessionID)
	}
	if !strings.HasPrefix(a1.SessionID, "ext-") || len(a1.SessionID) != len("ext-")+16 {
		t.Errorf("unkeyed SessionID shape unexpected: %q", a1.SessionID)
	}
	if !strings.HasPrefix(a2.SessionID, "ext-") || len(a2.SessionID) != len("ext-")+16 {
		t.Errorf("HMAC-derived SessionID shape unexpected: %q", a2.SessionID)
	}

	// Second call with the SAME key and SAME token must be deterministic.
	a2Again, err := srv2.AcceptForwardedIDToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("hmac-keyed second call: %v", err)
	}
	if a2.SessionID != a2Again.SessionID {
		t.Errorf("HMAC-keyed SessionID not deterministic across calls: %q vs %q", a2.SessionID, a2Again.SessionID)
	}
}

// TestAcceptForwardedIDToken_EmptyBearer guards the explicit empty-token check
// so callers get a clear error instead of a noisy parse_error metric on every
// unauthenticated request.
func TestAcceptForwardedIDToken_EmptyBearer(t *testing.T) {
	h := newForwardedTokenHarness(t)
	_, err := h.srv.AcceptForwardedIDToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty bearer token")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("err = %v, want 'must not be empty' message", err)
	}
}

func TestClassifyForwardedTokenError(t *testing.T) {
	// Wrap errForwardedTokenParseFailed the same way validateAndParseForwardedIDToken does.
	parseWrapped := fmt.Errorf("%w: junk", errForwardedTokenParseFailed)
	issuerWrapped := fmt.Errorf("ID token signature validation failed: %w: got \"x\", expected \"y\"", oidc.ErrIssuerMismatch)
	expiredWrapped := fmt.Errorf("ID token signature validation failed: %w", oidc.ErrTokenExpired)
	nbfWrapped := fmt.Errorf("ID token signature validation failed: %w", oidc.ErrTokenNotValidYet)

	cases := []struct {
		name string
		err  error
		want instrumentation.ForwardedIDTokenResult
	}{
		{"nil", nil, instrumentation.ForwardedIDTokenResultOK},
		{"parse", parseWrapped, instrumentation.ForwardedIDTokenResultParseError},
		{"issuer", issuerWrapped, instrumentation.ForwardedIDTokenResultIssMismatch},
		{"expired", expiredWrapped, instrumentation.ForwardedIDTokenResultExpired},
		{"nbf", nbfWrapped, instrumentation.ForwardedIDTokenResultNotYetValid},
		{"default", errors.New("some other failure"), instrumentation.ForwardedIDTokenResultSigInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyForwardedTokenError(tc.err); got != tc.want {
				t.Errorf("classifyForwardedTokenError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestAcceptForwardedIDToken_ExpiresAtMatchesExp(t *testing.T) {
	h := newForwardedTokenHarness(t)
	claims := h.validClaims()
	exp := time.Now().Add(23 * time.Minute).Truncate(time.Second)
	claims.Expiry = josejwt.NewNumericDate(exp)
	tok := h.signToken(t, claims)

	acc, err := h.srv.AcceptForwardedIDToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("AcceptForwardedIDToken: %v", err)
	}
	if !acc.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", acc.ExpiresAt, exp)
	}
}

func TestAcceptForwardedIDToken_ParseError(t *testing.T) {
	h := newForwardedTokenHarness(t)
	_, err := h.srv.AcceptForwardedIDToken(context.Background(), "not.a.jwt.at.all")
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// oauthOnlyProvider is a minimal Provider implementation that deliberately does
// not satisfy JWKSProvider, used to exercise the no-JWKS precondition.
type oauthOnlyProvider struct {
	name string
}

func (p *oauthOnlyProvider) Name() string            { return p.name }
func (p *oauthOnlyProvider) DefaultScopes() []string { return nil }
func (p *oauthOnlyProvider) AuthorizationURL(state, cc, ccm string, scopes []string, opts *providers.AuthorizationURLOptions) string {
	return ""
}

func (p *oauthOnlyProvider) ExchangeCode(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	return nil, nil
}

func (p *oauthOnlyProvider) ValidateToken(ctx context.Context, tok string) (*providers.UserInfo, error) {
	return nil, nil
}

func (p *oauthOnlyProvider) RefreshToken(ctx context.Context, rt string) (*oauth2.Token, error) {
	return nil, nil
}
func (p *oauthOnlyProvider) RevokeToken(ctx context.Context, tok string) error { return nil }
func (p *oauthOnlyProvider) HealthCheck(ctx context.Context) error             { return nil }
