package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

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
	jwks := oidc.JWKS{
		Keys: []oidc.JWK{{
			Kty: "RSA",
			Use: "sig",
			Kid: keyID,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
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
func (h *forwardedTokenHarness) signToken(t *testing.T, claims jwt.RegisteredClaims) string {
	t.Helper()
	idClaims := &oidc.IDTokenClaims{
		RegisteredClaims: claims,
		Email:            "user@test.example",
		Name:             "Test User",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
	token.Header["kid"] = h.keyID
	signed, err := token.SignedString(h.privateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// validClaims returns a claims set that should pass all checks.
func (h *forwardedTokenHarness) validClaims() jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		Subject:   "user-subject-123",
		Issuer:    h.issuer,
		Audience:  []string{h.audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
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
	if !strings.Contains(err.Error(), "issuer mismatch") {
		t.Errorf("err = %v, want issuer-mismatch message", err)
	}
}

func TestAcceptForwardedIDToken_InvalidSignature(t *testing.T) {
	h := newForwardedTokenHarness(t)
	// Sign with a completely different key so the signature fails verification.
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	idClaims := &oidc.IDTokenClaims{RegisteredClaims: h.validClaims()}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, idClaims)
	token.Header["kid"] = h.keyID
	bad, err := token.SignedString(otherKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

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
	claims.IssuedAt = jwt.NewNumericDate(past)
	claims.ExpiresAt = jwt.NewNumericDate(past.Add(time.Minute))
	tok := h.signToken(t, claims)

	_, err := h.srv.AcceptForwardedIDToken(context.Background(), tok)
	if err == nil {
		t.Fatal("expected error for expired JWT")
	}
}

func TestAcceptForwardedIDToken_NoJWKSProvider(t *testing.T) {
	h := newForwardedTokenHarness(t)
	// Replace the JWKSProvider-capable mock with a bare Provider implementation.
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

func TestAcceptForwardedIDToken_HMACKeyChangesSessionID(t *testing.T) {
	tok := "" // set below once harness is built
	h1 := newForwardedTokenHarness(t)
	tok = h1.signToken(t, h1.validClaims())

	a1, err := h1.srv.AcceptForwardedIDToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("default-key: %v", err)
	}

	// Second server with an HMAC key set; reuse the same provider/JWKS so the
	// validation succeeds, just with a different session-ID derivation.
	h2 := newForwardedTokenHarness(t, func(c *Config) {
		c.SessionIDHMACKey = []byte("per-deployment-secret-key")
	})
	// Re-sign under h2's key so the signature validates against h2's JWKS.
	tok2 := h2.signToken(t, h2.validClaims())
	a2, err := h2.srv.AcceptForwardedIDToken(context.Background(), tok2)
	if err != nil {
		t.Fatalf("hmac-key: %v", err)
	}

	if a1.SessionID == a2.SessionID {
		t.Errorf("SessionID should differ when HMAC key set: both = %q", a1.SessionID)
	}
	if !strings.HasPrefix(a2.SessionID, "ext-") {
		t.Errorf("HMAC-derived SessionID missing ext- prefix: %q", a2.SessionID)
	}
}

func TestAcceptForwardedIDToken_ExpiresAtMatchesExp(t *testing.T) {
	h := newForwardedTokenHarness(t)
	claims := h.validClaims()
	exp := time.Now().Add(23 * time.Minute).Truncate(time.Second)
	claims.ExpiresAt = jwt.NewNumericDate(exp)
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
