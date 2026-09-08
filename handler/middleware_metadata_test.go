package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const (
	msgMetadataLookupFailed = "Failed to retrieve token metadata"
	msgMetadataMiss         = "No stored token metadata for bearer"
)

// newForwardedTokenHandler builds a Handler whose Server accepts SSO-forwarded
// ID tokens (TrustedAudiences) signed by a test JWKS, plus a capturing logger
// at the given level shared by the Server and the Handler. It returns the
// handler, a valid forwarded ID token, and the log buffer.
func newForwardedTokenHandler(t *testing.T, level slog.Level) (*Handler, string, *bytes.Buffer) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	const keyID = "test-key-1"
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       privateKey.Public(),
		KeyID:     keyID,
		Algorithm: "RS256",
		Use:       "sig",
	}}}
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(jwksServer.Close)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(jwksServer.Certificate())

	const (
		issuer   = "https://auth.test.example"
		audience = "forwarded-audience"
	)
	provider := mock.NewProvider()
	provider.JWKSURIFunc = func(context.Context) (string, error) { return jwksServer.URL, nil }
	provider.IssuerURLFunc = func() string { return issuer }

	store := memory.New()
	t.Cleanup(store.Stop)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level}))

	srv, err := server.New(provider, store, store, store, &server.Config{
		Issuer:             issuer,
		TrustedAudiences:   []string{audience},
		AllowPrivateIPJWKS: true,
		JWKSRootCAs:        rootCAs,
	}, logger)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	now := time.Now()
	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: privateKey, KeyID: keyID, Algorithm: "RS256", Use: "sig"}}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	opts.WithHeader(jose.HeaderKey("kid"), keyID)
	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
	}
	token, err := josejwt.Signed(signer).Claims(oidc.IDTokenClaims{
		Claims: josejwt.Claims{
			Subject:  "user-subject-123",
			Issuer:   issuer,
			Audience: josejwt.Audience{audience},
			IssuedAt: josejwt.NewNumericDate(now),
			Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
		},
		Email: "user@test.example",
		Name:  "Test User",
	}).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	// server.New logs its configuration warnings (AllowPrivateIPJWKS, no
	// registration token) at construction; only per-request lines matter here.
	buf.Reset()
	return New(srv, logger), token, &buf
}

// logEntries decodes the JSON log buffer into one map per line.
func logEntries(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

func findLogEntry(entries []map[string]any, msg string) (map[string]any, bool) {
	for _, e := range entries {
		if e["msg"] == msg {
			return e, true
		}
	}
	return nil, false
}

// serveForwardedToken runs one authenticated request through ValidateToken and
// fails the test unless the request reached the inner handler with the
// forwarded identity.
func serveForwardedToken(t *testing.T, h *Handler, token string) {
	t.Helper()
	var got *providers.UserInfo
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = UserInfoFromContext(r.Context())
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ValidateToken(next).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", w.Code, http.StatusOK, w.Body.String())
	}
	if got == nil || got.ID != "user-subject-123" || got.TokenSource != providers.TokenSourceSSO {
		t.Fatalf("inner handler saw %+v, want the SSO-forwarded user", got)
	}
}

// TestValidateToken_ForwardedToken_MetadataMissIsSilentAtInfo pins the
// resource-server contract: a forwarded ID token has no stored metadata, and
// that miss must not surface at INFO or above on every request.
func TestValidateToken_ForwardedToken_MetadataMissIsSilentAtInfo(t *testing.T) {
	h, token, buf := newForwardedTokenHandler(t, slog.LevelInfo)

	for range 3 {
		serveForwardedToken(t, h, token)
	}

	entries := logEntries(t, buf)
	if _, found := findLogEntry(entries, msgMetadataLookupFailed); found {
		t.Fatalf("metadata miss for a forwarded token was logged at WARN:\n%s", buf.String())
	}
	for _, e := range entries {
		if lvl, _ := e["level"].(string); lvl == "WARN" || lvl == "ERROR" {
			t.Errorf("unexpected %s log on the forwarded-token happy path: %v", lvl, e)
		}
	}
}

// TestValidateToken_ForwardedToken_MetadataMissLoggedAtDebug keeps the miss
// diagnosable: at DEBUG the middleware names the validation path that accepted
// the bearer and a short token suffix, never the token itself.
func TestValidateToken_ForwardedToken_MetadataMissLoggedAtDebug(t *testing.T) {
	h, token, buf := newForwardedTokenHandler(t, slog.LevelDebug)

	serveForwardedToken(t, h, token)

	entries := logEntries(t, buf)
	e, found := findLogEntry(entries, msgMetadataMiss)
	if !found {
		t.Fatalf("expected a DEBUG %q entry, got:\n%s", msgMetadataMiss, buf.String())
	}
	if e["level"] != "DEBUG" {
		t.Errorf("level = %v, want DEBUG", e["level"])
	}
	if e["token_source"] != string(providers.TokenSourceSSO) {
		t.Errorf("token_source = %v, want %q", e["token_source"], providers.TokenSourceSSO)
	}
	suffix, _ := e["token_suffix"].(string)
	if suffix == "" || !strings.HasSuffix(token, suffix) || len(suffix) >= len(token) {
		t.Errorf("token_suffix = %q, want a short suffix of the bearer", suffix)
	}
	if strings.Contains(buf.String(), token) {
		t.Error("the full bearer token leaked into the log")
	}
	if _, found := findLogEntry(entries, msgMetadataLookupFailed); found {
		t.Errorf("a not-found miss must not also log %q", msgMetadataLookupFailed)
	}
}

// failingMetadataStore is a memory store whose metadata lookups fail with a
// transient backend error rather than storage.ErrTokenNotFound.
type failingMetadataStore struct {
	*memory.Store
	err error
}

func (s *failingMetadataStore) GetTokenMetadata(string) (*storage.TokenMetadata, error) {
	return nil, s.err
}

// TestValidateToken_MetadataBackendFailureStaysWarn guards the other half of
// the contract: a transient storage failure is still a WARN, so the DEBUG
// downgrade applies only to the documented not-found signal.
func TestValidateToken_MetadataBackendFailureStaysWarn(t *testing.T) {
	inner := memory.New()
	t.Cleanup(inner.Stop)
	store := &failingMetadataStore{Store: inner, err: errors.New("valkey: connection refused")}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv, err := server.New(mock.NewProvider(), store, inner, inner, &server.Config{Issuer: testIssuer}, logger)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h := New(srv, logger)

	const accessToken = "opaque-access-token"
	if err := inner.SaveToken(t.Context(), accessToken, &oauth2.Token{AccessToken: "provider-access", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	h.ValidateToken(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", w.Code, http.StatusOK, w.Body.String())
	}

	e, found := findLogEntry(logEntries(t, &buf), msgMetadataLookupFailed)
	if !found {
		t.Fatalf("expected a WARN %q entry for a transient store error, got:\n%s", msgMetadataLookupFailed, buf.String())
	}
	if e["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", e["level"])
	}
}

func TestTokenSourceForLog(t *testing.T) {
	cases := map[string]struct {
		in   *providers.UserInfo
		want string
	}{
		"nil":       {nil, "oauth"},
		"unset":     {&providers.UserInfo{}, "oauth"},
		"sso":       {&providers.UserInfo{TokenSource: providers.TokenSourceSSO}, "sso"},
		"jwt":       {&providers.UserInfo{TokenSource: providers.TokenSourceJWT}, "jwt"},
		"trusted":   {&providers.UserInfo{TokenSource: providers.TokenSourceTrustedIssuer}, "trusted-issuer"},
		"oauth-set": {&providers.UserInfo{TokenSource: providers.TokenSourceOAuth}, "oauth"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tokenSourceForLog(tc.in); got != tc.want {
				t.Errorf("tokenSourceForLog() = %q, want %q", got, tc.want)
			}
		})
	}
}
