package server

import (
	"context"
	"strings"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// principalTestClaims carries the principal claims the registered set lacks.
type principalTestClaims struct {
	josejwt.Claims
	AuthorizedParty string           `json:"azp,omitempty"`
	Act             *oidc.ActorClaim `json:"act,omitempty"`
}

func withPrincipalSessionIdentity(cfg *Config) {
	cfg.ForwardedSessionIdentity = ForwardedSessionIdentityPrincipal
}

// refreshed returns the same principal as c in a new token: another iat, exp
// and jti, as a gateway's refresh produces.
func refreshed(c principalTestClaims) principalTestClaims {
	now := time.Now()
	c.IssuedAt = josejwt.NewNumericDate(now.Add(-time.Minute))
	c.Expiry = josejwt.NewNumericDate(now.Add(2 * time.Hour))
	c.ID = "jti-refreshed"
	return c
}

func (h *forwardedTokenHarness) principalClaims() principalTestClaims {
	return principalTestClaims{
		Claims:          h.validClaims(),
		AuthorizedParty: "agent-gateway",
		Act: &oidc.ActorClaim{
			Issuer:  "https://agents.test.example",
			Subject: "agent-a",
		},
	}
}

// TestAcceptForwardedIDToken_PrincipalSession_SurvivesRefresh pins the fix:
// under the principal identity a refreshed token for the same person, client
// and actor keeps its session, while the default bearer identity still makes
// every token a session of its own.
func TestAcceptForwardedIDToken_PrincipalSession_SurvivesRefresh(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     []func(*Config)
		wantSame bool
	}{
		{name: "default bearer identity", wantSame: false},
		{name: "principal identity", opts: []func(*Config){withPrincipalSessionIdentity}, wantSame: true},
		{name: "principal identity with HMAC key", opts: []func(*Config){withPrincipalSessionIdentity, func(c *Config) {
			c.SessionIDHMACKey = []byte("0123456789abcdef0123456789abcdef")
		}}, wantSame: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newForwardedTokenHarness(t, tc.opts...)
			first := h.principalClaims()
			tok1 := signTestRS256Token(t, h.privateKey, h.keyID, first)
			tok2 := signTestRS256Token(t, h.privateKey, h.keyID, refreshed(first))
			if tok1 == tok2 {
				t.Fatal("test setup: the refreshed token must differ")
			}

			a1, err := h.srv.AcceptForwardedIDToken(context.Background(), tok1)
			if err != nil {
				t.Fatalf("first token: %v", err)
			}
			a2, err := h.srv.AcceptForwardedIDToken(context.Background(), tok2)
			if err != nil {
				t.Fatalf("refreshed token: %v", err)
			}
			if same := a1.SessionID == a2.SessionID; same != tc.wantSame {
				t.Errorf("same session = %v, want %v (%q, %q)", same, tc.wantSame, a1.SessionID, a2.SessionID)
			}
			if !strings.HasPrefix(a1.SessionID, "ext-") || len(a1.SessionID) != len("ext-")+16 {
				t.Errorf("SessionID shape unexpected: %q", a1.SessionID)
			}
		})
	}
}

// TestSessionIDForBearer_Principal_DistinguishesPrincipals pins that only
// the principal decides the session: another person, client, issuer or actor
// chain is another session; token-specific claims and aud order are not.
func TestSessionIDForBearer_Principal_DistinguishesPrincipals(t *testing.T) {
	h := newForwardedTokenHarness(t, withPrincipalSessionIdentity)
	base := h.principalClaims()
	sessionOf := func(c principalTestClaims) string {
		return h.srv.SessionIDForBearer(signTestRS256Token(t, h.privateKey, h.keyID, c))
	}
	want := sessionOf(base)

	for _, tc := range []struct {
		name     string
		mutate   func(c *principalTestClaims)
		wantSame bool
	}{
		{name: "refreshed token", mutate: func(c *principalTestClaims) { *c = refreshed(*c) }, wantSame: true},
		{name: "other person", mutate: func(c *principalTestClaims) { c.Subject = "other-user" }},
		{name: "other issuer", mutate: func(c *principalTestClaims) { c.Issuer = "https://other.test.example" }},
		{name: "other client", mutate: func(c *principalTestClaims) { c.AuthorizedParty = "other-client" }},
		{name: "other actor", mutate: func(c *principalTestClaims) { c.Act = &oidc.ActorClaim{Issuer: c.Act.Issuer, Subject: "agent-b"} }},
		{name: "other actor issuer", mutate: func(c *principalTestClaims) {
			c.Act = &oidc.ActorClaim{Issuer: "https://x.test.example", Subject: c.Act.Subject}
		}},
		{name: "no actor", mutate: func(c *principalTestClaims) { c.Act = nil }},
		{name: "deeper actor chain", mutate: func(c *principalTestClaims) {
			c.Act = &oidc.ActorClaim{Issuer: c.Act.Issuer, Subject: c.Act.Subject, Act: &oidc.ActorClaim{Issuer: c.Act.Issuer, Subject: "agent-root"}}
		}},
		{name: "azp absent, aud names the client", mutate: func(c *principalTestClaims) {
			c.AuthorizedParty = ""
			c.Audience = josejwt.Audience{"agent-gateway"}
		}},
		{name: "fields do not run into each other", mutate: func(c *principalTestClaims) {
			c.Subject += c.AuthorizedParty[:1]
			c.AuthorizedParty = c.AuthorizedParty[1:]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c)
			if same := sessionOf(c) == want; same != tc.wantSame {
				t.Errorf("same session as the base principal = %v, want %v", same, tc.wantSame)
			}
		})
	}

	t.Run("aud order is irrelevant without azp", func(t *testing.T) {
		a, b := base, base
		a.AuthorizedParty, b.AuthorizedParty = "", ""
		a.Audience = josejwt.Audience{"x", "y"}
		b.Audience = josejwt.Audience{"y", "x", "x"}
		if sessionOf(a) != sessionOf(b) {
			t.Error("the same aud set in another order must map to the same session")
		}
	})
}

// TestSessionIDForBearer_Principal_NoPrincipalKeepsBearerDerivation pins
// that a bearer without a principal keeps the bearer derivation, and that a
// principal-derived ID is never a bearer-derived one.
func TestSessionIDForBearer_Principal_NoPrincipalKeepsBearerDerivation(t *testing.T) {
	h := newForwardedTokenHarness(t, withPrincipalSessionIdentity)

	for _, bearer := range []string{
		"opaque-bearer",
		signTestRS256Token(t, h.privateKey, h.keyID, josejwt.Claims{Subject: "no-issuer"}),
		signTestRS256Token(t, h.privateKey, h.keyID, josejwt.Claims{Issuer: h.issuer}),
	} {
		if got, want := h.srv.SessionIDForBearer(bearer), h.srv.bearerSessionID(bearer); got != want {
			t.Errorf("bearer without a principal: got %q, want the bearer derivation %q", got, want)
		}
	}

	tok := signTestRS256Token(t, h.privateKey, h.keyID, h.principalClaims())
	if h.srv.SessionIDForBearer(tok) == h.srv.bearerSessionID(tok) {
		t.Error("principal and bearer derivations must be domain-separated")
	}
}

func TestConfigValidate_ForwardedSessionIdentity(t *testing.T) {
	for _, v := range []ForwardedSessionIdentity{"", ForwardedSessionIdentityBearer, ForwardedSessionIdentityPrincipal} {
		if err := (&Config{Issuer: "https://auth.test.example", ForwardedSessionIdentity: v}).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", v, err)
		}
	}
	if err := (&Config{Issuer: "https://auth.test.example", ForwardedSessionIdentity: "Principal"}).Validate(); err == nil {
		t.Error("Validate must reject an unknown ForwardedSessionIdentity")
	}
}
