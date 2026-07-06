package server

import (
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// parseIssuedClaims parses the private claims of a token issued by
// SelfIssuedExchange. pub is the issuer's public signing key.
func parseIssuedClaims(t *testing.T, token string, pub any) rfc9068Claims {
	t.Helper()
	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	var private rfc9068Claims
	require.NoError(t, parsed.Claims(pub, &private))
	return private
}

// TestSelfIssuedExchange_NestsPriorActorChain asserts a delegated exchange nests
// the actor already on the subject token (RFC 8693 §4.4) beneath the new actor,
// so a multi-hop A2A chain is preserved rather than overwritten.
func TestSelfIssuedExchange_NestsPriorActorChain(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer, Claims: &oidc.IDTokenClaims{
				Act: &oidc.ActorClaim{Issuer: "https://k8s.example.com", Subject: "agentA"},
			}},
			"act-tok": {Subject: "agentB", Issuer: "https://k8s.example.com"},
		}},
	}

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Actor:    TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.NoError(t, err)

	private := parseIssuedClaims(t, result.AccessToken, signingKey.Public())
	require.NotNil(t, private.Act)
	require.Equal(t, "agentB", private.Act.Sub, "outermost act is the most recent actor")
	require.NotNil(t, private.Act.Act)
	require.Equal(t, "agentA", private.Act.Act.Sub, "prior actor nested beneath the new one")
	require.Nil(t, private.Act.Act.Act, "chain ends at the first hop")
}

// TestSelfIssuedExchange_PreservesChainWithoutNewActor asserts that when no new
// actor delegates, an act chain already on the subject token is carried forward
// unchanged rather than dropped.
func TestSelfIssuedExchange_PreservesChainWithoutNewActor(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer, Claims: &oidc.IDTokenClaims{
				Act: &oidc.ActorClaim{Issuer: "https://k8s.example.com", Subject: "agentA"},
			}},
		}},
	}

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.NoError(t, err)

	private := parseIssuedClaims(t, result.AccessToken, signingKey.Public())
	require.NotNil(t, private.Act)
	require.Equal(t, "agentA", private.Act.Sub)
	require.Nil(t, private.Act.Act)
}

// TestSelfIssuedExchange_RejectsTooDeepActorChain asserts an act chain that would
// exceed maxActorChainDepth is rejected fail-closed and no token is issued.
func TestSelfIssuedExchange_RejectsTooDeepActorChain(t *testing.T) {
	srv, _ := newActorExchangeServer(t)

	// A prior chain already at the maximum depth; nesting a new actor exceeds it.
	deep := &oidc.ActorClaim{Issuer: testIssuer, Subject: "a0"}
	for i := 1; i < maxActorChainDepth; i++ {
		deep = &oidc.ActorClaim{Issuer: testIssuer, Subject: fmt.Sprintf("a%d", i), Act: deep}
	}
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer, Claims: &oidc.IDTokenClaims{Act: deep}},
			"act-tok": {Subject: "agentB", Issuer: "https://k8s.example.com"},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Actor:    TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "actor chain depth")
}

// TestSelfIssuedExchange_DefaultsIdentityFromSubject asserts the issued token
// defaults email/email_verified/name/groups from the validated subject when the
// caller supplies no Options, so a delegated exchange preserves the human's
// identity for downstream authorization and attribution.
func TestSelfIssuedExchange_DefaultsIdentityFromSubject(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer, Claims: &oidc.IDTokenClaims{
				Email:         "quentin@giantswarm.io",
				EmailVerified: true,
				Name:          "Quentin",
				Groups:        []string{"sre", "admin"},
			}},
		}},
	}

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.NoError(t, err)

	private := parseIssuedClaims(t, result.AccessToken, signingKey.Public())
	require.Equal(t, "quentin@giantswarm.io", private.Email)
	require.NotNil(t, private.EmailVerified)
	require.True(t, *private.EmailVerified)
	require.Equal(t, "Quentin", private.Name)
	require.Equal(t, []string{"sre", "admin"}, private.Groups)
}

// TestSelfIssuedExchange_ExplicitOptionsOverrideSubjectClaims asserts an explicit
// Options value takes precedence over the claims defaulted from the subject.
func TestSelfIssuedExchange_ExplicitOptionsOverrideSubjectClaims(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer, Claims: &oidc.IDTokenClaims{
				Email:  "from-subject@giantswarm.io",
				Groups: []string{"from-subject"},
			}},
		}},
	}

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		},
		Options: ExchangeOptions{
			Email:  "explicit@giantswarm.io",
			Groups: []string{"explicit"},
		},
	})
	require.NoError(t, err)

	private := parseIssuedClaims(t, result.AccessToken, signingKey.Public())
	require.Equal(t, "explicit@giantswarm.io", private.Email)
	require.Equal(t, []string{"explicit"}, private.Groups)
}

// TestSelfIssuedExchange_DefaultsAudienceToResourceIdentifier asserts that when
// the caller supplies no Resource, the issued token's aud defaults to the
// server's own resource identifier (the agent OBO path sends no resource).
func TestSelfIssuedExchange_DefaultsAudienceToResourceIdentifier(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject: TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Scope:   "read",
	}})
	require.NoError(t, err)

	parsed, err := josejwt.ParseSigned(result.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	var standard josejwt.Claims
	require.NoError(t, parsed.Claims(signingKey.Public(), &standard))
	require.Equal(t, josejwt.Audience{"https://api.example.com"}, standard.Audience,
		"aud defaults to the server resource identifier when no resource is supplied")
}

// TestSelfIssuedExchange_DeniesBareSelfRenewal asserts a token this server issued
// (subject iss == the server's Issuer) cannot be re-exchanged with no new actor:
// a bare renewal that would refresh the TTL open-endedly is rejected.
func TestSelfIssuedExchange_DeniesBareSelfRenewal(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"self-tok": {Subject: testSubject, Issuer: srv.Config.Issuer},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "self-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.ErrorIs(t, err, ErrSelfRenewalDenied)
}

// TestSelfIssuedExchange_DeniesSelfRenewalViaSelfActor asserts the renewal gate
// cannot be dodged by naming yourself as your own actor: an actor token that
// resolves to the same identity as the subject collapses to a no-op in
// resolveExchangeActor, leaving no new actor, so a self-issued subject is still
// denied. Locks the interaction between self-delegation collapse and the gate.
func TestSelfIssuedExchange_DeniesSelfRenewalViaSelfActor(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	// Both tokens resolve to the same self-issued identity, so the actor equals
	// the subject and is dropped before the renewal check runs.
	self := &SubjectIdentity{Subject: testSubject, Issuer: srv.Config.Issuer}
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"self-tok":  self,
			"self-tok2": self,
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "self-tok", Type: SubjectTokenTypeIDToken},
		Actor:    TypedToken{Token: "self-tok2", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.ErrorIs(t, err, ErrSelfRenewalDenied)
}

// TestSelfIssuedExchange_AllowsSelfSubjectChainExtension asserts re-exchanging a
// self-issued token IS allowed when a new actor is added, extending the A2A
// delegation chain (the prior actor is preserved beneath the new one).
func TestSelfIssuedExchange_AllowsSelfSubjectChainExtension(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"self-tok": {Subject: testSubject, Issuer: srv.Config.Issuer, Claims: &oidc.IDTokenClaims{
				Act: &oidc.ActorClaim{Issuer: "https://k8s.example.com", Subject: "agentA"},
			}},
			"act-tok": {Subject: "agentB", Issuer: "https://k8s.example.com"},
		}},
	}

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "self-tok", Type: SubjectTokenTypeIDToken},
		Actor:    TypedToken{Token: "act-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.NoError(t, err)

	private := parseIssuedClaims(t, result.AccessToken, signingKey.Public())
	require.Equal(t, "agentB", private.Act.Sub, "new actor added to the chain")
	require.NotNil(t, private.Act.Act)
	require.Equal(t, "agentA", private.Act.Act.Sub, "prior actor preserved beneath it")
}

// TestSelfIssuedExchange_DeniesRepeatedActorReattachment asserts re-exchanging a
// self-issued token whose outermost actor is A, naming A again as the new actor,
// adds no hop and is treated as a bare renewal: it is denied rather than granting
// a fresh TTL.
func TestSelfIssuedExchange_DeniesRepeatedActorReattachment(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"self-tok": {Subject: testSubject, Issuer: srv.Config.Issuer, Claims: &oidc.IDTokenClaims{
				Act: &oidc.ActorClaim{Issuer: "https://k8s.example.com", Subject: "agentA"},
			}},
			"act-a": {Subject: "agentA", Issuer: "https://k8s.example.com"},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "self-tok", Type: SubjectTokenTypeIDToken},
		Actor:    TypedToken{Token: "act-a", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.ErrorIs(t, err, ErrSelfRenewalDenied)
}

// TestSelfIssuedExchange_AllowsDifferentActorReattachment asserts a new actor
// that differs from the outermost actor on the subject's chain extends the chain
// normally, so legitimate multi-hop delegation is unaffected by the
// same-actor collapse.
func TestSelfIssuedExchange_AllowsDifferentActorReattachment(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"self-tok": {Subject: testSubject, Issuer: srv.Config.Issuer, Claims: &oidc.IDTokenClaims{
				Act: &oidc.ActorClaim{Issuer: "https://k8s.example.com", Subject: "agentA"},
			}},
			"act-b": {Subject: "agentB", Issuer: "https://k8s.example.com"},
		}},
	}

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "self-tok", Type: SubjectTokenTypeIDToken},
		Actor:    TypedToken{Token: "act-b", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
		Scope:    "read",
	}})
	require.NoError(t, err)

	private := parseIssuedClaims(t, result.AccessToken, signingKey.Public())
	require.Equal(t, "agentB", private.Act.Sub, "new distinct actor added to the chain")
	require.NotNil(t, private.Act.Act)
	require.Equal(t, "agentA", private.Act.Act.Sub, "prior actor preserved beneath it")
}

// TestSelfIssuedExchange_DeniesKeyBoundSubjectWithoutProof asserts a subject
// token carrying an RFC 9449 cnf.jkt binding cannot be re-exchanged when the
// request presents no DPoP proof for that key.
func TestSelfIssuedExchange_DeniesKeyBoundSubjectWithoutProof(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer, ConfirmationJKT: "jkt-subject"},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
	}})
	require.ErrorIs(t, err, ErrSubjectKeyMismatch)
}

// TestSelfIssuedExchange_DeniesKeyBoundSubjectWithDifferentKey asserts a
// key-bound subject token cannot be laundered into a token bound to a different
// key: a request proving possession of a key other than the subject's cnf.jkt is
// rejected.
func TestSelfIssuedExchange_DeniesKeyBoundSubjectWithDifferentKey(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer, ConfirmationJKT: "jkt-subject"},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
		},
		DPoPJKT: "jkt-attacker",
	})
	require.ErrorIs(t, err, ErrSubjectKeyMismatch)
}

// TestSelfIssuedExchange_AllowsKeyBoundSubjectWithMatchingKey asserts a key-bound
// subject re-exchanged by the holder of its confirmation key succeeds and the
// issued token is bound to that same key.
func TestSelfIssuedExchange_AllowsKeyBoundSubjectWithMatchingKey(t *testing.T) {
	srv, signingKey := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer, ConfirmationJKT: "jkt-subject"},
		}},
	}

	result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{
		SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
		},
		DPoPJKT: "jkt-subject",
	})
	require.NoError(t, err)

	private := parseIssuedClaims(t, result.AccessToken, signingKey.Public())
	require.NotNil(t, private.Cnf)
	require.Equal(t, "jkt-subject", private.Cnf.JKT, "issued token stays bound to the confirmation key")
}

// TestSelfIssuedExchange_AllowsListedResource asserts a requested resource in
// Config.TokenExchangeAllowedResources is served.
func TestSelfIssuedExchange_AllowsListedResource(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.Config.TokenExchangeAllowedResources = []string{"https://backend.example.com"}
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://backend.example.com",
	}})
	require.NoError(t, err)
}

// TestSelfIssuedExchange_DeniesUnlistedResource asserts a requested resource
// absent from a non-empty Config.TokenExchangeAllowedResources is rejected with
// invalid_target.
func TestSelfIssuedExchange_DeniesUnlistedResource(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.Config.TokenExchangeAllowedResources = []string{"https://backend.example.com"}
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://evil.example.com",
	}})
	require.ErrorIs(t, err, ErrInvalidTarget)
}

// TestSelfIssuedExchange_ResourceAllowlistPassthrough asserts an empty
// Config.TokenExchangeAllowedResources imposes no restriction, and the
// server's own resource identifier is always served even under a non-empty list.
func TestSelfIssuedExchange_ResourceAllowlistPassthrough(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://anything.example.com",
	}})
	require.NoError(t, err, "empty allowlist imposes no restriction")

	srv.Config.TokenExchangeAllowedResources = []string{"https://backend.example.com"}
	_, err = srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject: TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
	}})
	require.NoError(t, err, "server resource identifier is always allowed")
}

// TestSelfIssuedExchange_TokenExpiry asserts the issued token's expiry is exactly
// issue time plus the configured TTL. Run inside a synctest bubble so time is
// deterministic and the assertion cannot flake on wall-clock drift between
// capturing the start time and issuing the token.
func TestSelfIssuedExchange_TokenExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := memory.New()
		defer store.Stop()

		signingKey := generateRSAKey(t)
		cfg := &Config{
			Issuer:                      "https://auth.example.com",
			ResourceIdentifier:          "https://api.example.com",
			SupportedScopes:             []string{"read"},
			AccessTokenTTL:              600,
			AccessTokenFormat:           AccessTokenFormatJWT,
			AccessTokenSigningKey:       signingKey,
			AccessTokenSigningKeyID:     "expiry-test-kid",
			AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
			DisableNonceEchoRequirement: true,
		}
		srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
		require.NoError(t, err)
		srv.subjectValidators = map[string]SubjectTokenValidator{
			SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
				"sub-tok": {Subject: testSubject, Issuer: testIssuer},
			}},
		}

		start := time.Now().UTC()
		result, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
			Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
			Resource: "https://api.example.com",
			Scope:    "read",
		}})
		require.NoError(t, err)
		require.Equal(t, start.Add(600*time.Second), result.ExpiresAt,
			"expiry must be exactly issue time plus the configured TTL")
	})
}

// TestSelfIssuedExchange_RefusesUnverifiedSubjectEmail asserts the exchange
// fails closed when the validated subject asserts an email claim without
// email_verified=true: the issued token would carry that email for downstream
// authorization, so no token is issued.
func TestSelfIssuedExchange_RefusesUnverifiedSubjectEmail(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: testSubject, Issuer: testIssuer, Claims: &oidc.IDTokenClaims{
				Email:         "admin@giantswarm.io",
				EmailVerified: false,
			}},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
	}})
	require.ErrorIs(t, err, ErrUnverifiedSubjectEmail)
}

// TestSelfIssuedExchange_EmaillessSubjectExemptFromEmailGate asserts a subject
// with no email claim (a workload identity such as a Kubernetes ServiceAccount
// token) is exempt from the email_verified gate: its token asserts no email to
// prove.
func TestSelfIssuedExchange_EmaillessSubjectExemptFromEmailGate(t *testing.T) {
	srv, _ := newActorExchangeServer(t)
	srv.subjectValidators = map[string]SubjectTokenValidator{
		SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
			"sub-tok": {Subject: "system:serviceaccount:kagent:sre-agent", Issuer: testIssuer, Claims: &oidc.IDTokenClaims{}},
		}},
	}

	_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{SubjectExchange: SubjectExchange{
		Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
		Resource: "https://api.example.com",
	}})
	require.NoError(t, err)
}
