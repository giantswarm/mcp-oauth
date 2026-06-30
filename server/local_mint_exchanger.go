package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// maxActorChainDepth bounds RFC 8693 §4.4 act nesting in a minted token. A
// chain deeper than this is rejected fail-closed: real A2A topologies are
// shallow, and unbounded nesting is an abuse vector (token-size blowup and
// parser pressure on every downstream that validates the token).
const maxActorChainDepth = 10

// LocalMintExchanger implements Exchanger by minting an mcp-oauth-signed JWT
// access token locally, without delegating to a downstream issuer. It is the
// recommended implementation for token-exchange targets where the broker itself
// is the authoritative issuer.
//
// Callers are responsible for validating subject and actor tokens before
// calling Exchange; LocalMintExchanger does not re-run validation.
//
// Requires JWT access token mode (Config.IsJWTAccessTokenFormat() must be
// true); NewLocalMintExchanger returns an error otherwise.
type LocalMintExchanger struct {
	issuer AccessTokenIssuer
	ttl    time.Duration
}

// NewLocalMintExchanger constructs a LocalMintExchanger from a validated
// Config. cfg must be in JWT access token mode; an error is returned otherwise.
// The TTL is taken from cfg.AccessTokenTTL (default 10 minutes when zero or
// negative), matching the behaviour of ExchangeSubjectToken.
func NewLocalMintExchanger(cfg *Config) (*LocalMintExchanger, error) {
	if !cfg.IsJWTAccessTokenFormat() {
		return nil, fmt.Errorf("LocalMintExchanger requires JWT access token mode (set AccessTokenFormat=jwt)")
	}
	issuer, err := newJWTIssuer(cfg)
	if err != nil {
		return nil, fmt.Errorf("create local mint issuer: %w", err)
	}
	ttl := time.Duration(cfg.AccessTokenTTL) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &LocalMintExchanger{
		issuer: issuer,
		ttl:    ttl,
	}, nil
}

// Exchange mints a signed JWT access token for the request. The issued token
// carries:
//   - sub = req.Subject.Subject
//   - act = {iss: req.Actor.Issuer, sub: req.Actor.Subject} when req.Actor != nil,
//     with any act chain already on the subject token nested beneath it so a
//     multi-hop A2A delegation chain is preserved (RFC 8693 §4.4)
//   - email / email_verified / groups copied from the validated subject token
//     (req.Subject.Claims) so downstreams can authorize and attribute without
//     an extra IdP round-trip; email_verified is only emitted alongside email
//   - aud = req.Resource when non-empty, else req.Audience
//   - scope = intersection of req.Scope and req.Subject.AllowedScopes
//   - iss = the Issuer URL from the Config used to build LocalMintExchanger
func (l *LocalMintExchanger) Exchange(ctx context.Context, req *ExchangerRequest) (*ExchangerResult, error) {
	if req.Subject == nil {
		return nil, fmt.Errorf("local mint: ExchangerRequest.Subject must not be nil")
	}

	act, err := buildActorChain(req.Actor, priorActorChain(req.Subject))
	if err != nil {
		return nil, fmt.Errorf("local mint: %w", err)
	}

	audience := req.Resource
	if audience == "" {
		audience = req.Audience
	}

	grantedScope := grantedExchangeScope(req.Scope, req.Subject.AllowedScopes)

	now := time.Now().UTC()
	expiresAt := now.Add(l.ttl)
	jti := generateRandomToken()

	claims := AccessTokenClaims{
		Subject:   req.Subject.Subject,
		Audience:  audience,
		Scopes:    strings.Fields(grantedScope),
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		JTI:       jti,
		Act:       act,
	}
	if identity := req.Subject.Claims; identity != nil {
		claims.Email = identity.Email
		claims.EmailVerified = identity.EmailVerified
		claims.Groups = identity.Groups
	}

	tokenStr, err := l.issuer.Issue(ctx, claims)
	if err != nil {
		return nil, fmt.Errorf("local mint: issue token: %w", err)
	}

	return &ExchangerResult{
		AccessToken:     tokenStr,
		ExpiresAt:       expiresAt,
		Scope:           grantedScope,
		IssuedTokenType: SubjectTokenTypeAccessToken,
		JTI:             jti,
	}, nil
}

// priorActorChain returns the act chain already present on the validated subject
// token, converted to the mint-side Actor shape. Nil when the subject carries no
// act (the common single-hop OBO case).
func priorActorChain(subject *SubjectIdentity) *Actor {
	if subject == nil || subject.Claims == nil {
		return nil
	}
	return actorFromClaim(subject.Claims.Act)
}

// actorFromClaim recursively converts a decoded oidc.ActorClaim chain into the
// mint-side Actor shape, preserving nesting order.
func actorFromClaim(c *oidc.ActorClaim) *Actor {
	if c == nil {
		return nil
	}
	return &Actor{Iss: c.Issuer, Sub: c.Subject, Act: actorFromClaim(c.Act)}
}

// buildActorChain assembles the act claim for a minted token. When actor is
// non-nil it becomes the outermost (most recent) actor and prior is nested
// beneath it, extending a multi-hop delegation chain. When actor is nil the
// prior chain is carried forward unchanged. The combined depth is bounded by
// maxActorChainDepth and rejected fail-closed when exceeded.
func buildActorChain(actor *SubjectIdentity, prior *Actor) (*Actor, error) {
	act := prior
	if actor != nil {
		act = &Actor{Iss: actor.Issuer, Sub: actor.Subject, Act: prior}
	}
	if depth := actorChainDepth(act); depth > maxActorChainDepth {
		return nil, fmt.Errorf("actor chain depth %d exceeds maximum %d", depth, maxActorChainDepth)
	}
	return act, nil
}

// actorChainDepth counts the hops in an act chain.
func actorChainDepth(a *Actor) int {
	n := 0
	for ; a != nil; a = a.Act {
		n++
	}
	return n
}
