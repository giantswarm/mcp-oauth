package server

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// LocalMintExchanger implements Exchanger by minting an mcp-oauth-signed JWT
// access token locally, without delegating to a downstream issuer. It is the
// recommended implementation for token-exchange targets where the broker itself
// is the authoritative issuer.
//
// Callers are responsible for validating subject and actor tokens and enforcing
// ActorDelegationPolicy before calling Exchange; LocalMintExchanger does not
// re-run policy.
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
//   - sub = req.Subject.Subject (human subject)
//   - act = {iss: req.Actor.Issuer, sub: req.Actor.Subject} when req.Actor != nil
//   - aud = req.Resource when non-empty, else req.Audience
//   - scope = intersection of req.Scope and req.Subject.AllowedScopes
//   - iss = the Issuer URL from the Config used to build LocalMintExchanger
func (l *LocalMintExchanger) Exchange(ctx context.Context, req *ExchangerRequest) (*ExchangerResult, error) {
	if req.Subject == nil {
		return nil, fmt.Errorf("local mint: ExchangerRequest.Subject must not be nil")
	}
	var act *Actor
	if req.Actor != nil {
		act = &Actor{Iss: req.Actor.Issuer, Sub: req.Actor.Subject}
	}

	audience := req.Resource
	if audience == "" {
		audience = req.Audience
	}

	grantedScope := grantedExchangeScope(req.Scope, req.Subject.AllowedScopes)

	now := time.Now().UTC()
	expiresAt := now.Add(l.ttl)

	tokenStr, err := l.issuer.Issue(ctx, AccessTokenClaims{
		Subject:   req.Subject.Subject,
		Audience:  audience,
		Scopes:    strings.Fields(grantedScope),
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		JTI:       generateRandomToken(),
		Act:       act,
	})
	if err != nil {
		return nil, fmt.Errorf("local mint: issue token: %w", err)
	}

	return &ExchangerResult{
		AccessToken:     tokenStr,
		ExpiresAt:       expiresAt,
		Scope:           grantedScope,
		IssuedTokenType: SubjectTokenTypeAccessToken,
	}, nil
}
