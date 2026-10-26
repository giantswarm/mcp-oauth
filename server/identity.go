package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// identityScope is the scope an identity flow records; the provider is asked
// for its identifying scopes only (AuthorizationURLOptions.IdentityOnly).
const identityScope = "openid"

// identityCodeTTL bounds an identity code's lifetime (or AuthorizationCodeTTL
// when shorter): the return URL redeems it as soon as the browser lands.
const identityCodeTTL = 60 * time.Second

// ErrInvalidIdentityCode is returned by RedeemIdentityCode for a code that is
// unknown, expired, already used, not an identity code, bound to another
// return URL, or presented with the wrong PKCE verifier.
var ErrInvalidIdentityCode = errors.New("invalid identity code")

// StartIdentityFlow starts a sign-in at the provider that only establishes
// who the person in the browser is. Unlike StartAuthorizationFlow it grants
// nothing: the provider callback stores no provider token, runs no
// SessionCreationHandler, and issues a code that ExchangeAuthorizationCode
// refuses and only RedeemIdentityCode accepts.
//
// The browser is sent to the returned provider URL. After the provider
// callback it lands on returnURL with code, state (clientState) and iss, as a
// client's redirect URI does. returnURL must be on the issuer's origin, so the
// flow cannot report an identity to another site. codeChallenge is an S256
// PKCE challenge whose verifier the caller keeps for RedeemIdentityCode.
func (s *Server) StartIdentityFlow(ctx context.Context, returnURL *url.URL, codeChallenge, clientState string) (string, error) {
	if clientState == "" {
		return "", fmt.Errorf("%s: state is required", ErrorCodeInvalidRequest)
	}
	if err := s.validateClientStateParameter(clientState); err != nil {
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidRequest, err)
	}
	if codeChallenge == "" {
		return "", fmt.Errorf("%s: an S256 code challenge is required", ErrorCodeInvalidRequest)
	}
	if err := s.validatePKCEForAuthFlow(ctx, "", codeChallenge, PKCEMethodS256); err != nil {
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidRequest, err)
	}
	if err := s.onIssuerOrigin(returnURL); err != nil {
		return "", fmt.Errorf("%s: %w", ErrorCodeInvalidRequest, err)
	}

	providerState := generateRandomToken()
	providerCodeChallenge, providerCodeVerifier := generatePKCEPair()
	nonce, authOpts := s.resolveAuthorizationNonce("", identityScope, &providers.AuthorizationURLOptions{IdentityOnly: true})

	now := time.Now()
	authState := &storage.AuthorizationState{
		StateID:              clientState,
		OriginalClientState:  clientState,
		RedirectURI:          returnURL.String(),
		Scope:                identityScope,
		CodeChallenge:        codeChallenge,
		CodeChallengeMethod:  PKCEMethodS256,
		ProviderState:        providerState,
		ProviderCodeVerifier: providerCodeVerifier,
		Nonce:                nonce,
		IdentityOnly:         true,
		CreatedAt:            now,
		ExpiresAt:            now.Add(time.Duration(s.Config.AuthorizationCodeTTL) * time.Second),
	}
	if err := s.flowStore.SaveAuthorizationState(ctx, authState); err != nil {
		return "", fmt.Errorf("failed to save authorization state: %w", err)
	}

	return s.provider.AuthorizationURL(providerState, providerCodeChallenge, PKCEMethodS256, []string{identityScope}, authOpts), nil
}

// RedeemIdentityCode consumes a code issued by an identity flow and returns
// the subject of the person who signed in: the provider's user ID, as
// UserInfo.ID of a regular sign-in. returnURL and codeVerifier must be the
// flow's. A code is redeemed once.
func (s *Server) RedeemIdentityCode(ctx context.Context, code string, returnURL *url.URL, codeVerifier string) (string, error) {
	authCode, err := s.flowStore.AtomicCheckAndMarkAuthCodeUsed(ctx, code)
	if err != nil {
		if storage.IsTransientError(err) {
			return "", s.storageUnavailable(ctx, "check identity code", "", "", err)
		}
		s.logIdentityRedeemFailure(ctx, "invalid_identity_code: "+err.Error(), code)
		return "", ErrInvalidIdentityCode
	}
	defer func() { _ = s.flowStore.DeleteAuthorizationCode(ctx, code) }()

	switch {
	case !authCode.IdentityOnly:
		s.logIdentityRedeemFailure(ctx, "not_an_identity_code", code)
		return "", ErrInvalidIdentityCode
	case returnURL == nil || authCode.RedirectURI != returnURL.String():
		s.logIdentityRedeemFailure(ctx, "return_url_mismatch", code)
		return "", ErrInvalidIdentityCode
	case authCode.CodeChallenge == "":
		s.logIdentityRedeemFailure(ctx, "missing_code_challenge", code)
		return "", ErrInvalidIdentityCode
	}
	if err := s.validatePKCEWithAudit(ctx, authCode, "", codeVerifier, nil); err != nil {
		return "", ErrInvalidIdentityCode
	}
	if s.Auditor != nil {
		s.Auditor.LogEvent(ctx, security.Event{
			Type:   security.EventIdentityCodeRedeemed,
			UserID: authCode.UserID,
		})
	}
	return authCode.UserID, nil
}

// onIssuerOrigin reports whether u is an absolute URL on the issuer's
// scheme and host.
func (s *Server) onIssuerOrigin(u *url.URL) error {
	if u == nil || !u.IsAbs() {
		return fmt.Errorf("return URL must be absolute")
	}
	issuer, err := url.Parse(s.Config.Issuer)
	if err != nil {
		return fmt.Errorf("issuer is not a valid URL: %w", err)
	}
	if u.Scheme != issuer.Scheme || u.Host != issuer.Host {
		return fmt.Errorf("return URL must be on the issuer's origin %s://%s", issuer.Scheme, issuer.Host)
	}
	return nil
}

func (s *Server) logIdentityRedeemFailure(ctx context.Context, reason, code string) {
	s.Logger.Warn("Identity code rejected", logKeyReason, reason, "code_prefix", helpers.SafeTruncate(code, 8))
	if s.Auditor != nil {
		s.Auditor.LogAuthFailure(ctx, "", "", "", reason)
	}
}
