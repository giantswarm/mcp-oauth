package server

import (
	"context"
	"fmt"
	"path"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// SubjectTokenValidator validates incoming subject tokens for RFC 8693 token exchange.
type SubjectTokenValidator interface {
	Validate(ctx context.Context, subjectToken, subjectTokenType string) (SubjectIdentity, error)
}

// SubjectIdentity carries the verified identity extracted from a subject token.
type SubjectIdentity struct {
	// Subject is the verbatim workload identity; becomes the sub claim in the issued token.
	Subject string
	// Issuer is the original token's iss claim; becomes act.iss in the issued token.
	Issuer string
	// AllowedScopes is the maximum scope envelope for this identity,
	// from TrustedIssuer.AllowedScopes. Nil means no restriction.
	AllowedScopes []string
}

// TrustedIssuer configures a trusted external token issuer for OIDCValidator.
// The JwksURL and Issuer are intentionally independent: the JWKS location is
// not derived from Issuer via OIDC discovery, so callers can point at an
// in-cluster proxy without changing the Issuer value.
type TrustedIssuer struct {
	// Issuer is the expected iss claim value. Only tokens whose iss equals this
	// value will be routed to this entry.
	Issuer string
	// JwksURL is the JWKS endpoint used to fetch the public key set.
	JwksURL string
	// AllowedAudiences is the list of accepted aud values. An empty list accepts
	// any audience (not recommended for production).
	AllowedAudiences []string
	// AllowedScopes caps the scopes that can be issued for tokens from this issuer.
	// Nil means no per-issuer restriction.
	AllowedScopes []string
	// AllowedClaims constrains which tokens are accepted by requiring each named
	// claim to match its pattern. Keys are JWT claim names; values are exact
	// strings or path.Match glob patterns (e.g. "system:serviceaccount:ns:*").
	// Nil or empty means no claim restrictions.
	AllowedClaims map[string]string
}

// OIDCValidator validates tokens from statically configured trusted issuers.
// It accepts the following subject_token_type values:
//   - urn:ietf:params:oauth:token-type:id_token
//   - urn:ietf:params:oauth:token-type:access_token
type OIDCValidator struct {
	issuers    map[string]TrustedIssuer
	jwksClient *oidc.JWKSClient
}

// NewOIDCValidator constructs an OIDCValidator for the given trusted issuers.
// An SSRF-safe JWKS client is created automatically.
func NewOIDCValidator(issuers []TrustedIssuer) (*OIDCValidator, error) {
	return newOIDCValidatorWithClient(issuers, oidc.NewJWKSClient(nil, 0, nil))
}

// newOIDCValidatorWithClient is the internal constructor used by tests to inject
// a custom JWKS client (e.g. one configured to allow private IPs for httptest).
func newOIDCValidatorWithClient(issuers []TrustedIssuer, client *oidc.JWKSClient) (*OIDCValidator, error) {
	if len(issuers) == 0 {
		return nil, fmt.Errorf("at least one trusted issuer is required")
	}
	m := make(map[string]TrustedIssuer, len(issuers))
	for _, ti := range issuers {
		if ti.Issuer == "" {
			return nil, fmt.Errorf("trusted issuer must have a non-empty Issuer field")
		}
		if ti.JwksURL == "" {
			return nil, fmt.Errorf("trusted issuer %q must have a non-empty JwksURL", ti.Issuer)
		}
		m[ti.Issuer] = ti
	}
	return &OIDCValidator{issuers: m, jwksClient: client}, nil
}

// Validate verifies the subject token and returns the verified identity.
// The unverified iss claim is used only to route to the correct TrustedIssuer
// config; the full signature + claim validation that follows is the security
// boundary.
func (v *OIDCValidator) Validate(ctx context.Context, subjectToken, subjectTokenType string) (SubjectIdentity, error) {
	switch subjectTokenType {
	case SubjectTokenTypeIDToken, SubjectTokenTypeAccessToken, SubjectTokenTypeJWT:
	default:
		return SubjectIdentity{}, fmt.Errorf("unsupported subject_token_type: %q", subjectTokenType)
	}

	rawClaims, err := oidc.ParseUnverifiedClaims(subjectToken)
	if err != nil {
		return SubjectIdentity{}, fmt.Errorf("invalid subject_token: %w", err)
	}
	iss, _ := rawClaims["iss"].(string)
	if iss == "" {
		return SubjectIdentity{}, fmt.Errorf("subject_token missing iss claim")
	}

	ti, ok := v.issuers[iss]
	if !ok {
		return SubjectIdentity{}, fmt.Errorf("untrusted issuer: %q", iss)
	}

	claims, err := oidc.ValidateIDToken(ctx, subjectToken, v.jwksClient, ti.JwksURL, ti.Issuer, ti.AllowedAudiences)
	if err != nil {
		return SubjectIdentity{}, fmt.Errorf("subject token validation failed: %w", err)
	}

	if len(ti.AllowedClaims) > 0 {
		rawClaims, err := oidc.ParseUnverifiedClaims(subjectToken)
		if err != nil {
			return SubjectIdentity{}, fmt.Errorf("parsing token claims: %w", err)
		}
		for claimName, pattern := range ti.AllowedClaims {
			claimValue, _ := rawClaims[claimName].(string)
			matched, err := path.Match(pattern, claimValue)
			if err != nil {
				return SubjectIdentity{}, fmt.Errorf("claim %q: invalid pattern %q: %w", claimName, pattern, err)
			}
			if !matched {
				return SubjectIdentity{}, fmt.Errorf("claim %q: value %q does not match allowed pattern %q", claimName, claimValue, pattern)
			}
		}
	}

	return SubjectIdentity{
		Subject:       claims.Subject,
		Issuer:        claims.Issuer,
		AllowedScopes: ti.AllowedScopes,
	}, nil
}

// Token-type URN constants shared between OIDCValidator and the token-exchange handler.
const (
	SubjectTokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"
	SubjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	SubjectTokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)
