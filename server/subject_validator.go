package server

import (
	"context"
	"fmt"
	"path"
	"strings"

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
	// strings or glob patterns where '*' matches any sequence of characters
	// (including '/') and '?' matches any single character. Use '*' freely
	// across path segments, e.g. "system:serviceaccount:ns:*" or
	// "repo:org/repo:*". Absent claims and claims with non-string values
	// (numbers, arrays, objects) are rejected. Nil or empty means no claim
	// restrictions.
	AllowedClaims map[string]string
	// AllowPrivateIPJWKS allows JwksURL to resolve to a private or loopback IP
	// address. Set this when the JWKS endpoint is an in-cluster service (e.g.
	// the Kubernetes API server's /openid/v1/jwks) that is not reachable via a
	// public address.
	//
	// WARNING: Disables SSRF protection for this issuer's JWKS fetch. Only set
	// when JwksURL is a known, controlled in-cluster endpoint.
	AllowPrivateIPJWKS bool
}

// OIDCValidator validates tokens from statically configured trusted issuers.
// It accepts the following subject_token_type values:
//   - urn:ietf:params:oauth:token-type:id_token
//   - urn:ietf:params:oauth:token-type:access_token
//   - urn:ietf:params:oauth:token-type:jwt
type OIDCValidator struct {
	issuers          map[string]TrustedIssuer
	safeClient       *oidc.JWKSClient
	permissiveClient *oidc.JWKSClient // non-nil only when at least one issuer sets AllowPrivateIPJWKS
}

// NewOIDCValidator constructs an OIDCValidator for the given trusted issuers.
// JWKS clients are created automatically: a private-IP-blocking client is used
// by default; issuers with AllowPrivateIPJWKS set share a second client that
// permits private-IP resolution.
func NewOIDCValidator(issuers []TrustedIssuer) (*OIDCValidator, error) {
	safe := oidc.NewJWKSClient(nil, 0, nil)
	var permissive *oidc.JWKSClient
	for _, ti := range issuers {
		if ti.AllowPrivateIPJWKS {
			permissive = oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{AllowPrivateIP: true})
			break
		}
	}
	return newOIDCValidatorWithClients(issuers, safe, permissive)
}

// newOIDCValidatorWithClient is the internal constructor used by tests to inject
// a custom JWKS client. Both safe and permissive slots are set to client, so
// AllowPrivateIPJWKS routing works transparently in tests.
func newOIDCValidatorWithClient(issuers []TrustedIssuer, client *oidc.JWKSClient) (*OIDCValidator, error) {
	return newOIDCValidatorWithClients(issuers, client, client)
}

func newOIDCValidatorWithClients(issuers []TrustedIssuer, safeClient, permissiveClient *oidc.JWKSClient) (*OIDCValidator, error) {
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
	return &OIDCValidator{issuers: m, safeClient: safeClient, permissiveClient: permissiveClient}, nil
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

	jwksClient := v.safeClient
	if ti.AllowPrivateIPJWKS && v.permissiveClient != nil {
		jwksClient = v.permissiveClient
	}
	claims, err := oidc.ValidateIDToken(ctx, subjectToken, jwksClient, ti.JwksURL, ti.Issuer, ti.AllowedAudiences)
	if err != nil {
		return SubjectIdentity{}, fmt.Errorf("subject token validation failed: %w", err)
	}

	if err := checkAllowedClaims(ti.AllowedClaims, rawClaims); err != nil {
		return SubjectIdentity{}, err
	}

	return SubjectIdentity{
		Subject:       claims.Subject,
		Issuer:        claims.Issuer,
		AllowedScopes: ti.AllowedScopes,
	}, nil
}

// checkAllowedClaims verifies that every claim in allowed is present in raw and
// matches its pattern. raw is the unverified JWT payload map.
func checkAllowedClaims(allowed map[string]string, raw map[string]any) error {
	for claimName, pattern := range allowed {
		rawVal, present := raw[claimName]
		if !present {
			return fmt.Errorf("claim %q: not present in token", claimName)
		}
		claimValue, ok := rawVal.(string)
		if !ok {
			return fmt.Errorf("claim %q: value has non-string type %T", claimName, rawVal)
		}
		if err := matchClaimPattern(pattern, claimValue); err != nil {
			return fmt.Errorf("claim %q: %w", claimName, err)
		}
	}
	return nil
}

// matchClaimPattern matches value against a glob pattern using path.Match
// semantics, but with '/' stripped of its separator role so '*' spans the
// whole string (including slashes). This lets patterns like
// "repo:org/repo:*" match GHA subjects that contain '/'.
func matchClaimPattern(pattern, value string) error {
	// Replace '/' with '\x01' in both sides so path.Match never sees a
	// separator; any other path.Match feature (?, [...]) is preserved.
	// \x01 is safe: JWT claims are printable Unicode, so it cannot appear
	// in a real claim value or operator-supplied pattern.
	const sep, placeholder = "/", "\x01"
	matched, err := path.Match(
		strings.ReplaceAll(pattern, sep, placeholder),
		strings.ReplaceAll(value, sep, placeholder),
	)
	if err != nil {
		return fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	if !matched {
		return fmt.Errorf("value %q does not match allowed pattern %q", value, pattern)
	}
	return nil
}

// Token-type URN constants shared between OIDCValidator and the token-exchange handler.
const (
	SubjectTokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"
	SubjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	SubjectTokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)
