package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// SubjectTokenValidator verifies a JWT against a set of trusted issuers and
// returns the verified identity. defaultAudiences applies when the matched
// issuer's AllowedAudiences is empty; pass nil to accept any audience.
type SubjectTokenValidator interface {
	Validate(ctx context.Context, tokenString string, defaultAudiences []string) (*SubjectIdentity, error)
}

// selfIssuedSubjectValidator accepts subject tokens this server issued itself
// (iss == Config.Issuer, at+jwt, signed by the server key), verified through the
// same self-issued JWT pipeline used for bearer authentication (signature, typ,
// iss, exp, audience, revocation, family). The server signs its own tokens, so it
// trusts them as exchange subjects without a self-referential trustedIssuers
// entry. This is what lets a multi-hop A2A delegation re-exchange an OBO token
// that already carries an act chain to nest the next actor beneath it (RFC 8693
// §4.4): only a self-issued token carries act, since external issuers (Dex,
// Kubernetes) do not emit it. Any other token is delegated to next (the
// trusted-issuer validator), preserving external-issuer behaviour.
type selfIssuedSubjectValidator struct {
	srv  *Server
	next SubjectTokenValidator
}

func (v *selfIssuedSubjectValidator) Validate(ctx context.Context, tokenString string, defaultAudiences []string) (*SubjectIdentity, error) {
	if !v.srv.looksLikeSelfIssuedJWT(tokenString) {
		if v.next != nil {
			return v.next.Validate(ctx, tokenString, defaultAudiences)
		}
		return nil, fmt.Errorf("%w: not self-issued and no trusted-issuer validator configured", ErrIssuerNotTrusted)
	}
	_, claims, err := v.srv.validateSelfIssuedJWT(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	return subjectIdentityFromSelfIssuedClaims(claims)
}

// registerSelfIssuedSubjectValidator chains a self-issued validator ahead of any
// trusted-issuer validator for the JWT subject token types, so the server trusts
// its own issued at+jwt tokens as exchange subjects without a self-referential
// WithTrustedIssuers entry. This lets a multi-hop A2A delegation re-exchange an
// OBO token (sub=human, act=prior actor) to add the next actor and extend the
// chain. Only meaningful in JWT access-token mode, where the server can verify
// its own signature.
func (s *Server) registerSelfIssuedSubjectValidator() {
	if !s.Config.IsJWTAccessTokenFormat() {
		return
	}
	if s.subjectValidators == nil {
		s.subjectValidators = make(map[string]SubjectTokenValidator)
	}
	for _, tokenType := range []string{SubjectTokenTypeIDToken, SubjectTokenTypeAccessToken, SubjectTokenTypeJWT} {
		s.subjectValidators[tokenType] = &selfIssuedSubjectValidator{srv: s, next: s.subjectValidators[tokenType]}
	}
}

// subjectIdentityFromSelfIssuedClaims projects the verified claim map of a
// self-issued token into a SubjectIdentity, preserving the act delegation chain
// so a re-exchange carries it forward.
func subjectIdentityFromSelfIssuedClaims(claims map[string]any) (*SubjectIdentity, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal self-issued claims: %w", err)
	}
	var idtc oidc.IDTokenClaims
	if err := json.Unmarshal(raw, &idtc); err != nil {
		return nil, fmt.Errorf("decode self-issued claims: %w", err)
	}
	return &SubjectIdentity{
		Subject:         idtc.Subject,
		Issuer:          idtc.Issuer,
		Claims:          &idtc,
		ConfirmationJKT: confirmationJKTFromClaims(claims),
	}, nil
}

// SubjectIdentity carries the verified identity extracted from a JWT.
// Claims is the full verified payload; callers that only need the
// canonical fields can use Subject, Issuer, and AllowedScopes directly.
type SubjectIdentity struct {
	Subject       string
	Issuer        string
	AllowedScopes []string
	Claims        *oidc.IDTokenClaims
	// ConfirmationJKT is the RFC 9449 §6.1 cnf.jkt thumbprint the token is bound
	// to, empty when the token carries no proof-of-possession confirmation.
	ConfirmationJKT string
}

// confirmationJKTFromClaims extracts the RFC 9449 §6.1 cnf.jkt thumbprint from a
// verified claim map, returning "" when no confirmation key is present.
func confirmationJKTFromClaims(claims map[string]any) string {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return ""
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt
}

// ErrIssuerNotTrusted is returned by Validate when the token is not a JWT,
// has no iss claim, or its iss is not in the configured issuer set.
// Resource-server callers may use errors.Is to fall through to other
// validation paths.
var ErrIssuerNotTrusted = errors.New("untrusted issuer")

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
	// SubjectClaim names the verified claim whose value becomes
	// SubjectIdentity.Subject (and thus the sub of any token issued from this
	// identity). Empty keeps the standard sub claim. Use this when the issuer's sub is an opaque identifier
	// but a different claim (e.g. "email") carries the canonical subject the
	// downstream relies on. Fail-closed: if set and the claim is absent or not a
	// non-empty string, the token is rejected.
	SubjectClaim string
	// AllowPrivateIPJWKS allows JwksURL to resolve to a private or loopback IP
	// address. Set this when the JWKS endpoint is an in-cluster service (e.g.
	// the Kubernetes API server's /openid/v1/jwks) that is not reachable via a
	// public address.
	//
	// WARNING: Disables SSRF protection for this issuer's JWKS fetch. Only set
	// when JwksURL is a known, controlled in-cluster endpoint. Prefer
	// AllowPrivateIPJWKSHosts when the endpoint is a specific known service.
	AllowPrivateIPJWKS bool

	// AllowPrivateIPJWKSHosts lists the specific hostnames whose JWKS URL is
	// permitted to resolve to a private IP. All other hosts retain SSRF
	// protection. Use this instead of AllowPrivateIPJWKS when the private
	// endpoint is a known in-cluster service (e.g.
	// muster.agent-platform.svc.cluster.local). Ignored when
	// AllowPrivateIPJWKS is true.
	AllowPrivateIPJWKSHosts []string

	// RootCAs is the CA pool used to verify this issuer's JWKS endpoint TLS
	// certificate when AllowPrivateIPJWKS or AllowPrivateIPJWKSHosts is set and
	// the endpoint presents a certificate from an internal CA. nil uses the
	// system pool.
	RootCAs *x509.CertPool
	// AcceptedTypHeaders lists the JWT typ header values accepted when a
	// Bearer token from this issuer is presented to the resource server.
	// Empty defaults to ["at+jwt"] (RFC 9068 §4). Issuers that issue plain
	// JWTs need an explicit list: Kubernetes ServiceAccount tokens carry no
	// typ header at all, so use [""] to accept them. Signature, audience,
	// and claim checks still apply unchanged.
	AcceptedTypHeaders []string
}

// OIDCValidator validates JWTs from statically configured trusted issuers.
// The unverified iss claim routes the token to its TrustedIssuer entry;
// signature, audience, and AllowedClaims checks against that entry are
// the security boundary.
type OIDCValidator struct {
	issuers       map[string]TrustedIssuer
	safeClient    *oidc.JWKSClient
	issuerClients map[string]*oidc.JWKSClient // per-issuer permissive clients (AllowPrivateIPJWKS / AllowPrivateIPJWKSHosts)
}

// NewOIDCValidator constructs an OIDCValidator for the given trusted issuers.
// SSRF-safe JWKS fetches are the default; set AllowPrivateIPJWKSHosts on an
// issuer to allow private-IP JWKS only for the listed hostnames, or
// AllowPrivateIPJWKS to disable SSRF protection entirely for that issuer.
func NewOIDCValidator(issuers []TrustedIssuer) (*OIDCValidator, error) {
	safe := oidc.NewJWKSClient(nil, 0, nil)
	issuerClients := map[string]*oidc.JWKSClient{}
	for _, ti := range issuers {
		if ti.AllowPrivateIPJWKS {
			// AllowPrivateIPJWKS targets a controlled in-cluster endpoint,
			// which commonly presents a certificate from an internal CA.
			// NewJWKSClientWithOptions builds the permissive client via
			// NewPrivateIPAllowedHTTPClient, which keeps the cross-host
			// redirect guard and tuned timeouts and verifies against the
			// issuer's RootCAs pool (nil = system pool). Each issuer gets its
			// own client so per-issuer RootCAs are honored.
			issuerClients[ti.Issuer] = oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{
				AllowPrivateIP: true,
				RootCAs:        ti.RootCAs,
			})
		} else if len(ti.AllowPrivateIPJWKSHosts) > 0 {
			issuerClients[ti.Issuer] = oidc.NewJWKSClientWithOptions(oidc.JWKSClientOptions{
				AllowPrivateIPHosts: ti.AllowPrivateIPJWKSHosts,
				RootCAs:             ti.RootCAs,
			})
		}
	}
	return newOIDCValidatorWithClients(issuers, safe, issuerClients)
}

// newOIDCValidatorWithClient is the internal constructor used by tests to inject
// a custom JWKS client used for every issuer.
func newOIDCValidatorWithClient(issuers []TrustedIssuer, client *oidc.JWKSClient) (*OIDCValidator, error) {
	return newOIDCValidatorWithClients(issuers, client, nil)
}

func newOIDCValidatorWithClients(issuers []TrustedIssuer, safeClient *oidc.JWKSClient, issuerClients map[string]*oidc.JWKSClient) (*OIDCValidator, error) {
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
	return &OIDCValidator{issuers: m, safeClient: safeClient, issuerClients: issuerClients}, nil
}

// BearerTypHeaders returns the JWT typ header values accepted for Bearer
// tokens from the given issuer, defaulting to ["at+jwt"] (RFC 9068 §4) when
// the issuer is unknown or has no AcceptedTypHeaders configured.
func (v *OIDCValidator) BearerTypHeaders(issuer string) []string {
	if ti, ok := v.issuers[issuer]; ok && len(ti.AcceptedTypHeaders) > 0 {
		return ti.AcceptedTypHeaders
	}
	return []string{rfc9068TokenType}
}

// Validate verifies a JWT against the configured trusted issuers. The
// unverified iss claim routes to the matching TrustedIssuer entry; the
// signature, audience, and AllowedClaims checks that follow are the
// security boundary. defaultAudiences applies when the matched entry's
// AllowedAudiences is empty.
//
// Returns ErrIssuerNotTrusted (wrapped) when the token cannot be routed
// to a configured issuer (not a JWT, missing iss, or iss not in the set).
func (v *OIDCValidator) Validate(ctx context.Context, tokenString string, defaultAudiences []string) (*SubjectIdentity, error) {
	if !oidc.IsJWT(tokenString) {
		return nil, fmt.Errorf("%w: not a JWT", ErrIssuerNotTrusted)
	}
	rawClaims, err := oidc.ParseUnverifiedClaims(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIssuerNotTrusted, err)
	}
	iss, _ := rawClaims["iss"].(string)
	if iss == "" {
		return nil, fmt.Errorf("%w: missing iss claim", ErrIssuerNotTrusted)
	}
	ti, ok := v.issuers[iss]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrIssuerNotTrusted, iss)
	}

	jwksClient := v.safeClient
	if client, ok := v.issuerClients[iss]; ok {
		jwksClient = client
	}
	audiences := ti.AllowedAudiences
	if len(audiences) == 0 {
		audiences = defaultAudiences
	}

	claims, err := oidc.ValidateIDToken(ctx, tokenString, jwksClient, ti.JwksURL, ti.Issuer, audiences)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if err := checkAllowedClaims(ti.AllowedClaims, rawClaims); err != nil {
		return nil, err
	}

	// rawClaims is authentic here: ValidateIDToken verified the signature over
	// the same token, so reading an additional claim from it is sound.
	subject := claims.Subject
	if ti.SubjectClaim != "" {
		mapped, ok := rawClaims[ti.SubjectClaim].(string)
		if !ok || mapped == "" {
			return nil, fmt.Errorf("subjectClaim %q: not present as a non-empty string", ti.SubjectClaim)
		}
		subject = mapped
	}

	return &SubjectIdentity{
		Subject:         subject,
		Issuer:          claims.Issuer,
		AllowedScopes:   ti.AllowedScopes,
		Claims:          claims,
		ConfirmationJKT: confirmationJKTFromClaims(rawClaims),
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
	SubjectTokenTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"     // #nosec G101 -- RFC 8693 token-type URN identifier, not a credential
	SubjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" // #nosec G101 -- RFC 8693 token-type URN identifier, not a credential
	SubjectTokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"          // #nosec G101 -- RFC 8693 token-type URN identifier, not a credential
)
