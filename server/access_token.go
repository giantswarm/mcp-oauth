package server

import (
	"context"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
)

// AccessTokenClaims is the input passed to AccessTokenIssuer.Issue. It carries
// the OAuth-flow context the issuer needs to construct the bearer string.
//
// The shape is provider-agnostic: opaque issuers ignore most of these fields
// and just generate a 256-bit random string, while JWT issuers fold them into
// signed claims per RFC 9068 §2.2.
type AccessTokenClaims struct {
	// Subject is the authenticated user identifier (RFC 9068 sub claim).
	Subject string

	// ClientID is the OAuth client this token was issued to (RFC 9068
	// client_id claim).
	ClientID string

	// Audience is the resource server identifier this token is bound to
	// per RFC 8707. Becomes the JWT aud claim and is enforced at validation
	// time against Config.GetResourceIdentifier().
	Audience string

	// Scopes are the granted scopes; serialized space-delimited into the
	// scope claim per RFC 9068 §2.2.3. Empty slice produces no claim.
	Scopes []string

	// Email is the verified user email when present from the upstream
	// provider's UserInfo, included for downstream identity-attributed audit
	// logs without an extra IdP round-trip.
	Email string

	// EmailVerified mirrors providers.UserInfo.EmailVerified. Emitted as the
	// email_verified claim only when Email is non-empty, so that introspection
	// of a JWT access token (RFC 7662 §2.2) projects the same identity
	// attributes as the opaque branch.
	EmailVerified bool

	// Name mirrors providers.UserInfo.Name. Emitted as the OIDC standard name
	// claim when non-empty; same parity rationale as EmailVerified.
	Name string

	// Groups are the user's group memberships from the upstream provider.
	// Included verbatim under the "groups" claim when non-empty.
	Groups []string

	// IssuedAt and ExpiresAt define the validity window. The issuer copies
	// IssuedAt into iat and ExpiresAt into exp; ExpiresAt must be set to a
	// non-zero time in the future or validation will reject the token.
	IssuedAt  time.Time
	ExpiresAt time.Time

	// JTI is an optional caller-supplied unique identifier. When empty the
	// issuer generates one. Exported so a caller running its own jti
	// allocation (e.g. correlated with a trace ID) can inject it.
	JTI string

	// FamilyID is the OAuth 2.1 refresh-token family identifier this access
	// token belongs to (storage.RefreshTokenFamilyMetadata.FamilyID). When
	// non-empty it is written into the JWT as the family_id claim and
	// checked at validation time against RefreshTokenFamilyStore — revoking
	// the family invalidates all in-flight access tokens in the family,
	// not only future issuance.
	//
	// Empty when the underlying token store does not implement
	// RefreshTokenFamilyStore.
	FamilyID string

	// Act carries the RFC 8693 §4.4 actor claim. Non-nil only for token-exchange
	// issued tokens.
	Act *Actor

	// JKT is the JWK thumbprint of the DPoP public key this token is bound to
	// (RFC 9449 §6.1). Non-empty only when the token was requested with a DPoP proof.
	JKT string

	// Extra holds application-defined claims merged into the JWT body verbatim
	// after the standard claims. Keys must not collide with RFC 7519 §4.1
	// registered claim names (iss, sub, aud, exp, nbf, iat, jti) — Issue
	// returns an error if they do. OIDC-profile claims (email, name, groups,
	// email_verified) set via struct fields are not guarded and can be
	// overridden by Extra. Nil is a no-op.
	Extra map[string]any
}

// Actor is the RFC 8693 §4.4 act claim: the acting party in a delegation chain.
// Act nests the prior actor so a multi-hop A2A chain (human → agentA → agentB)
// is preserved: the outermost Act is the most recent actor, Act.Act the one
// before it. Nil at the end of the chain.
type Actor struct {
	Iss string `json:"iss,omitempty"`
	Sub string `json:"sub,omitempty"`
	Act *Actor `json:"act,omitempty"`
}

// Confirmation is the RFC 9449 §6.1 cnf claim: proof-of-possession key binding.
type Confirmation struct {
	JKT string `json:"jkt,omitempty"`
}

// AccessTokenIssuer encodes AccessTokenClaims into a bearer string. Two
// implementations exist:
//
//   - opaqueIssuer: generates a 256-bit random string keyed into TokenStore.
//   - jwtIssuer: signs a JWT per RFC 9068 ("JWT Profile for OAuth 2.0 Access
//     Tokens") with the configured key, kid, and algorithm.
//
// The Server holds exactly one AccessTokenIssuer for its lifetime, selected
// at construction from Config.AccessTokenFormat.
type AccessTokenIssuer interface {
	// Issue produces a bearer string for the given claims. The returned
	// string is what the client receives in the access_token field of the
	// token response and what it sends back as a Bearer credential.
	Issue(ctx context.Context, c AccessTokenClaims) (string, error)
}

// opaqueIssuer wraps generateRandomToken. All claim fields in
// AccessTokenClaims are ignored: opaque tokens carry no data, only a
// database key.
type opaqueIssuer struct{}

// Issue returns a 256-bit random base64url-encoded string. Returned errors
// would only surface from a system RNG failure inside generateRandomToken
// (which panics — see its godoc for the rationale).
func (o opaqueIssuer) Issue(_ context.Context, _ AccessTokenClaims) (string, error) {
	return generateRandomToken(), nil
}

// jwtIssuer signs RFC 9068 access tokens with a single key. The Server
// constructor wires this implementation in when Config.AccessTokenFormat is
// AccessTokenFormatJWT and Config.Validate has accepted the key/alg pair.
type jwtIssuer struct {
	signer jose.Signer
	issuer string
}

// newJWTIssuer constructs a jwtIssuer from a validated configuration. The
// caller MUST have already run Config.Validate so that key/alg compatibility
// is guaranteed. issuer is the OAuth Issuer URL that becomes the iss claim.
func newJWTIssuer(cfg *Config) (*jwtIssuer, error) {
	alg := jose.SignatureAlgorithm(cfg.AccessTokenSigningAlgorithm)
	signingKey := jose.SigningKey{
		Algorithm: alg,
		Key: jose.JSONWebKey{
			Key:       cfg.AccessTokenSigningKey,
			KeyID:     cfg.AccessTokenSigningKeyID,
			Algorithm: cfg.AccessTokenSigningAlgorithm,
			Use:       "sig",
		},
	}
	opts := &jose.SignerOptions{}
	opts.WithType(rfc9068TokenType)
	opts.WithHeader(jose.HeaderKey("kid"), cfg.AccessTokenSigningKeyID)

	signer, err := jose.NewSigner(signingKey, opts)
	if err != nil {
		return nil, fmt.Errorf("create JWT signer: %w", err)
	}
	return &jwtIssuer{
		signer: signer,
		issuer: cfg.Issuer,
	}, nil
}

// rfc9068TokenType is the JWT typ header per RFC 9068 §2.1. Resource servers
// use it to distinguish access tokens from id_tokens during validation —
// confusing the two enables a class of token-substitution attacks.
const rfc9068TokenType = "at+jwt"

// jwtReservedClaims is the set of RFC 7519 §4.1 registered claim names that
// Issue sets explicitly. Allowing Extra to override them would let callers
// extend token lifetime (exp), forge issuers (iss), or substitute subjects (sub).
var jwtReservedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {},
	"exp": {}, "nbf": {}, "iat": {}, "jti": {},
}

// rfc9068Claims is the on-the-wire claim shape for an RFC 9068 access token.
// Standard registered claims live on the embedded josejwt.Claims; the rest
// are RFC 9068 §2.2 plus the OIDC-style email/groups extras carried for
// downstream consumers.
type rfc9068Claims struct {
	josejwt.Claims

	ClientID      string        `json:"client_id,omitempty"`
	Scope         string        `json:"scope,omitempty"`
	Email         string        `json:"email,omitempty"`
	EmailVerified *bool         `json:"email_verified,omitempty"`
	Name          string        `json:"name,omitempty"`
	Groups        []string      `json:"groups,omitempty"`
	FamilyID      string        `json:"family_id,omitempty"`
	Act           *Actor        `json:"act,omitempty"`
	Cnf           *Confirmation `json:"cnf,omitempty"`
}

// Issue signs an RFC 9068 access token. The header carries alg/kid/typ; the
// payload carries the standard claims plus optional email/groups when set on
// AccessTokenClaims. A jti is generated when the caller did not supply one.
func (j *jwtIssuer) Issue(_ context.Context, c AccessTokenClaims) (string, error) {
	if c.ExpiresAt.IsZero() {
		return "", fmt.Errorf("AccessTokenClaims.ExpiresAt is required for JWT mode")
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = time.Now().UTC()
	}
	jti := c.JTI
	if jti == "" {
		jti = generateRandomToken()
	}

	claims := rfc9068Claims{
		Claims: josejwt.Claims{
			Issuer:    j.issuer,
			Subject:   c.Subject,
			Audience:  josejwt.Audience{c.Audience},
			Expiry:    josejwt.NewNumericDate(c.ExpiresAt),
			IssuedAt:  josejwt.NewNumericDate(c.IssuedAt),
			NotBefore: josejwt.NewNumericDate(c.IssuedAt),
			ID:        jti,
		},
		ClientID: c.ClientID,
		Scope:    helpers.JoinScopes(c.Scopes),
		Email:    c.Email,
		Name:     c.Name,
		Groups:   c.Groups,
		FamilyID: c.FamilyID,
		Act:      c.Act,
		Cnf:      newConfirmation(c.JKT),
	}
	if c.Email != "" {
		verified := c.EmailVerified
		claims.EmailVerified = &verified
	}

	builder := josejwt.Signed(j.signer).Claims(claims)
	if len(c.Extra) > 0 {
		for k := range c.Extra {
			if _, reserved := jwtReservedClaims[k]; reserved {
				return "", fmt.Errorf("extra map contains reserved JWT claim %q", k)
			}
		}
		builder = builder.Claims(c.Extra)
	}
	signed, err := builder.Serialize()
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}

// publicJWKFromConfig returns a single public JWK for the configured access
// token signing key. Returns nil with no error when the server is configured
// for opaque mode; the JWKS endpoint translates that into a 404.
//
// Encoding is delegated to go-jose, which knows the canonical RFC 7517 /
// RFC 7518 JWK representation for RSA and ECDSA public keys.
func publicJWKFromConfig(cfg *Config) (*jose.JSONWebKey, error) {
	if !cfg.IsJWTAccessTokenFormat() {
		return nil, nil
	}
	if cfg.AccessTokenSigningKey == nil {
		return nil, fmt.Errorf("access token signing key is not configured")
	}
	jwk := &jose.JSONWebKey{
		Key:       cfg.AccessTokenSigningKey.Public(),
		KeyID:     cfg.AccessTokenSigningKeyID,
		Algorithm: cfg.AccessTokenSigningAlgorithm,
		Use:       "sig",
	}
	if !jwk.IsPublic() {
		return nil, fmt.Errorf("derived JWK contains non-public material; refusing to publish")
	}
	return jwk, nil
}

// publicJWKSFromConfig returns the JWKS envelope for the configured signing
// key, or an empty key set in opaque mode (callers serving the endpoint
// translate that into a 404 to avoid advertising what isn't used).
func publicJWKSFromConfig(cfg *Config) (*jose.JSONWebKeySet, error) {
	jwk, err := publicJWKFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	if jwk == nil {
		return &jose.JSONWebKeySet{}, nil
	}
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*jwk}}, nil
}

// PublicJWKS returns the JWKS envelope to be served at the JWKS discovery
// endpoint. In AccessTokenFormatJWT mode the returned set contains the
// public half of the access-token signing key; in opaque mode the set is
// empty. Callers serving the HTTP endpoint should respond 404 in the
// empty case rather than serving an empty key array.
//
// Exported so the http.Handler in the root oauth package can build the
// response without reaching into server-package internals.
func (s *Server) PublicJWKS() (*jose.JSONWebKeySet, error) {
	return publicJWKSFromConfig(s.Config)
}
