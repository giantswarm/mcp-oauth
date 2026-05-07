package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
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
	signer    jwt.SigningMethod
	key       any
	kid       string
	issuer    string
	tokenType string
}

// newJWTIssuer constructs a jwtIssuer from a validated configuration. The
// caller MUST have already run Config.Validate so that key/alg compatibility
// is guaranteed. issuer is the OAuth Issuer URL that becomes the iss claim.
func newJWTIssuer(cfg *Config) (*jwtIssuer, error) {
	signer, err := signingMethodForAlgorithm(cfg.AccessTokenSigningAlgorithm)
	if err != nil {
		return nil, err
	}
	return &jwtIssuer{
		signer:    signer,
		key:       cfg.AccessTokenSigningKey,
		kid:       cfg.AccessTokenSigningKeyID,
		issuer:    cfg.Issuer,
		tokenType: rfc9068TokenType,
	}, nil
}

// rfc9068TokenType is the JWT typ header per RFC 9068 §2.1. Resource servers
// use it to distinguish access tokens from id_tokens during validation —
// confusing the two enables a class of token-substitution attacks.
const rfc9068TokenType = "at+jwt"

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

	mapClaims := jwt.MapClaims{
		"iss":       j.issuer,
		"sub":       c.Subject,
		"aud":       c.Audience,
		"exp":       c.ExpiresAt.Unix(),
		"iat":       c.IssuedAt.Unix(),
		"jti":       jti,
		"client_id": c.ClientID,
	}
	if scope := joinScopes(c.Scopes); scope != "" {
		mapClaims["scope"] = scope
	}
	if c.Email != "" {
		mapClaims["email"] = c.Email
	}
	if len(c.Groups) > 0 {
		mapClaims["groups"] = c.Groups
	}
	if c.FamilyID != "" {
		mapClaims["family_id"] = c.FamilyID
	}

	tok := jwt.NewWithClaims(j.signer, mapClaims)
	tok.Header["typ"] = j.tokenType
	tok.Header["kid"] = j.kid

	signed, err := tok.SignedString(j.key)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}

// signingMethodForAlgorithm returns the golang-jwt SigningMethod for an
// algorithm string. Only the closed set documented in
// supportedSigningAlgorithms is recognized.
func signingMethodForAlgorithm(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case SigningAlgorithmRS256:
		return jwt.SigningMethodRS256, nil
	case SigningAlgorithmRS384:
		return jwt.SigningMethodRS384, nil
	case SigningAlgorithmRS512:
		return jwt.SigningMethodRS512, nil
	case SigningAlgorithmES256:
		return jwt.SigningMethodES256, nil
	case SigningAlgorithmES384:
		return jwt.SigningMethodES384, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q", alg)
	}
}

// joinScopes concatenates non-empty scopes with single spaces per RFC 6749
// §3.3 scope encoding. Empty entries are dropped to avoid stray separators.
func joinScopes(scopes []string) string {
	out := scopes[:0:0]
	for _, s := range scopes {
		if s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
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
