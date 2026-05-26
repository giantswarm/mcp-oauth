package server

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

const (
	dpopTypHeader    = "dpop+jwt"
	dpopMaxClockSkew = 5 * time.Minute
	dpopProofTTL     = 5 * time.Minute
)

// DPoPProofClaims holds the validated output of a DPoP proof JWT.
// JKT is the only field callers need: it is the JWK thumbprint to bind into
// the issued access token cnf claim.
type DPoPProofClaims struct {
	// JKT is the JWK thumbprint of the public key that signed the proof.
	JKT string
}

// dpopRawClaims is the on-the-wire shape of a DPoP proof JWT body.
type dpopRawClaims struct {
	josejwt.Claims
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	ATH string `json:"ath,omitempty"`
}

// ValidateDPoPProof parses and validates a DPoP proof JWT per RFC 9449 §4.3.
// method and uri are the HTTP method and URI of the current request.
// accessToken is non-empty only at the resource server (enables ath check).
func ValidateDPoPProof(ctx context.Context, proof, method, uri, accessToken string, replay DPoPReplayCache, now time.Time) (*DPoPProofClaims, error) {
	jws, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512,
	})
	if err != nil {
		return nil, fmt.Errorf("dpop: parse proof: %w", err)
	}

	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("dpop: proof must have exactly one signature")
	}

	header := jws.Signatures[0].Header

	// typ is stored in ExtraHeaders for non-standard header parameters.
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, dpopTypHeader) {
		return nil, fmt.Errorf("dpop: typ header must be %q, got %q", dpopTypHeader, typ)
	}

	// go-jose parses the jwk header directly into header.JSONWebKey.
	embeddedJWK := header.JSONWebKey
	if embeddedJWK == nil {
		return nil, fmt.Errorf("dpop: jwk header is required")
	}
	if !embeddedJWK.IsPublic() {
		return nil, fmt.Errorf("dpop: jwk header must contain a public key")
	}

	payload, err := jws.Verify(embeddedJWK)
	if err != nil {
		return nil, fmt.Errorf("dpop: signature verification failed: %w", err)
	}

	var claims dpopRawClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("dpop: parse claims: %w", err)
	}

	if claims.ID == "" {
		return nil, fmt.Errorf("dpop: jti claim is required")
	}

	if !strings.EqualFold(claims.HTM, method) {
		return nil, fmt.Errorf("dpop: htm claim %q does not match request method %q", claims.HTM, method)
	}

	if stripQueryAndFragment(uri) != stripQueryAndFragment(claims.HTU) {
		return nil, fmt.Errorf("dpop: htu claim %q does not match request uri %q", claims.HTU, uri)
	}

	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("dpop: iat claim is required")
	}
	iat := claims.IssuedAt.Time()
	if now.Sub(iat) > dpopMaxClockSkew || iat.Sub(now) > dpopMaxClockSkew {
		return nil, fmt.Errorf("dpop: iat is outside allowed clock skew window")
	}

	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		expected := base64.RawURLEncoding.EncodeToString(hash[:])
		if claims.ATH != expected {
			return nil, fmt.Errorf("dpop: ath claim does not match access token hash")
		}
	}

	seen, err := replay.Seen(ctx, claims.ID, dpopProofTTL)
	if err != nil {
		return nil, fmt.Errorf("dpop: replay cache error: %w", err)
	}
	if seen {
		return nil, fmt.Errorf("dpop: proof jti has already been used (replay detected)")
	}

	thumb, err := embeddedJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("dpop: compute JWK thumbprint: %w", err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)

	return &DPoPProofClaims{JKT: jkt}, nil
}

// stripQueryAndFragment removes query string and fragment from a URI per RFC 9449.
func stripQueryAndFragment(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		uri = uri[:i]
	}
	return uri
}

// newConfirmation builds the cnf claim for a DPoP-bound access token.
// Returns nil when jkt is empty so the claim is omitted from the JWT.
func newConfirmation(jkt string) *Confirmation {
	if jkt == "" {
		return nil
	}
	return &Confirmation{JKT: jkt}
}
