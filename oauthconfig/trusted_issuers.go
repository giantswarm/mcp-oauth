package oauthconfig

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/giantswarm/mcp-oauth/server"
)

// trustedIssuer is one OAUTH_TRUSTED_ISSUERS entry. Keys use the terms of
// RFC 8414 (issuer, jwks_uri) and RFC 7519 (aud).
type trustedIssuer struct {
	Issuer                  string            `json:"issuer"`
	JWKSURI                 string            `json:"jwksURI"`
	Audiences               []string          `json:"audiences"`
	SubjectClaim            string            `json:"subjectClaim,omitempty"`
	AcceptedTypHeaders      []string          `json:"acceptedTypHeaders,omitempty"`
	AllowedClaims           map[string]string `json:"allowedClaims,omitempty"`
	CAFile                  string            `json:"caFile,omitempty"`
	AllowPrivateIPJWKSHosts []string          `json:"allowPrivateIPJWKSHosts,omitempty"`
}

// TrustedIssuersFromEnv reads OAUTH_TRUSTED_ISSUERS, the issuers whose JWTs
// the server accepts, for [server.WithTrustedIssuers] or
// [Settings.TrustedIssuers]. An unset variable returns nil.
//
// The value is a JSON array of objects with these keys; unknown keys are
// refused:
//
//   - issuer                   (required) https issuer identifier, no query or fragment
//   - jwksURI                  (required) https JWKS endpoint
//   - audiences                (required, non-empty) accepted aud values: strings or absolute URIs
//   - subjectClaim             "" or "sub" (the default), or "email", accepted only when email_verified is true
//   - acceptedTypHeaders       JWT typ values; default ["at+jwt"] (RFC 9068 §4)
//   - allowedClaims            claim name to exact value or glob pattern
//   - caFile                   PEM bundle added to the system roots for the JWKS endpoint
//   - allowPrivateIPJWKSHosts  hostnames whose JWKS endpoint may resolve to a private address
//
// Trusted issuers are never advertised; OAUTH_AUTHORIZATION_SERVERS names the
// ones a client should use. The list is a trust anchor: load it only from
// configuration that installation administrators control.
func TrustedIssuersFromEnv() ([]server.TrustedIssuer, error) {
	return TrustedIssuersFromEnvWithPrefix("OAUTH_")
}

// TrustedIssuersFromEnvWithPrefix is [TrustedIssuersFromEnv] with a
// caller-supplied prefix. See [FromEnvWithPrefix] for the convention.
func TrustedIssuersFromEnvWithPrefix(prefix string) ([]server.TrustedIssuer, error) {
	name := prefix + "TRUSTED_ISSUERS"
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	var entries []trustedIssuer
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	issuers := make([]server.TrustedIssuer, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for i, entry := range entries {
		issuer, err := entry.resolve()
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
		}
		if seen[issuer.Issuer] {
			return nil, fmt.Errorf("%s[%d]: issuer %q is listed twice", name, i, issuer.Issuer)
		}
		seen[issuer.Issuer] = true
		issuers = append(issuers, issuer)
	}
	if _, err := server.NewOIDCValidator(issuers); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return issuers, nil
}

func (entry trustedIssuer) resolve() (server.TrustedIssuer, error) {
	if entry.Issuer == "" {
		return server.TrustedIssuer{}, fmt.Errorf("issuer is required")
	}
	if err := validateIssuerIdentifier(entry.Issuer, false); err != nil {
		return server.TrustedIssuer{}, err
	}
	jwks, err := url.Parse(entry.JWKSURI)
	if entry.JWKSURI == "" || err != nil || !strings.EqualFold(jwks.Scheme, "https") || jwks.Host == "" {
		return server.TrustedIssuer{}, fmt.Errorf("jwksURI %q must be an https URL", entry.JWKSURI)
	}
	if len(entry.Audiences) == 0 {
		return server.TrustedIssuer{}, fmt.Errorf("audiences is required (RFC 9068 §4)")
	}
	for _, audience := range entry.Audiences {
		if err := validateAudience(audience); err != nil {
			return server.TrustedIssuer{}, err
		}
	}
	switch entry.SubjectClaim {
	case "", "sub", "email":
	default:
		return server.TrustedIssuer{}, fmt.Errorf("subjectClaim %q: want sub or email", entry.SubjectClaim)
	}
	roots, err := LoadRootCAs(entry.CAFile)
	if err != nil {
		return server.TrustedIssuer{}, fmt.Errorf("caFile: %w", err)
	}
	return server.TrustedIssuer{
		Issuer:                  entry.Issuer,
		JwksURL:                 entry.JWKSURI,
		AllowedAudiences:        entry.Audiences,
		AllowedClaims:           entry.AllowedClaims,
		SubjectClaim:            entry.SubjectClaim,
		AcceptedTypHeaders:      entry.AcceptedTypHeaders,
		AllowPrivateIPJWKSHosts: entry.AllowPrivateIPJWKSHosts,
		RootCAs:                 roots,
	}, nil
}

// validateAudience accepts an RFC 7519 StringOrURI: any non-empty string, and
// an absolute URI when it contains a colon.
func validateAudience(audience string) error {
	if strings.TrimSpace(audience) == "" {
		return fmt.Errorf("audiences: empty value")
	}
	if !strings.Contains(audience, ":") {
		return nil
	}
	u, err := url.Parse(audience)
	if err != nil || !u.IsAbs() {
		return fmt.Errorf("audiences: %q contains a colon but is not an absolute URI", audience)
	}
	return nil
}
