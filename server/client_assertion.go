package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/giantswarm/mcp-oauth/storage"
)

// TokenEndpointAuthMethodPrivateKeyJWT identifies RFC 7523 asymmetric client authentication.
const (
	TokenEndpointAuthMethodPrivateKeyJWT = "private_key_jwt" //nolint:gosec // OAuth authentication method identifier.
	// ClientAssertionTypeJWTBearer is the RFC 7523 client assertion type.
	ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // Protocol identifier, not a credential.
	signingKeyUse                = "sig"
	clientAssertionSkew          = 30 * time.Second
)

// ClientAssertionReplayStore atomically records assertion identities until their TTL expires.
// Seen returns true for an identity already recorded. Errors must fail authentication.
type ClientAssertionReplayStore interface {
	Seen(context.Context, string, time.Duration) (bool, error)
}

// NewMemoryClientAssertionReplayStore returns a process-local store.
// Replicas must share a store to prevent cross-replica replay.
func NewMemoryClientAssertionReplayStore() ClientAssertionReplayStore {
	return NewMemoryDPoPReplayCache()
}

// WithClientAssertionReplayStore sets the shared assertion replay store.
func WithClientAssertionReplayStore(store ClientAssertionReplayStore) Option {
	return func(s *Server) { s.clientAssertionReplayStore = store }
}

// ValidateClientKeyMetadata validates inline public signing keys without discarding private fields.
func ValidateClientKeyMetadata(method string, raw json.RawMessage, algorithm string, jwksURI string) error {
	if jwksURI != "" {
		return errors.New("jwks_uri is not supported")
	}
	if method != TokenEndpointAuthMethodPrivateKeyJWT {
		if len(raw) != 0 || algorithm != "" {
			return errors.New("key metadata requires private_key_jwt")
		}
		return nil
	}
	if algorithm != SigningAlgorithmES256 && algorithm != SigningAlgorithmRS256 && algorithm != "PS256" {
		return errors.New("unsupported client signing algorithm")
	}
	var envelope struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Keys) == 0 {
		return errors.New("nonempty jwks required")
	}
	identifiers := make(map[string]bool)
	for _, encoded := range envelope.Keys {
		key, err := validateClientJWK(encoded, algorithm)
		if err != nil {
			return err
		}
		if invalidClientKeyID(key.KeyID, len(envelope.Keys), identifiers) {
			return errors.New("keys require unique kid values")
		}
		identifiers[key.KeyID] = true
	}
	return nil
}

// ClientAssertionIssuer extracts an untrusted lookup hint. Verification must follow lookup.
func ClientAssertionIssuer(assertion string) (string, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 || parts[2] == "" {
		return "", errors.New("assertion_malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("assertion_malformed")
	}
	var hint struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(payload, &hint) != nil || hint.Issuer == "" {
		return "", errors.New("assertion_identity")
	}
	return hint.Issuer, nil
}

// ValidateClientAssertion verifies registered credentials and atomically consumes the assertion.
func (s *Server) ValidateClientAssertion(ctx context.Context, client *storage.Client, assertion string) error {
	fail := func(reason string) error { return errors.New(reason) }
	if client.TokenEndpointAuthMethod != TokenEndpointAuthMethodPrivateKeyJWT {
		return fail("assertion_auth_method")
	}
	if err := ValidateClientKeyMetadata(client.TokenEndpointAuthMethod, client.JWKS, client.TokenEndpointAuthSigningAlg, ""); err != nil {
		return fail("assertion_key_metadata")
	}
	parsed, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(client.TokenEndpointAuthSigningAlg)})
	if err != nil || len(parsed.Headers) != 1 {
		return fail("assertion_signature")
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(client.JWKS, &keys) != nil {
		return fail("assertion_key_metadata")
	}
	var selected *jose.JSONWebKey
	for i := range keys.Keys {
		if parsed.Headers[0].KeyID == keys.Keys[i].KeyID || parsed.Headers[0].KeyID == "" && len(keys.Keys) == 1 {
			selected = &keys.Keys[i]
			break
		}
	}
	if selected == nil {
		return fail("assertion_kid")
	}
	var claims jwt.Claims
	if parsed.Claims(selected.Key, &claims) != nil {
		return fail("assertion_signature")
	}
	s.warnUnexpectedAssertionType(client.ClientID, parsed.Headers[0])
	now := time.Now()
	if err := s.validateAssertionClaims(client.ClientID, claims, now); err != nil {
		return err
	}
	expiry := claims.Expiry.Time()
	identity, _ := json.Marshal([]string{client.ClientID, claims.ID})
	digest := sha256.Sum256(identity)
	seen, err := s.clientAssertionReplayStore.Seen(ctx, hex.EncodeToString(digest[:]), expiry.Add(clientAssertionSkew).Sub(now))
	if err != nil {
		return s.storageUnavailable(ctx, "record client assertion", client.ClientID, "", err)
	}
	if seen {
		return fail("assertion_replayed")
	}
	return nil
}

// clientAssertionTypHeader is the RFC 10070 §4 typ of a client assertion.
const clientAssertionTypHeader = "client-authentication+jwt"

// warnUnexpectedAssertionType logs an assertion whose explicit typ is neither
// JWT nor client-authentication+jwt (RFC 10070 §4, RFC 8725 §3.11): a JWT
// typed for another purpose, such as at+jwt or dpop+jwt, must not
// authenticate a client. A missing typ stays accepted.
func (s *Server) warnUnexpectedAssertionType(clientID string, header jose.Header) {
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	switch strings.TrimPrefix(strings.ToLower(typ), "application/") {
	case "", "jwt", clientAssertionTypHeader:
		return
	}
	s.Logger.Warn("DEPRECATED: client assertion with an explicit typ other than client-authentication+jwt is accepted; a later release refuses it (RFC 10070 section 4)",
		paramClientID, clientID, "typ", typ)
}

func validateClientJWK(encoded json.RawMessage, algorithm string) (*jose.JSONWebKey, error) {
	if err := validateClientJWKFields(encoded); err != nil {
		return nil, err
	}
	var key jose.JSONWebKey
	if json.Unmarshal(encoded, &key) != nil || !key.Valid() || !key.IsPublic() {
		return nil, errors.New("invalid public JWK")
	}
	if key.Use != "" && key.Use != signingKeyUse || key.Algorithm != "" && key.Algorithm != algorithm {
		return nil, errors.New("incompatible key algorithm or use")
	}
	switch public := key.Key.(type) {
	case *ecdsa.PublicKey:
		if algorithm != SigningAlgorithmES256 || public.Curve != elliptic.P256() {
			return nil, errors.New("ES256 requires P-256")
		}
	case *rsa.PublicKey:
		if algorithm == SigningAlgorithmES256 || public.N.BitLen() < 2048 {
			return nil, errors.New("RSA requires RS256/PS256 and at least 2048 bits")
		}
	default:
		return nil, errors.New("unsupported public key type")
	}
	return &key, nil
}

func (s *Server) validateAssertionClaims(clientID string, claims jwt.Claims, now time.Time) error {
	if claims.Issuer != clientID || claims.Subject != clientID {
		return errors.New("assertion_identity")
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != s.Config.Issuer {
		return errors.New("assertion_audience")
	}
	if claims.Expiry == nil || claims.IssuedAt == nil {
		return errors.New("assertion_time_missing")
	}
	expiry, issued := claims.Expiry.Time(), claims.IssuedAt.Time()
	if !expiry.After(issued) || expiry.Sub(issued) > 5*time.Minute {
		return errors.New("assertion_lifetime")
	}
	if !now.Before(expiry.Add(clientAssertionSkew)) {
		return errors.New("assertion_expired")
	}
	if issued.After(now.Add(clientAssertionSkew)) {
		return errors.New("assertion_future_iat")
	}
	if claims.NotBefore != nil && claims.NotBefore.Time().After(now.Add(clientAssertionSkew)) {
		return errors.New("assertion_future_nbf")
	}
	if claims.ID == "" {
		return errors.New("assertion_jti_missing")
	}
	return nil
}

func invalidClientKeyID(identifier string, count int, seen map[string]bool) bool {
	return count > 1 && identifier == "" || identifier != "" && seen[identifier]
}

func validateClientJWKFields(encoded json.RawMessage) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return errors.New("invalid JWK")
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, exists := fields[name]; exists {
			return errors.New("private key material is forbidden")
		}
	}
	var operations []string
	if value, exists := fields["key_ops"]; exists {
		if json.Unmarshal(value, &operations) != nil || len(operations) != 1 || operations[0] != "verify" {
			return errors.New("key_ops must allow verification only")
		}
	}
	return nil
}
