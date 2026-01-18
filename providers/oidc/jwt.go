// Package oidc provides OIDC (OpenID Connect) utilities for OAuth providers.
package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
)

// JWKSClient fetches and caches JWKS (JSON Web Key Sets) for JWT validation.
// It provides SSRF protection and caches keys with configurable TTL.
//
// The client is thread-safe and can be used concurrently from multiple goroutines.
type JWKSClient struct {
	httpClient   *http.Client
	cache        sync.Map // jwksURI -> *cachedJWKS
	cacheTTL     time.Duration
	logger       *slog.Logger
	timeProvider timeProvider
}

// cachedJWKS holds a JWKS with its fetch timestamp.
type cachedJWKS struct {
	keys      *JWKS
	fetchedAt time.Time
}

// JWKS represents a JSON Web Key Set per RFC 7517.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key per RFC 7517.
// Supports both RSA and EC (Elliptic Curve) key types.
type JWK struct {
	Kty string `json:"kty"` // Key Type: "RSA" or "EC"
	Use string `json:"use"` // Public Key Use (e.g., "sig")
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm (e.g., "RS256", "ES256")

	// RSA key parameters
	N string `json:"n,omitempty"` // RSA modulus (base64url)
	E string `json:"e,omitempty"` // RSA exponent (base64url)

	// EC key parameters
	Crv string `json:"crv,omitempty"` // EC curve name (e.g., "P-256", "P-384", "P-521")
	X   string `json:"x,omitempty"`   // EC x coordinate (base64url)
	Y   string `json:"y,omitempty"`   // EC y coordinate (base64url)
}

const (
	// maxJWKSDocumentSize is the maximum allowed size for a JWKS response.
	// JWKS documents are typically a few KB. 1MB is a generous safety margin
	// to prevent memory exhaustion attacks from malicious JWKS endpoints.
	maxJWKSDocumentSize = 1024 * 1024 // 1MB

	// maxJWKSKeyCount is the maximum number of keys allowed in a JWKS.
	// This prevents memory exhaustion from malicious endpoints returning
	// millions of keys. 100 keys is far more than any legitimate provider needs.
	maxJWKSKeyCount = 100

	// KeyTypeRSA is the JWK key type for RSA keys.
	KeyTypeRSA = "RSA"
	// KeyTypeEC is the JWK key type for Elliptic Curve keys.
	KeyTypeEC = "EC"
)

// NewJWKSClient creates a new JWKS client with default configuration.
//
// Parameters:
//   - httpClient: HTTP client to use for requests (nil uses SSRF-safe client with DNS rebinding protection)
//   - cacheTTL: Time-to-live for cached JWKS (0 uses default 1 hour)
//   - logger: Logger for debug/info messages (nil uses default logger)
//
// Security Features (when httpClient is nil):
//   - DNS Rebinding Protection: Validates resolved IPs at connection time
//   - SSRF Protection: Blocks private, loopback, and link-local addresses
//   - TLS Verification: Uses default TLS settings
func NewJWKSClient(httpClient *http.Client, cacheTTL time.Duration, logger *slog.Logger) *JWKSClient {
	if httpClient == nil {
		// SECURITY: Use SSRF-safe client with DNS rebinding protection
		httpClient = NewSSRFSafeHTTPClient(DefaultHTTPTimeout)
	}
	if cacheTTL == 0 {
		cacheTTL = DefaultCacheTTL
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &JWKSClient{
		httpClient:   httpClient,
		cacheTTL:     cacheTTL,
		logger:       logger,
		timeProvider: realTime{},
	}
}

// FetchJWKS fetches the JWKS from a given URI with caching.
// Uses HTTPS validation and SSRF protection for security.
//
// Security Features:
//   - SSRF Protection: Validates URI to block private IPs, loopback, and link-local addresses
//   - Response Size Limit: Limits response body to 1MB to prevent memory exhaustion
//   - Key Count Limit: Limits JWKS to 100 keys to prevent memory exhaustion
//   - Caching: Reduces attack surface by caching valid responses
func (c *JWKSClient) FetchJWKS(ctx context.Context, jwksURI string) (*JWKS, error) {
	// Check cache first
	if cached, ok := c.cache.Load(jwksURI); ok {
		doc, ok := cached.(*cachedJWKS)
		if ok && c.timeProvider.Since(doc.fetchedAt) < c.cacheTTL {
			c.logger.Debug("JWKS cache hit", "uri", jwksURI)
			return doc.keys, nil
		}
	}

	// SECURITY: Validate JWKS URI with full SSRF protection
	// This blocks private IPs, loopback, and link-local addresses
	if err := ValidateExternalURL(jwksURI, "JWKS URI"); err != nil {
		return nil, fmt.Errorf("invalid JWKS URI: %w", err)
	}

	c.logger.Debug("Fetching JWKS", "uri", jwksURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch failed with status %d", resp.StatusCode)
	}

	// SECURITY: Limit response body size to prevent memory exhaustion attacks
	// JWKS documents are typically a few KB, 1MB is a generous safety margin
	limitedBody := http.MaxBytesReader(nil, resp.Body, maxJWKSDocumentSize)
	defer func() { _ = limitedBody.Close() }()

	var jwks JWKS
	if err := json.NewDecoder(limitedBody).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// SECURITY: Limit number of keys to prevent memory exhaustion
	// No legitimate provider needs more than 100 keys
	if len(jwks.Keys) > maxJWKSKeyCount {
		return nil, fmt.Errorf("JWKS contains too many keys (%d > %d)", len(jwks.Keys), maxJWKSKeyCount)
	}

	// Cache the JWKS
	c.cache.Store(jwksURI, &cachedJWKS{
		keys:      &jwks,
		fetchedAt: c.timeProvider.Now(),
	})

	c.logger.Debug("JWKS fetched successfully", "uri", jwksURI, "key_count", len(jwks.Keys))

	return &jwks, nil
}

// GetKey retrieves a key from the JWKS by key ID.
// Returns nil if the key is not found.
func (j *JWKS) GetKey(kid string) *JWK {
	for i := range j.Keys {
		if j.Keys[i].Kid == kid {
			return &j.Keys[i]
		}
	}
	return nil
}

// PublicKey returns the appropriate public key based on the key type (RSA or EC).
// This is the preferred method for obtaining a key for signature verification.
func (j *JWK) PublicKey() (any, error) {
	switch j.Kty {
	case KeyTypeRSA:
		return j.RSAPublicKey()
	case KeyTypeEC:
		return j.ECDSAPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type: %s (supported: RSA, EC)", j.Kty)
	}
}

// RSAPublicKey converts a JWK to an RSA public key for signature verification.
// Returns an error if the key type is not RSA.
func (j *JWK) RSAPublicKey() (*rsa.PublicKey, error) {
	if j.Kty != KeyTypeRSA {
		return nil, fmt.Errorf("key type is %s, not RSA", j.Kty)
	}

	// Decode modulus (N)
	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode exponent (E)
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// ECDSAPublicKey converts a JWK to an ECDSA public key for signature verification.
// Supports P-256 (ES256), P-384 (ES384), and P-521 (ES512) curves.
// Returns an error if the key type is not EC or the curve is unsupported.
func (j *JWK) ECDSAPublicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != KeyTypeEC {
		return nil, fmt.Errorf("key type is %s, not EC", j.Kty)
	}

	// Determine the curve
	var curve elliptic.Curve
	switch j.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s (supported: P-256, P-384, P-521)", j.Crv)
	}

	// Decode X coordinate
	xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X coordinate: %w", err)
	}
	x := new(big.Int).SetBytes(xBytes)

	// Decode Y coordinate
	yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y coordinate: %w", err)
	}
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// IsJWT checks if a token string looks like a JWT (has 3 parts separated by dots).
// This is a quick syntactic check, not cryptographic validation.
func IsJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 && len(parts[2]) > 0
}

// ParseUnverifiedClaims extracts claims from a JWT without verifying the signature.
// This is useful for routing decisions (e.g., checking audience) before full validation.
// SECURITY: Never trust the claims returned from this function for authorization decisions.
func ParseUnverifiedClaims(tokenString string) (jwt.MapClaims, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	return claims, nil
}

// GetAudienceFromClaims extracts the audience claim from JWT claims.
// The audience can be a single string or an array of strings.
// Returns nil if no audience is present.
func GetAudienceFromClaims(claims jwt.MapClaims) []string {
	aud, exists := claims["aud"]
	if !exists {
		return nil
	}

	// Single string audience
	if audStr, ok := aud.(string); ok {
		return []string{audStr}
	}

	// Array of audiences
	if audSlice, ok := aud.([]interface{}); ok {
		result := make([]string, 0, len(audSlice))
		for _, a := range audSlice {
			if s, ok := a.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}

	return nil
}

// IDTokenClaims represents the standard claims in an OIDC ID token.
type IDTokenClaims struct {
	jwt.RegisteredClaims

	// Standard OIDC claims
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	GivenName     string   `json:"given_name,omitempty"`
	FamilyName    string   `json:"family_name,omitempty"`
	Picture       string   `json:"picture,omitempty"`
	Locale        string   `json:"locale,omitempty"`
	Groups        []string `json:"groups,omitempty"`
}

// ValidateIDToken validates an ID token (JWT) using the provider's JWKS.
// This is used for SSO token forwarding where ID tokens are passed as Bearer tokens.
//
// Validation includes:
//   - Signature verification using JWKS
//   - Expiration check
//   - Issuer validation (if expectedIssuer is non-empty)
//   - Audience validation (checks if any audience matches trustedAudiences)
//
// Returns the parsed claims if validation succeeds.
func ValidateIDToken(ctx context.Context, tokenString string, jwksClient *JWKSClient, jwksURI, expectedIssuer string, trustedAudiences []string) (*IDTokenClaims, error) {
	// Fetch JWKS
	jwks, err := jwksClient.FetchJWKS(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse and validate token signature
	claims, err := parseAndValidateToken(tokenString, jwks)
	if err != nil {
		return nil, err
	}

	// Validate issuer if expected
	if err := validateIssuer(claims, expectedIssuer); err != nil {
		return nil, err
	}

	// Validate audience
	if err := validateAudience(claims, trustedAudiences); err != nil {
		return nil, err
	}

	return claims, nil
}

// parseAndValidateToken parses a JWT and validates its signature using JWKS.
func parseAndValidateToken(tokenString string, jwks *JWKS) (*IDTokenClaims, error) {
	parser := jwt.NewParser(
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	claims := &IDTokenClaims{}
	keyFunc := createKeyFunc(jwks)

	token, err := parser.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return claims, nil
}

// signingMethodType represents the category of JWT signing method.
type signingMethodType int

const (
	signingMethodUnknown signingMethodType = iota
	signingMethodRSA
	signingMethodECDSA
)

// classifySigningMethod determines the signing method type from a JWT token.
// Returns signingMethodUnknown for unsupported methods (like HMAC).
//
// SECURITY: This explicitly checks the Method type (not just the "alg" header)
// to prevent algorithm confusion attacks where an attacker changes the alg
// header to HS256 and signs with the public key.
func classifySigningMethod(token *jwt.Token) signingMethodType {
	switch token.Method.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		return signingMethodRSA
	case *jwt.SigningMethodECDSA:
		return signingMethodECDSA
	default:
		return signingMethodUnknown
	}
}

// validateKeyTypeForMethod checks that the JWK key type matches the signing method.
func validateKeyTypeForMethod(methodType signingMethodType, key *JWK, alg interface{}, kid string) error {
	switch methodType {
	case signingMethodRSA:
		if key.Kty != KeyTypeRSA {
			return fmt.Errorf("algorithm %v requires RSA key, but key %s is %s", alg, kid, key.Kty)
		}
	case signingMethodECDSA:
		if key.Kty != KeyTypeEC {
			return fmt.Errorf("algorithm %v requires EC key, but key %s is %s", alg, kid, key.Kty)
		}
	}
	return nil
}

// createKeyFunc creates a jwt.Keyfunc that resolves keys from the JWKS.
//
// SECURITY: Algorithm Restrictions
//
// This function only accepts asymmetric signing algorithms (RSA and ECDSA).
// Symmetric algorithms like HS256/HS384/HS512 are explicitly rejected to prevent
// "algorithm confusion" attacks (CVE-2015-9235 and similar).
//
// In an algorithm confusion attack, an attacker could:
// 1. Take a JWT signed with RS256
// 2. Change the "alg" header to HS256
// 3. Sign the JWT using the public RSA key as the HMAC secret
// 4. The server might incorrectly verify this using the public key
//
// By explicitly checking for RSA or ECDSA signing methods (not just checking "alg"),
// we ensure the cryptographic operation matches the expected asymmetric algorithm.
//
// Supported algorithms:
//   - RSA: RS256, RS384, RS512, PS256, PS384, PS512
//   - ECDSA: ES256, ES384, ES512
func createKeyFunc(jwks *JWKS) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// SECURITY: Only allow asymmetric algorithms to prevent algorithm confusion attacks
		methodType := classifySigningMethod(token)
		if methodType == signingMethodUnknown {
			return nil, fmt.Errorf("unsupported signing method: %v (only RSA and ECDSA are allowed)", token.Header["alg"])
		}

		// Get key ID from header
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("token missing kid header")
		}

		// Find and validate the key
		key := jwks.GetKey(kid)
		if key == nil {
			return nil, fmt.Errorf("key %s not found in JWKS", kid)
		}

		if err := validateKeyTypeForMethod(methodType, key, token.Header["alg"], kid); err != nil {
			return nil, err
		}

		return key.PublicKey()
	}
}

// validateIssuer checks the token issuer matches the expected issuer.
func validateIssuer(claims *IDTokenClaims, expectedIssuer string) error {
	if expectedIssuer == "" {
		return nil
	}
	if claims.Issuer != expectedIssuer {
		return fmt.Errorf("issuer mismatch: got %q, expected %q", claims.Issuer, expectedIssuer)
	}
	return nil
}

// validateAudience checks that at least one token audience matches a trusted audience.
// Uses URL normalization to handle trailing slashes and constant-time comparison for security.
// This is consistent with findMatchingTrustedAudience in server/flows_sso.go.
func validateAudience(claims *IDTokenClaims, trustedAudiences []string) error {
	if len(trustedAudiences) == 0 {
		return nil
	}

	for _, tokenAud := range claims.Audience {
		normalizedTokenAud := helpers.NormalizeURL(tokenAud)
		for _, trusted := range trustedAudiences {
			normalizedTrusted := helpers.NormalizeURL(trusted)
			// Use constant-time comparison for defense-in-depth
			if subtle.ConstantTimeCompare([]byte(normalizedTokenAud), []byte(normalizedTrusted)) == 1 {
				return nil
			}
		}
	}

	return fmt.Errorf("audience mismatch: token audiences %v not in trusted %v", claims.Audience, trustedAudiences)
}

// ClearCache clears the JWKS cache.
func (c *JWKSClient) ClearCache() {
	c.cache.Range(func(key, _ any) bool {
		c.cache.Delete(key)
		return true
	})
	c.logger.Debug("JWKS cache cleared")
}
