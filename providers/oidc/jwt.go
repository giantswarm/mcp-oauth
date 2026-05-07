// Package oidc provides OIDC (OpenID Connect) utilities for OAuth providers.
package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/giantswarm/mcp-oauth/internal/helpers"
)

// JWKSClient fetches and caches JWKS (JSON Web Key Sets) for JWT validation.
// It provides SSRF protection and caches keys with configurable TTL.
//
// The client is thread-safe and can be used concurrently from multiple goroutines.
type JWKSClient struct {
	httpClient     *http.Client
	cache          sync.Map // jwksURI -> *cachedJWKS
	cacheTTL       time.Duration
	logger         *slog.Logger
	timeProvider   timeProvider
	allowPrivateIP bool // When true, SSRF protection is disabled for private IdP deployments
}

// cachedJWKS holds a JWKS with its fetch timestamp.
type cachedJWKS struct {
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
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
)

// supportedSignatureAlgorithms is the closed set of asymmetric algorithms
// accepted for ID-token signature verification. HMAC variants and "none" are
// absent by design — accepting them would enable algorithm-confusion attacks
// where an attacker who knows the public key signs with HS256 using the public
// key bytes as the secret. The set is enforced by jose.ParseSigned, which
// rejects any token whose alg header is not in the list.
var supportedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
}

// JWKSClientOptions contains optional configuration for JWKSClient.
type JWKSClientOptions struct {
	// HTTPClient is the HTTP client to use for requests.
	// If nil, an appropriate client is created based on AllowPrivateIP setting.
	HTTPClient *http.Client

	// CacheTTL is the time-to-live for cached JWKS (0 uses default 1 hour).
	CacheTTL time.Duration

	// Logger is the logger for debug/info messages (nil uses default logger).
	Logger *slog.Logger

	// AllowPrivateIP allows JWKS endpoints to resolve to private IP addresses.
	// WARNING: Reduces SSRF protection. Only enable for internal/VPN deployments
	// where the IdP legitimately runs on private networks.
	AllowPrivateIP bool
}

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
	return NewJWKSClientWithOptions(JWKSClientOptions{
		HTTPClient:     httpClient,
		CacheTTL:       cacheTTL,
		Logger:         logger,
		AllowPrivateIP: false,
	})
}

// NewJWKSClientWithOptions creates a new JWKS client with configurable options.
// This allows fine-grained control over SSRF protection for private IdP deployments.
//
// When AllowPrivateIP is true:
//   - SSRF protection is disabled (private, loopback, and link-local IPs are allowed)
//   - HTTPS is still enforced
//   - A warning is logged about reduced security
//
// Security Features:
//   - TLS Verification: Uses default TLS settings (no InsecureSkipVerify)
//   - Response Size Limit: Limits response body to 1MB
//   - Key Count Limit: Limits JWKS to 100 keys
//
// Example:
//
//	client := NewJWKSClientWithOptions(JWKSClientOptions{
//	    AllowPrivateIP: true,  // For internal Dex
//	    Logger:         logger,
//	})
func NewJWKSClientWithOptions(opts JWKSClientOptions) *JWKSClient {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		if opts.AllowPrivateIP {
			httpClient = NewPrivateIPAllowedHTTPClient(DefaultHTTPTimeout)
		} else {
			httpClient = NewSSRFSafeHTTPClient(DefaultHTTPTimeout)
		}
	}

	cacheTTL := opts.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = DefaultCacheTTL
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &JWKSClient{
		httpClient:     httpClient,
		cacheTTL:       cacheTTL,
		logger:         logger,
		timeProvider:   realTime{},
		allowPrivateIP: opts.AllowPrivateIP,
	}
}

// FetchJWKS fetches the JWKS from a given URI with caching.
// Uses HTTPS validation and SSRF protection for security.
//
// Security Features:
//   - SSRF Protection: Validates URI to block private IPs, loopback, and link-local addresses
//     (unless AllowPrivateIP is enabled for private IdP deployments)
//   - HTTPS Enforcement: Always requires HTTPS (even with AllowPrivateIP)
//   - Response Size Limit: Limits response body to 1MB to prevent memory exhaustion
//   - Key Count Limit: Limits JWKS to 100 keys to prevent memory exhaustion
//   - Caching: Reduces attack surface by caching valid responses
func (c *JWKSClient) FetchJWKS(ctx context.Context, jwksURI string) (*jose.JSONWebKeySet, error) {
	logger := c.logger
	if logger == nil {
		logger = slog.Default()
	}

	if cached, ok := c.cache.Load(jwksURI); ok {
		doc, ok := cached.(*cachedJWKS)
		if ok && c.timeProvider.Since(doc.fetchedAt) < c.cacheTTL {
			logger.Debug("JWKS cache hit", "uri", jwksURI)
			return doc.keys, nil
		}
	}

	if c.allowPrivateIP {
		if err := ValidateHTTPSURL(jwksURI, "JWKS URI"); err != nil {
			return nil, fmt.Errorf("invalid JWKS URI: %w", err)
		}
		logger.Debug("Fetching JWKS with private IP allowance",
			"uri", jwksURI,
			"allow_private_ip", true)
	} else {
		if err := ValidateExternalURL(jwksURI, "JWKS URI"); err != nil {
			return nil, fmt.Errorf("invalid JWKS URI: %w", err)
		}
		logger.Debug("Fetching JWKS", "uri", jwksURI)
	}

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

	limitedBody := http.MaxBytesReader(nil, resp.Body, maxJWKSDocumentSize)
	defer func() { _ = limitedBody.Close() }()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(limitedBody).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	if len(jwks.Keys) > maxJWKSKeyCount {
		return nil, fmt.Errorf("JWKS contains too many keys (%d > %d)", len(jwks.Keys), maxJWKSKeyCount)
	}

	c.cache.Store(jwksURI, &cachedJWKS{
		keys:      &jwks,
		fetchedAt: c.timeProvider.Now(),
	})

	logger.Debug("JWKS fetched successfully", "uri", jwksURI, "key_count", len(jwks.Keys))

	return &jwks, nil
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
func ParseUnverifiedClaims(tokenString string) (map[string]any, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("not a JWT: expected 3 non-empty segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT claims: %w", err)
	}
	return claims, nil
}

// GetAudienceFromClaims extracts the audience claim from JWT claims.
// The audience can be a single string or an array of strings.
// Returns nil if no audience is present.
func GetAudienceFromClaims(claims map[string]any) []string {
	aud, ok := claims["aud"]
	if !ok {
		return nil
	}

	if audStr, ok := aud.(string); ok {
		if audStr == "" {
			return nil
		}
		return []string{audStr}
	}

	if audSlice, ok := aud.([]any); ok {
		result := make([]string, 0, len(audSlice))
		for _, a := range audSlice {
			if s, ok := a.(string); ok && s != "" {
				result = append(result, s)
			}
		}
		return result
	}

	return nil
}

// IDTokenClaims represents the standard claims in an OIDC ID token. The
// embedded josejwt.Claims carries the registered claims (iss, sub, aud, exp,
// nbf, iat, jti); the additional fields are OIDC-specific extensions defined
// by OpenID Connect Core 1.0 §5.1.
type IDTokenClaims struct {
	josejwt.Claims

	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	GivenName     string   `json:"given_name,omitempty"`
	FamilyName    string   `json:"family_name,omitempty"`
	Picture       string   `json:"picture,omitempty"`
	Locale        string   `json:"locale,omitempty"`
	Groups        []string `json:"groups,omitempty"`
}

// ErrIssuerMismatch is returned (wrapped) when a JWT's iss claim does not match
// the expected issuer.
var ErrIssuerMismatch = errors.New("issuer mismatch")

// ErrTokenExpired is returned (wrapped) when a JWT's exp claim is in the past
// beyond the configured leeway. Wraps the underlying go-jose sentinel so
// errors.Is against either this or josejwt.ErrExpired works.
var ErrTokenExpired = errors.New("token expired")

// ErrTokenNotValidYet is returned (wrapped) when a JWT's nbf claim is in the
// future beyond the configured leeway.
var ErrTokenNotValidYet = errors.New("token not valid yet")

// ValidateIDToken validates an ID token (JWT) using the provider's JWKS.
// This is used for SSO token forwarding where ID tokens are passed as Bearer tokens.
//
// Validation includes:
//   - Signature verification using JWKS (alg pinned to the supported asymmetric set)
//   - Expiration check (exp claim, required)
//   - Not-before check (nbf claim, validated if present)
//   - Issued-at validation (iat claim, validated if present)
//   - Clock skew tolerance (DefaultClockSkewLeeway = 30 seconds)
//   - Issuer validation (if expectedIssuer is non-empty)
//   - Audience validation (checks if any audience matches trustedAudiences)
//
// Returns the parsed claims if validation succeeds.
func ValidateIDToken(ctx context.Context, tokenString string, jwksClient *JWKSClient, jwksURI, expectedIssuer string, trustedAudiences []string) (*IDTokenClaims, error) {
	jwks, err := jwksClient.FetchJWKS(ctx, jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	claims, err := parseAndValidateToken(tokenString, jwks)
	if err != nil {
		return nil, err
	}

	if err := validateTimeAndIssuer(claims, expectedIssuer); err != nil {
		return nil, err
	}

	if err := validateAudience(claims, trustedAudiences); err != nil {
		return nil, err
	}

	return claims, nil
}

// parseAndValidateToken parses a JWT, locates the matching key from the JWKS
// by kid, and verifies the signature. The jose.ParseSigned algorithm allowlist
// rejects HMAC and "none" before the keyfunc is consulted, blocking
// algorithm-confusion attacks at parse time.
func parseAndValidateToken(tokenString string, jwks *jose.JSONWebKeySet) (*IDTokenClaims, error) {
	parsed, err := josejwt.ParseSigned(tokenString, supportedSignatureAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if len(parsed.Headers) == 0 {
		return nil, fmt.Errorf("token has no signature headers")
	}
	kid := parsed.Headers[0].KeyID
	if kid == "" {
		return nil, fmt.Errorf("token missing kid header")
	}
	keys := jwks.Key(kid)
	if len(keys) == 0 {
		return nil, fmt.Errorf("key %s not found in JWKS", kid)
	}

	var claims IDTokenClaims
	if err := parsed.Claims(keys[0].Key, &claims); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims.Expiry == nil {
		return nil, fmt.Errorf("token validation failed: missing required exp claim")
	}

	return &claims, nil
}

// validateTimeAndIssuer enforces exp/nbf/iat with leeway and the optional
// issuer match. go-jose returns its own sentinels; we wrap them so callers
// using errors.Is against ErrTokenExpired / ErrTokenNotValidYet /
// ErrIssuerMismatch see consistent results regardless of upstream message
// changes.
func validateTimeAndIssuer(claims *IDTokenClaims, expectedIssuer string) error {
	expected := josejwt.Expected{Time: time.Now()}
	if expectedIssuer != "" {
		expected.Issuer = expectedIssuer
	}

	err := claims.Claims.ValidateWithLeeway(expected, DefaultClockSkewLeeway)
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, josejwt.ErrInvalidIssuer):
		return fmt.Errorf("%w: got %q, expected %q", ErrIssuerMismatch, claims.Issuer, expectedIssuer)
	case errors.Is(err, josejwt.ErrExpired):
		return fmt.Errorf("%w: %v", ErrTokenExpired, err)
	case errors.Is(err, josejwt.ErrNotValidYet):
		return fmt.Errorf("%w: %v", ErrTokenNotValidYet, err)
	default:
		return fmt.Errorf("token validation failed: %w", err)
	}
}

// validateAudience checks that at least one token audience matches a trusted
// audience. Uses helpers.FindMatchingAudience for URL normalization and
// constant-time comparison, matching the SSO and self-issued JWT branches.
func validateAudience(claims *IDTokenClaims, trustedAudiences []string) error {
	if len(trustedAudiences) == 0 {
		return nil
	}

	if helpers.FindMatchingAudience([]string(claims.Audience), trustedAudiences) != "" {
		return nil
	}

	return fmt.Errorf("audience mismatch: token audiences %v not in trusted %v", []string(claims.Audience), trustedAudiences)
}

// ClearCache clears the JWKS cache.
func (c *JWKSClient) ClearCache() {
	c.cache.Range(func(key, _ any) bool {
		c.cache.Delete(key)
		return true
	})
	c.logger.Debug("JWKS cache cleared")
}
