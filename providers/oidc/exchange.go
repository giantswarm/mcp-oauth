package oidc

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// RFC 8693 OAuth 2.0 Token Exchange constants.
// These are standard URN identifiers defined in RFC 8693, not credentials.
const (
	// GrantTypeTokenExchange is the RFC 8693 grant type for token exchange.
	// #nosec G101 -- This is an RFC-defined URN identifier, not a credential.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

	// TokenTypeIDToken is the token type URN for ID tokens.
	// #nosec G101 -- This is an RFC-defined URN identifier, not a credential.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"

	// TokenTypeAccessToken is the token type URN for access tokens.
	// #nosec G101 -- This is an RFC-defined URN identifier, not a credential.
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// TokenTypeRefreshToken is the token type URN for refresh tokens.
	// #nosec G101 -- This is an RFC-defined URN identifier, not a credential.
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"

	// TokenTypeJWT is the token type URN for JWT tokens.
	// #nosec G101 -- This is an RFC-defined URN identifier, not a credential.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"

	// maxTokenExchangeResponseSize is the maximum allowed size for a token exchange response.
	// Token responses are typically small (<10KB). 1MB provides a generous safety margin
	// while preventing memory exhaustion attacks from malicious servers.
	maxTokenExchangeResponseSize = 1024 * 1024 // 1MB

	// maxResourceLength is the maximum length for the resource parameter (RFC 3986 recommended).
	// This prevents DoS attacks via extremely long URIs.
	maxResourceLength = 2048

	// maxSubjectTokenLength is the maximum allowed length for the subject token.
	// JWTs are typically 1-4KB, but can be larger with many claims. 64KB is generous
	// while preventing abuse via extremely large tokens.
	maxSubjectTokenLength = 64 * 1024 // 64KB
)

// TokenExchangeClient performs RFC 8693 OAuth 2.0 Token Exchange operations.
// It enables cross-cluster SSO scenarios where each cluster has its own Identity Provider
// (e.g., separate Dex instances).
//
// The client is thread-safe and can be used concurrently from multiple goroutines.
//
// # Security Features
//
//   - SSRF protection via URL validation (unless AllowPrivateIP is enabled)
//   - HTTPS enforcement for token endpoints
//   - Response size limiting to prevent memory exhaustion
//   - Subject token size limiting (64KB max)
//   - Structured logging for security monitoring
//
// # Rate Limiting
//
// This client does not implement rate limiting internally. For production deployments,
// callers SHOULD implement rate limiting to prevent abuse, especially when the token
// exchange endpoint is exposed to user-controlled input. Consider using:
//
//   - Per-user rate limits to prevent individual users from overwhelming the IdP
//   - Global rate limits to protect against coordinated attacks
//   - The [github.com/giantswarm/mcp-oauth/providers/tokencache.Cache] to reduce redundant exchange requests
//
// # Example Usage
//
//	client := oidc.NewTokenExchangeClient(nil)
//	resp, err := client.Exchange(ctx, oidc.TokenExchangeRequest{
//	    TokenEndpoint:    "https://dex.cluster-b.example.com/token",
//	    SubjectToken:     userIDToken,
//	    SubjectTokenType: oidc.TokenTypeIDToken,
//	    ConnectorID:      "cluster-a-dex",
//	    Scope:            "openid profile email groups",
//	})
//	if err != nil {
//	    return err
//	}
//	// Use resp.AccessToken for requests to Cluster B
type TokenExchangeClient struct {
	httpClient     *http.Client
	logger         *slog.Logger
	allowPrivateIP bool
}

// TokenExchangeClientOptions contains optional configuration for TokenExchangeClient.
type TokenExchangeClientOptions struct {
	// HTTPClient is the HTTP client to use for requests.
	// If nil, an appropriate client is created based on AllowPrivateIP setting.
	HTTPClient *http.Client

	// Logger is the logger for debug/info messages (nil uses default logger).
	Logger *slog.Logger

	// AllowPrivateIP allows token endpoints to resolve to private IP addresses.
	// WARNING: Reduces SSRF protection. Only enable for internal/VPN deployments
	// where the IdP legitimately runs on private networks.
	AllowPrivateIP bool

	// RootCAs is the CA pool used to verify the token endpoint's TLS certificate
	// (e.g. an internal-CA Dex). It applies with or without AllowPrivateIP. The
	// pool replaces the system roots rather than extending them. nil uses the
	// system pool. Ignored when HTTPClient is provided.
	RootCAs *x509.CertPool
}

// TokenExchangeRequest represents the token exchange request parameters.
type TokenExchangeRequest struct {
	// TokenEndpoint is the remote IdP's token endpoint URL.
	// Required. Must use HTTPS.
	TokenEndpoint string

	// SubjectToken is the original token to exchange.
	// Required.
	SubjectToken string

	// SubjectTokenType is the type of the subject token.
	// Use TokenTypeIDToken or TokenTypeAccessToken.
	// Defaults to TokenTypeIDToken if not specified.
	SubjectTokenType string

	// ConnectorID is the connector ID on the remote IdP that validates this token.
	// For Dex, this is passed via the "connector_id" parameter.
	// Required.
	ConnectorID string

	// Scope is the requested scope for the new token (optional).
	Scope string

	// RequestedTokenType is the type of token to receive (optional).
	// Defaults to access_token if not specified by the server.
	RequestedTokenType string

	// ClientID for client authentication (optional, for confidential clients).
	ClientID string

	// ClientSecret for client authentication (optional, for confidential clients).
	ClientSecret string

	// Audience is the intended audience of the new token (optional).
	// RFC 8693 Section 2.1: This is the logical name of the target service.
	Audience string

	// Resource is the absolute URI of the target resource (optional).
	// RFC 8693 Section 2.1: Indicates the location of the target service.
	Resource string
}

// TokenExchangeResponse represents the token exchange response.
type TokenExchangeResponse struct {
	// AccessToken is the security token issued by the authorization server.
	AccessToken string `json:"access_token"`

	// IssuedTokenType is the type of token issued (e.g., access_token, id_token).
	IssuedTokenType string `json:"issued_token_type"`

	// TokenType is the token type (typically "Bearer").
	TokenType string `json:"token_type"`

	// ExpiresIn is the lifetime in seconds of the access token.
	ExpiresIn int `json:"expires_in,omitempty"`

	// Scope is the scope of the access token.
	Scope string `json:"scope,omitempty"`

	// RefreshToken is a refresh token (optional).
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenExchangeErrorResponse represents an OAuth 2.0 error response.
type TokenExchangeErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// NewTokenExchangeClient creates a new token exchange client with default configuration.
//
// Parameters:
//   - logger: Logger for debug/info messages (nil uses default logger)
//
// Security Features:
//   - DNS Rebinding Protection: Validates resolved IPs at connection time
//   - SSRF Protection: Blocks private, loopback, and link-local addresses
//   - TLS Verification: Uses default TLS settings
func NewTokenExchangeClient(logger *slog.Logger) *TokenExchangeClient {
	return NewTokenExchangeClientWithOptions(TokenExchangeClientOptions{
		Logger:         logger,
		AllowPrivateIP: false,
	})
}

// NewTokenExchangeClientWithOptions creates a new token exchange client with configurable options.
// This allows fine-grained control over SSRF protection for private IdP deployments.
//
// When AllowPrivateIP is true:
//   - SSRF protection is disabled (private, loopback, and link-local IPs are allowed)
//   - HTTPS is still enforced
//   - A warning is logged about reduced security
//
// Example:
//
//	client := NewTokenExchangeClientWithOptions(TokenExchangeClientOptions{
//	    AllowPrivateIP: true,  // For internal Dex
//	    Logger:         logger,
//	})
func NewTokenExchangeClientWithOptions(opts TokenExchangeClientOptions) *TokenExchangeClient {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		if opts.AllowPrivateIP {
			// Use client without SSRF protection for private IdP deployments
			httpClient = NewPrivateIPAllowedHTTPClient(DefaultHTTPTimeout, opts.RootCAs)
		} else {
			// SECURITY: Use SSRF-safe client with DNS rebinding protection
			httpClient = NewSSRFSafeHTTPClient(DefaultHTTPTimeout, opts.RootCAs)
		}
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if opts.AllowPrivateIP {
		logger.Warn("Token exchange client created with AllowPrivateIP=true, SSRF protection is disabled")
	}

	return &TokenExchangeClient{
		httpClient:     httpClient,
		logger:         logger,
		allowPrivateIP: opts.AllowPrivateIP,
	}
}

// Exchange performs the RFC 8693 token exchange operation.
//
// This method exchanges a subject token from one Identity Provider for a token
// from another Identity Provider. This is useful for cross-cluster SSO scenarios
// where each cluster has its own Dex instance.
//
// Security Features:
//   - SSRF Protection: Validates token endpoint URL (unless AllowPrivateIP is enabled)
//   - HTTPS Enforcement: Always requires HTTPS
//   - Response Size Limit: Limits response body to 1MB
//   - Audit Logging: Logs exchange operations for security monitoring
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Token exchange request parameters
//
// Returns:
//   - TokenExchangeResponse with the new token if successful
//   - Error if validation fails, network error occurs, or server returns an error
func (c *TokenExchangeClient) Exchange(ctx context.Context, req TokenExchangeRequest) (*TokenExchangeResponse, error) {
	// Validate required fields
	if err := c.validateRequest(&req); err != nil {
		return nil, err
	}

	// SECURITY: Validate token endpoint URL
	if err := c.validateTokenEndpoint(req.TokenEndpoint); err != nil {
		return nil, err
	}

	// Build form data
	form := c.buildFormData(&req)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add client authentication if provided.
	//
	// RFC 6749 §2.3.1 requires the client identifier and secret to be encoded
	// using application/x-www-form-urlencoded *before* they are combined into
	// the HTTP Basic credential. Go's http.Request.SetBasicAuth does not do
	// this encoding, so a secret containing characters that the form encoding
	// alters (notably "+", which decodes back to a space) would be corrupted on
	// the wire and rejected by spec-compliant servers (e.g. Dex) with
	// "invalid_client". Pre-encode both components to comply with the RFC.
	if req.ClientID != "" && req.ClientSecret != "" {
		httpReq.SetBasicAuth(url.QueryEscape(req.ClientID), url.QueryEscape(req.ClientSecret))
	}

	// Execute request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}

	// SECURITY: Limit response body size to prevent memory exhaustion attacks.
	// MaxBytesReader wraps the original body, so closing it also closes resp.Body.
	limitedBody := http.MaxBytesReader(nil, resp.Body, maxTokenExchangeResponseSize)
	defer func() { _ = limitedBody.Close() }()

	body, err := io.ReadAll(limitedBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read token exchange response: %w", err)
	}

	// Handle error responses
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp.StatusCode, body)
	}

	// Parse success response
	var exchangeResp TokenExchangeResponse
	if err := json.Unmarshal(body, &exchangeResp); err != nil {
		return nil, fmt.Errorf("failed to parse token exchange response: %w", err)
	}

	// Validate response
	if exchangeResp.AccessToken == "" {
		return nil, fmt.Errorf("token exchange response missing access_token")
	}

	c.logger.Debug(
		"Token exchange successful",
		"token_endpoint", req.TokenEndpoint,
		"connector_id", req.ConnectorID,
		"issued_token_type", exchangeResp.IssuedTokenType,
		"expires_in", exchangeResp.ExpiresIn,
	)

	return &exchangeResp, nil
}

// validateRequest validates the token exchange request parameters.
func (c *TokenExchangeClient) validateRequest(req *TokenExchangeRequest) error {
	if req.TokenEndpoint == "" {
		return fmt.Errorf("token endpoint is required")
	}
	if req.SubjectToken == "" {
		return fmt.Errorf("subject token is required")
	}
	// SECURITY: Prevent DoS via extremely large subject tokens
	if len(req.SubjectToken) > maxSubjectTokenLength {
		return fmt.Errorf("subject token exceeds maximum length of %d bytes", maxSubjectTokenLength)
	}
	if req.ConnectorID == "" {
		return fmt.Errorf("connector ID is required")
	}

	// Validate connector ID format
	if err := ValidateConnectorID(req.ConnectorID); err != nil {
		return fmt.Errorf("invalid connector ID: %w", err)
	}

	// Validate Resource parameter if provided (RFC 8693 Section 2.1)
	if req.Resource != "" {
		if err := validateResourceParameter(req.Resource); err != nil {
			return fmt.Errorf("invalid resource parameter: %w", err)
		}
	}

	// Default subject token type if not specified
	if req.SubjectTokenType == "" {
		req.SubjectTokenType = TokenTypeIDToken
	}

	return nil
}

// validateResourceParameter validates the resource parameter per RFC 8693.
// The resource must be an absolute URI (RFC 3986) and should use HTTPS.
func validateResourceParameter(resource string) error {
	// Check length to prevent DoS
	if len(resource) > maxResourceLength {
		return fmt.Errorf("resource exceeds maximum length of %d characters", maxResourceLength)
	}

	// Parse as URL
	u, err := url.Parse(resource)
	if err != nil {
		return fmt.Errorf("resource must be a valid URI: %w", err)
	}

	// Must be absolute URI (has scheme)
	if !u.IsAbs() {
		return fmt.Errorf("resource must be an absolute URI")
	}

	// Should use HTTPS (or HTTP for localhost development)
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("resource must use HTTP or HTTPS scheme")
	}

	return nil
}

// validateTokenEndpoint validates the token endpoint URL for security.
func (c *TokenExchangeClient) validateTokenEndpoint(tokenEndpoint string) error {
	if c.allowPrivateIP {
		// When private IPs are allowed, only validate HTTPS (skip IP checks)
		if err := ValidateHTTPSURL(tokenEndpoint, "token endpoint"); err != nil {
			c.logger.Warn("Token endpoint HTTPS validation failed",
				"url", tokenEndpoint,
				"error", err.Error())
			return fmt.Errorf("invalid token endpoint: %w", err)
		}
		c.logger.Debug("Validating token endpoint with private IP allowance",
			"url", tokenEndpoint,
			"allow_private_ip", true)
	} else {
		// SECURITY: Validate with full SSRF protection
		if err := ValidateExternalURL(tokenEndpoint, "token endpoint"); err != nil {
			// Log at Warn level for security monitoring (potential SSRF attempt)
			c.logger.Warn("Token endpoint validation failed (potential SSRF attempt)",
				"url", tokenEndpoint,
				"error", err.Error())
			return fmt.Errorf("invalid token endpoint: %w", err)
		}
	}
	return nil
}

// buildFormData builds the URL-encoded form data for the token exchange request.
func (c *TokenExchangeClient) buildFormData(req *TokenExchangeRequest) url.Values {
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", req.SubjectToken)
	form.Set("subject_token_type", req.SubjectTokenType)
	form.Set("connector_id", req.ConnectorID) // Dex-specific parameter

	if req.Scope != "" {
		form.Set("scope", req.Scope)
	}
	if req.RequestedTokenType != "" {
		form.Set("requested_token_type", req.RequestedTokenType)
	}
	if req.Audience != "" {
		form.Set("audience", req.Audience)
	}
	if req.Resource != "" {
		form.Set("resource", req.Resource)
	}

	return form
}

// parseErrorResponse parses an OAuth 2.0 error response.
func (c *TokenExchangeClient) parseErrorResponse(statusCode int, body []byte) error {
	var oauthErr TokenExchangeErrorResponse
	if err := json.Unmarshal(body, &oauthErr); err == nil && oauthErr.Error != "" {
		if oauthErr.ErrorDescription != "" {
			return fmt.Errorf("token exchange failed: %s - %s", oauthErr.Error, oauthErr.ErrorDescription)
		}
		return fmt.Errorf("token exchange failed: %s", oauthErr.Error)
	}
	return fmt.Errorf("token exchange failed with status %d: %s", statusCode, string(body))
}
