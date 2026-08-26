// Package dex implements the OAuth provider interface for Dex (https://dexidp.io/).
// It supports OIDC authentication with Dex-specific optimizations including connector_id
// support for bypassing the connector selection UI and proper handling of refresh token rotation.
package dex

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// Provider implements the providers.Provider interface for Dex OAuth.
// It uses OIDC discovery to fetch endpoints dynamically and supports Dex-specific
// features like connector_id parameter and groups claim.
type Provider struct {
	*oauth2.Config
	discoveryClient *oidc.DiscoveryClient
	issuerURL       string
	connectorID     string
	httpClient      *http.Client
	requestTimeout  time.Duration
	maxGroups       int
	logger          *slog.Logger

	// audienceResolver is Config.AudienceResolver. Nil means only the static
	// Scopes set applies.
	audienceResolver func() []string

	// scopeFilter reports whether a scope reaches the IdP. Nil forwards every
	// scope.
	scopeFilter func(string) bool

	// audienceScopesEnabled reports whether cross-client audience scopes reach
	// the IdP. False also turns off audienceResolver.
	audienceScopesEnabled bool

	// warnedAudiences memoises the audiences warnRejectedAudiences has already
	// logged, so a malformed value cannot flood the log from the per-request
	// path. warnedAudienceCount bounds that memo.
	warnedAudiences     sync.Map
	warnedAudienceCount atomic.Int64
}

// Config holds Dex OAuth configuration
type Config struct {
	// IssuerURL is the Dex issuer URL (e.g., https://dex.example.com)
	IssuerURL string

	// ClientID is the OAuth client ID
	ClientID string

	// ClientSecret is the OAuth client secret
	ClientSecret string

	// RedirectURL is the OAuth redirect URL
	RedirectURL string

	// ConnectorID is the optional Dex connector to use (e.g., "github", "ldap")
	// When set, bypasses the Dex connector selection UI
	ConnectorID string

	// Scopes are optional custom scopes (defaults to Dex-optimized scopes if empty)
	// Default: ["openid", "profile", "email", "groups", "offline_access"]
	//
	// This is the set the provider requests when the client asks for none, and
	// the set mandatory-scope merging draws from. DefaultScopes returns the
	// default value. An IdP that rejects one of the defaults (Keycloak has no
	// groups scope unless an operator adds one) needs a set configured here.
	Scopes []string

	// AllowedScopes replaces the scopes the provider forwards to the IdP. Every
	// other scope is dropped from the authorization request, silently, because
	// an IdP that rejects one unknown scope rejects the whole request.
	//
	// Empty uses DefaultAllowedScopes: the standard OIDC scopes plus the
	// Dex-only groups and federated:id. "openid" is always allowed, whatever
	// this list holds. Cross-client audience scopes are governed by
	// DisableCrossClientAudienceScopes, not by this list.
	//
	// Set this for an IdP whose scope vocabulary differs from Dex's, for
	// example Keycloak realm scopes (roles, organization) or Entra ID
	// application scopes.
	AllowedScopes []string

	// DisableScopeFilter forwards every requested scope to the IdP unchanged,
	// so no allowlist applies. Use it when the caller already restricts the
	// scopes it accepts and the IdP vocabulary is not known in advance.
	// NewProvider rejects it together with AllowedScopes, because one of the
	// two would have no effect.
	//
	// Cross-client audience scopes are still dropped when
	// DisableCrossClientAudienceScopes is set.
	DisableScopeFilter bool

	// DisableCrossClientAudienceScopes stops the provider from sending Dex
	// cross-client audience scopes (AudienceScopePrefix). It drops them from
	// Scopes, from every requested set, and it turns off AudienceResolver.
	//
	// Set it for any issuer that is not Dex. The scope shape is a Dex
	// extension: Keycloak and Entra ID reject the whole authorization request
	// when they receive one.
	DisableCrossClientAudienceScopes bool

	// AudienceResolver reports the Dex cross-client audiences to request, as
	// plain client IDs. The provider merges one AudienceScopePrefix scope per
	// audience into both DefaultScopes() and AuthorizationURL(), so an audience
	// that the caller learns about after startup still reaches the next login.
	// Nil keeps the static Scopes set.
	//
	// Prefer this over audience scopes in Scopes whenever the audience set is
	// not known at construction time, for example when it comes from Kubernetes
	// resources that reconcile after the process starts.
	//
	// The provider calls it from request goroutines, so it must be safe for
	// concurrent use. It can also run more than once for a single authorization
	// request, because both DefaultScopes() and AuthorizationURL() consult it,
	// and it takes no context: read cached state and return, do not block on a
	// network call. Duplicates cost nothing, and invalid audiences are skipped
	// and logged once each, so one bad value costs only its own scope.
	//
	// DisableCrossClientAudienceScopes turns the resolver off: the provider
	// never calls it and no audience scope reaches the IdP.
	//
	// The merged set stays within oidc.MaxScopeCount. An audience that does not
	// fit is skipped and logged.
	//
	// A server that restricts scopes must list the resulting audience scopes in
	// its supported-scopes configuration, because DefaultScopes() feeds that
	// allowlist.
	AudienceResolver func() []string

	// HTTPClient is an optional custom HTTP client
	HTTPClient *http.Client

	// RequestTimeout is the timeout for provider API calls (default: 30s)
	RequestTimeout time.Duration

	// MaxGroups is the maximum number of groups to accept from the OIDC groups claim.
	// Groups beyond this limit are truncated (not rejected) and a warning is logged.
	// Default: oidc.DefaultMaxGroups (600). Set higher for enterprise environments
	// with very large group counts (e.g., Active Directory).
	MaxGroups int

	// Logger is an optional structured logger for operational warnings (e.g., group truncation).
	// Default: slog.Default()
	Logger *slog.Logger

	// AllowPrivateIP allows the Dex issuer URL to resolve to a private or
	// loopback IP address during OIDC discovery and token endpoint calls. Required
	// when Dex is fronted by an internal-only load balancer (e.g. Azure internal LB,
	// air-gapped clusters) where the public hostname resolves to an RFC 1918 address.
	// Emits a startup warning when set.
	//
	// Note: IP-literal private addresses in IssuerURL (e.g. https://10.0.0.1) are
	// still rejected by URL validation regardless of this flag. This flag only lifts
	// the transport-level SSRF check for hostnames that resolve to private IPs at
	// connection time.
	//
	// WARNING: Reduces SSRF protection. Only enable for private IdP deployments.
	AllowPrivateIP bool

	// RootCAs is the CA pool used to verify Dex's TLS certificate during OIDC
	// discovery and token endpoint calls when AllowPrivateIP is set and no
	// explicit HTTPClient is provided (e.g. an internal-CA Dex). nil uses the
	// system pool.
	RootCAs *x509.CertPool

	// discoveryClient overrides the OIDC discovery client. Nil means
	// NewProvider constructs one from the other config fields. Same-package
	// tests use this to inject a client pointed at a loopback httptest server.
	discoveryClient *oidc.DiscoveryClient
}

// NewProvider creates a new Dex OAuth provider.
// It performs OIDC discovery to fetch authorization and token endpoints.
func NewProvider(cfg *Config) (*Provider, error) {
	if err := validateRequiredConfig(cfg); err != nil {
		return nil, err
	}

	scopes, err := resolveScopes(cfg.Scopes)
	if err != nil {
		return nil, err
	}

	audienceScopesEnabled := !cfg.DisableCrossClientAudienceScopes

	scopeFilter, err := newScopeFilter(cfg.AllowedScopes, cfg.DisableScopeFilter, audienceScopesEnabled)
	if err != nil {
		return nil, err
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	requestTimeout := resolveTimeout(cfg.RequestTimeout)
	httpClient := resolveHTTPClient(cfg.HTTPClient, cfg.AllowPrivateIP, cfg.RootCAs, requestTimeout)
	if cfg.AllowPrivateIP {
		logger.Warn("SECURITY WARNING: AllowPrivateIP is enabled for Dex OIDC discovery and token endpoints",
			"risk", "OIDC discovery and token endpoints can resolve to private/internal IP addresses — SSRF possible",
			"recommendation", "Only enable when the IdP is behind an internal-only load balancer; ensure the issuer URL is not attacker-controlled",
			"cwe", "CWE-918",
		)
	}
	discoveryClient := resolveDiscoveryClient(cfg.discoveryClient, httpClient, logger)

	doc, err := performOIDCDiscovery(discoveryClient, cfg.IssuerURL, requestTimeout)
	if err != nil {
		return nil, err
	}

	maxGroups := cfg.MaxGroups
	if maxGroups <= 0 {
		maxGroups = oidc.DefaultMaxGroups
	}

	return &Provider{
		Config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  doc.AuthorizationEndpoint,
				TokenURL: doc.TokenEndpoint,
			},
		},
		discoveryClient: discoveryClient,
		issuerURL:       cfg.IssuerURL,
		connectorID:     cfg.ConnectorID,
		httpClient:      httpClient,
		requestTimeout:  requestTimeout,
		maxGroups:       maxGroups,
		logger:          logger,

		audienceResolver:      cfg.AudienceResolver,
		scopeFilter:           scopeFilter,
		audienceScopesEnabled: audienceScopesEnabled,
	}, nil
}

// validateRequiredConfig validates required configuration fields.
func validateRequiredConfig(cfg *Config) error {
	if cfg.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if cfg.ClientSecret == "" {
		return fmt.Errorf("client secret is required")
	}
	if cfg.IssuerURL == "" {
		return fmt.Errorf("issuer URL is required")
	}

	// SECURITY: Validate issuer URL with SSRF protection.
	// When a discovery client is injected (tests only), skip URL validation:
	// the injected client is already bound to a trusted server.
	if cfg.discoveryClient == nil {
		if err := oidc.ValidateIssuerURL(cfg.IssuerURL); err != nil {
			return fmt.Errorf("invalid issuer URL: %w", err)
		}
	}

	// SECURITY: Validate connector_id if provided
	if cfg.ConnectorID != "" {
		if err := oidc.ValidateConnectorID(cfg.ConnectorID); err != nil {
			return fmt.Errorf("invalid connector ID: %w", err)
		}
	}

	return nil
}

// scopeOpenID is the OpenID Connect scope required by Dex per the OIDC spec.
const scopeOpenID = "openid"

// defaultDexScopes are the default scopes for Dex providers.
var defaultDexScopes = []string{
	scopeOpenID,
	"profile",
	"email",
	"groups",         // Dex-specific: required for group membership
	"offline_access", // Required for refresh tokens
}

// defaultAllowedScopes are the scopes the provider forwards when
// Config.AllowedScopes is empty: the standard OIDC scopes plus the Dex-only
// groups and federated:id.
var defaultAllowedScopes = []string{
	scopeOpenID,
	"profile",
	"email",
	"offline_access",
	"groups",
	"federated:id",
}

// DefaultScopes returns the scopes NewProvider requests when Config.Scopes is
// empty. Use it to build a custom set on top of the defaults.
//
// Provider.DefaultScopes returns what one provider actually requests, which
// includes any cross-client audience scope.
func DefaultScopes() []string {
	return providers.CloneScopes(defaultDexScopes)
}

// DefaultAllowedScopes returns the scope allowlist the provider applies when
// Config.AllowedScopes is empty. Use it to extend the defaults instead of
// replacing them.
func DefaultAllowedScopes() []string {
	return providers.CloneScopes(defaultAllowedScopes)
}

// newScopeFilter builds the predicate AuthorizationURL applies to the merged
// scope set. A nil predicate forwards every scope.
//
// "openid" always passes, whatever allowedScopes holds: OIDC requires it on
// every authorization request.
func newScopeFilter(allowedScopes []string, disableFilter bool, audienceScopesEnabled bool) (func(string) bool, error) {
	if err := oidc.ValidateScopes(allowedScopes); err != nil {
		return nil, fmt.Errorf("invalid allowed scopes: %w", err)
	}
	if disableFilter && len(allowedScopes) > 0 {
		return nil, fmt.Errorf("AllowedScopes and DisableScopeFilter are mutually exclusive")
	}

	if disableFilter {
		if audienceScopesEnabled {
			return nil, nil
		}
		return func(scope string) bool {
			return !strings.HasPrefix(scope, AudienceScopePrefix)
		}, nil
	}

	if len(allowedScopes) == 0 {
		allowedScopes = defaultAllowedScopes
	}
	allowed := make(map[string]struct{}, len(allowedScopes))
	for _, scope := range allowedScopes {
		allowed[scope] = struct{}{}
	}

	return func(scope string) bool {
		if scope == scopeOpenID {
			return true
		}
		if strings.HasPrefix(scope, AudienceScopePrefix) {
			return audienceScopesEnabled
		}
		_, ok := allowed[scope]
		return ok
	}, nil
}

// resolveScopes returns validated scopes, using defaults if none provided.
func resolveScopes(configScopes []string) ([]string, error) {
	scopes := configScopes
	if len(scopes) == 0 {
		scopes = defaultDexScopes
	}

	if err := oidc.ValidateScopes(scopes); err != nil {
		return nil, fmt.Errorf("invalid scopes: %w", err)
	}

	return scopes, nil
}

// resolveTimeout returns the timeout, using default if not set.
func resolveTimeout(timeout time.Duration) time.Duration {
	if timeout == 0 {
		return 30 * time.Second
	}
	return timeout
}

// resolveHTTPClient returns the HTTP client to use for Dex API calls and OIDC
// discovery. When allowPrivateIP is true and no explicit client is provided, a
// client without SSRF protection is returned so that Dex issuer URLs resolving
// to RFC 1918 addresses (e.g. internal load balancers) are reachable.
func resolveHTTPClient(client *http.Client, allowPrivateIP bool, rootCAs *x509.CertPool, timeout time.Duration) *http.Client {
	if client != nil {
		return client
	}
	if allowPrivateIP {
		return oidc.NewPrivateIPAllowedHTTPClient(timeout, rootCAs)
	}
	return &http.Client{Timeout: timeout}
}

// resolveDiscoveryClient returns override when non-nil, otherwise constructs a
// production discovery client from httpClient.
func resolveDiscoveryClient(override *oidc.DiscoveryClient, httpClient *http.Client, logger *slog.Logger) *oidc.DiscoveryClient {
	if override != nil {
		return override
	}
	return oidc.NewDiscoveryClient(httpClient, 1*time.Hour, logger)
}

// performOIDCDiscovery performs OIDC discovery to fetch endpoints.
func performOIDCDiscovery(client *oidc.DiscoveryClient, issuerURL string, timeout time.Duration) (*oidc.DiscoveryDocument, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	doc, err := client.Discover(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	return doc, nil
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "dex"
}

// DefaultScopes returns a deep copy of the provider's configured default
// scopes so callers cannot mutate the provider's slice. When
// Config.AudienceResolver is set, the cross-client audience scopes it reports
// are merged in, so the result can differ between calls.
//
// This calls the resolver, which logs any audience it skips.
func (p *Provider) DefaultScopes() []string {
	return p.effectiveScopes()
}

// effectiveScopes returns the configured scopes plus one cross-client audience
// scope per audience that Config.AudienceResolver reports. The result is always
// a fresh slice, so callers cannot mutate the provider's own.
//
// The merged set stays within oidc.MaxScopeCount, the bound NewProvider
// enforces on the configured set, so the resolver cannot grow an authorization
// request past what the constructor would accept. Audiences that do not fit are
// reported as rejected.
//
// Config.DisableCrossClientAudienceScopes drops every audience scope instead,
// the configured ones included, and the resolver never runs.
func (p *Provider) effectiveScopes() []string {
	scopes := providers.CloneScopes(p.Scopes)
	if !p.audienceScopesEnabled {
		return withoutAudienceScopes(scopes)
	}
	if p.audienceResolver == nil {
		return scopes
	}

	audiences := p.audienceResolver()
	if len(audiences) == 0 {
		return scopes
	}

	present := make(map[string]struct{}, len(scopes)+len(audiences))
	for _, scope := range scopes {
		present[scope] = struct{}{}
	}

	audienceScopes, rejected := partitionAudienceScopes(
		audiences,
		min(MaxAudienceCount, oidc.MaxScopeCount-len(scopes)),
		present,
	)
	p.warnRejectedAudiences(rejected)

	return append(scopes, audienceScopes...)
}

// withoutAudienceScopes returns scopes with every cross-client audience scope
// removed. It filters in place, so the caller must pass a slice it owns.
func withoutAudienceScopes(scopes []string) []string {
	kept := scopes[:0]
	for _, scope := range scopes {
		if !strings.HasPrefix(scope, AudienceScopePrefix) {
			kept = append(kept, scope)
		}
	}
	return kept
}

// maxWarnedAudiences bounds the warnedAudiences memo. A resolver that returns
// changing invalid values stops producing warnings at this point instead of
// growing the memo without bound.
const maxWarnedAudiences = 64

// maxLoggedAudienceLength caps the audience value in a log line. A rejected
// audience can be arbitrarily long: length is one of the reasons to reject an
// audience, and partitionAudienceScopes rejects an over-budget audience without
// validating it at all.
const maxLoggedAudienceLength = 64

// warnRejectedAudiences logs each rejected audience once. The resolver runs on
// every authorization request, so an unconditional log would let one malformed
// value flood the log.
func (p *Provider) warnRejectedAudiences(rejected []audienceRejection) {
	for _, rejection := range rejected {
		if p.warnedAudienceCount.Load() >= maxWarnedAudiences {
			return
		}
		if _, loaded := p.warnedAudiences.LoadOrStore(rejection.Audience, struct{}{}); loaded {
			continue
		}
		p.warnedAudienceCount.Add(1)

		p.logger.Warn("Skipping invalid cross-client audience reported by AudienceResolver",
			"audience", truncateAudienceForLog(rejection.Audience),
			"reason", rejection.Reason)
	}
}

// truncateAudienceForLog shortens an audience to maxLoggedAudienceLength and
// marks the result when it cut something off.
func truncateAudienceForLog(audience string) string {
	if len(audience) <= maxLoggedAudienceLength {
		return audience
	}
	return audience[:maxLoggedAudienceLength] + "...(truncated)"
}

// AuthorizationURL generates the Dex OAuth authorization URL with PKCE support.
// If connector_id is configured, it appends the parameter to bypass Dex's connector selection UI.
// If scopes is empty, the provider's default configured scopes are used.
// opts contains optional OIDC parameters like prompt, login_hint, max_age (nil for defaults).
func (p *Provider) AuthorizationURL(state string, codeChallenge string, codeChallengeMethod string, scopes []string, authOpts *providers.AuthorizationURLOptions) string {
	var authCodeOpts []oauth2.AuthCodeOption

	// Add PKCE parameters if provided
	if codeChallenge != "" && codeChallengeMethod != "" {
		authCodeOpts = append(
			authCodeOpts,
			oauth2.SetAuthURLParam("code_challenge", codeChallenge),
			oauth2.SetAuthURLParam("code_challenge_method", codeChallengeMethod),
		)
	}

	// Add connector_id parameter if configured (Dex-specific feature)
	// This bypasses the Dex connector selection screen
	if p.connectorID != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("connector_id", p.connectorID))
	}

	// Apply optional OIDC parameters (Dex supports standard OIDC params)
	authCodeOpts = append(authCodeOpts, providers.ApplyAuthorizationURLOptions(authOpts)...)

	// FilterScopes drops scopes the IdP would reject ("Unrecognized scope(s)"),
	// deep-copies the input, and force-merges mandatory scopes (openid,
	// audience:server:client_id:*) from defaults via CopyScopes internally.
	// The defaults come from effectiveScopes, not from the Scopes field, so an
	// audience that Config.AudienceResolver reports after startup is merged too.
	// A nil p.scopeFilter forwards every merged scope.
	scopesToUse := providers.FilterScopes(scopes, p.effectiveScopes(), p.scopeFilter)

	// Create a config with the determined scopes
	config := *p.Config
	config.Scopes = scopesToUse
	return config.AuthCodeURL(state, authCodeOpts...)
}

// ensureOpenIDScope guarantees that "openid" is present in the scope list.
// This is defense-in-depth for OIDC compliance: Dex requires "openid" per spec,
// and this ensures it is always included even if both the client and provider
// defaults somehow omit it.
func ensureOpenIDScope(scopes []string) []string {
	for _, s := range scopes {
		if s == scopeOpenID {
			return scopes
		}
	}
	return append(scopes, scopeOpenID)
}

// ExchangeCode exchanges an authorization code for tokens with PKCE verification.
// Returns standard oauth2.Token.
func (p *Provider) ExchangeCode(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	return providers.ExchangeCodeWithPKCE(ctx, p, p.httpClient, code, verifier)
}

// ValidateToken validates an access token by calling Dex's userinfo endpoint.
// It parses user information including groups claim if available.
func (p *Provider) ValidateToken(ctx context.Context, accessToken string) (*providers.UserInfo, error) {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	// Get discovery document to find userinfo endpoint
	doc, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	if doc.UserInfoEndpoint == "" {
		return nil, fmt.Errorf("userinfo endpoint not available in discovery document")
	}

	// Use custom HTTP client for tests (trusts test TLS certificates)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	// Create HTTP client with the token
	token := &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	}
	client := p.Client(ctx, token)

	// Call Dex's userinfo endpoint
	resp, err := client.Get(doc.UserInfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	// Parse Dex's user info response
	var dexUserInfo struct {
		Sub           string   `json:"sub"`
		Email         string   `json:"email"`
		EmailVerified bool     `json:"email_verified"`
		Name          string   `json:"name"`
		GivenName     string   `json:"given_name"`
		FamilyName    string   `json:"family_name"`
		Picture       string   `json:"picture"`
		Locale        string   `json:"locale"`
		Groups        []string `json:"groups"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&dexUserInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	groups := dexUserInfo.Groups
	if len(groups) > 0 {
		validated, truncated, err := oidc.ValidateGroups(groups, p.maxGroups)
		if err != nil {
			return nil, fmt.Errorf("invalid groups claim: %w", err)
		}
		if truncated {
			p.logger.Warn(
				"groups claim truncated for user",
				"user_id", dexUserInfo.Sub,
				"original_count", len(groups),
				"limit", p.maxGroups,
			)
		}
		groups = validated
	}

	return &providers.UserInfo{
		ID:            dexUserInfo.Sub,
		Email:         dexUserInfo.Email,
		EmailVerified: dexUserInfo.EmailVerified,
		Name:          dexUserInfo.Name,
		GivenName:     dexUserInfo.GivenName,
		FamilyName:    dexUserInfo.FamilyName,
		Picture:       dexUserInfo.Picture,
		Locale:        dexUserInfo.Locale,
		Groups:        groups,
	}, nil
}

// RefreshToken refreshes an expired token using a refresh token.
// CRITICAL: Dex implements refresh token rotation - it returns a NEW refresh token
// on every refresh operation. The oauth2 library automatically captures this new token.
// Returns standard oauth2.Token with the new refresh token.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	// Use custom HTTP client
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	// Create token source from refresh token
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	tokenSource := p.TokenSource(ctx, token)

	// Get fresh token - this automatically handles Dex's refresh token rotation
	// The oauth2 library captures the new refresh token from the response
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	// CRITICAL: newToken.RefreshToken contains the NEW refresh token from Dex
	// The server layer will store this new token, replacing the old one
	return newToken, nil
}

// RevokeToken revokes a token at Dex's revocation endpoint if available.
// Gracefully degrades if revocation endpoint is not supported.
func (p *Provider) RevokeToken(ctx context.Context, token string) error {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	doc, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return fmt.Errorf("OIDC discovery failed: %w", err)
	}
	if doc.RevocationEndpoint == "" {
		// Spec-compliant gracefully-degraded path: some OIDC providers don't
		// support revocation.
		return nil
	}
	return oidc.RevokeAtEndpoint(ctx, p.httpClient, doc.RevocationEndpoint, token, p.ClientID, p.ClientSecret)
}

// HealthCheck verifies that the Dex OIDC discovery endpoint is reachable.
// It performs a lightweight check by fetching the OpenID Connect discovery document.
//
// Security Considerations:
//   - This method is designed for server-side health monitoring (k8s probes, monitoring systems)
//   - DO NOT expose the returned error messages directly to untrusted clients
//   - Error messages may contain HTTP status codes that could leak provider state information
//   - For public health endpoints, return generic "healthy/unhealthy" status only
func (p *Provider) HealthCheck(ctx context.Context) error {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	// Attempt to fetch discovery document
	_, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return fmt.Errorf("dex provider unreachable: %w", err)
	}

	return nil
}

// JWKSURI returns the JWKS URI for Dex from the discovery document.
// This implements the JWKSProvider interface for SSO token forwarding.
func (p *Provider) JWKSURI(ctx context.Context) (string, error) {
	ctx, cancel := providers.EnsureTimeout(ctx, p.requestTimeout)
	defer cancel()

	doc, err := p.discoveryClient.Discover(ctx, p.issuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to discover JWKS URI: %w", err)
	}

	return doc.JWKSUri, nil
}

// IssuerURL returns the Dex issuer URL for JWT validation.
func (p *Provider) IssuerURL() string {
	return p.issuerURL
}
