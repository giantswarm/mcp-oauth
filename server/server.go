package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// SessionCreationHandler is called synchronously when a new token family is
// created during authorization code exchange. Consumers can use this to
// initialize per-session state (e.g., establish SSO connections).
//
// The provided context is the HTTP request context of the token exchange and
// may be canceled when the request completes. If the handler performs slow
// initialization, it should derive a new context with its own deadline.
//
// The handler is only invoked when the token store supports refresh token
// family tracking (implements [storage.RefreshTokenFamilyStore]). If the store
// does not support families, the handler is silently skipped.
//
// Parameters:
//   - ctx: the HTTP request context of the token exchange
//   - userID: the authenticated user's identifier
//   - familyID: the newly created token family ID (used as session ID)
//   - token: the issued OAuth token (contains id_token in Extra for OIDC flows)
type SessionCreationHandler func(ctx context.Context, userID, familyID string, token *oauth2.Token)

// SessionRevocationHandler is called when a token family is revoked (e.g., on logout).
// Consumers can use this to clean up per-session state associated with the family ID.
//
// The provided context is the HTTP request context that triggered the revocation and
// may be canceled when the request completes. If the handler performs slow cleanup
// operations, it should derive a new context with its own deadline.
type SessionRevocationHandler func(ctx context.Context, userID, familyID string)

// TokenRefreshHandler is called synchronously after a provider token is
// refreshed, either proactively (near-expiry) or reactively (expired token
// during validation). Consumers can use this to update downstream caches
// (e.g., ID token caches for SSO forwarding) without a separate polling layer.
//
// The provided context is the HTTP request context that triggered the refresh.
// If the handler performs slow operations, it should derive a new context with
// its own deadline.
//
// Parameters:
//   - ctx: the HTTP request context that triggered the refresh
//   - userID: the authenticated user's identifier
//   - familyID: the token family ID (session ID); empty if the store does not support families
//   - newToken: the freshly obtained provider token (contains id_token in Extra for OIDC flows)
type TokenRefreshHandler func(ctx context.Context, userID, familyID string, newToken *oauth2.Token)

// TokenFamilyRevocationHandler is the old name for SessionRevocationHandler.
//
// Deprecated: Use SessionRevocationHandler instead.
type TokenFamilyRevocationHandler = SessionRevocationHandler

// Server implements the OAuth 2.1 server logic (provider-agnostic).
// It coordinates the OAuth flow using a Provider and storage backends.
type Server struct {
	provider                      providers.Provider
	tokenStore                    storage.TokenStore
	clientStore                   storage.ClientStore
	flowStore                     storage.FlowStore
	sessionCreationHandler        SessionCreationHandler
	sessionRevocationHandler      SessionRevocationHandler
	tokenRefreshHandler           TokenRefreshHandler
	Encryptor                     *security.Encryptor
	Auditor                       *security.Auditor
	RateLimiter                   *security.RateLimiter                   // IP-based rate limiter
	UserRateLimiter               *security.RateLimiter                   // User-based rate limiter (authenticated requests)
	SecurityEventRateLimiter      *security.RateLimiter                   // Rate limiter for security event logging (DoS prevention)
	ClientRegistrationRateLimiter *security.ClientRegistrationRateLimiter // Time-windowed rate limiter for client registrations
	Instrumentation               *instrumentation.Instrumentation        // OpenTelemetry instrumentation
	tracer                        trace.Tracer                            // OpenTelemetry tracer for server operations
	metadataCache                 *clientMetadataCache                    // Cache for URL-based client metadata (MCP 2025-11-25)
	metadataFetchGroup            singleflight.Group                      // Deduplicates concurrent metadata fetches (DoS protection)
	metadataFetchRateLimiter      *security.RateLimiter                   // Per-domain rate limiter for metadata fetches
	metadataCacheCleanupCtx       context.Context                         // Context for metadata cache cleanup goroutine
	metadataCacheCleanupCancel    context.CancelFunc                      // Cancel function for cleanup goroutine
	jwksClient                    *oidc.JWKSClient                        // JWKS client for SSO token forwarding validation
	jwksClientOnce                sync.Once                               // Ensures JWKS client is initialized only once
	tokenPairs                    sync.Map                                // Maps client access token -> client refresh token for paired updates
	tokenPairsByRefresh           sync.Map                                // Maps client refresh token -> client access token for pair cleanup
	refreshGroup                  singleflight.Group                      // Deduplicates concurrent provider token refreshes per access token
	Logger                        *slog.Logger
	Config                        *Config
	shutdownOnce                  sync.Once // Ensures Shutdown is called only once
}

// NewWithCombined is an additive constructor for backends that implement the
// [storage.Combined] interface (both memory and valkey do). It avoids the
// awkward call site where the same *Store value is passed three times to [New]
// because TokenStore/ClientStore/FlowStore are separate parameters:
//
//	// Old:
//	srv, err := server.New(provider, store, store, store, cfg, logger)
//
//	// New:
//	srv, err := server.NewWithCombined(provider, store, cfg, logger)
//
// [New] is unchanged so callers that split persistence across different
// backing stores (e.g. Postgres tokens + memory flows) keep working.
func NewWithCombined(
	provider providers.Provider,
	store storage.Combined,
	config *Config,
	logger *slog.Logger,
) (*Server, error) {
	// Delegate to New with the same value in all three slots. The embedded
	// interfaces guarantee the method sets match.
	return New(provider, store, store, store, config, logger)
}

// New creates a new OAuth server
func New(
	provider providers.Provider,
	tokenStore storage.TokenStore,
	clientStore storage.ClientStore,
	flowStore storage.FlowStore,
	config *Config,
	logger *slog.Logger,
) (*Server, error) {
	if err := validateServerDependencies(provider, tokenStore, clientStore, flowStore); err != nil {
		return nil, err
	}

	config, logger = applyDefaults(config, logger)

	// Create cleanup context for background goroutines
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())

	srv := &Server{
		provider:                   provider,
		tokenStore:                 tokenStore,
		clientStore:                clientStore,
		flowStore:                  flowStore,
		Config:                     config,
		Logger:                     logger,
		metadataCache:              newClientMetadataCache(config.ClientMetadataCacheTTL, 1000),
		metadataCacheCleanupCtx:    cleanupCtx,
		metadataCacheCleanupCancel: cleanupCancel,
	}

	if err := srv.validateHTTPSEnforcement(); err != nil {
		return nil, err
	}

	configureStorageRetention(tokenStore, config)
	srv.initializeInstrumentation(tokenStore, clientStore, flowStore)
	srv.initializeMetadataSupport()
	srv.validateProviderDefaultScopes(logger)

	return srv, nil
}

// validateServerDependencies checks that all required dependencies are provided.
func validateServerDependencies(provider providers.Provider, tokenStore storage.TokenStore, clientStore storage.ClientStore, flowStore storage.FlowStore) error {
	if provider == nil {
		return fmt.Errorf("provider is required")
	}
	if tokenStore == nil {
		return fmt.Errorf("token store is required")
	}
	if clientStore == nil {
		return fmt.Errorf("client store is required")
	}
	if flowStore == nil {
		return fmt.Errorf("flow store is required")
	}
	return nil
}

// applyDefaults applies default values for config and logger, then applies secure defaults.
func applyDefaults(config *Config, logger *slog.Logger) (*Config, *slog.Logger) {
	if config == nil {
		config = &Config{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return applySecureDefaults(config, logger), logger
}

// configureStorageRetention sets retention days on storage if it supports it.
func configureStorageRetention(tokenStore storage.TokenStore, config *Config) {
	type retentionSetter interface {
		SetRevokedFamilyRetentionDays(days int64)
	}
	if setter, ok := tokenStore.(retentionSetter); ok {
		setter.SetRevokedFamilyRetentionDays(config.RevokedFamilyRetentionDays)
	}
}

// initializeInstrumentation sets up OpenTelemetry instrumentation if enabled.
func (s *Server) initializeInstrumentation(tokenStore storage.TokenStore, clientStore storage.ClientStore, flowStore storage.FlowStore) {
	if !s.Config.Instrumentation.Enabled {
		return
	}

	instConfig := buildInstrumentationConfig(s.Config.Instrumentation)
	inst, err := instrumentation.New(instConfig)
	if err != nil {
		s.Logger.Warn("Failed to initialize instrumentation, continuing without it", "error", err)
		return
	}

	s.Instrumentation = inst
	s.tracer = inst.Tracer("server")
	propagateInstrumentation(inst, tokenStore, clientStore, flowStore)

	s.Logger.Info("Instrumentation initialized",
		"service_name", instConfig.ServiceName,
		"service_version", instConfig.ServiceVersion)
}

// buildInstrumentationConfig creates an instrumentation config with defaults.
func buildInstrumentationConfig(cfg InstrumentationConfig) instrumentation.Config {
	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "mcp-oauth"
	}
	serviceVersion := cfg.ServiceVersion
	if serviceVersion == "" {
		serviceVersion = "unknown"
	}

	return instrumentation.Config{
		Enabled:                  true,
		ServiceName:              serviceName,
		ServiceVersion:           serviceVersion,
		LogClientIPs:             cfg.LogClientIPs,
		IncludeClientIDInMetrics: cfg.IncludeClientIDInMetrics,
		MetricsExporter:          cfg.MetricsExporter,
		TracesExporter:           cfg.TracesExporter,
		OTLPEndpoint:             cfg.OTLPEndpoint,
		OTLPInsecure:             cfg.OTLPInsecure,
	}
}

// propagateInstrumentation propagates instrumentation to storage layers that support it.
func propagateInstrumentation(inst *instrumentation.Instrumentation, tokenStore storage.TokenStore, clientStore storage.ClientStore, flowStore storage.FlowStore) {
	type instrumentationSetter interface {
		SetInstrumentation(*instrumentation.Instrumentation)
	}
	if setter, ok := tokenStore.(instrumentationSetter); ok {
		setter.SetInstrumentation(inst)
	}
	if setter, ok := clientStore.(instrumentationSetter); ok {
		setter.SetInstrumentation(inst)
	}
	if setter, ok := flowStore.(instrumentationSetter); ok {
		setter.SetInstrumentation(inst)
	}
}

// initializeMetadataSupport initializes client ID metadata document support if enabled.
func (s *Server) initializeMetadataSupport() {
	if !s.Config.EnableClientIDMetadataDocuments {
		return
	}

	// SECURITY: Initialize rate limiter for metadata fetches (10 req/min per domain)
	s.metadataFetchRateLimiter = security.NewRateLimiter(10, 20, s.Logger)
	s.Logger.Info("Initialized metadata fetch rate limiter",
		"rate", "10 requests/min per domain",
		"burst", 20,
		"purpose", "DoS protection")

	// SECURITY WARNING: Log when SSRF protection is relaxed for internal networks
	if s.Config.AllowPrivateIPClientMetadata {
		s.Logger.Warn("SSRF protection reduced: AllowPrivateIPClientMetadata is enabled",
			"config", "AllowPrivateIPClientMetadata=true",
			"warning", "Client metadata can be fetched from private/internal IP addresses",
			"allowed_ranges", "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1, link-local")
	}

	// SECURITY WARNING: Log when SSRF protection is relaxed for JWKS endpoints
	if s.Config.AllowPrivateIPJWKS {
		s.Logger.Warn("SSRF protection reduced: AllowPrivateIPJWKS is enabled",
			"config", "AllowPrivateIPJWKS=true",
			"warning", "JWKS endpoints can resolve to private/internal IP addresses",
			"use_case", "Private IdP deployments (e.g., internal Dex)",
			"allowed_ranges", "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, ::1, link-local")
	}

	go s.metadataCacheCleanupLoop()
	s.Logger.Debug("Started metadata cache cleanup goroutine")
}

// validateProviderDefaultScopes checks if provider default scopes are supported by server configuration.
// This is a startup-time sanity check to catch configuration mismatches early.
// Logs warnings for any provider defaults that aren't in the server's supported scopes list.
// Also logs informational messages about mandatory audience scopes that will be auto-merged.
func (s *Server) validateProviderDefaultScopes(logger *slog.Logger) {
	providerDefaults := s.provider.DefaultScopes()

	// Log mandatory audience scopes (these will be auto-merged into all requests)
	// This helps administrators understand which audiences will always be included in tokens
	s.logMandatoryAudienceScopes(logger, providerDefaults)

	// Skip validation if no supported scopes configured (allow-all mode)
	if len(s.Config.SupportedScopes) == 0 {
		return
	}

	if len(providerDefaults) == 0 {
		return
	}

	// Build a set of supported scopes for efficient lookup
	supportedSet := make(map[string]bool, len(s.Config.SupportedScopes))
	for _, scope := range s.Config.SupportedScopes {
		supportedSet[scope] = true
	}

	// Check each provider default scope
	for _, scope := range providerDefaults {
		if !supportedSet[scope] {
			logger.Warn("Provider default scope not in server supported scopes - clients relying on defaults may encounter errors",
				"scope", scope,
				"provider", s.provider.Name(),
				"supported_scopes", s.Config.SupportedScopes)
		}
	}
}

// logMandatoryAudienceScopes logs information about cross-client audience scopes
// configured in provider defaults. These scopes are automatically merged into ALL
// authorization requests to support SSO token forwarding scenarios.
func (s *Server) logMandatoryAudienceScopes(logger *slog.Logger, providerDefaults []string) {
	var audienceScopes []string
	for _, scope := range providerDefaults {
		if isAudienceScope(scope) {
			audienceScopes = append(audienceScopes, scope)
		}
	}

	if len(audienceScopes) > 0 {
		logger.Info("Mandatory cross-client audience scopes configured - these will be merged into ALL authorization requests",
			"audience_scopes", audienceScopes,
			"provider", s.provider.Name(),
			"count", len(audienceScopes))
	}
}

// isAudienceScope checks if a scope is a Dex cross-client audience scope.
func isAudienceScope(scope string) bool {
	return len(scope) > len(providers.CrossClientAudienceScopePrefix) &&
		scope[:len(providers.CrossClientAudienceScopePrefix)] == providers.CrossClientAudienceScopePrefix
}

// SetEncryptor sets the token encryptor for server and storage
func (s *Server) SetEncryptor(enc *security.Encryptor) {
	s.Encryptor = enc

	// Also set encryptor on storage if it's a memory store
	type encryptorSetter interface {
		SetEncryptor(*security.Encryptor)
	}
	if setter, ok := s.tokenStore.(encryptorSetter); ok {
		setter.SetEncryptor(enc)
	}
}

// SetAuditor sets the security auditor
func (s *Server) SetAuditor(aud *security.Auditor) {
	s.Auditor = aud
}

// SetRateLimiter sets the IP-based rate limiter
func (s *Server) SetRateLimiter(rl *security.RateLimiter) {
	s.RateLimiter = rl
}

// SetUserRateLimiter sets the user-based rate limiter for authenticated requests
func (s *Server) SetUserRateLimiter(rl *security.RateLimiter) {
	s.UserRateLimiter = rl
}

// SetSecurityEventRateLimiter sets the rate limiter for security event logging
// This prevents DoS attacks via log flooding from repeated security events
func (s *Server) SetSecurityEventRateLimiter(rl *security.RateLimiter) {
	s.SecurityEventRateLimiter = rl
}

// SetClientRegistrationRateLimiter sets the time-windowed rate limiter for client registrations
// This prevents resource exhaustion through repeated registration/deletion cycles
func (s *Server) SetClientRegistrationRateLimiter(rl *security.ClientRegistrationRateLimiter) {
	s.ClientRegistrationRateLimiter = rl
}

// SetMetadataFetchRateLimiter sets the per-domain rate limiter for Client ID Metadata Document fetches
// This prevents abuse and DoS attacks via repeated metadata fetches from different URLs
// Recommended: 10 requests per minute per domain
func (s *Server) SetMetadataFetchRateLimiter(rl *security.RateLimiter) {
	s.metadataFetchRateLimiter = rl
}

// SetSessionCreationHandler sets a callback that fires synchronously when a new
// token family is created during authorization code exchange. This lets consumers
// initialize per-session state (e.g., establish SSO connections to downstream servers).
// Must be called during server initialization, before the server starts handling requests.
//
// The handler is only invoked when the token store implements
// [storage.RefreshTokenFamilyStore]. A warning is logged at registration time
// if the current store does not support families.
func (s *Server) SetSessionCreationHandler(handler SessionCreationHandler) {
	s.sessionCreationHandler = handler
	if handler != nil {
		if _, ok := s.tokenStore.(storage.RefreshTokenFamilyStore); !ok {
			s.Logger.Warn("SessionCreationHandler registered but token store does not support refresh token families -- handler will never fire")
		}
	}
}

// SetSessionRevocationHandler sets a callback that fires when a token family is
// revoked (e.g., on logout). This lets consumers clean up per-session state.
// Must be called during server initialization, before the server starts handling requests.
func (s *Server) SetSessionRevocationHandler(handler SessionRevocationHandler) {
	s.sessionRevocationHandler = handler
}

// SetTokenRefreshHandler sets a callback that fires synchronously after a
// provider token is refreshed (proactively near expiry, or reactively when
// an expired token is encountered during validation). This lets consumers
// react to refresh events immediately, eliminating the need for separate
// ID token caching layers.
// Must be called during server initialization, before the server starts handling requests.
//
// The handler always fires on refresh events. However, userID and familyID
// are only populated when the token store implements
// [storage.TokenMetadataGetter]. A warning is logged at registration time
// if the current store does not support metadata lookups.
func (s *Server) SetTokenRefreshHandler(handler TokenRefreshHandler) {
	s.tokenRefreshHandler = handler
	if handler != nil {
		if _, ok := s.tokenStore.(storage.TokenMetadataGetter); !ok {
			s.Logger.Warn("TokenRefreshHandler registered but token store does not support TokenMetadataGetter -- handler will not receive userID/familyID")
		}
	}
}

// SetTokenFamilyRevocationHandler is the old name for SetSessionRevocationHandler.
//
// Deprecated: Use SetSessionRevocationHandler instead.
func (s *Server) SetTokenFamilyRevocationHandler(handler TokenFamilyRevocationHandler) {
	s.SetSessionRevocationHandler(handler)
}

// SetInstrumentation sets the OpenTelemetry instrumentation for server and storage
func (s *Server) SetInstrumentation(inst *instrumentation.Instrumentation) {
	s.Instrumentation = inst
	if inst != nil {
		s.tracer = inst.Tracer("server")

		// Also set instrumentation on storage if it supports it
		type instrumentationSetter interface {
			SetInstrumentation(*instrumentation.Instrumentation)
		}
		if setter, ok := s.tokenStore.(instrumentationSetter); ok {
			setter.SetInstrumentation(inst)
		}
		if setter, ok := s.clientStore.(instrumentationSetter); ok {
			setter.SetInstrumentation(inst)
		}
		if setter, ok := s.flowStore.(instrumentationSetter); ok {
			setter.SetInstrumentation(inst)
		}
	}
}

// TokenStore returns the token store used by the server.
// This allows the handler to access token metadata for scope validation.
func (s *Server) TokenStore() storage.TokenStore {
	return s.tokenStore
}

// tokenMetadataParams bundles the parameters for saveTokenMetadata to avoid
// a long positional-string parameter list that is easy to misorder.
type tokenMetadataParams struct {
	TokenID   string
	UserID    string
	ClientID  string
	TokenType string
	Audience  string
	FamilyID  string
	Scopes    []string
}

// saveTokenMetadata saves token metadata using the most capable store method available.
// It tries methods in order of capability:
// 1. SaveTokenMetadataWithFamily (newest - includes family ID, scopes, and audience)
// 2. SaveTokenMetadataWithScopesAndAudience (includes scopes and audience)
// 3. SaveTokenMetadataWithAudience (includes audience only)
// 4. SaveTokenMetadata (basic - no audience or scopes)
//
// This ensures backward compatibility with stores that don't support the newest methods.
func (s *Server) saveTokenMetadata(p tokenMetadataParams) {
	if store, ok := s.tokenStore.(storage.TokenMetadataStoreWithFamily); ok {
		if err := store.SaveTokenMetadataWithFamily(p.TokenID, p.UserID, p.ClientID, p.TokenType, p.Audience, p.FamilyID, p.Scopes); err != nil {
			s.Logger.Warn("Failed to save token metadata with family", "error", err)
		}
		return
	}

	if store, ok := s.tokenStore.(storage.TokenMetadataStoreWithScopesAndAudience); ok {
		if err := store.SaveTokenMetadataWithScopesAndAudience(p.TokenID, p.UserID, p.ClientID, p.TokenType, p.Audience, p.Scopes); err != nil {
			s.Logger.Warn("Failed to save token metadata with scopes and audience", "error", err)
		}
		return
	}

	if store, ok := s.tokenStore.(storage.TokenMetadataStoreWithAudience); ok {
		if err := store.SaveTokenMetadataWithAudience(p.TokenID, p.UserID, p.ClientID, p.TokenType, p.Audience); err != nil {
			s.Logger.Warn("Failed to save token metadata with audience", "error", err)
		}
		return
	}

	if store, ok := s.tokenStore.(storage.TokenMetadataStore); ok {
		if err := store.SaveTokenMetadata(p.TokenID, p.UserID, p.ClientID, p.TokenType); err != nil {
			s.Logger.Warn("Failed to save token metadata", "error", err)
		}
	}
}

const (
	// MinTokenBytes is the minimum number of random bytes required for secure tokens.
	// 32 bytes = 256 bits of entropy, which exceeds NIST recommendations for
	// cryptographic keys and is sufficient to prevent brute-force attacks.
	// Base64url encoding without padding produces 43 characters from 32 bytes.
	MinTokenBytes = 32
)

// generateRandomToken generates a cryptographically secure random token.
// It uses crypto/rand to generate 32 bytes (256 bits) of entropy and
// encodes them as a 43-character base64url string without padding.
//
// This function is used for all security-critical tokens:
//   - Authorization codes, access tokens, refresh tokens
//   - Token family IDs (for refresh token rotation)
//   - Provider state values (CSRF protection)
//   - Client IDs and secrets
//
// The function panics if the system's random number generator fails,
// which indicates a critical system-level security failure.
func generateRandomToken() string {
	b := make([]byte, MinTokenBytes)
	if _, err := rand.Read(b); err != nil {
		// CRITICAL: System RNG failure - cannot generate secure tokens
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// generatePKCEPair generates a PKCE challenge and verifier pair per RFC 7636.
// Returns S256 challenge and the corresponding verifier (43 chars each).
// Used for server-to-provider code binding. See SECURITY_ARCHITECTURE.md.
func generatePKCEPair() (challenge, verifier string) {
	verifier = generateRandomToken()
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return challenge, verifier
}

// ExtractIDToken extracts the id_token string from an oauth2.Token's Extra field.
// Returns empty string if the token is nil, id_token is not present, or not a valid string.
// Per OpenID Connect Core 1.0 Section 3.1.3.3, the id_token is REQUIRED in token
// responses for OIDC flows, enabling silent re-authentication with id_token_hint.
func ExtractIDToken(token *oauth2.Token) string {
	if token == nil {
		return ""
	}
	if idToken := token.Extra("id_token"); idToken != nil {
		if idTokenStr, ok := idToken.(string); ok {
			return idTokenStr
		}
	}
	return ""
}

// metadataCacheCleanupLoop runs in a background goroutine to periodically clean
// expired entries from the metadata cache. This prevents memory leaks from
// expired cache entries that haven't been naturally evicted by LRU.
func (s *Server) metadataCacheCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			removed := s.metadataCache.CleanupExpired()
			if removed > 0 {
				s.Logger.Debug("Cleaned expired metadata cache entries",
					"count", removed,
					"cache_size", s.metadataCache.Size())
			}
		case <-s.metadataCacheCleanupCtx.Done():
			s.Logger.Debug("Metadata cache cleanup goroutine stopped")
			return
		}
	}
}

// Shutdown gracefully shuts down the server and all its components.
// It stops rate limiters, closes storage connections, and cleans up resources.
// Safe to call multiple times - only the first call will execute shutdown.
//
// The context parameter controls the shutdown timeout. If the context is cancelled
// or times out before shutdown completes, Shutdown returns the context error.
//
// IMPORTANT: This method only stops background goroutines (rate limiters, cleanup tasks).
// It does NOT handle in-flight HTTP requests. For production deployments, you should:
//
//  1. Stop accepting new connections (e.g., http.Server.Shutdown())
//  2. Wait for in-flight requests to complete
//  3. Call this method to clean up background processes
//
// Recommended production shutdown sequence:
//
//	// Step 1: Stop accepting new requests (with timeout)
//	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := httpServer.Shutdown(shutdownCtx); err != nil {
//	    log.Printf("HTTP server shutdown error: %v", err)
//	}
//
//	// Step 2: Clean up OAuth server background processes
//	if err := oauthServer.Shutdown(shutdownCtx); err != nil {
//	    log.Printf("OAuth server shutdown error: %v", err)
//	}
//
// Simple example for non-production use:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	if err := server.Shutdown(ctx); err != nil {
//	    log.Printf("Shutdown error: %v", err)
//	}
func (s *Server) Shutdown(ctx context.Context) error {
	var shutdownErr error

	s.shutdownOnce.Do(func() {
		s.Logger.Info("Starting graceful shutdown...")
		done := make(chan struct{})

		go func() {
			defer close(done)
			s.performShutdown(ctx)
		}()

		select {
		case <-done:
			// Shutdown completed successfully
		case <-ctx.Done():
			shutdownErr = fmt.Errorf("shutdown cancelled: %w", ctx.Err())
			s.Logger.Warn("Shutdown timed out or was cancelled", "error", shutdownErr)
		}
	})

	return shutdownErr
}

// performShutdown performs the actual shutdown of all server components.
func (s *Server) performShutdown(ctx context.Context) {
	s.stopRateLimiters()
	s.stopMetadataCacheCleanup()
	s.shutdownInstrumentation(ctx)
	s.stopStorage()
	s.Logger.Info("Graceful shutdown completed")
}

// stopRateLimiters stops all rate limiters.
func (s *Server) stopRateLimiters() {
	if s.RateLimiter != nil {
		s.Logger.Debug("Stopping IP rate limiter...")
		s.RateLimiter.Stop()
	}
	if s.UserRateLimiter != nil {
		s.Logger.Debug("Stopping user rate limiter...")
		s.UserRateLimiter.Stop()
	}
	if s.SecurityEventRateLimiter != nil {
		s.Logger.Debug("Stopping security event rate limiter...")
		s.SecurityEventRateLimiter.Stop()
	}
	if s.ClientRegistrationRateLimiter != nil {
		s.Logger.Debug("Stopping client registration rate limiter...")
		s.ClientRegistrationRateLimiter.Stop()
	}
	if s.metadataFetchRateLimiter != nil {
		s.Logger.Debug("Stopping metadata fetch rate limiter...")
		s.metadataFetchRateLimiter.Stop()
	}
}

// stopMetadataCacheCleanup stops the metadata cache cleanup goroutine.
func (s *Server) stopMetadataCacheCleanup() {
	if s.metadataCacheCleanupCancel != nil {
		s.Logger.Debug("Stopping metadata cache cleanup goroutine...")
		s.metadataCacheCleanupCancel()
	}
}

// shutdownInstrumentation shuts down the instrumentation subsystem.
func (s *Server) shutdownInstrumentation(ctx context.Context) {
	if s.Instrumentation == nil {
		return
	}
	s.Logger.Debug("Shutting down instrumentation...")
	if err := s.Instrumentation.Shutdown(ctx); err != nil {
		s.Logger.Warn("Failed to shutdown instrumentation", "error", err)
	}
}

// stopStorage stops storage cleanup goroutines if supported.
func (s *Server) stopStorage() {
	type stoppableStore interface {
		Stop()
	}
	if store, ok := s.tokenStore.(stoppableStore); ok {
		s.Logger.Debug("Stopping storage cleanup...")
		store.Stop()
	}
}

// ShutdownWithTimeout is a convenience wrapper around Shutdown that creates
// a context with the specified timeout.
//
// Example usage:
//
//	if err := server.ShutdownWithTimeout(30 * time.Second); err != nil {
//	    log.Printf("Shutdown error: %v", err)
//	}
func (s *Server) ShutdownWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.Shutdown(ctx)
}
