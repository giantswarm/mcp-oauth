package instrumentation

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metric attribute keys - using constants for consistency and DRY
const (
	// Common attributes (reused across metrics)
	metricAttrMethod    = "method"
	metricAttrEndpoint  = "endpoint"
	metricAttrStatus    = "status"
	metricAttrOperation = "operation"

	// OAuth flow attributes
	metricAttrClientID   = "client_id"
	metricAttrSuccess    = "success"
	metricAttrPKCEMethod = "pkce_method"
	metricAttrRotated    = "rotated"
	metricAttrClientType = "client_type"

	// Security attributes
	metricAttrLimiterType = "limiter_type"
	metricAttrCategory    = "category"
	metricAttrStage       = "stage"

	// Storage attributes
	metricAttrResult = "result"

	// Provider attributes
	metricAttrProvider  = "provider"
	metricAttrErrorType = "error_type"

	// Audit attributes
	metricAttrEventType = "event_type"
)

// Metrics holds all metric instruments for the OAuth library
type Metrics struct {
	// HTTP Layer Metrics
	HTTPRequestsTotal   metric.Int64Counter
	HTTPRequestDuration metric.Float64Histogram

	// OAuth Flow Metrics
	AuthorizationStarted metric.Int64Counter
	CallbackProcessed    metric.Int64Counter
	CodeExchanged        metric.Int64Counter
	TokenRefreshed       metric.Int64Counter
	TokenRevoked         metric.Int64Counter
	ClientRegistered     metric.Int64Counter

	// Security Metrics
	RateLimitExceeded           metric.Int64Counter
	PKCEValidationFailed        metric.Int64Counter
	CodeReuseDetected           metric.Int64Counter
	TokenReuseDetected          metric.Int64Counter
	RedirectURISecurityRejected metric.Int64Counter // Redirect URI validation failures by category

	// Storage Metrics
	StorageOperationTotal    metric.Int64Counter
	StorageOperationDuration metric.Float64Histogram
	// Storage size gauges (observable) - updated via callbacks from storage implementations
	StorageTokensCount        metric.Int64ObservableGauge
	StorageClientsCount       metric.Int64ObservableGauge
	StorageFlowsCount         metric.Int64ObservableGauge
	StorageFamiliesCount      metric.Int64ObservableGauge
	StorageRefreshTokensCount metric.Int64ObservableGauge

	// Provider Metrics
	ProviderAPICallsTotal metric.Int64Counter
	ProviderAPIDuration   metric.Float64Histogram
	ProviderAPIErrors     metric.Int64Counter

	// Audit Metrics
	AuditEventsTotal metric.Int64Counter

	// Encryption Metrics
	EncryptionOperationsTotal metric.Int64Counter
	EncryptionDuration        metric.Float64Histogram

	// CIMD (Client ID Metadata Document) Metrics
	CIMDFetchTotal    metric.Int64Counter     // Total fetch attempts (labels: result=success/error/blocked)
	CIMDFetchDuration metric.Float64Histogram // Fetch duration in milliseconds
	CIMDCacheTotal    metric.Int64Counter     // Cache operations (labels: operation=hit/miss/negative_hit)

	// Configuration values (copied from instrumentation config to avoid circular dependency)
	includeClientIDInMetrics bool
}

// createCounter is a helper to reduce repetition when creating counters
func createCounter(meter metric.Meter, name, desc, unit string) (metric.Int64Counter, error) {
	counter, err := meter.Int64Counter(name,
		metric.WithDescription(desc),
		metric.WithUnit(unit),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s counter: %w", name, err)
	}
	return counter, nil
}

// createHistogram is a helper to reduce repetition when creating histograms
func createHistogram(meter metric.Meter, name, desc, unit string) (metric.Float64Histogram, error) {
	hist, err := meter.Float64Histogram(name,
		metric.WithDescription(desc),
		metric.WithUnit(unit),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s histogram: %w", name, err)
	}
	return hist, nil
}

// newMetrics creates and registers all metric instruments
func newMetrics(inst *Instrumentation) (*Metrics, error) {
	m := &Metrics{
		includeClientIDInMetrics: inst.config.IncludeClientIDInMetrics,
	}
	var err error

	// Create meters for each layer
	httpMeter := inst.Meter("http")
	serverMeter := inst.Meter("server")
	storageMeter := inst.Meter("storage")
	providerMeter := inst.Meter("provider")
	securityMeter := inst.Meter("security")

	// HTTP Layer Metrics
	m.HTTPRequestsTotal, err = createCounter(httpMeter,
		"oauth.http.requests.total",
		"Total number of HTTP requests",
		"{request}")
	if err != nil {
		return nil, err
	}

	m.HTTPRequestDuration, err = createHistogram(httpMeter,
		"oauth.http.request.duration",
		"HTTP request duration in milliseconds",
		"ms")
	if err != nil {
		return nil, err
	}

	// OAuth Flow Metrics
	m.AuthorizationStarted, err = createCounter(serverMeter,
		"oauth.authorization.started",
		"Number of authorization flows started",
		"{flow}")
	if err != nil {
		return nil, err
	}

	m.CallbackProcessed, err = createCounter(serverMeter,
		"oauth.callback.processed",
		"Number of provider callbacks processed",
		"{callback}")
	if err != nil {
		return nil, err
	}

	m.CodeExchanged, err = createCounter(serverMeter,
		"oauth.code.exchanged",
		"Number of authorization codes exchanged for tokens",
		"{exchange}")
	if err != nil {
		return nil, err
	}

	m.TokenRefreshed, err = createCounter(serverMeter,
		"oauth.token.refreshed",
		"Number of tokens refreshed",
		"{refresh}")
	if err != nil {
		return nil, err
	}

	m.TokenRevoked, err = createCounter(serverMeter,
		"oauth.token.revoked",
		"Number of tokens revoked",
		"{revocation}")
	if err != nil {
		return nil, err
	}

	m.ClientRegistered, err = createCounter(serverMeter,
		"oauth.client.registered",
		"Number of clients registered",
		"{client}")
	if err != nil {
		return nil, err
	}

	// Security Metrics
	m.RateLimitExceeded, err = createCounter(securityMeter,
		"oauth.rate_limit.exceeded",
		"Number of rate limit violations",
		"{violation}")
	if err != nil {
		return nil, err
	}

	m.PKCEValidationFailed, err = createCounter(securityMeter,
		"oauth.pkce.validation_failed",
		"Number of PKCE validation failures",
		"{failure}")
	if err != nil {
		return nil, err
	}

	m.CodeReuseDetected, err = createCounter(securityMeter,
		"oauth.code.reuse_detected",
		"Number of authorization code reuse attempts detected",
		"{attempt}")
	if err != nil {
		return nil, err
	}

	m.TokenReuseDetected, err = createCounter(securityMeter,
		"oauth.token.reuse_detected",
		"Number of token reuse attempts detected",
		"{attempt}")
	if err != nil {
		return nil, err
	}

	m.RedirectURISecurityRejected, err = createCounter(securityMeter,
		"oauth.redirect_uri.security_rejected",
		"Number of redirect URI validation failures (SSRF/XSS protection)",
		"{rejection}")
	if err != nil {
		return nil, err
	}

	// Storage Metrics
	m.StorageOperationTotal, err = createCounter(storageMeter,
		"storage.operation.total",
		"Total number of storage operations",
		"{operation}")
	if err != nil {
		return nil, err
	}

	m.StorageOperationDuration, err = createHistogram(storageMeter,
		"storage.operation.duration",
		"Storage operation duration in milliseconds",
		"ms")
	if err != nil {
		return nil, err
	}

	// Storage Size Gauges (observable)
	// These are populated via callbacks registered by storage implementations
	m.StorageTokensCount, err = storageMeter.Int64ObservableGauge(
		"storage.tokens.count",
		metric.WithDescription("Current number of tokens in storage"),
		metric.WithUnit("{token}"))
	if err != nil {
		return nil, fmt.Errorf("failed to create storage.tokens.count gauge: %w", err)
	}

	m.StorageClientsCount, err = storageMeter.Int64ObservableGauge(
		"storage.clients.count",
		metric.WithDescription("Current number of registered clients in storage"),
		metric.WithUnit("{client}"))
	if err != nil {
		return nil, fmt.Errorf("failed to create storage.clients.count gauge: %w", err)
	}

	m.StorageFlowsCount, err = storageMeter.Int64ObservableGauge(
		"storage.flows.count",
		metric.WithDescription("Current number of active authorization flows in storage"),
		metric.WithUnit("{flow}"))
	if err != nil {
		return nil, fmt.Errorf("failed to create storage.flows.count gauge: %w", err)
	}

	m.StorageFamiliesCount, err = storageMeter.Int64ObservableGauge(
		"storage.families.count",
		metric.WithDescription("Current number of token families in storage (includes revoked)"),
		metric.WithUnit("{family}"))
	if err != nil {
		return nil, fmt.Errorf("failed to create storage.families.count gauge: %w", err)
	}

	m.StorageRefreshTokensCount, err = storageMeter.Int64ObservableGauge(
		"storage.refresh_tokens.count",
		metric.WithDescription("Current number of refresh tokens in storage"),
		metric.WithUnit("{token}"))
	if err != nil {
		return nil, fmt.Errorf("failed to create storage.refresh_tokens.count gauge: %w", err)
	}

	// Provider Metrics
	m.ProviderAPICallsTotal, err = createCounter(providerMeter,
		"provider.api.calls.total",
		"Total number of provider API calls",
		"{call}")
	if err != nil {
		return nil, err
	}

	m.ProviderAPIDuration, err = createHistogram(providerMeter,
		"provider.api.duration",
		"Provider API call duration in milliseconds",
		"ms")
	if err != nil {
		return nil, err
	}

	m.ProviderAPIErrors, err = createCounter(providerMeter,
		"provider.api.errors.total",
		"Total number of provider API errors",
		"{error}")
	if err != nil {
		return nil, err
	}

	// Audit Metrics
	m.AuditEventsTotal, err = createCounter(securityMeter,
		"oauth.audit.events.total",
		"Total number of audit events",
		"{event}")
	if err != nil {
		return nil, err
	}

	// Encryption Metrics
	m.EncryptionOperationsTotal, err = createCounter(securityMeter,
		"oauth.encryption.operations.total",
		"Total number of encryption/decryption operations",
		"{operation}")
	if err != nil {
		return nil, err
	}

	m.EncryptionDuration, err = createHistogram(securityMeter,
		"oauth.encryption.duration",
		"Encryption/decryption operation duration in milliseconds",
		"ms")
	if err != nil {
		return nil, err
	}

	// CIMD (Client ID Metadata Document) Metrics
	cimdMeter := inst.Meter("cimd")

	m.CIMDFetchTotal, err = createCounter(cimdMeter,
		"oauth.cimd.fetch.total",
		"Total number of CIMD metadata fetch attempts",
		"{fetch}")
	if err != nil {
		return nil, err
	}

	m.CIMDFetchDuration, err = createHistogram(cimdMeter,
		"oauth.cimd.fetch.duration",
		"CIMD metadata fetch duration in milliseconds",
		"ms")
	if err != nil {
		return nil, err
	}

	m.CIMDCacheTotal, err = createCounter(cimdMeter,
		"oauth.cimd.cache.total",
		"Total number of CIMD cache operations",
		"{operation}")
	if err != nil {
		return nil, err
	}

	return m, nil
}

// Helper methods for common metric recording patterns
//
// CARDINALITY WARNING: Many of these methods include client_id as a label.
// In high-scale deployments (>10,000 clients), this can cause high cardinality.
// See package documentation for cardinality management strategies.

// addClientIDIfEnabled conditionally adds client_id attribute based on config
// This helper reduces code duplication for client ID attribute handling
func (m *Metrics) addClientIDIfEnabled(attrs []attribute.KeyValue, clientID string) []attribute.KeyValue {
	if m.shouldIncludeClientID() && clientID != "" {
		return append(attrs, attribute.String(metricAttrClientID, clientID))
	}
	return attrs
}

// shouldIncludeClientID checks if client_id should be included in metrics
func (m *Metrics) shouldIncludeClientID() bool {
	return m.includeClientIDInMetrics
}

// RecordHTTPRequest records an HTTP request metric
func (m *Metrics) RecordHTTPRequest(ctx context.Context, method, endpoint string, statusCode int, durationMs float64) {
	attrs := []attribute.KeyValue{
		attribute.String(metricAttrMethod, method),
		attribute.String(metricAttrEndpoint, endpoint),
		attribute.Int(metricAttrStatus, statusCode),
	}

	m.HTTPRequestsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.HTTPRequestDuration.Record(ctx, durationMs, metric.WithAttributes(attribute.String(metricAttrEndpoint, endpoint)))
}

// RecordAuthorizationStarted records an authorization flow start
func (m *Metrics) RecordAuthorizationStarted(ctx context.Context, clientID string) {
	var attrs []attribute.KeyValue
	attrs = m.addClientIDIfEnabled(attrs, clientID)
	m.AuthorizationStarted.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordCallbackProcessed records a provider callback processing
func (m *Metrics) RecordCallbackProcessed(ctx context.Context, clientID string, success bool) {
	attrs := []attribute.KeyValue{
		attribute.Bool(metricAttrSuccess, success),
	}
	attrs = m.addClientIDIfEnabled(attrs, clientID)
	m.CallbackProcessed.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordCodeExchange records an authorization code exchange
func (m *Metrics) RecordCodeExchange(ctx context.Context, clientID, pkceMethod string) {
	attrs := []attribute.KeyValue{
		attribute.String(metricAttrPKCEMethod, pkceMethod),
	}
	attrs = m.addClientIDIfEnabled(attrs, clientID)
	m.CodeExchanged.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordTokenRefresh records a token refresh operation
func (m *Metrics) RecordTokenRefresh(ctx context.Context, clientID string, rotated bool) {
	attrs := []attribute.KeyValue{
		attribute.Bool(metricAttrRotated, rotated),
	}
	attrs = m.addClientIDIfEnabled(attrs, clientID)
	m.TokenRefreshed.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordTokenRevocation records a token revocation
func (m *Metrics) RecordTokenRevocation(ctx context.Context, clientID string) {
	var attrs []attribute.KeyValue
	attrs = m.addClientIDIfEnabled(attrs, clientID)
	m.TokenRevoked.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordClientRegistration records a client registration
func (m *Metrics) RecordClientRegistration(ctx context.Context, clientType string) {
	m.ClientRegistered.Add(ctx, 1, metric.WithAttributes(
		attribute.String(metricAttrClientType, clientType),
	))
}

// RecordRateLimitExceeded records a rate limit violation
func (m *Metrics) RecordRateLimitExceeded(ctx context.Context, limiterType string) {
	m.RateLimitExceeded.Add(ctx, 1, metric.WithAttributes(
		attribute.String(metricAttrLimiterType, limiterType),
	))
}

// RecordPKCEValidationFailed records a PKCE validation failure
func (m *Metrics) RecordPKCEValidationFailed(ctx context.Context, method string) {
	m.PKCEValidationFailed.Add(ctx, 1, metric.WithAttributes(
		attribute.String(metricAttrMethod, method),
	))
}

// RecordCodeReuseDetected records an authorization code reuse attempt
func (m *Metrics) RecordCodeReuseDetected(ctx context.Context) {
	m.CodeReuseDetected.Add(ctx, 1)
}

// RecordTokenReuseDetected records a token reuse attempt
func (m *Metrics) RecordTokenReuseDetected(ctx context.Context) {
	m.TokenReuseDetected.Add(ctx, 1)
}

// RecordRedirectURISecurityRejected records a redirect URI security validation failure.
// This metric helps monitor SSRF and XSS attack attempts.
//
// Parameters:
//   - category: The error category (e.g., "blocked_scheme", "private_ip", "link_local",
//     "dns_resolves_to_private_ip", "loopback_not_allowed", "http_not_allowed")
//   - stage: When the rejection occurred ("registration" or "authorization")
func (m *Metrics) RecordRedirectURISecurityRejected(ctx context.Context, category, stage string) {
	m.RedirectURISecurityRejected.Add(ctx, 1, metric.WithAttributes(
		attribute.String(metricAttrCategory, category),
		attribute.String(metricAttrStage, stage),
	))
}

// RecordStorageOperation records a storage operation
func (m *Metrics) RecordStorageOperation(ctx context.Context, operation, result string, durationMs float64) {
	attrs := []attribute.KeyValue{
		attribute.String(metricAttrOperation, operation),
		attribute.String(metricAttrResult, result),
	}

	m.StorageOperationTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.StorageOperationDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String(metricAttrOperation, operation),
	))
}

// RecordProviderAPICall records a provider API call
func (m *Metrics) RecordProviderAPICall(ctx context.Context, provider, operation string, statusCode int, durationMs float64, err error) {
	attrs := []attribute.KeyValue{
		attribute.String(metricAttrProvider, provider),
		attribute.String(metricAttrOperation, operation),
		attribute.Int(metricAttrStatus, statusCode),
	}

	m.ProviderAPICallsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.ProviderAPIDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String(metricAttrProvider, provider),
		attribute.String(metricAttrOperation, operation),
	))

	if err != nil {
		errorType := "unknown"
		if statusCode >= 400 && statusCode < 500 {
			errorType = "client_error"
		} else if statusCode >= 500 {
			errorType = "server_error"
		}

		m.ProviderAPIErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String(metricAttrProvider, provider),
			attribute.String(metricAttrOperation, operation),
			attribute.String(metricAttrErrorType, errorType),
		))
	}
}

// RecordAuditEvent records an audit event
func (m *Metrics) RecordAuditEvent(ctx context.Context, eventType string) {
	m.AuditEventsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String(metricAttrEventType, eventType),
	))
}

// RecordEncryptionOperation records an encryption/decryption operation
func (m *Metrics) RecordEncryptionOperation(ctx context.Context, operation string, durationMs float64) {
	attrs := []attribute.KeyValue{
		attribute.String(metricAttrOperation, operation),
	}

	m.EncryptionOperationsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.EncryptionDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String(metricAttrOperation, operation),
	))
}

// RecordCIMDFetch records a Client ID Metadata Document fetch attempt.
// This metric helps track CIMD fetch latency and success/failure rates.
//
// Parameters:
//   - result: The outcome of the fetch ("success", "error", or "blocked")
//   - durationMs: The duration of the fetch operation in milliseconds
func (m *Metrics) RecordCIMDFetch(ctx context.Context, result string, durationMs float64) {
	m.CIMDFetchTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String(metricAttrResult, result),
	))
	m.CIMDFetchDuration.Record(ctx, durationMs)
}

// RecordCIMDCache records a CIMD cache operation.
// This metric helps monitor cache hit/miss rates for CIMD metadata.
//
// Parameters:
//   - operation: The type of cache operation ("hit", "miss", or "negative_hit")
func (m *Metrics) RecordCIMDCache(ctx context.Context, operation string) {
	m.CIMDCacheTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String(metricAttrOperation, operation),
	))
}
