package instrumentation

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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
	RateLimitExceeded    metric.Int64Counter
	PKCEValidationFailed metric.Int64Counter
	CodeReuseDetected    metric.Int64Counter
	TokenReuseDetected   metric.Int64Counter

	// Storage Metrics
	StorageOperationTotal    metric.Int64Counter
	StorageOperationDuration metric.Float64Histogram

	// Provider Metrics
	ProviderAPICallsTotal metric.Int64Counter
	ProviderAPIDuration   metric.Float64Histogram
	ProviderAPIErrors     metric.Int64Counter

	// Audit Metrics
	AuditEventsTotal metric.Int64Counter

	// Encryption Metrics
	EncryptionOperationsTotal metric.Int64Counter
	EncryptionDuration        metric.Float64Histogram
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
	m := &Metrics{}
	var err error

	// HTTP Layer Metrics
	m.HTTPRequestsTotal, err = createCounter(inst.httpMeter,
		"oauth.http.requests.total",
		"Total number of HTTP requests",
		"{request}")
	if err != nil {
		return nil, err
	}

	m.HTTPRequestDuration, err = createHistogram(inst.httpMeter,
		"oauth.http.request.duration",
		"HTTP request duration in milliseconds",
		"ms")
	if err != nil {
		return nil, err
	}

	// OAuth Flow Metrics
	m.AuthorizationStarted, err = createCounter(inst.serverMeter,
		"oauth.authorization.started",
		"Number of authorization flows started",
		"{flow}")
	if err != nil {
		return nil, err
	}

	m.CallbackProcessed, err = createCounter(inst.serverMeter,
		"oauth.callback.processed",
		"Number of provider callbacks processed",
		"{callback}")
	if err != nil {
		return nil, err
	}

	m.CodeExchanged, err = createCounter(inst.serverMeter,
		"oauth.code.exchanged",
		"Number of authorization codes exchanged for tokens",
		"{exchange}")
	if err != nil {
		return nil, err
	}

	m.TokenRefreshed, err = createCounter(inst.serverMeter,
		"oauth.token.refreshed",
		"Number of tokens refreshed",
		"{refresh}")
	if err != nil {
		return nil, err
	}

	m.TokenRevoked, err = createCounter(inst.serverMeter,
		"oauth.token.revoked",
		"Number of tokens revoked",
		"{revocation}")
	if err != nil {
		return nil, err
	}

	m.ClientRegistered, err = createCounter(inst.serverMeter,
		"oauth.client.registered",
		"Number of clients registered",
		"{client}")
	if err != nil {
		return nil, err
	}

	// Security Metrics
	m.RateLimitExceeded, err = createCounter(inst.securityMeter,
		"oauth.rate_limit.exceeded",
		"Number of rate limit violations",
		"{violation}")
	if err != nil {
		return nil, err
	}

	m.PKCEValidationFailed, err = createCounter(inst.securityMeter,
		"oauth.pkce.validation_failed",
		"Number of PKCE validation failures",
		"{failure}")
	if err != nil {
		return nil, err
	}

	m.CodeReuseDetected, err = createCounter(inst.securityMeter,
		"oauth.code.reuse_detected",
		"Number of authorization code reuse attempts detected",
		"{attempt}")
	if err != nil {
		return nil, err
	}

	m.TokenReuseDetected, err = createCounter(inst.securityMeter,
		"oauth.token.reuse_detected",
		"Number of token reuse attempts detected",
		"{attempt}")
	if err != nil {
		return nil, err
	}

	// Storage Metrics
	m.StorageOperationTotal, err = createCounter(inst.storageMeter,
		"storage.operation.total",
		"Total number of storage operations",
		"{operation}")
	if err != nil {
		return nil, err
	}

	m.StorageOperationDuration, err = createHistogram(inst.storageMeter,
		"storage.operation.duration",
		"Storage operation duration in milliseconds",
		"ms")
	if err != nil {
		return nil, err
	}

	// Provider Metrics
	m.ProviderAPICallsTotal, err = createCounter(inst.providerMeter,
		"provider.api.calls.total",
		"Total number of provider API calls",
		"{call}")
	if err != nil {
		return nil, err
	}

	m.ProviderAPIDuration, err = createHistogram(inst.providerMeter,
		"provider.api.duration",
		"Provider API call duration in milliseconds",
		"ms")
	if err != nil {
		return nil, err
	}

	m.ProviderAPIErrors, err = createCounter(inst.providerMeter,
		"provider.api.errors.total",
		"Total number of provider API errors",
		"{error}")
	if err != nil {
		return nil, err
	}

	// Audit Metrics
	m.AuditEventsTotal, err = createCounter(inst.securityMeter,
		"oauth.audit.events.total",
		"Total number of audit events",
		"{event}")
	if err != nil {
		return nil, err
	}

	// Encryption Metrics
	m.EncryptionOperationsTotal, err = createCounter(inst.securityMeter,
		"oauth.encryption.operations.total",
		"Total number of encryption/decryption operations",
		"{operation}")
	if err != nil {
		return nil, err
	}

	m.EncryptionDuration, err = createHistogram(inst.securityMeter,
		"oauth.encryption.duration",
		"Encryption/decryption operation duration in milliseconds",
		"ms")
	if err != nil {
		return nil, err
	}

	return m, nil
}

// Helper methods for common metric recording patterns

// RecordHTTPRequest records an HTTP request metric
func (m *Metrics) RecordHTTPRequest(ctx context.Context, method, endpoint string, statusCode int, durationMs float64) {
	attrs := []attribute.KeyValue{
		attribute.String("method", method),
		attribute.String("endpoint", endpoint),
		attribute.Int("status", statusCode),
	}

	m.HTTPRequestsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.HTTPRequestDuration.Record(ctx, durationMs, metric.WithAttributes(attribute.String("endpoint", endpoint)))
}

// RecordAuthorizationStarted records an authorization flow start
func (m *Metrics) RecordAuthorizationStarted(ctx context.Context, clientID string) {
	m.AuthorizationStarted.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client_id", clientID),
	))
}

// RecordCallbackProcessed records a provider callback processing
func (m *Metrics) RecordCallbackProcessed(ctx context.Context, clientID string, success bool) {
	m.CallbackProcessed.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client_id", clientID),
		attribute.Bool("success", success),
	))
}

// RecordCodeExchange records an authorization code exchange
func (m *Metrics) RecordCodeExchange(ctx context.Context, clientID, pkceMethod string) {
	m.CodeExchanged.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client_id", clientID),
		attribute.String("pkce_method", pkceMethod),
	))
}

// RecordTokenRefresh records a token refresh operation
func (m *Metrics) RecordTokenRefresh(ctx context.Context, clientID string, rotated bool) {
	m.TokenRefreshed.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client_id", clientID),
		attribute.Bool("rotated", rotated),
	))
}

// RecordTokenRevocation records a token revocation
func (m *Metrics) RecordTokenRevocation(ctx context.Context, clientID string) {
	m.TokenRevoked.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client_id", clientID),
	))
}

// RecordClientRegistration records a client registration
func (m *Metrics) RecordClientRegistration(ctx context.Context, clientType string) {
	m.ClientRegistered.Add(ctx, 1, metric.WithAttributes(
		attribute.String("client_type", clientType),
	))
}

// RecordRateLimitExceeded records a rate limit violation
func (m *Metrics) RecordRateLimitExceeded(ctx context.Context, limiterType string) {
	m.RateLimitExceeded.Add(ctx, 1, metric.WithAttributes(
		attribute.String("limiter_type", limiterType),
	))
}

// RecordPKCEValidationFailed records a PKCE validation failure
func (m *Metrics) RecordPKCEValidationFailed(ctx context.Context, method string) {
	m.PKCEValidationFailed.Add(ctx, 1, metric.WithAttributes(
		attribute.String("method", method),
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

// RecordStorageOperation records a storage operation
func (m *Metrics) RecordStorageOperation(ctx context.Context, operation, result string, durationMs float64) {
	attrs := []attribute.KeyValue{
		attribute.String("operation", operation),
		attribute.String("result", result),
	}

	m.StorageOperationTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.StorageOperationDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("operation", operation),
	))
}

// RecordProviderAPICall records a provider API call
func (m *Metrics) RecordProviderAPICall(ctx context.Context, provider, operation string, statusCode int, durationMs float64, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("provider", provider),
		attribute.String("operation", operation),
		attribute.Int("status", statusCode),
	}

	m.ProviderAPICallsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.ProviderAPIDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("provider", provider),
		attribute.String("operation", operation),
	))

	if err != nil {
		errorType := "unknown"
		if statusCode >= 400 && statusCode < 500 {
			errorType = "client_error"
		} else if statusCode >= 500 {
			errorType = "server_error"
		}

		m.ProviderAPIErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("provider", provider),
			attribute.String("operation", operation),
			attribute.String("error_type", errorType),
		))
	}
}

// RecordAuditEvent records an audit event
func (m *Metrics) RecordAuditEvent(ctx context.Context, eventType string) {
	m.AuditEventsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("event_type", eventType),
	))
}

// RecordEncryptionOperation records an encryption/decryption operation
func (m *Metrics) RecordEncryptionOperation(ctx context.Context, operation string, durationMs float64) {
	attrs := []attribute.KeyValue{
		attribute.String("operation", operation),
	}

	m.EncryptionOperationsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.EncryptionDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("operation", operation),
	))
}
