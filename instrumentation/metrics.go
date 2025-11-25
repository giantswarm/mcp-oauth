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
	RateLimitExceeded       metric.Int64Counter
	PKCEValidationFailed    metric.Int64Counter
	CodeReuseDetected       metric.Int64Counter
	TokenReuseDetected      metric.Int64Counter
	RateLimitActiveLimiters metric.Int64ObservableGauge

	// Storage Metrics
	StorageOperationTotal    metric.Int64Counter
	StorageOperationDuration metric.Float64Histogram
	StorageSizeTokens        metric.Int64ObservableGauge
	StorageSizeClients       metric.Int64ObservableGauge
	StorageSizeFlows         metric.Int64ObservableGauge

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

// newMetrics creates and registers all metric instruments
func newMetrics(inst *Instrumentation) (*Metrics, error) {
	m := &Metrics{}

	// HTTP Layer Metrics
	var err error
	m.HTTPRequestsTotal, err = inst.httpMeter.Int64Counter(
		"oauth.http.requests.total",
		metric.WithDescription("Total number of HTTP requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create http.requests.total counter: %w", err)
	}

	m.HTTPRequestDuration, err = inst.httpMeter.Float64Histogram(
		"oauth.http.request.duration",
		metric.WithDescription("HTTP request duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create http.request.duration histogram: %w", err)
	}

	// OAuth Flow Metrics
	m.AuthorizationStarted, err = inst.serverMeter.Int64Counter(
		"oauth.authorization.started",
		metric.WithDescription("Number of authorization flows started"),
		metric.WithUnit("{flow}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization.started counter: %w", err)
	}

	m.CallbackProcessed, err = inst.serverMeter.Int64Counter(
		"oauth.callback.processed",
		metric.WithDescription("Number of provider callbacks processed"),
		metric.WithUnit("{callback}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create callback.processed counter: %w", err)
	}

	m.CodeExchanged, err = inst.serverMeter.Int64Counter(
		"oauth.code.exchanged",
		metric.WithDescription("Number of authorization codes exchanged for tokens"),
		metric.WithUnit("{exchange}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create code.exchanged counter: %w", err)
	}

	m.TokenRefreshed, err = inst.serverMeter.Int64Counter(
		"oauth.token.refreshed",
		metric.WithDescription("Number of tokens refreshed"),
		metric.WithUnit("{refresh}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token.refreshed counter: %w", err)
	}

	m.TokenRevoked, err = inst.serverMeter.Int64Counter(
		"oauth.token.revoked",
		metric.WithDescription("Number of tokens revoked"),
		metric.WithUnit("{revocation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token.revoked counter: %w", err)
	}

	m.ClientRegistered, err = inst.serverMeter.Int64Counter(
		"oauth.client.registered",
		metric.WithDescription("Number of clients registered"),
		metric.WithUnit("{client}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client.registered counter: %w", err)
	}

	// Security Metrics
	m.RateLimitExceeded, err = inst.securityMeter.Int64Counter(
		"oauth.rate_limit.exceeded",
		metric.WithDescription("Number of rate limit violations"),
		metric.WithUnit("{violation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate_limit.exceeded counter: %w", err)
	}

	m.PKCEValidationFailed, err = inst.securityMeter.Int64Counter(
		"oauth.pkce.validation_failed",
		metric.WithDescription("Number of PKCE validation failures"),
		metric.WithUnit("{failure}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create pkce.validation_failed counter: %w", err)
	}

	m.CodeReuseDetected, err = inst.securityMeter.Int64Counter(
		"oauth.code.reuse_detected",
		metric.WithDescription("Number of authorization code reuse attempts detected"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create code.reuse_detected counter: %w", err)
	}

	m.TokenReuseDetected, err = inst.securityMeter.Int64Counter(
		"oauth.token.reuse_detected",
		metric.WithDescription("Number of token reuse attempts detected"),
		metric.WithUnit("{attempt}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token.reuse_detected counter: %w", err)
	}

	// Storage Metrics
	m.StorageOperationTotal, err = inst.storageMeter.Int64Counter(
		"storage.operation.total",
		metric.WithDescription("Total number of storage operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage.operation.total counter: %w", err)
	}

	m.StorageOperationDuration, err = inst.storageMeter.Float64Histogram(
		"storage.operation.duration",
		metric.WithDescription("Storage operation duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage.operation.duration histogram: %w", err)
	}

	// Provider Metrics
	m.ProviderAPICallsTotal, err = inst.providerMeter.Int64Counter(
		"provider.api.calls.total",
		metric.WithDescription("Total number of provider API calls"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider.api.calls.total counter: %w", err)
	}

	m.ProviderAPIDuration, err = inst.providerMeter.Float64Histogram(
		"provider.api.duration",
		metric.WithDescription("Provider API call duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider.api.duration histogram: %w", err)
	}

	m.ProviderAPIErrors, err = inst.providerMeter.Int64Counter(
		"provider.api.errors.total",
		metric.WithDescription("Total number of provider API errors"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider.api.errors.total counter: %w", err)
	}

	// Audit Metrics
	m.AuditEventsTotal, err = inst.securityMeter.Int64Counter(
		"oauth.audit.events.total",
		metric.WithDescription("Total number of audit events"),
		metric.WithUnit("{event}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit.events.total counter: %w", err)
	}

	// Encryption Metrics
	m.EncryptionOperationsTotal, err = inst.securityMeter.Int64Counter(
		"oauth.encryption.operations.total",
		metric.WithDescription("Total number of encryption/decryption operations"),
		metric.WithUnit("{operation}"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption.operations.total counter: %w", err)
	}

	m.EncryptionDuration, err = inst.securityMeter.Float64Histogram(
		"oauth.encryption.duration",
		metric.WithDescription("Encryption/decryption operation duration in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption.duration histogram: %w", err)
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
