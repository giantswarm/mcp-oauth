// Package instrumentation provides OpenTelemetry (OTEL) instrumentation for the mcp-oauth library.
//
// This package enables comprehensive observability across all library layers through:
// - Metrics: Counters, histograms, and gauges for monitoring OAuth operations
// - Traces: Distributed tracing for request flows across components
// - Logging: Structured logs with trace context integration
//
// # Quick Start
//
// Enable basic instrumentation with stdout exporters (development):
//
//	import "github.com/giantswarm/mcp-oauth/instrumentation"
//
//	// Initialize instrumentation
//	inst, err := instrumentation.New(instrumentation.Config{
//		ServiceName:     "my-oauth-service",
//		ServiceVersion:  "1.0.0",
//		MetricsExporter: "stdout",  // Print metrics to stdout
//		TracesExporter:  "stdout",  // Print traces to stdout
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer inst.Shutdown(context.Background())
//
//	// Pass to server configuration
//	server.SetInstrumentation(inst)
//
// # Exporter Configuration
//
// The library supports multiple exporters for metrics and traces:
//
// Metrics Exporters:
//   - "prometheus": Export metrics in Prometheus format (production recommended)
//   - "stdout": Print metrics to stdout (development/debugging)
//   - "none" or "": No metrics export (default, zero overhead)
//
// Trace Exporters:
//   - "otlp": Export traces via OTLP HTTP (production recommended, requires OTLPEndpoint)
//   - "stdout": Print traces to stdout (development/debugging)
//   - "none" or "": No trace export (default, zero overhead)
//
// # Prometheus Metrics (Production)
//
// Export metrics to Prometheus:
//
//	import (
//		"github.com/giantswarm/mcp-oauth/instrumentation"
//		"github.com/prometheus/client_golang/prometheus/promhttp"
//	)
//
//	inst, err := instrumentation.New(instrumentation.Config{
//		ServiceName:     "my-oauth-service",
//		ServiceVersion:  "1.0.0",
//		MetricsExporter: "prometheus",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Expose /metrics endpoint for Prometheus to scrape
//	http.Handle("/metrics", promhttp.Handler())
//
// # OTLP Traces (Production)
//
// Export traces to Jaeger, Grafana Tempo, or any OTLP-compatible backend:
//
//	inst, err := instrumentation.New(instrumentation.Config{
//		ServiceName:     "my-oauth-service",
//		ServiceVersion:  "1.0.0",
//		MetricsExporter: "prometheus",
//		TracesExporter:  "otlp",
//		OTLPEndpoint:    "localhost:4318", // OTLP HTTP endpoint
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Zero Overhead (Default)
//
// When exporters are not configured, the library uses no-op providers with zero overhead:
//
//	inst, err := instrumentation.New(instrumentation.Config{
//		ServiceName:     "my-oauth-service",
//		ServiceVersion:  "1.0.0",
//		// MetricsExporter defaults to "none"
//		// TracesExporter defaults to "none"
//	})
//	// No metrics or traces exported, zero performance impact
//
// # Available Metrics
//
// HTTP Layer:
//   - oauth.http.requests.total{method, endpoint, status} - Total HTTP requests
//   - oauth.http.request.duration{endpoint} - Request duration in milliseconds
//
// OAuth Flows:
//   - oauth.authorization.started{client_id} - Authorization flows started
//   - oauth.code.exchanged{client_id, pkce_method} - Authorization codes exchanged
//   - oauth.token.refreshed{client_id, rotated} - Tokens refreshed
//   - oauth.token.revoked{client_id} - Tokens revoked
//
// Security:
//   - oauth.rate_limit.exceeded{limiter_type} - Rate limit violations
//   - oauth.pkce.validation_failed{method} - PKCE validation failures
//   - oauth.code.reuse_detected - Authorization code reuse attempts
//   - oauth.token.reuse_detected - Token reuse attempts
//
// Storage:
//   - storage.operation.total{operation, result} - Storage operations
//   - storage.operation.duration{operation} - Operation duration in milliseconds
//   - storage.size{type} - Current storage size (tokens, clients, flows)
//
// Provider:
//   - provider.api.calls.total{provider, operation, status} - Provider API calls
//   - provider.api.duration{provider, operation} - API call duration in milliseconds
//   - provider.api.errors.total{provider, operation, error_type} - Provider API errors
//
// # Distributed Tracing
//
// Spans are created for all major operations:
//   - HTTP requests (via otelhttp middleware)
//   - OAuth flows (authorization, callback, token exchange, refresh, revocation)
//   - Storage operations (save, get, delete)
//   - Provider API calls (exchange, validate, refresh, revoke)
//
// Example span structure:
//
//	http.request
//	├── oauth.http.authorization
//	│   └── oauth.server.start_authorization_flow
//	│       ├── storage.save_authorization_state
//	│       └── provider.google.authorization_url
//	└── oauth.http.callback
//	    └── oauth.server.handle_provider_callback
//	        ├── storage.get_authorization_state
//	        ├── provider.google.exchange_code
//	        └── storage.save_token
//
// # Performance
//
// When instrumentation is not configured or disabled:
//   - Zero overhead (uses no-op providers)
//   - No allocations or latency impact
//
// When enabled:
//   - < 1% latency overhead
//   - ~1-2 MB memory for metric registry
//   - Lock-free atomic operations for metrics
//   - Object pooling for span creation
//
// # Thread Safety
//
// All instrumentation operations are thread-safe and can be called concurrently from multiple goroutines.
//
// # Metric Cardinality Considerations
//
// Metric cardinality refers to the number of unique label combinations for a metric.
// High cardinality can cause memory pressure and slow queries in monitoring systems.
//
// Label cardinality in this library:
//   - client_id: One value per registered OAuth client (typically 1-1000s)
//   - user_id: One value per authenticated user (can be high for consumer apps)
//   - endpoint: Fixed set (5-10 endpoints)
//   - operation: Fixed set (10-20 operations)
//   - status: Fixed set (HTTP status codes ~10-20 values)
//   - provider: Fixed set (number of identity providers, typically 1-5)
//
// Cardinality recommendations:
//
// LOW SCALE (<100 clients):
//   - Use client_id labels freely for detailed per-client metrics
//   - Track individual client operations and error rates
//   - No special configuration needed
//
// MEDIUM SCALE (100-10,000 clients):
//   - Monitor total metric cardinality in your observability platform
//   - Consider aggregating metrics by client type instead of client_id
//   - Set recording rules in Prometheus to pre-aggregate high-cardinality metrics
//   - Example: aggregate rate(oauth_token_refreshed_total[5m]) by client_type
//
// HIGH SCALE (>10,000 clients):
//   - REMOVE client_id labels from high-frequency metrics
//   - Use sampling: only record metrics for a subset of clients
//   - Implement custom metric aggregation in your application
//   - Consider using exemplars (Prometheus 2.26+) to link metrics to traces
//   - Use distributed tracing (spans) for per-client debugging instead of metrics
//
// Estimating metric cardinality:
//   - oauth.http.requests.total{method, endpoint, status}: ~3 methods * 10 endpoints * 20 statuses = 600 series
//   - oauth.authorization.started{client_id}: N clients = N series (HIGH CARDINALITY)
//   - oauth.token.refreshed{client_id, rotated}: N clients * 2 = 2N series (HIGH CARDINALITY)
//
// For very high scale (millions of users/clients), consider:
//   - Using aggregated metrics (total counts without client_id)
//   - Sampling metrics (record 1% of operations)
//   - Using logs or traces for per-client debugging
//   - External systems like ClickHouse or BigQuery for high-cardinality analysis
//
// # Security Considerations
//
// IMPORTANT: This package is designed to collect observability data, not sensitive credentials.
//
// When instrumenting OAuth flows, you MUST:
//   - NEVER log actual token values (access tokens, refresh tokens, authorization codes)
//   - NEVER log client secrets or PKCE verifiers
//   - ONLY log metadata (token types, expiry times, validation results, family IDs)
//
// Data collected in traces and metrics may be:
//   - Persisted for extended periods in observability backends
//   - Accessible to operations teams and potentially wider audiences
//   - Subject to compliance requirements (GDPR, PCI-DSS, SOC 2, etc.)
//   - Replicated across monitoring infrastructure
//
// Privacy considerations:
//   - Client IP addresses may be considered PII in some jurisdictions
//   - User IDs may be subject to privacy regulations
//   - Configure appropriate retention policies and access controls
//   - Document data collection in your privacy policy
//
// See the README.md "Privacy & Compliance" section for detailed guidance.
package instrumentation
