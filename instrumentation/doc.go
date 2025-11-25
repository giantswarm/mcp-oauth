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
//		ServiceName:    "my-oauth-service",
//		ServiceVersion: "1.0.0",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer inst.Shutdown(context.Background())
//
//	// Pass to server configuration
//	server.SetInstrumentation(inst)
//
// # Prometheus Metrics
//
// Export metrics to Prometheus:
//
//	import (
//		"github.com/giantswarm/mcp-oauth/instrumentation"
//		"github.com/prometheus/client_golang/prometheus/promhttp"
//	)
//
//	inst, err := instrumentation.New(instrumentation.Config{
//		ServiceName:    "my-oauth-service",
//		ServiceVersion: "1.0.0",
//		MetricExporter: "prometheus",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Expose /metrics endpoint
//	http.Handle("/metrics", promhttp.Handler())
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
package instrumentation
