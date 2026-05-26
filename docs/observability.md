# Observability Guide

The library provides OpenTelemetry (OTEL) instrumentation for metrics, distributed tracing, and structured logging.

## Contents

1. [Quick Start](#quick-start)
2. [Exporter Configuration](#exporter-configuration)
3. [Available Metrics](#available-metrics)
4. [Distributed Tracing](#distributed-tracing)
5. [Privacy Considerations](#privacy-considerations)
6. [Integration Examples](#integration-examples)

## Quick Start

Build the instrumentation pipeline yourself with `instrumentation.New`, then pass it to the server via `oauth.WithInstrumentation`. The same pipeline can be shared with other components in the process.

```go
import (
    oauth "github.com/giantswarm/mcp-oauth"
    "github.com/giantswarm/mcp-oauth/instrumentation"
)

inst, err := instrumentation.New(instrumentation.Config{
    Enabled:         true,
    ServiceName:     "my-oauth-server",
    ServiceVersion:  "1.0.0",
    MetricsExporter: "prometheus",
    TracesExporter:  "otlp",
    OTLPEndpoint:    "localhost:4318",
})
if err != nil {
    log.Fatalf("init instrumentation: %v", err)
}

server, _ := oauth.NewServer(
    provider, tokenStore, clientStore, flowStore,
    &oauth.ServerConfig{
        Issuer: "https://your-domain.com",
    },
    logger,
    oauth.WithInstrumentation(inst),
)

// Expose Prometheus metrics endpoint
import "github.com/prometheus/client_golang/prometheus/promhttp"
http.Handle("/metrics", promhttp.Handler())
```

## Exporter Configuration

### Metrics Exporters

| Value | Description | Use Case |
|-------|-------------|----------|
| `"prometheus"` | Prometheus format | Production (pull-based) |
| `"stdout"` | Print to stdout | Development/debugging |
| `"none"` or `""` | No export | Disabled (zero overhead) |

### Trace Exporters

| Value | Description | Use Case |
|-------|-------------|----------|
| `"otlp"` | OTLP HTTP | Production (requires `OTLPEndpoint`) |
| `"stdout"` | Print to stdout | Development/debugging |
| `"none"` or `""` | No export | Disabled (zero overhead) |

### Configuration Examples

All examples build `instrumentation.Config` and pass the result via `oauth.WithInstrumentation(inst)` to `oauth.NewServer`.

**Production: Prometheus + OTLP traces**

```go
instrumentation.Config{
    Enabled:         true,
    MetricsExporter: "prometheus",
    TracesExporter:  "otlp",
    OTLPEndpoint:    "jaeger:4318",
}
```

**Development: stdout for local debugging**

```go
instrumentation.Config{
    Enabled:         true,
    MetricsExporter: "stdout",
    TracesExporter:  "stdout",
}
```

**Minimal: Metrics only, no tracing**

```go
instrumentation.Config{
    Enabled:         true,
    MetricsExporter: "prometheus",
    TracesExporter:  "none",
}
```

## Available Metrics

### HTTP Layer

| Metric | Labels | Description |
|--------|--------|-------------|
| `oauth.http.requests.total` | `method`, `endpoint`, `status` | Total HTTP requests |
| `oauth.http.request.duration` | `endpoint` | Request duration (ms) |

### OAuth Flows

| Metric | Labels | Description |
|--------|--------|-------------|
| `oauth.authorization.started` | `client_id` | Authorization flows started |
| `oauth.callback.processed` | `client_id`, `success` | Provider callbacks processed |
| `oauth.code.exchanged` | `client_id`, `pkce_method` | Codes exchanged for tokens |
| `oauth.token.refreshed` | `client_id`, `rotated` | Tokens refreshed |
| `oauth.token.revoked` | `client_id` | Tokens revoked |
| `oauth.client.registered` | `client_type` | Clients registered |
| `oauth.token_endpoint.failures.total` | `grant_type`, `error_code` | Token-endpoint failures broken down by RFC 6749 `error_code` (`invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, `server_error`). Cardinality budget: ~8 × ~7 series. |

### Security

| Metric | Labels | Description |
|--------|--------|-------------|
| `oauth.rate_limit.exceeded` | `limiter_type` | Rate limit violations |
| `oauth.pkce.validation_failed` | `method` | PKCE validation failures |
| `oauth.code.reuse_detected` | - | Authorization code reuse attempts |
| `oauth.token.reuse_detected` | - | Refresh token reuse attempts |
| `oauth.refresh_token.legacy_rejected` | - | Legacy refresh tokens rejected for missing client binding (OAuth 2.1) |
| `oauth.forwarded_id_token.accepted_total` | `issuer`, `audience`, `result` | Forwarded ID token acceptance attempts; `result` is a bounded enum (`ok`, `aud_mismatch`, `iss_mismatch`, `sig_invalid`, `expired`, `not_yet_valid`, `no_jwks`, `parse_error`) |
| `oauth.redirect_uri.security_rejected` | `category`, `stage` | Redirect URI security validation failures (SSRF/XSS protection) |

### Audit and Encryption

| Metric | Labels | Description |
|--------|--------|-------------|
| `oauth.audit.events.total` | `event_type` | Audit events emitted by the security `Auditor` |
| `oauth.audit.drops.total` | `reason` | Audit events dropped (`reason=disabled` when an `Auditor` is configured but its enabled flag is `false`) |
| `oauth.encryption.operations.total` | `operation`, `result` | Token encryption/decryption calls; `operation` ∈ `{encrypt, decrypt}`, `result` ∈ `{ok, fail}` |
| `oauth.encryption.duration` | `operation`, `result` | Encryption/decryption duration (ms) |

### Client ID Metadata Document (MCP 2025-11-25)

| Metric | Labels | Description |
|--------|--------|-------------|
| `oauth.cimd.fetch.total` | `result` | CIMD metadata fetch attempts (`result` ∈ `{success, error, blocked}`) |
| `oauth.cimd.fetch.duration` | - | CIMD fetch duration (ms) |
| `oauth.cimd.cache.total` | `operation` | CIMD cache operations (`operation` ∈ `{hit, miss, negative_hit}`) |

**Redirect URI Security Categories:**

The `oauth.redirect_uri.security_rejected` metric tracks security validation failures with detailed categorization:

| Category | Description |
|----------|-------------|
| `blocked_scheme` | Dangerous scheme (javascript:, data:, file:, etc.) |
| `private_ip` | RFC 1918 private IP (10.x, 172.16.x, 192.168.x) |
| `link_local` | Link-local address (169.254.x.x - cloud metadata SSRF) |
| `loopback_not_allowed` | Loopback when AllowLocalhostRedirectURIs=false |
| `http_not_allowed` | HTTP on non-loopback in ProductionMode |
| `dns_resolves_to_private_ip` | Hostname resolves to private IP (DNS rebinding) |
| `dns_resolves_to_link_local` | Hostname resolves to link-local (DNS rebinding) |
| `dns_resolution_failed` | DNS lookup failed (strict mode) |
| `unspecified_address` | 0.0.0.0 or :: (always blocked) |
| `fragment_not_allowed` | URI contains fragment (OAuth 2.0 BCP violation) |
| `invalid_format` | Malformed URI |

The `stage` label indicates when the rejection occurred:
- `registration`: During client registration
- `authorization`: During authorization request (TOCTOU protection)

### Storage

| Metric | Labels | Description |
|--------|--------|-------------|
| `storage.operation.total` | `operation`, `result` | Storage operations |
| `storage.operation.duration` | `operation` | Operation duration (ms) |

### Provider

| Metric | Labels | Description |
|--------|--------|-------------|
| `provider.api.calls.total` | `provider`, `operation`, `status` | Provider API calls |
| `provider.api.duration` | `provider`, `operation` | API call duration (ms) |
| `provider.api.errors.total` | `provider`, `operation`, `error_type` | Provider API errors |

## Distributed Tracing

Spans are emitted from the HTTP layer and storage layer. The current emit
set is:

| Span | Notable attributes |
|------|--------------------|
| `oauth.http.authorization` | `oauth.client_id`, `oauth.pkce.method`, `oauth.response_type`, `oauth.scope` |
| `oauth.http.callback` | `oauth.client_id` |
| `oauth.http.token_exchange` | `oauth.client_id`, `oauth.client_type`, `oauth.grant_type=authorization_code` |
| `oauth.http.token_refresh` | `oauth.client_id`, `oauth.grant_type=refresh_token`, `oauth.client_authenticated` |
| `oauth.http.token_revocation` | `oauth.client_id` |
| `oauth.http.introspection` | `oauth.client_id`, `oauth.token_type` |
| `storage.<operation>` | `operation`, `storage.backend` (one span per storage call when a Tracer is wired into the store) |

`oauth.token.rotated=true` is added as a span attribute on whichever span
covers a refresh-token rotation in `flows.go`.

### Trace Context

Traces include relevant context:
- Client ID
- User ID (when available)
- OAuth flow stage
- Error information

## Privacy Considerations

### Data Collection

When instrumentation is enabled, the following data may be collected:

| Data Type | Purpose | Sensitivity |
|-----------|---------|-------------|
| Client IPs | Security monitoring, rate limiting | PII in some jurisdictions |
| Client IDs | Flow tracking | Low sensitivity |
| User IDs | Flow tracking | May be PII |
| OAuth metadata | Debugging | Low sensitivity |
| Timing info | Performance monitoring | Not sensitive |
| Error codes | Debugging | Not sensitive |

### Security Guarantees

Actual credentials are **never** logged:
- Access tokens
- Refresh tokens
- Authorization codes
- Client secrets

Only metadata about tokens (type, expiry, family ID) is recorded.

### GDPR and Privacy

- Client IP addresses may be PII in some jurisdictions
- User IDs may be subject to privacy regulations
- Configure appropriate trace sampling and retention policies
- Consider data minimization in high-privacy environments

### Recommendations

1. Review jurisdiction's privacy laws before enabling instrumentation
2. Configure appropriate trace sampling rates (e.g., 1% for high-volume)
3. Set reasonable retention periods (7-30 days recommended)
4. Implement access controls on observability infrastructure
5. Document data collection in your privacy policy

### Minimal Data Collection

For privacy-sensitive environments, simply omit `oauth.WithInstrumentation` from `oauth.NewServer`. The library uses no-op providers when no instrumentation is configured (zero overhead, no data collection).

## Integration Examples

### Prometheus

The Prometheus exporter works with the standard `prometheus/client_golang` library:

```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

// Expose metrics endpoint
http.Handle("/metrics", promhttp.Handler())
```

Configure Prometheus to scrape:

```yaml
scrape_configs:
  - job_name: 'oauth-server'
    static_configs:
      - targets: ['oauth-server:8080']
```

### Jaeger / OpenTelemetry Collector

Use the OTLP trace exporter:

```bash
# Run Jaeger with OTLP support
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4318:4318 \
  jaegertracing/all-in-one:latest
```

```go
instrumentation.Config{
    Enabled:        true,
    TracesExporter: "otlp",
    OTLPEndpoint:   "localhost:4318",
}
```

### Grafana

Combine Prometheus metrics and Jaeger traces in Grafana:

1. Add Prometheus as data source
2. Add Jaeger as data source
3. Create dashboards using OAuth metrics
4. Link to traces from metrics panels

### Example Dashboard Queries

**Request rate by endpoint:**
```promql
rate(oauth_http_requests_total[5m])
```

**Token refresh rate:**
```promql
rate(oauth_token_refreshed_total[5m])
```

**Rate limit violations:**
```promql
increase(oauth_rate_limit_exceeded_total[1h])
```

**Redirect URI security rejections (SSRF/XSS attempts):**
```promql
increase(oauth_redirect_uri_security_rejected_total[1h])
```

**Redirect URI rejections by category:**
```promql
sum by (category) (increase(oauth_redirect_uri_security_rejected_total[1h]))
```

**P99 latency:**
```promql
histogram_quantile(0.99, rate(oauth_http_request_duration_bucket[5m]))
```

## Performance

| State | Impact |
|-------|--------|
| Disabled | Zero overhead (uses no-op providers) |
| Enabled | < 1% latency increase, ~1-2 MB memory |

- Thread-safe concurrent access
- Lock-free atomic operations for metrics

## Next Steps

- [Security Guide](./security.md) - Security event monitoring
- [Configuration Guide](./configuration.md) - Server configuration
- [instrumentation package docs](https://pkg.go.dev/github.com/giantswarm/mcp-oauth/instrumentation) - API reference
