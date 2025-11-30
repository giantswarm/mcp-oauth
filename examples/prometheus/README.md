# Prometheus Metrics Example

This example demonstrates how to use the `mcp-oauth` library with Prometheus metrics exporting for production monitoring and observability.

## Security Warning

**This example uses environment variables for secrets for simplicity. This is NOT SECURE for production use.**

For production deployments:
- Use a secret manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
- See the [Production Example](../production/README.md#secret-management-required-for-production) for secure patterns
- NEVER commit secrets to version control
- NEVER use environment variables for secrets in production

**This is a development/learning example only.**

## Features

- OpenTelemetry instrumentation enabled
- Prometheus metrics endpoint at `/metrics`
- Storage size gauges for capacity monitoring
- Security metrics for rate limiting and attack detection
- HTTP request metrics for latency and error rate monitoring

## Prerequisites

1. **Google OAuth Credentials**: Create OAuth 2.0 credentials at [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. **Prometheus**: Install Prometheus to scrape the metrics endpoint

## Running the Example

1. Set your Google OAuth credentials:
```bash
export GOOGLE_CLIENT_ID="your-client-id"
export GOOGLE_CLIENT_SECRET="your-client-secret"
export GOOGLE_REDIRECT_URI="http://localhost:8080/oauth/callback"
```

2. Run the server:
```bash
cd examples/prometheus
go run main.go
```

3. The server will start on `http://localhost:8080`
4. Metrics are exposed at `http://localhost:8080/metrics`

## Testing the Metrics

View raw metrics:
```bash
curl http://localhost:8080/metrics
```

You should see metrics like:
```
# HELP oauth_http_requests_total Total number of HTTP requests
# TYPE oauth_http_requests_total counter
oauth_http_requests_total{endpoint="authorization",method="GET",status="200"} 5

# HELP storage_tokens_count Current number of tokens in storage
# TYPE storage_tokens_count gauge
storage_tokens_count 3

# HELP oauth_rate_limit_exceeded Rate limit violations
# TYPE oauth_rate_limit_exceeded counter
oauth_rate_limit_exceeded{limiter_type="ip"} 2
```

## Prometheus Configuration

Add this job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'mcp-oauth'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8080']
```

## Available Metrics

### HTTP Metrics
- `oauth_http_requests_total{method, endpoint, status}` - Total HTTP requests
- `oauth_http_request_duration_milliseconds{endpoint}` - Request duration histogram

### OAuth Flow Metrics  
- `oauth_authorization_started{client_id}` - Authorization flows started
- `oauth_callback_processed{client_id, success}` - Callbacks processed
- `oauth_code_exchanged{client_id, pkce_method}` - Codes exchanged for tokens
- `oauth_token_refreshed{client_id, rotated}` - Tokens refreshed
- `oauth_token_revoked{client_id}` - Tokens revoked
- `oauth_client_registered{client_type}` - Clients registered

### Security Metrics
- `oauth_rate_limit_exceeded{limiter_type}` - Rate limit violations
- `oauth_pkce_validation_failed{method}` - PKCE validation failures
- `oauth_code_reuse_detected` - Authorization code reuse attempts
- `oauth_token_reuse_detected` - Refresh token reuse attempts

### Storage Metrics
- `storage_operation_total{operation, result}` - Storage operations count
- `storage_operation_duration_milliseconds{operation}` - Storage operation latency
- `storage_tokens_count` - Current tokens in storage (gauge)
- `storage_clients_count` - Current clients registered (gauge)
- `storage_flows_count` - Current active authorization flows (gauge)
- `storage_families_count` - Current token families tracked (gauge)
- `storage_refresh_tokens_count` - Current refresh tokens (gauge)

### Provider Metrics
- `provider_api_calls_total{provider, operation, status}` - Provider API calls
- `provider_api_duration_milliseconds{provider, operation}` - Provider API latency
- `provider_api_errors_total{provider, operation, error_type}` - Provider API errors

## Example Prometheus Queries

Monitor request rate:
```promql
rate(oauth_http_requests_total[5m])
```

Calculate error rate:
```promql
rate(oauth_http_requests_total{status=~"5.."}[5m]) 
/ 
rate(oauth_http_requests_total[5m])
```

Monitor storage growth:
```promql
storage_tokens_count
```

Track security incidents:
```promql
rate(oauth_rate_limit_exceeded[5m])
```

Monitor token refresh success rate:
```promql
rate(oauth_token_refreshed{success="true"}[5m])
```

## Alerting Examples

Add these alerts to your Prometheus `alerts.yml`:

```yaml
groups:
  - name: oauth
    rules:
      - alert: HighErrorRate
        expr: |
          rate(oauth_http_requests_total{status=~"5.."}[5m]) 
          / 
          rate(oauth_http_requests_total[5m]) > 0.05
        for: 5m
        annotations:
          summary: "High error rate detected"

      - alert: RateLimitAttack
        expr: rate(oauth_rate_limit_exceeded[5m]) > 10
        for: 2m
        annotations:
          summary: "Potential DoS attack detected"

      - alert: TokenReuseDetected
        expr: increase(oauth_token_reuse_detected[5m]) > 0
        for: 1m
        annotations:
          summary: "Token reuse attack detected"
          severity: critical

      - alert: StorageGrowth
        expr: storage_tokens_count > 10000
        for: 10m
        annotations:
          summary: "Storage growing unusually fast"
```

## Grafana Dashboard

Import the included Grafana dashboard JSON to visualize all metrics.

## Learn More

- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)

