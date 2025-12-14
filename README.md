# mcp-oauth

A **provider-agnostic** OAuth 2.1 Authorization Server library for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers, with support for multiple identity providers.

## MCP Specification Compliance

| Specification Version | Support Status | Documentation |
|-----------------------|----------------|---------------|
| [2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | Full Support | [Migration Guide](./docs/mcp-2025-11-25.md) |
| 2025-06-18 (previous) | Full Support | Backward compatible |

## Key Features

- **Provider Abstraction** - Google, GitHub, and Dex OAuth built-in, easy to add custom providers
- **Storage Abstraction** - In-memory storage included, simple interface for custom backends
- **OAuth 2.1 Security** - PKCE enforcement, refresh token rotation, secure defaults
- **MCP 2025-11-25** - Protected Resource Metadata (RFC 9728), scope discovery, resource binding
- **Client ID Metadata Documents** - URL-based client IDs with dynamic metadata discovery
- **Observability** - OpenTelemetry instrumentation with Prometheus and OTLP support

## Architecture

```
┌─────────────────┐
│   Your MCP App  │
└────────┬────────┘
         │
    ┌────▼─────┐
    │ Handler  │  HTTP layer
    └────┬─────┘
         │
    ┌────▼─────┐
    │  Server  │  Business logic
    └──┬───┬───┘
       │   │
   ┌───▼┐ ┌▼────────┐
   │Pro-│ │ Storage │
   │vider│ │         │
   └────┘ └─────────┘
```

- **Handler**: HTTP request/response handling
- **Server**: OAuth business logic (provider-agnostic)
- **Provider**: Identity provider integration (Google, GitHub, Dex, or custom)
- **Storage**: Token/client/flow persistence

## Quick Start

```go
package main

import (
    "net/http"
    "os"

    oauth "github.com/giantswarm/mcp-oauth"
    "github.com/giantswarm/mcp-oauth/providers/google"
    "github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
    // 1. Choose a provider
    provider, _ := google.NewProvider(&google.Config{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:8080/oauth/callback",
        Scopes:       []string{"openid", "email", "profile"},
    })

    // 2. Choose storage
    store := memory.New()
    defer store.Stop()

    // 3. Create OAuth server
    server, _ := oauth.NewServer(
        provider,
        store, // TokenStore
        store, // ClientStore
        store, // FlowStore
        &oauth.ServerConfig{
            Issuer: "http://localhost:8080",
        },
        nil,
    )

    // 4. Create HTTP handler and routes
    handler := oauth.NewHandler(server, nil)
    mux := http.NewServeMux()
    
    handler.RegisterProtectedResourceMetadataRoutes(mux, "/mcp")
    mux.Handle("/mcp", handler.ValidateToken(yourMCPHandler))

    http.ListenAndServe(":8080", mux)
}
```

## Installation

```bash
go get github.com/giantswarm/mcp-oauth
```

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](./docs/getting-started.md) | Installation, providers, storage, first OAuth server |
| [Configuration](./docs/configuration.md) | All configuration options, CORS, interstitial pages, proxy settings |
| [Security Guide](./docs/security.md) | Security features, best practices, production checklist |
| [Observability](./docs/observability.md) | OpenTelemetry, Prometheus metrics, distributed tracing |
| [Discovery Mechanisms](./docs/discovery.md) | OAuth discovery (RFC 8414, RFC 9728) |
| [MCP 2025-11-25](./docs/mcp-2025-11-25.md) | New specification features and migration |
| [Client ID Metadata Documents](./docs/cimd.md) | URL-based client IDs with dynamic metadata discovery |
| [Security Architecture](./SECURITY_ARCHITECTURE.md) | Deep-dive into security implementation |

## Examples

The [`examples/`](./examples) directory contains runnable examples:

- **[basic](./examples/basic)** - Minimal setup with Google
- **[github](./examples/github)** - GitHub OAuth with organization restriction
- **[dex](./examples/dex)** - Dex provider with connector_id and groups support
- **[production](./examples/production)** - Full security features
- **[custom-scopes](./examples/custom-scopes)** - Endpoint-specific scope requirements
- **[mcp-2025-11-25](./examples/mcp-2025-11-25)** - New MCP specification features
- **[cimd](./examples/cimd)** - Client ID Metadata Documents (URL-based client IDs)
- **[prometheus](./examples/prometheus)** - Observability integration

## Security

This library implements OAuth 2.1 with secure defaults:

- PKCE required (S256 only)
- Refresh token rotation with reuse detection
- Token encryption at rest (AES-256-GCM)
- Rate limiting and audit logging

### Secret Management (CRITICAL for Production)

**NEVER use environment variables for production secrets!**

Production deployments **MUST** use a secret manager:
- **HashiCorp Vault** (recommended for Kubernetes)
- **AWS Secrets Manager** (for AWS deployments)
- **Google Cloud Secret Manager** (for GCP deployments)
- **Azure Key Vault** (for Azure deployments)

**NEVER:**
- Use environment variables for secrets in production
- Hardcode secrets in code or configuration files
- Commit secrets to version control
- Store secrets in container images or Dockerfiles

See [Production Example - Secret Management](./examples/production/README.md#secret-management-required-for-production) for implementation guidance and examples.

### Documentation

See the [Security Guide](./docs/security.md) for configuration and the [Security Architecture](./SECURITY_ARCHITECTURE.md) for implementation details.

**Vulnerability Reporting**: See [SECURITY.md](./SECURITY.md) for responsible disclosure.

## Contributing

Contributions welcome. Especially:

- New provider implementations
- Storage backends
- Security enhancements

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0
