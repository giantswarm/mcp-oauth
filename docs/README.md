# Documentation

This folder contains the documentation for the mcp-oauth library.

## Guides

| Document | Description |
|----------|-------------|
| [Getting Started](./getting-started.md) | Installation, providers, storage, first OAuth server |
| [Configuration](./configuration.md) | All configuration options, CORS, interstitial pages, proxy settings |
| [Security](./security.md) | Security features, best practices, production checklist |
| [Silent Authentication](./silent-authentication.md) | `prompt=none` silent re-auth with interactive fallback |
| [Observability](./observability.md) | OpenTelemetry, Prometheus metrics, distributed tracing |

## Reference

| Document | Description |
|----------|-------------|
| [Discovery Mechanisms](./discovery.md) | OAuth discovery (RFC 8414, RFC 9728), WWW-Authenticate |
| [MCP 2025-11-25](./mcp-2025-11-25.md) | New MCP specification features and migration |
| [Client ID Metadata Documents](./cimd.md) | URL-based client IDs with dynamic metadata discovery |
| [Security Architecture](../SECURITY_ARCHITECTURE.md) | Deep technical security implementation details |

## Security Assessments

| Document | Description |
|----------|-------------|
| [Security Assessment (Claude Opus 4.5)](./security-assessment-opus-4.5.md) | Comprehensive security assessment by Claude Opus 4.5 (January 2026) |
| [Security Assessment (GPT-5.2-Codex)](./security-assessment-gpt-5.2-codex.md) | Security assessment with high-severity finding on refresh token binding |
| [Security Assessment (Gemini 3 Pro)](./security-assessment-gemini-3-pro.md) | Security assessment focusing on compliance and infrastructure |

## Quick Links

- [README](../README.md) - Project overview
- [Examples](../examples/) - Runnable examples
- [API Reference](https://pkg.go.dev/github.com/giantswarm/mcp-oauth) - Godoc
- [Changelog](../CHANGELOG.md) - Version history
