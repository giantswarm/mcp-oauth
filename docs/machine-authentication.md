# Machine Authentication Guide

This guide covers authenticating Kubernetes service accounts and other machine identities using OAuth token exchange via Dex.

## Contents

1. [Overview](#overview)
2. [How It Works](#how-it-works)
3. [Configuration](#configuration)
4. [Dex Setup](#dex-setup)
5. [Client Implementation](#client-implementation)
6. [Synthetic Identity Enrichment](#synthetic-identity-enrichment)
7. [Security Considerations](#security-considerations)

## Overview

Machine authentication enables workloads running in Kubernetes (or other OIDC-enabled environments) to authenticate using their service account tokens. This is achieved through [OAuth 2.0 Token Exchange (RFC 8693)](https://datatracker.ietf.org/doc/html/rfc8693), where a machine exchanges its existing token for a Dex-issued token.

**Use Cases:**
- CI/CD pipelines authenticating to MCP servers
- Kubernetes operators accessing protected APIs
- Background jobs that need user-like authentication
- Service-to-service authentication with identity propagation

## How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   K8s Service   │     │       Dex       │     │   mcp-oauth     │
│    Account      │     │                 │     │   Protected     │
│                 │     │                 │     │      API        │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  1. SA Token (JWT)    │                       │
         │ ─────────────────────>│                       │
         │                       │                       │
         │  2. Token Exchange    │                       │
         │  (Dex validates with  │                       │
         │   K8s OIDC issuer)    │                       │
         │                       │                       │
         │  3. Dex Access Token  │                       │
         │ <─────────────────────│                       │
         │                       │                       │
         │                       │  4. API Request       │
         │                       │  + Bearer Token       │
         │ ──────────────────────────────────────────────>
         │                       │                       │
         │                       │  5. Validate Token    │
         │                       │ <──────────────────── │
         │                       │                       │
         │                       │  6. UserInfo          │
         │                       │ ─────────────────────>│
         │                       │                       │
         │                       │  7. Enrich Identity   │
         │                       │  (synthetic email +   │
         │                       │   derived groups)     │
         │                       │                       │
         │                       │  8. API Response      │
         │ <──────────────────────────────────────────────
```

**Flow Explanation:**

1. **Service Account Token**: Kubernetes injects a projected service account token (JWT) into the pod
2. **Token Exchange**: The application exchanges this token with Dex using the `urn:ietf:params:oauth:grant-type:token-exchange` grant type
3. **Dex Token**: Dex validates the K8s token and issues a Dex access token
4. **API Request**: The application calls the mcp-oauth protected API with the Dex token
5-6. **Validation**: mcp-oauth validates the token by calling Dex's userinfo endpoint
7. **Enrichment**: If enabled, mcp-oauth enriches the identity with synthetic email and derived K8s groups
8. **Response**: API request succeeds with the enriched identity

## Configuration

### Enabling Machine Identity Support

```go
import (
    oauth "github.com/giantswarm/mcp-oauth"
    "github.com/giantswarm/mcp-oauth/server"
)

config := &server.Config{
    Issuer: "https://auth.example.com",
    
    // Enable machine identity enrichment
    MachineIdentity: server.MachineIdentityConfig{
        Enabled:      true,                       // Enable the feature
        EmailDomain:  "serviceaccount.local",     // Domain for synthetic emails (default)
        DeriveGroups: true,                       // Derive K8s groups from SA identity
    },
}

srv, err := oauth.NewServer(provider, tokenStore, clientStore, flowStore, config, logger)
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `Enabled` | bool | `false` | Enable machine identity support |
| `EmailDomain` | string | `serviceaccount.local` | Domain suffix for synthetic emails |
| `DeriveGroups` | bool | `true` | Derive K8s groups from SA identity (when `Enabled=true`) |

## Dex Setup

### 1. Configure Dex OIDC Connector for Kubernetes

Add an OIDC connector that trusts your Kubernetes OIDC issuer:

```yaml
# dex-config.yaml
connectors:
- type: oidc
  id: kubernetes
  name: Kubernetes
  config:
    # For in-cluster: Kubernetes API server's OIDC issuer
    issuer: https://kubernetes.default.svc.cluster.local
    # For EKS: https://oidc.eks.{region}.amazonaws.com/id/{cluster-id}
    # For GKE: https://container.googleapis.com/v1/projects/{project}/locations/{location}/clusters/{cluster}
    
    scopes:
      - openid
    
    # Map the 'sub' claim from K8s token
    userNameKey: sub
    
    # Required for token validation via userinfo endpoint
    getUserInfo: true
```

### 2. Enable Token Exchange Grant

```yaml
oauth2:
  grantTypes:
    - "authorization_code"
    - "refresh_token"
    - "urn:ietf:params:oauth:grant-type:token-exchange"  # Add this
```

### 3. Create a Static Client for Token Exchange

```yaml
staticClients:
  - name: SA Token Exchanger
    id: sa-exchanger
    secret: your-secret-here
    public: true  # Public client for token exchange
```

### Complete Dex Configuration Example

```yaml
issuer: https://dex.example.com

storage:
  type: sqlite3
  config:
    file: dex.db

web:
  http: 0.0.0.0:5556

oauth2:
  grantTypes:
    - "authorization_code"
    - "refresh_token"
    - "urn:ietf:params:oauth:grant-type:token-exchange"

connectors:
- type: oidc
  id: kubernetes
  name: Kubernetes
  config:
    issuer: https://kubernetes.default.svc.cluster.local
    scopes: [openid]
    userNameKey: sub
    getUserInfo: true

staticClients:
  - name: SA Exchanger
    id: sa-exchanger
    secret: ${DEX_SA_EXCHANGER_SECRET}
    public: true
```

## Client Implementation

### Go Example

```go
package main

import (
    "io"
    "net/http"
    "net/url"
    "os"
)

func main() {
    // Read the projected service account token
    saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
    if err != nil {
        panic(err)
    }

    // Exchange the token with Dex
    resp, err := http.PostForm("https://dex.example.com/token", url.Values{
        "grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
        "client_id":          {"sa-exchanger"},
        "client_secret":      {"your-secret"},
        "subject_token":      {string(saToken)},
        "subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
        "connector_id":       {"kubernetes"},
        "scope":              {"openid"},
    })
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    // Parse the response to get the Dex token
    // Use this token to call mcp-oauth protected APIs
    body, _ := io.ReadAll(resp.Body)
    // {"access_token":"...", "token_type":"bearer", "expires_in":86399}
}
```

### Kubernetes Deployment

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app
  namespace: default
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      serviceAccountName: my-app
      containers:
      - name: app
        image: my-app:latest
        volumeMounts:
        - name: token
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          readOnly: true
      volumes:
      - name: token
        projected:
          sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600
              audience: dex-sa-exchanger  # Match your Dex client ID
```

## Synthetic Identity Enrichment

When `MachineIdentity.Enabled=true`, mcp-oauth enriches machine identities that lack email and groups:

### Kubernetes Service Accounts

For identities with format `system:serviceaccount:namespace:name`:

| Field | Generated Value |
|-------|-----------------|
| Email | `{name}@{namespace}.serviceaccount.local` |
| Groups | `["system:serviceaccounts", "system:serviceaccounts:{namespace}", "system:authenticated"]` |

**Example:**

Input (from Dex):
```json
{
  "sub": "CjJzeXN0ZW06c2VydmljZWFjY291bnQ6b3JnLWdpYW50c3dhcm06Z3JpenpseS1zaG9vdBIKa3ViZXJuZXRlcw",
  "aud": "sa-exchanger"
}
```

Output (enriched UserInfo):
```json
{
  "id": "CjJzeXN0ZW06c2VydmljZWFjY291bnQ6b3JnLWdpYW50c3dhcm06Z3JpenpseS1zaG9vdBIKa3ViZXJuZXRlcw",
  "email": "grizzly-shoot@org-giantswarm.serviceaccount.local",
  "groups": [
    "system:serviceaccounts",
    "system:serviceaccounts:org-giantswarm",
    "system:authenticated"
  ]
}
```

### Dex Subject Encoding

Dex encodes federated identities as base64-encoded protobuf. The library automatically handles:
- Base64 decoding (standard and URL-safe variants)
- Protobuf parsing to extract the upstream subject
- K8s service account identity parsing

### Fallback for Non-K8s Identities

For machine identities that don't match the K8s service account format, a fallback email is generated:

```
{sanitized-sub}@machine.local
```

## Security Considerations

### 1. Token Exchange Scope

Configure Dex to limit the scopes available via token exchange. Service accounts typically don't need user scopes like `email` or `profile`.

### 2. Connector Isolation

Use a dedicated Dex connector for Kubernetes token exchange. This isolates machine authentication from user authentication.

### 3. Synthetic Email Domain

The `.local` TLD is reserved and cannot be registered, preventing:
- Email spoofing attacks
- Collision with real email addresses
- Phishing attempts using synthetic emails

### 4. Derived Groups

The derived groups (`system:serviceaccounts`, `system:serviceaccounts:{namespace}`, `system:authenticated`) match what Kubernetes assigns, ensuring:
- No privilege escalation
- Consistent authorization policies
- Compatibility with existing K8s RBAC

### 5. Audit Trail

Enable audit logging to track machine identity enrichment:

```go
auditor := security.NewAuditor(logger)
srv.SetAuditor(auditor)
```

Events logged:
- `machine_identity_enriched` - When a K8s SA identity is enriched

### 6. Opt-in Only

Machine identity enrichment is disabled by default (`Enabled: false`). Only enable it when you need to support service account authentication.

## Troubleshooting

### Token Exchange Fails

**Symptom:** `invalid_grant` error from Dex

**Checks:**
1. Verify the K8s OIDC issuer URL in Dex connector config
2. Ensure the SA token audience matches Dex's client ID
3. Check that `getUserInfo: true` is set in the connector config
4. Verify the token hasn't expired

### Empty Email/Groups After Validation

**Symptom:** UserInfo has empty email and groups

**Checks:**
1. Verify `MachineIdentity.Enabled: true` in config
2. Check if `DeriveGroups: true` is set
3. Ensure the sub claim is a valid K8s SA format
4. Check logs for "Enriched K8s service account identity" debug message

### Subject Not Recognized

**Symptom:** Identity not recognized as K8s service account

**Checks:**
1. Verify the sub claim follows K8s format: `system:serviceaccount:namespace:name`
2. For Dex tokens, ensure the sub is properly base64-encoded protobuf
3. Check that namespace and name follow K8s naming conventions (lowercase, alphanumeric, hyphens)

## Related Documentation

- [Dex Token Exchange Guide](https://dexidp.io/docs/guides/token-exchange/)
- [RFC 8693: OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [Kubernetes Projected Service Account Tokens](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection)

