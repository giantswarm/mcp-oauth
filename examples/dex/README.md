# Dex OAuth Provider Example

This example demonstrates how to use the Dex OAuth provider with the `mcp-oauth` library.

## Features Demonstrated

- **OIDC Discovery**: Automatically discovers Dex authorization and token endpoints
- **Connector ID Support**: Optional parameter to bypass Dex's connector selection UI
- **Groups Claim**: Retrieves user group memberships from Dex
- **Refresh Token Rotation**: Properly handles Dex's strict refresh token rotation
- **Protected Resources**: Demonstrates group-based access control

## Prerequisites

1. **Running Dex Instance**: You need a Dex server running and accessible
2. **Dex Client Configuration**: Register this application as an OAuth client in Dex

### Dex Configuration Example

Add this client to your Dex configuration:

```yaml
# dex-config.yaml
staticClients:
  - id: demo-client
    secret: demo-secret
    name: 'Dex OAuth Example'
    redirectURIs:
      - 'http://localhost:8080/oauth/callback'

connectors:
  - type: github
    id: github
    name: GitHub
    config:
      clientID: $GITHUB_CLIENT_ID
      clientSecret: $GITHUB_CLIENT_SECRET
      redirectURI: https://dex.example.com/callback
      orgs:
        - name: your-org
```

## Environment Variables

Set the following environment variables before running the example:

```bash
# Required
export DEX_ISSUER_URL="https://dex.example.com"     # Your Dex issuer URL
export DEX_CLIENT_ID="demo-client"                   # OAuth client ID
export DEX_CLIENT_SECRET="demo-secret"               # OAuth client secret

# Optional
export DEX_CONNECTOR_ID="github"                     # Skip connector selection (use specific connector)
```

## Running the Example

### Option 1: Using go run

```bash
go run main.go
```

### Option 2: Build and run

```bash
go build -o dex-example
./dex-example
```

The server will start on http://localhost:8080

## Usage

1. **Visit the home page**: Open http://localhost:8080 in your browser

2. **Sign in**: Click the "Sign in with Dex" button

3. **Connector Selection** (if DEX_CONNECTOR_ID not set):
   - Dex will show a list of configured connectors (GitHub, LDAP, etc.)
   - Choose your preferred authentication method

4. **Connector Selection** (if DEX_CONNECTOR_ID is set):
   - You'll be redirected directly to the specified connector
   - No connector selection screen will be shown

5. **Authenticate**: Complete authentication with your chosen provider

6. **Access Protected Resource**: Try accessing http://localhost:8080/api/resource
   - You need to be in the "developers" or "admins" group
   - The response will show your user information and groups

## What Makes This Dex-Specific?

### 1. Connector ID Parameter

The `DEX_CONNECTOR_ID` environment variable enables the Dex-specific feature to bypass the connector selection UI:

```go
dexProvider, err := dex.NewProvider(&dex.Config{
    IssuerURL:    issuerURL,
    ClientID:     clientID,
    ClientSecret: clientSecret,
    RedirectURL:  "http://localhost:8080/oauth/callback",
    ConnectorID:  connectorID, // Dex-specific: skip connector selection
})
```

### 2. Groups Claim

The provider automatically includes the `groups` scope in default scopes:

```go
// Default scopes (automatically included):
// - openid
// - profile
// - email
// - groups         <- Dex-specific
// - offline_access
```

### 3. Refresh Token Rotation

Dex enforces strict refresh token rotation. The provider handles this automatically by returning the new refresh token from each refresh operation.

## Group-Based Access Control

The example demonstrates how to use Dex group memberships for access control:

```go
// Check if user is in required group
hasAccess := false
for _, group := range userInfo.Groups {
    if group == "developers" || group == "admins" {
        hasAccess = true
        break
    }
}

if !hasAccess {
    http.Error(w, "Forbidden: requires 'developers' or 'admins' group", http.StatusForbidden)
    return
}
```

## Security Considerations

1. **HTTPS in Production**: This example uses HTTP for simplicity. In production:
   - Use HTTPS for all OAuth endpoints
   - Configure Dex with HTTPS
   - Update redirect URIs to use HTTPS

2. **Secret Management**: Don't hardcode secrets. In production:
   - Use environment variables (as shown)
   - Or use secret management systems (Vault, AWS Secrets Manager, etc.)

3. **Group Validation**: The groups claim is validated for security:
   - Maximum 100 groups per user
   - Maximum 256 characters per group name
   - Prevents memory exhaustion attacks

## Troubleshooting

### "OIDC discovery failed"
- Check that `DEX_ISSUER_URL` is correct and accessible
- Ensure Dex is running and reachable from your machine
- Verify the discovery document is available at `$DEX_ISSUER_URL/.well-known/openid-configuration`

### "Failed to exchange code"
- Verify `DEX_CLIENT_ID` and `DEX_CLIENT_SECRET` match your Dex configuration
- Check that the redirect URI in Dex config matches: `http://localhost:8080/oauth/callback`

### "Connector not found"
- If using `DEX_CONNECTOR_ID`, ensure the connector ID matches one in your Dex config
- Check Dex logs for connector configuration errors

### "Forbidden: requires developers or admins group"
- Your user account needs to be in the "developers" or "admins" group
- Check your identity provider's group configuration
- Verify Dex is configured to pass through group claims

## Related Documentation

- [Dex Documentation](https://dexidp.io/docs/)
- [Dex connector_id Parameter](https://dexidp.io/docs/configuration/custom-scopes-claims-clients/#authentication-through-connector_id)
- [Dex Refresh Token Rotation](https://dexidp.io/docs/configuration/custom-scopes-claims-clients/#refresh-token-rotation)
- [mcp-oauth Library Documentation](../../README.md)

