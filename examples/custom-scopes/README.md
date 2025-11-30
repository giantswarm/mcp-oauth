# Custom Scopes Example

This example demonstrates how to configure OAuth with multiple Google API scopes for different services.

## Security Warning

**This example uses environment variables for secrets for simplicity. This is NOT SECURE for production use.**

For production deployments:
- Use a secret manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)
- See the [Production Example](../production/README.md#secret-management-required-for-production) for secure patterns
- NEVER commit secrets to version control
- NEVER use environment variables for secrets in production

**This is a development/learning example only.**

## Google API Scopes

This example supports the following Google services:

### Gmail API
- `gmail.readonly` - Read emails
- `gmail.modify` - Read and modify emails
- `gmail.labels` - Manage labels
- `gmail.metadata` - Read metadata only

### Google Drive API
- `drive.readonly` - Read files
- `drive.file` - Read and write files created by the app
- `drive.metadata.readonly` - Read file metadata

### Google Calendar API
- `calendar.readonly` - Read calendar events
- `calendar.events.readonly` - Read event details only

### Google Contacts API
- `contacts.readonly` - Read contacts

### User Info
- `userinfo.email` - User's email address
- `userinfo.profile` - User's profile information

## Setup

### 1. Enable Google APIs

Go to [Google Cloud Console](https://console.cloud.google.com/) and enable:
- Gmail API
- Google Drive API
- Google Calendar API
- Google People API (for Contacts)

### 2. Configure OAuth Consent Screen

1. Go to "APIs & Services" > "OAuth consent screen"
2. Add the scopes you need
3. Add test users (if in testing mode)

### 3. Set Environment Variables

```bash
export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-client-secret"
```

### 4. Run the Server

```bash
go run main.go
```

## Usage

### Register a Client

```bash
curl -X POST http://localhost:8080/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Multi-Scope Client",
    "client_type": "public",
    "redirect_uris": ["http://localhost:3000/callback"],
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/calendar.readonly"
  }'
```

Save the `client_id` from the response.

### Start Authorization Flow

**For Gmail access:**
```
http://localhost:8080/oauth/authorize?client_id=CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=https://www.googleapis.com/auth/gmail.readonly&state=random&code_challenge=CHALLENGE&code_challenge_method=S256&response_type=code
```

**For multiple scopes (space-separated, URL-encoded):**
```
http://localhost:8080/oauth/authorize?client_id=CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=https://www.googleapis.com/auth/gmail.readonly%20https://www.googleapis.com/auth/drive.readonly%20https://www.googleapis.com/auth/calendar.readonly&state=random&code_challenge=CHALLENGE&code_challenge_method=S256&response_type=code
```

### Access Different APIs

After obtaining an access token:

**Gmail API:**
```bash
curl http://localhost:8080/api/gmail \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

**Google Drive API:**
```bash
curl http://localhost:8080/api/drive \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

**Google Calendar API:**
```bash
curl http://localhost:8080/api/calendar \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

**Google Contacts API:**
```bash
curl http://localhost:8080/api/contacts \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## Scope Selection Best Practices

### Principle of Least Privilege

Only request scopes you actually need:

```go
// Bad: Requesting too many scopes
SupportedScopes: []string{
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",  // Don't need this
    "https://www.googleapis.com/auth/drive",         // Too broad
}

// Good: Request only what you need
SupportedScopes: []string{
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
}
```

### Incremental Authorization

Request additional scopes when needed:

1. Start with minimal scopes (email, profile)
2. Request additional scopes when user accesses features
3. Update the authorization URL with new scopes

### Scope Descriptions

When requesting scopes, Google shows descriptions to users:

| Scope | User Sees |
|-------|-----------|
| `gmail.readonly` | "Read your email messages and settings" |
| `drive.readonly` | "See and download all your Google Drive files" |
| `calendar.readonly` | "See your calendar events" |
| `contacts.readonly` | "See your contacts" |

## Common Scope Combinations

### Email Client (Read-Only)
```go
[]string{
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
}
```

### Email Client (Full Access)
```go
[]string{
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.email",
}
```

### Document Manager
```go
[]string{
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/userinfo.email",
}
```

### Calendar Integration
```go
[]string{
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
}
```

### Full Productivity Suite
```go
[]string{
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/contacts.readonly",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
}
```

## Calling Google APIs

After receiving the access token, you can call Google APIs:

```go
func callGmailAPI(accessToken string) {
    client := &http.Client{}
    req, _ := http.NewRequest("GET", 
        "https://gmail.googleapis.com/gmail/v1/users/me/messages", nil)
    req.Header.Add("Authorization", "Bearer "+accessToken)
    
    resp, err := client.Do(req)
    // Handle response...
}
```

Or use the official Google API client:

```go
import "google.golang.org/api/gmail/v1"

func getEmails(accessToken string) {
    ctx := context.Background()
    config := &oauth2.Config{...}
    token := &oauth2.Token{AccessToken: accessToken}
    client := config.Client(ctx, token)
    
    srv, err := gmail.New(client)
    messages, err := srv.Users.Messages.List("me").Do()
    // Process messages...
}
```

## Troubleshooting

### Scope Not Granted

If a scope isn't granted:
1. Check if the API is enabled in Google Cloud Console
2. Verify the scope is in the OAuth consent screen
3. Ensure the user approved the scope during authorization

### Invalid Scope Error

If you get "invalid_scope" error:
1. Verify scope URL is correct (check for typos)
2. Ensure scope is enabled in Google Cloud Console
3. Check if scope requires verification (some scopes need Google approval)

### Access Denied

If the user denies access to a scope:
1. The entire authorization request fails
2. Request only essential scopes initially
3. Use incremental authorization for optional features

## Resources

- [Google OAuth 2.0 Scopes](https://developers.google.com/identity/protocols/oauth2/scopes)
- [Gmail API Scopes](https://developers.google.com/gmail/api/auth/scopes)
- [Drive API Scopes](https://developers.google.com/drive/api/guides/api-specific-auth)
- [Calendar API Scopes](https://developers.google.com/calendar/api/auth)
- [People API Scopes](https://developers.google.com/people/api/rest/v1/people/get)

