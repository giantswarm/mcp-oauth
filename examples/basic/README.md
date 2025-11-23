# Basic OAuth Example

This example demonstrates a minimal OAuth 2.1 setup for an MCP server.

## Prerequisites

1. **Google OAuth Credentials**:
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a project and enable required APIs
   - Create OAuth 2.0 credentials (Web application)
   - Add redirect URI: `http://localhost:8080/oauth/google/callback`
   - Copy Client ID and Client Secret

## Running the Example

1. **Set environment variables**:
   ```bash
   export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
   export GOOGLE_CLIENT_SECRET="your-client-secret"
   ```

2. **Run the server**:
   ```bash
   go run main.go
   ```

3. **Register a client** (in another terminal):
   ```bash
   curl -X POST http://localhost:8080/oauth/register \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "My Test Client",
       "client_type": "public",
       "redirect_uris": ["http://localhost:3000/callback"],
       "token_endpoint_auth_method": "none",
       "grant_types": ["authorization_code", "refresh_token"],
       "scope": "https://www.googleapis.com/auth/gmail.readonly"
     }'
   ```

   Save the returned `client_id` for the next step.

4. **Start authorization flow**:
   
   Open in browser (replace `CLIENT_ID` with the one from step 3):
   ```
   http://localhost:8080/oauth/authorize?client_id=CLIENT_ID&redirect_uri=http://localhost:3000/callback&scope=https://www.googleapis.com/auth/gmail.readonly&state=random-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&response_type=code
   ```

5. **Exchange code for token**:
   
   After authorization, you'll get a code in the redirect. Exchange it:
   ```bash
   curl -X POST http://localhost:8080/oauth/token \
     -d "grant_type=authorization_code" \
     -d "code=AUTHORIZATION_CODE" \
     -d "redirect_uri=http://localhost:3000/callback" \
     -d "client_id=CLIENT_ID" \
     -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
   ```

6. **Access protected endpoint**:
   ```bash
   curl http://localhost:8080/mcp \
     -H "Authorization: Bearer ACCESS_TOKEN"
   ```

## Features Demonstrated

- ✅ Basic OAuth configuration
- ✅ Google OAuth integration
- ✅ Client registration
- ✅ Token validation middleware
- ✅ User info extraction
- ✅ Metadata endpoints

## Next Steps

See the [production example](../production) for:
- Token encryption at rest
- Rate limiting
- Comprehensive audit logging
- Production-ready security settings

