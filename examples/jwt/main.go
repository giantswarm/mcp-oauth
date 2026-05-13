// Package main demonstrates the AccessTokenFormatJWT mode of mcp-oauth.
//
// On startup the example generates an ephemeral RSA key — convenient for
// local experiments, NOT suitable for production. A real deployment would
// load the key from a mounted Kubernetes Secret, an HSM, or a cloud KMS.
//
// The server publishes its public key at /.well-known/jwks.json so an
// MCP-aware proxy (e.g. agentgateway) can verify access tokens locally
// without an introspection round-trip per request.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	oauth "github.com/giantswarm/mcp-oauth"
	oauthhandler "github.com/giantswarm/mcp-oauth/handler"
	"github.com/giantswarm/mcp-oauth/providers/dex"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
	issuerURL := os.Getenv("DEX_ISSUER_URL")
	if issuerURL == "" {
		log.Fatal("DEX_ISSUER_URL environment variable is required")
	}
	clientID := os.Getenv("DEX_CLIENT_ID")
	if clientID == "" {
		log.Fatal("DEX_CLIENT_ID environment variable is required")
	}
	clientSecret := os.Getenv("DEX_CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatal("DEX_CLIENT_SECRET environment variable is required")
	}
	connectorID := os.Getenv("DEX_CONNECTOR_ID")

	dexProvider, err := dex.NewProvider(&dex.Config{
		IssuerURL:    issuerURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:8080/oauth/callback",
		ConnectorID:  connectorID,
	})
	if err != nil {
		log.Fatalf("Failed to create Dex provider: %v", err)
	}

	// Generate an ephemeral signing key on startup. Production deployments
	// must load the key from a mounted Secret, HSM, or KMS instead — see
	// SECURITY_ARCHITECTURE.md → Access Token Format Modes → Key management.
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate signing key: %v", err)
	}
	keyID := fmt.Sprintf("ephemeral-%d", time.Now().Unix())

	store := memory.New()
	defer store.Stop()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	srv, err := oauth.NewServer(
		dexProvider,
		store, store, store,
		&oauth.ServerConfig{
			Issuer:                      "http://localhost:8080",
			ResourceIdentifier:          "http://localhost:8080",
			AllowInsecureHTTP:           true, // localhost only — required for HTTP issuer
			AccessTokenTTL:              900,  // 15 min, recommended for stateless JWT mode
			AccessTokenFormat:           server.AccessTokenFormatJWT,
			AccessTokenSigningKey:       signingKey,
			AccessTokenSigningKeyID:     keyID,
			AccessTokenSigningAlgorithm: server.SigningAlgorithmRS256,
		},
		logger,
	)
	if err != nil {
		log.Fatalf("Failed to create OAuth server: %v", err)
	}

	handler := oauthhandler.New(srv, logger)
	mux := http.NewServeMux()
	handler.RegisterOAuthRoutes(mux, oauthhandler.OAuthRoutesOptions{IncludeMetadata: true})

	// Protected echo endpoint — wraps ValidateToken so the JWT is verified
	// locally on every request (signature + typ + iss + exp + aud + jti +
	// family) before the handler runs.
	mux.Handle("/api/whoami", handler.ValidateToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userInfo, _ := oauthhandler.UserInfoFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":          userInfo.ID,
			"email":        userInfo.Email,
			"groups":       userInfo.Groups,
			"token_source": userInfo.TokenSource,
		})
	})))

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, indexHTML, keyID)
	})

	log.Printf("Listening on :8080")
	log.Printf("JWKS: http://localhost:8080/.well-known/jwks.json (kid=%s)", keyID)
	log.Printf("Discovery: http://localhost:8080/.well-known/oauth-authorization-server")
	if err := http.ListenAndServe(":8080", mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("Server failed: %v", err)
	}
}

const indexHTML = `<!DOCTYPE html>
<html><head><title>mcp-oauth JWT mode example</title></head>
<body style="font-family:sans-serif;max-width:760px;margin:40px auto;padding:0 16px">
<h1>mcp-oauth JWT mode example</h1>
<p>This example issues access tokens as signed JWTs (RFC 9068) and publishes the public key as a JWKS for local validation.</p>
<p>Active signing key id (ephemeral, regenerated on each restart): <code>%s</code></p>
<h2>Try it</h2>
<ol>
  <li>Start the auth flow: <a href="/oauth/authorize?client_id=demo-client&response_type=code&scope=openid+profile+email+groups&state=demo&redirect_uri=http://localhost:8080/oauth/callback">/oauth/authorize</a></li>
  <li>Inspect the issued JWT at <a href="https://jwt.io">jwt.io</a> — note <code>typ:"at+jwt"</code> and the <code>jti</code> claim</li>
  <li>Fetch the JWKS: <a href="/.well-known/jwks.json">/.well-known/jwks.json</a></li>
  <li>Hit the protected endpoint with the bearer: <code>curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/whoami</code></li>
  <li>Revoke: <code>curl -X POST -d "token=$TOKEN" http://localhost:8080/oauth/revoke</code> — subsequent calls return 401</li>
</ol>
</body></html>`
