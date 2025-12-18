// Package main demonstrates OAuth setup with Prometheus metrics.
//
// This example shows how to expose OpenTelemetry metrics in Prometheus format
// for monitoring OAuth operations.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/providers/google"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func main() {
	// 1. Create a provider (Google in this case)
	googleProvider, err := google.NewProvider(&google.Config{
		ClientID:     getEnvOrFail("GOOGLE_CLIENT_ID"),
		ClientSecret: getEnvOrFail("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  getEnvOrDefault("GOOGLE_REDIRECT_URI", "http://localhost:8080/oauth/callback"),
		Scopes: []string{
			"openid",
			"email",
			"profile",
			"https://www.googleapis.com/auth/gmail.readonly",
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// 2. Create storage (in-memory for simplicity)
	store := memory.New()
	defer store.Stop()

	// 3. Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 4. Create OAuth server with Prometheus instrumentation enabled
	server, err := oauth.NewServer(
		googleProvider,
		store, // TokenStore
		store, // ClientStore
		store, // FlowStore
		&oauth.ServerConfig{
			Issuer:            "http://localhost:8080",
			AllowInsecureHTTP: true, // Required for HTTP on localhost (development only)

			// IMPORTANT: OpenTelemetry instrumentation with Prometheus metrics
			Instrumentation: oauth.InstrumentationConfig{
				Enabled:         true,
				ServiceName:     "mcp-oauth-prometheus-example",
				ServiceVersion:  "1.0.0",
				LogClientIPs:    getBoolEnv("LOG_CLIENT_IPS", false), // Privacy: disabled by default
				MetricsExporter: "prometheus",                        // Export metrics in Prometheus format
			},
		},
		logger,
	)
	if err != nil {
		log.Fatal(err)
	}

	// 5. Add rate limiting to demonstrate security metrics
	// 1 request per second with burst of 10 = ~60 requests per minute
	rateLimiter := security.NewRateLimiter(1, 10, logger)
	server.SetRateLimiter(rateLimiter)
	logger.Info("Rate limiting enabled", "requests_per_second", 1, "burst", 10)

	// 6. Add audit logging for security events
	auditor := security.NewAuditor(logger, true)
	server.SetAuditor(auditor)
	logger.Info("Audit logging enabled")

	// 7. Optional: Add token encryption
	if encKeyB64 := os.Getenv("OAUTH_ENCRYPTION_KEY"); encKeyB64 != "" {
		encKey, err := security.KeyFromBase64(encKeyB64)
		if err != nil {
			log.Fatalf("Invalid encryption key: %v", err)
		}
		encryptor, _ := security.NewEncryptor(encKey)
		server.SetEncryptor(encryptor)
		logger.Info("Token encryption enabled")
	}

	// 8. Set up HTTP handlers
	handler := oauth.NewHandler(server, logger)
	mux := http.NewServeMux()

	// OAuth endpoints
	mux.HandleFunc("/oauth/authorize", handler.ServeAuthorization)
	mux.HandleFunc("/oauth/callback", handler.ServeCallback)
	mux.HandleFunc("/oauth/token", handler.ServeToken)
	mux.HandleFunc("/oauth/revoke", handler.ServeTokenRevocation)
	mux.HandleFunc("/oauth/introspect", handler.ServeTokenIntrospection)
	mux.HandleFunc("/oauth/register", handler.ServeClientRegistration)

	// Metadata endpoints (multi-tenant aware)
	handler.RegisterAuthorizationServerMetadataRoutes(mux)

	// PROMETHEUS METRICS ENDPOINT
	// This exposes all OpenTelemetry metrics in Prometheus format
	mux.Handle("/metrics", promhttp.Handler())
	logger.Info("Prometheus metrics endpoint enabled", "url", "http://localhost:8080/metrics")

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy"}`)
	})

	// Home page with links
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
    <title>OAuth Server with Prometheus Metrics</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        .endpoint { background: #f4f4f4; padding: 10px; margin: 10px 0; border-left: 4px solid #007bff; }
        .code { font-family: monospace; background: #eee; padding: 2px 6px; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>🔒 OAuth 2.1 Server with Prometheus Metrics</h1>
    <p>This server demonstrates OpenTelemetry instrumentation with Prometheus metrics export.</p>
    
    <h2>📊 Metrics Endpoint</h2>
    <div class="endpoint">
        <strong>Prometheus Metrics:</strong> <a href="/metrics">/metrics</a><br>
        <small>Scrape this endpoint with Prometheus to collect metrics</small>
    </div>

    <h2>🔐 OAuth Endpoints</h2>
    <div class="endpoint">
        <strong>Start OAuth Flow:</strong> <span class="code">GET /oauth/authorize?client_id=YOUR_CLIENT&redirect_uri=YOUR_URI&scope=openid email&state=STATE&code_challenge=CHALLENGE&code_challenge_method=S256</span>
    </div>
    <div class="endpoint">
        <strong>Register Client:</strong> <span class="code">POST /oauth/register</span>
    </div>
    <div class="endpoint">
        <strong>Metadata:</strong> <a href="/.well-known/oauth-authorization-server">/.well-known/oauth-authorization-server</a>
    </div>

    <h2>📈 Example Metrics Queries</h2>
    <pre>
# Monitor request rate
rate(oauth_http_requests_total[5m])

# Track storage size
storage_tokens_count

# Security incidents
rate(oauth_rate_limit_exceeded[5m])

# Error rate
rate(oauth_http_requests_total{status=~"5.."}[5m]) 
/ 
rate(oauth_http_requests_total[5m])
    </pre>

    <h2>🚀 Getting Started</h2>
    <ol>
        <li>Configure Prometheus to scrape <span class="code">http://localhost:8080/metrics</span></li>
        <li>Register a client via <span class="code">POST /oauth/register</span></li>
        <li>Start an OAuth flow using the registered client</li>
        <li>View metrics in Prometheus or Grafana</li>
    </ol>
</body>
</html>
		`)
	})

	// 9. Start HTTP server with graceful shutdown
	httpServer := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to listen for interrupt signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		logger.Info("OAuth server starting",
			"addr", "http://localhost:8080",
			"metrics", "http://localhost:8080/metrics")
		logger.Info("Press Ctrl+C to stop")

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server error", "error", err)
		}
	}()

	// Wait for interrupt signal
	<-stop
	logger.Info("Shutting down gracefully...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown error", "error", err)
	}

	// Shutdown OAuth server (stops rate limiters, cleanup goroutines, etc.)
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("OAuth server shutdown error", "error", err)
	}

	logger.Info("Server stopped")
}

func getEnvOrFail(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Environment variable %s is required", key)
	}
	return value
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}
