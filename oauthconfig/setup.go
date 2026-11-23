package oauthconfig

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/giantswarm/mcp-oauth/handler"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/dex"
	"github.com/giantswarm/mcp-oauth/providers/github"
	"github.com/giantswarm/mcp-oauth/providers/google"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

// Settings contains resolved configuration. Exactly one provider must be set,
// or none when Server.DisableAuthorizationServer is true.
// Nil Valkey selects in-memory storage; persistent storage requires encryption.
// TrustedIssuers are the issuers whose JWTs are accepted besides the server's
// own tokens; see [TrustedIssuersFromEnv].
type Settings struct {
	Server          *server.Config
	TrustedIssuers  []server.TrustedIssuer
	Dex             *dex.Config
	Google          *google.Config
	GitHub          *github.Config
	RootCAFile      string
	Valkey          *valkey.Config
	Encryptor       *security.Encryptor
	Instrumentation *instrumentation.Instrumentation
	Logger          *slog.Logger
}

// Runtime contains the OAuth server and its routes.
// The caller owns HTTP registration and invokes cleanup after requests drain.
type Runtime struct {
	Server  *server.Server
	Handler *handler.Handler
}

// Setup constructs OAuth resources without reading environment variables.
// Cleanup is idempotent and also closes persistent storage connections.
func Setup(settings Settings, options ...server.Option) (*Runtime, func(context.Context) error, error) {
	if settings.Server == nil {
		return nil, nil, fmt.Errorf("OAuth server configuration is required")
	}
	if settings.Valkey != nil && settings.Encryptor == nil {
		return nil, nil, fmt.Errorf("persistent OAuth token storage requires encryption")
	}
	logger := settings.Logger
	if logger == nil {
		logger = slog.Default()
	}
	serverConfig := *settings.Server
	if err := applyRootCAs(&settings, &serverConfig); err != nil {
		return nil, nil, err
	}
	// Settings go first so that a caller's explicit options, such as
	// server.WithSubjectTokenValidator, take precedence.
	options = append([]server.Option{server.WithTrustedIssuers(settings.TrustedIssuers)}, options...)
	provider, err := configuredProvider(settings)
	if err != nil {
		return nil, nil, err
	}
	store, closeStore, err := configuredStorage(settings.Valkey, settings.Encryptor, settings.Instrumentation, logger)
	if err != nil {
		return nil, nil, err
	}
	if settings.Instrumentation != nil {
		options = append(options, server.WithInstrumentation(settings.Instrumentation))
	}
	authorizationServer, err := server.NewWithCombined(provider, store, &serverConfig, logger, options...)
	if err != nil {
		closeStore()
		return nil, nil, fmt.Errorf("OAuth server: %w", err)
	}
	var cleanupOnce sync.Once
	var cleanupError error
	cleanup := func(ctx context.Context) error {
		cleanupOnce.Do(func() {
			cleanupError = authorizationServer.Shutdown(ctx)
			if settings.Valkey != nil {
				closeStore()
			}
		})
		return cleanupError
	}
	return &Runtime{Server: authorizationServer, Handler: handler.New(authorizationServer, logger)}, cleanup, nil
}

// applyRootCAs points the provider and the forwarded-token JWKS client at
// RootCAFile, on copies so the caller's configuration stays unchanged.
func applyRootCAs(settings *Settings, serverConfig *server.Config) error {
	if settings.RootCAFile == "" {
		return nil
	}
	roots, err := LoadRootCAs(settings.RootCAFile)
	if err != nil {
		return err
	}
	serverConfig.JWKSRootCAs = roots
	if settings.Dex != nil {
		dexConfig := *settings.Dex
		dexConfig.RootCAs = roots
		settings.Dex = &dexConfig
	}
	return nil
}

func configuredStorage(configuration *valkey.Config, encryptor *security.Encryptor, telemetry *instrumentation.Instrumentation, logger *slog.Logger) (storage.Combined, func(), error) {
	if configuration == nil {
		store := memory.New(memory.WithEncryptor(encryptor), memory.WithInstrumentation(telemetry))
		return store, store.Stop, nil
	}
	if encryptor == nil {
		return nil, nil, fmt.Errorf("persistent OAuth token storage requires encryption")
	}
	valkeyConfig := *configuration
	if valkeyConfig.Logger == nil {
		valkeyConfig.Logger = logger
	}
	store, err := valkey.New(valkeyConfig, valkey.WithEncryptor(encryptor), valkey.WithInstrumentation(telemetry))
	if err != nil {
		return nil, nil, fmt.Errorf("OAuth storage: %w", err)
	}
	return store, store.Close, nil
}

func configuredProvider(settings Settings) (providers.Provider, error) {
	count := 0
	for _, present := range []bool{settings.Dex != nil, settings.Google != nil, settings.GitHub != nil} {
		if present {
			count++
		}
	}
	if settings.Server != nil && settings.Server.DisableAuthorizationServer {
		if count != 0 {
			return nil, fmt.Errorf("an OAuth provider configuration requires the authorization server")
		}
		return nil, nil
	}
	if count != 1 {
		return nil, fmt.Errorf("exactly one OAuth provider configuration is required")
	}
	switch {
	case settings.Dex != nil:
		return dex.NewProvider(settings.Dex)
	case settings.Google != nil:
		return google.NewProvider(settings.Google)
	default:
		return github.NewProvider(settings.GitHub)
	}
}

// LoadRootCAs adds an operator's PEM bundle to system trust.
// An empty path returns nil, selecting system trust in TLS clients.
func LoadRootCAs(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(caFile) // #nosec G304 G703 -- operator-configured CA bundle
	if err != nil {
		return nil, fmt.Errorf("read OAuth CA bundle: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("OAuth CA bundle contains no certificates")
	}
	return roots, nil
}
