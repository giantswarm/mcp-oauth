package oauthconfig

import (
	"log/slog"

	"github.com/giantswarm/mcp-oauth/server"
)

// LogStartupWarnings emits operator-facing warnings for security-sensitive
// *server.Config flags that are easy to leave enabled by mistake:
//
//   - AllowInsecureHTTP — the OAuth issuer is running over plain HTTP.
//   - AllowPublicClientRegistration — anyone on the network can register a
//     client without a registration token.
//
// Call once after building the config and before starting request handling.
// Each warning fires at most once per call (the helper is not request-scoped).
//
// Consumers (mcp-observability-platform, muster, mcp-prometheus) previously
// rolled the same two slog.Warn calls in their own startup code; centralizing
// the wording here keeps the operator message consistent across mcp-oauth
// deployments.
//
// nil cfg or nil logger returns silently — convenient for callers that want
// to defer the helper unconditionally.
func LogStartupWarnings(cfg *server.Config, logger *slog.Logger) {
	if cfg == nil || logger == nil {
		return
	}
	if cfg.AllowInsecureHTTP {
		logger.Warn(
			"OAUTH_ALLOW_INSECURE_HTTP=true: OAuth server is running over plain HTTP. Disable in production by removing the env var or setting it to false.",
			"issuer", cfg.Issuer,
		)
	}
	if cfg.AllowPublicClientRegistration {
		logger.Warn(
			"OAUTH_ALLOW_PUBLIC_CLIENT_REGISTRATION=true: any client on the network can register without a registration token. Disable in production and configure OAUTH_REGISTRATION_ACCESS_TOKEN instead.",
		)
	}
}
