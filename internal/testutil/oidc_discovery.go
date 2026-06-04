package testutil

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/giantswarm/mcp-oauth/providers/oidc"
)

// NewDiscoveryClient returns an OIDC discovery client with SSRF validation
// disabled. Use only in tests that spin up httptest servers on loopback
// addresses.
func NewDiscoveryClient(httpClient *http.Client, cacheTTL time.Duration, logger *slog.Logger) *oidc.DiscoveryClient {
	return oidc.NewDiscoveryClientWithOptions(httpClient, cacheTTL, logger, oidc.WithSkipValidation())
}
