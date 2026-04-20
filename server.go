package oauth

import (
	"log/slog"

	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

// Server is a type alias for backward compatibility.
// All server logic is now in the server package.
type Server = server.Server

// ServerConfig is a type alias for backward compatibility.
// Use server.Config for new code.
type ServerConfig = server.Config

// InstrumentationConfig is a type alias for backward compatibility.
// Use server.InstrumentationConfig for new code.
type InstrumentationConfig = server.InstrumentationConfig

// ForwardedIDTokenAcceptance is re-exported from the server package for
// consumers that want to call Server.AcceptForwardedIDToken via the top-level
// alias without importing the server package directly.
type ForwardedIDTokenAcceptance = server.ForwardedIDTokenAcceptance

// ErrTrustedAudienceMismatch is re-exported from the server package for the
// same reason — callers typically compare with errors.Is to decide whether
// to respond 401.
var ErrTrustedAudienceMismatch = server.ErrTrustedAudienceMismatch

// NewServer creates a new OAuth server.
// This is a convenience wrapper for server.New() to maintain backward compatibility.
func NewServer(
	provider providers.Provider,
	tokenStore storage.TokenStore,
	clientStore storage.ClientStore,
	flowStore storage.FlowStore,
	config *ServerConfig,
	logger *slog.Logger,
) (*Server, error) {
	return server.New(provider, tokenStore, clientStore, flowStore, config, logger)
}

// NewServerWithCombined is a convenience wrapper for server.NewWithCombined
// — the additive constructor that takes a [storage.Combined] backend instead
// of three separate store arguments. Use it when your backend (memory, valkey,
// or anything else) implements all three storage interfaces, which is the
// common case.
func NewServerWithCombined(
	provider providers.Provider,
	store storage.Combined,
	config *ServerConfig,
	logger *slog.Logger,
) (*Server, error) {
	return server.NewWithCombined(provider, store, config, logger)
}
