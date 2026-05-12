package server

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
)

// LogValue implements [slog.LogValuer] so callers can emit a structured
// snapshot of the server's security posture:
//
//	logger.Info("oauth server initialized", "server", srv)
//
// Fields are limited to state that is either derived (encryption-enabled,
// instrumentation-wired) or mutated by [applySecureDefaults] (production
// mode, redirect-URI validation flags) — i.e. state the caller's
// pre-build Config does not faithfully reflect.
func (s *Server) LogValue() slog.Value {
	cfg := s.Config
	attrs := []slog.Attr{
		slog.String("issuer", cfg.Issuer),
		slog.Bool("production_mode", cfg.ProductionMode),
		slog.String("access_token_format", string(cfg.AccessTokenFormat)),
		slog.Bool("encryption_at_rest", s.Encryptor != nil && s.Encryptor.IsEnabled()),
		slog.Bool("instrumentation_on", s.Instrumentation != nil),
		slog.Group("redirect_uri_policy",
			slog.Bool("dns_validation", cfg.DNSValidation),
			slog.Bool("dns_validation_strict", cfg.DNSValidationStrict),
			slog.Bool("authorization_time_validation", cfg.ValidateRedirectURIAtAuthorization),
			slog.Duration("dns_timeout", cfg.DNSValidationTimeout),
			slog.Bool("allow_localhost", cfg.AllowLocalhostRedirectURIs),
			slog.Bool("allow_private_ip", cfg.AllowPrivateIPRedirectURIs),
			slog.Bool("allow_link_local", cfg.AllowLinkLocalRedirectURIs),
		),
	}
	if len(cfg.SessionIDHMACKey) > 0 {
		sum := sha256.Sum256(cfg.SessionIDHMACKey)
		attrs = append(attrs, slog.String("session_id_hmac_key_fingerprint", hex.EncodeToString(sum[:8])))
	}
	return slog.GroupValue(attrs...)
}
