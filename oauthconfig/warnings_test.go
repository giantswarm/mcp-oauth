package oauthconfig_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/giantswarm/mcp-oauth/oauthconfig"
	"github.com/giantswarm/mcp-oauth/server"
)

// insecureWarnNeedle and pubRegWarnNeedle are stable substrings of the warning
// messages emitted by LogStartupWarnings. They include the env var name so an
// operator grepping their logs can find the matching config knob.
const (
	insecureWarnNeedle = "OAUTH_ALLOW_INSECURE_HTTP=true"
	pubRegWarnNeedle   = "OAUTH_ALLOW_PUBLIC_CLIENT_REGISTRATION=true"
)

func TestLogStartupWarnings(t *testing.T) {
	cases := []struct {
		name             string
		allowInsecure    bool
		allowPubReg      bool
		wantInsecureHits int
		wantPubRegHits   int
	}{
		{name: "no flags, no warnings"},
		{name: "insecure http only", allowInsecure: true, wantInsecureHits: 1},
		{name: "public registration only", allowPubReg: true, wantPubRegHits: 1},
		{name: "both flags, both warnings", allowInsecure: true, allowPubReg: true, wantInsecureHits: 1, wantPubRegHits: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			cfg := &server.Config{
				Issuer:                        "https://auth.example",
				AllowInsecureHTTP:             tc.allowInsecure,
				AllowPublicClientRegistration: tc.allowPubReg,
			}

			oauthconfig.LogStartupWarnings(cfg, logger)

			out := buf.String()
			if got := strings.Count(out, insecureWarnNeedle); got != tc.wantInsecureHits {
				t.Errorf("insecure-HTTP warning hits = %d, want %d; log = %q", got, tc.wantInsecureHits, out)
			}
			if got := strings.Count(out, pubRegWarnNeedle); got != tc.wantPubRegHits {
				t.Errorf("public-registration warning hits = %d, want %d; log = %q", got, tc.wantPubRegHits, out)
			}
		})
	}
}

// TestLogStartupWarnings_FiresOncePerCall guards against an accidental
// per-request emission pattern: if the helper is mistakenly wired into a
// middleware, this test would flag the regression by failing on a hit count
// >1 after a single invocation.
func TestLogStartupWarnings_FiresOncePerCall(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg := &server.Config{
		Issuer:                        "http://auth.example",
		AllowInsecureHTTP:             true,
		AllowPublicClientRegistration: true,
	}

	oauthconfig.LogStartupWarnings(cfg, logger)

	out := buf.String()
	if got := strings.Count(out, insecureWarnNeedle); got != 1 {
		t.Errorf("insecure warning fired %d times, want 1", got)
	}
	if got := strings.Count(out, pubRegWarnNeedle); got != 1 {
		t.Errorf("public-registration warning fired %d times, want 1", got)
	}
}

// TestLogStartupWarnings_NilSafe documents the nil-cfg / nil-logger contract
// so callers can defer the helper unconditionally.
func TestLogStartupWarnings_NilSafe(t *testing.T) {
	oauthconfig.LogStartupWarnings(nil, slog.Default())
	oauthconfig.LogStartupWarnings(&server.Config{AllowInsecureHTTP: true}, nil)
	oauthconfig.LogStartupWarnings(nil, nil)
}
