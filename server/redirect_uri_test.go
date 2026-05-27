package server

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestServer_ValidateRedirectURIForAuthorization(t *testing.T) {
	ctx := context.Background()
	srv, _, _ := setupFlowTestServer(t)
	srv.config.AllowLocalhostRedirectURIs = true

	client, _, err := srv.RegisterClient(
		ctx,
		"client",
		ClientTypePublic,
		"",
		[]string{"http://localhost/callback"},
		[]string{"openid"},
		"192.168.1.100",
		10,
	)
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}

	tests := []struct {
		name        string
		clientID    string
		redirectURI string
		want        string // expected canonical URI string; empty if error expected
		errContains string // expected substring of err.Error(); empty if success
	}{
		{
			name:        "exact match returns canonical URI",
			clientID:    client.ClientID,
			redirectURI: "http://localhost/callback",
			want:        "http://localhost/callback",
		},
		{
			name:        "unknown client_id yields invalid_client",
			clientID:    "does-not-exist",
			redirectURI: "http://localhost/callback",
			errContains: ErrorCodeInvalidClient,
		},
		{
			name:        "empty client_id yields invalid_client",
			clientID:    "",
			redirectURI: "http://localhost/callback",
			errContains: ErrorCodeInvalidClient,
		},
		{
			name:        "unregistered redirect_uri yields invalid_redirect_uri",
			clientID:    client.ClientID,
			redirectURI: "http://localhost/elsewhere",
			errContains: ErrorCodeInvalidRedirectURI,
		},
		{
			name:        "empty redirect_uri yields invalid_redirect_uri",
			clientID:    client.ClientID,
			redirectURI: "",
			errContains: ErrorCodeInvalidRedirectURI,
		},
		{
			name:        "scheme mismatch yields invalid_redirect_uri",
			clientID:    client.ClientID,
			redirectURI: "https://localhost/callback",
			errContains: ErrorCodeInvalidRedirectURI,
		},
		{
			name:        "loopback port-agnostic match preserves request port (RFC 8252 §7.3)",
			clientID:    client.ClientID,
			redirectURI: "http://localhost:54123/callback",
			want:        "http://localhost:54123/callback",
		},
		{
			name:        "loopback path mismatch yields invalid_redirect_uri",
			clientID:    client.ClientID,
			redirectURI: "http://localhost:54123/other",
			errContains: ErrorCodeInvalidRedirectURI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := srv.ValidateRedirectURIForAuthorization(ctx, tt.clientID, tt.redirectURI)

			if tt.errContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (canonical=%v)", tt.errContains, got)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errContains)
				}
				if got != nil {
					t.Errorf("expected nil canonical URL on error, got %v", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error = %v", err)
			}
			if got == nil {
				t.Fatal("expected non-nil canonical URL on success")
			}
			wantURL, parseErr := url.Parse(tt.want)
			if parseErr != nil {
				t.Fatalf("test wantURL not parseable: %v", parseErr)
			}
			if got.String() != wantURL.String() {
				t.Errorf("canonical = %q, want %q", got.String(), wantURL.String())
			}
		})
	}
}
