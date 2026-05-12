package server

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateTrustedPublicRegistrationRedirectURIs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      []string
		wantSet    []string
		wantLogged []string
	}{
		{
			name:    "empty input",
			input:   nil,
			wantSet: nil,
		},
		{
			name:    "single valid https URI",
			input:   []string{"https://claude.ai/api/mcp/auth_callback"},
			wantSet: []string{"https://claude.ai/api/mcp/auth_callback"},
		},
		{
			name:    "uppercase host normalised",
			input:   []string{"https://CLAUDE.AI/cb"},
			wantSet: []string{"https://claude.ai/cb"},
		},
		{
			name:    "default port stripped",
			input:   []string{"https://example.com:443/cb"},
			wantSet: []string{"https://example.com/cb"},
		},
		{
			name:       "http rejected",
			input:      []string{"http://example.com/cb"},
			wantSet:    nil,
			wantLogged: []string{"only https is allowed"},
		},
		{
			name:    "loopback rejected (both entries)",
			input:   []string{"https://localhost/cb", "https://127.0.0.1/cb"},
			wantSet: nil,
			wantLogged: []string{
				`uri=https://localhost/cb`,
				`uri=https://127.0.0.1/cb`,
				"loopback host is not allowed",
			},
		},
		{
			name:       "private IP rejected",
			input:      []string{"https://10.0.0.1/cb"},
			wantSet:    nil,
			wantLogged: []string{"private IP is not allowed"},
		},
		{
			name:       "link-local IP rejected",
			input:      []string{"https://169.254.169.254/cb"},
			wantSet:    nil,
			wantLogged: []string{"link-local IP is not allowed"},
		},
		{
			name:       "unspecified IP rejected",
			input:      []string{"https://0.0.0.0/cb"},
			wantSet:    nil,
			wantLogged: []string{"unspecified IP is not allowed"},
		},
		{
			name:       "fragment rejected",
			input:      []string{"https://example.com/cb#x"},
			wantSet:    nil,
			wantLogged: []string{"fragment is not allowed"},
		},
		{
			name:       "userinfo rejected",
			input:      []string{"https://u:p@example.com/cb"},
			wantSet:    nil,
			wantLogged: []string{"userinfo is not allowed"},
		},
		{
			name:       "missing host rejected",
			input:      []string{"https:///cb"},
			wantSet:    nil,
			wantLogged: []string{"missing host"},
		},
		{
			name:       "duplicates collapsed",
			input:      []string{"https://example.com/cb", "https://EXAMPLE.com/cb", "https://example.com:443/cb"},
			wantSet:    []string{"https://example.com/cb"},
			wantLogged: []string{"duplicate"},
		},
		{
			name:       "mix of valid and invalid keeps valid",
			input:      []string{"http://nope.example", "https://ok.example/cb"},
			wantSet:    []string{"https://ok.example/cb"},
			wantLogged: []string{"only https is allowed"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			cfg := &Config{
				Issuer:                                "https://auth.example.com",
				TrustedPublicRegistrationRedirectURIs: append([]string(nil), tt.input...),
			}

			applySecureDefaults(cfg, logger)

			require.Equal(t, tt.wantSet, cfg.TrustedPublicRegistrationRedirectURIs)
			if len(tt.wantSet) == 0 {
				require.Empty(t, cfg.trustedRedirectURIsSet)
			} else {
				require.Len(t, cfg.trustedRedirectURIsSet, len(tt.wantSet))
				for _, u := range tt.wantSet {
					require.True(t, cfg.trustedRedirectURIsSet[u], "set should contain %q", u)
				}
			}

			for _, want := range tt.wantLogged {
				require.Contains(t, buf.String(), want)
			}
		})
	}
}

func TestValidateTrustedPublicRegistrationRedirectURIs_RedundantWithAllowPublic(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	cfg := &Config{
		Issuer:                                "https://auth.example.com",
		AllowPublicClientRegistration:         true,
		TrustedPublicRegistrationRedirectURIs: []string{"https://claude.ai/cb"},
	}
	applySecureDefaults(cfg, logger)

	require.Contains(t, buf.String(), "TrustedPublicRegistrationRedirectURIs is redundant when AllowPublicClientRegistration=true")
}

func TestNormalizeTrustedRedirectURI_Errors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
		err  string
	}{
		{"empty", "", "empty URI"},
		{"unparseable", "https://%zz/", "parse"},
		{"http scheme", "http://example.com/cb", "only https is allowed"},
		{"missing scheme", "//example.com/cb", "only https is allowed"},
		{"with fragment", "https://example.com/cb#x", "fragment"},
		{"with userinfo", "https://u@example.com/cb", "userinfo"},
		{"missing host", "https:///cb", "missing host"},
		{"loopback", "https://localhost/cb", "loopback"},
		{"127.0.0.1", "https://127.0.0.1/cb", "loopback"},
		{"private IP", "https://192.168.1.1/cb", "private IP"},
		{"link-local", "https://169.254.169.254/cb", "link-local"},
		{"unspecified", "https://0.0.0.0/cb", "unspecified IP"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := normalizeTrustedRedirectURI(tc.uri)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.err)
		})
	}
}

func TestNormalizeTrustedRedirectURI_Canonical(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"https://example.com/cb":                    "https://example.com/cb",
		"https://EXAMPLE.com/cb":                    "https://example.com/cb",
		"https://example.com:443/cb":                "https://example.com/cb",
		"https://example.com/cb?x=1":                "https://example.com/cb?x=1",
		"https://example.com/Path/Case":             "https://example.com/Path/Case",
		"https://claude.ai/api/mcp/auth_callback":   "https://claude.ai/api/mcp/auth_callback",
		"https://claude.ai:443/api/mcp/auth_callback": "https://claude.ai/api/mcp/auth_callback",
	}

	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeTrustedRedirectURI(input)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}
