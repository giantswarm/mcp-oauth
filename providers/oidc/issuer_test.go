package oidc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateIssuerURL(t *testing.T) {
	for _, issuer := range []string{
		"https://dex.example.com", "https://dex.example.com:8443/dex",
		"https://dex.example.com/dex%3Ftenant%23one",
		"https://localhost:32000/dex", "https://127.0.0.1/dex", "https://[::1]/dex",
		"https://10.0.0.1/dex", "https://172.16.0.1/dex", "https://192.168.0.1/dex",
		"https://[fd00::1]/dex", "https://169.254.169.254/dex", "https://[fe80::1]/dex",
		"https://253.1.2.3/dex", "https://unresolvable.invalid/dex",
	} {
		t.Run(issuer, func(t *testing.T) {
			require.NoError(t, ValidateIssuerURL(issuer))
		})
	}
	for _, testCase := range []struct {
		issuer string
		error  string
	}{
		{"", "HTTPS"},
		{"dex.example.com", "HTTPS"},
		{"http://dex.example.com", "HTTPS"},
		{"https://", "hostname"},
		{"https://dex.example.com:invalid", "invalid"},
		{"https://dex.example.com/dex?tenant=one", "query component"},
		{"https://dex.example.com/dex?", "query component"},
		{"https://dex.example.com/dex#tenant", "fragment component"},
		{"https://dex.example.com/dex#", "fragment component"},
		{"https://user:password@dex.example.com/dex", "user information"},
	} {
		t.Run(testCase.issuer, func(t *testing.T) {
			require.ErrorContains(t, ValidateIssuerURL(testCase.issuer), testCase.error)
		})
	}
}
