package oidc

import (
	"testing"
)

// FuzzValidateExternalURL drives the SSRF-safe URL validator with arbitrary
// strings. The function must never panic regardless of input — output is
// always a tidy error or nil.
func FuzzValidateExternalURL(f *testing.F) {
	seeds := []string{
		"",
		"https://example.com/foo",
		"http://127.0.0.1:8080",
		"https://10.0.0.1/",
		"https://::ffff:127.0.0.1/",
		"https://[::1]/",
		"javascript:alert(1)",
		"https://example.com:80\x00/foo",
		"https://exämple.com/",
		"https://user:pass@example.com/",
		"%41%42%43",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, rawURL string) {
		_ = ValidateExternalURL(rawURL, "fuzz") // panics fail the fuzzer
	})
}
