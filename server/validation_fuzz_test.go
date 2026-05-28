package server

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// FuzzComputePKCEChallenge_S256 verifies the S256 PKCE challenge computation
// is deterministic and matches a hand-rolled SHA-256(verifier) for every
// input the fuzzer produces.
func FuzzComputePKCEChallenge_S256(f *testing.F) {
	srv := &Server{
		instrumentation: testInstrumentation(f),
		auditor:         testAuditor(),
	}
	for _, seed := range []string{
		"abcDEF-._~",
		"43-char-verifier-aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"",
		"a",
		"\x00\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, verifier string) {
		got, err := srv.computePKCEChallenge(verifier, PKCEMethodS256)
		if err != nil {
			t.Fatalf("S256 must never error; got %v for %q", err, verifier)
		}
		sum := sha256.Sum256([]byte(verifier))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if got != want {
			t.Fatalf("S256(%q) = %q, want %q", verifier, got, want)
		}
	})
}

// FuzzPKCEVerifierFormat ensures validateCodeVerifierFormat never panics
// and that any returned non-nil error matches a precondition: empty,
// length out of range, or a non-allowed character. Inputs that pass all
// preconditions must validate successfully.
func FuzzPKCEVerifierFormat(f *testing.F) {
	for _, seed := range []string{
		"",
		"x",
		"abcDEF-._~",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 44 chars
		"contains space",
		"contains+plus",
		"contains/slash",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, verifier string) {
		err := validateCodeVerifierFormat(verifier)
		if err == nil {
			return
		}
		// If an error was returned, at least one precondition must have failed.
		if verifier == "" || len(verifier) < MinCodeVerifierLength || len(verifier) > MaxCodeVerifierLength {
			return
		}
		for _, ch := range verifier {
			if !isValidPKCEVerifierChar(ch) {
				return
			}
		}
		t.Fatalf("validateCodeVerifierFormat returned %v for a value that satisfies all preconditions: %q", err, verifier)
	})
}
