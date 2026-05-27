package oidc

import (
	"testing"
)

// FuzzJWTHeaderParse drives IsJWT and ParseUnverifiedClaims with arbitrary
// input. Neither function should panic regardless of input. When
// ParseUnverifiedClaims succeeds, IsJWT must have returned true for the same
// input.
func FuzzJWTHeaderParse(f *testing.F) {
	seeds := []string{
		"",
		"a.b.c",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.sig",
		// invalid base64 payload
		"eyJhbGciOiJSUzI1NiJ9.!!!.sig",
		// non-JSON payload
		"eyJhbGciOiJSUzI1NiJ9." + "bm90anNvbg" + ".sig",
		// only two parts
		"header.payload",
		// empty parts
		"...",
		// UTF-8 in payload
		"\xc3\xa9.\xc3\xa9.\xc3\xa9",
		// null bytes
		"\x00.\x00.\x00",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, token string) {
		isJWT := IsJWT(token)
		claims, err := ParseUnverifiedClaims(token)
		if err == nil {
			// A successful parse implies the token looks like a JWT.
			if !isJWT {
				t.Fatalf("ParseUnverifiedClaims succeeded but IsJWT returned false for %q", token)
			}
			if claims == nil {
				t.Fatal("ParseUnverifiedClaims returned nil claims with nil error")
			}
		}
	})
}
