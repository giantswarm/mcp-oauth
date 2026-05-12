package oauth

import (
	"testing"
)

// FuzzParseCallbackQuery exercises the OAuth callback query parser with
// arbitrary input. The function is a pure-data constructor, so the only
// observable failure mode is a panic — the fuzzer asserts that the parser
// returns a non-nil pointer for every input.
func FuzzParseCallbackQuery(f *testing.F) {
	seeds := [][5]string{
		{"", "", "", "", ""},
		{"abc", "xyz", "", "", ""},
		{"", "", "invalid_request", "missing code", "https://example.com/err"},
		{"\x00", "%00", "access_denied", "user said no\n", "javascript:alert(1)"},
		{"code\xff\xfe", "state\xc3\xa9", "", "  ", ""},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1], s[2], s[3], s[4])
	}

	f.Fuzz(func(t *testing.T, code, state, errCode, errDesc, errURI string) {
		got := ParseCallbackQuery(code, state, errCode, errDesc, errURI)
		if got == nil {
			t.Fatal("ParseCallbackQuery returned nil")
		}
		if got.Code != code || got.State != state || got.Error != errCode || got.ErrorDescription != errDesc || got.ErrorURI != errURI {
			t.Fatalf("ParseCallbackQuery round-trip mismatch: %+v vs (%q,%q,%q,%q,%q)", got, code, state, errCode, errDesc, errURI)
		}
	})
}
