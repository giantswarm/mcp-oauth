package valkeytls

import (
	"crypto/tls"
	"testing"
)

func TestNew(t *testing.T) {
	cases := []struct {
		name         string
		opts         Options
		wantNil      bool
		wantInsecure bool
	}{
		{"disabled-returns-nil", Options{}, true, false},
		{"enabled-default-secure", Options{Enabled: true}, false, false},
		{"enabled-insecure-opt-in", Options{Enabled: true, InsecureSkipVerify: true}, false, true},
		{"insecure-without-enabled-is-still-nil", Options{InsecureSkipVerify: true}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := New(tc.opts)
			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil *tls.Config")
			}
			if got.MinVersion != tls.VersionTLS12 {
				t.Errorf("MinVersion = %d, want VersionTLS12", got.MinVersion)
			}
			if got.InsecureSkipVerify != tc.wantInsecure {
				t.Errorf("InsecureSkipVerify = %v, want %v", got.InsecureSkipVerify, tc.wantInsecure)
			}
		})
	}
}
