package dex

import "testing"

// Dex's sub is its IDTokenSubject message, user_id (1) and conn_id (2),
// protobuf-encoded and base64url without padding.
func TestConnectorFromSubject(t *testing.T) {
	for name, tc := range map[string]struct {
		subject string
		want    string
		ok      bool
	}{
		"github connector":   {subject: "CgVhbGljZRIGZ2l0aHVi", want: "github", ok: true},
		"azure-ad connector": {subject: "CgVhbGljZRIIYXp1cmUtYWQ", want: "azure-ad", ok: true},
		"no connector":       {subject: "CgVhbGljZQ"},
		"not base64url":      {subject: "alice@example.com"},
		"not protobuf":       {subject: "YWxpY2U"},
		"empty":              {subject: ""},
		"truncated message":  {subject: "CgVhbGlj"},
		"unknown field":      {subject: "CgVhbGljZRoBeA"},
		"padded base64":      {subject: "CgVhbGljZRIGZ2l0aHVi=="},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := ConnectorFromSubject(tc.subject)
			if ok != tc.ok || got != tc.want {
				t.Errorf("ConnectorFromSubject(%q) = %q, %v; want %q, %v", tc.subject, got, ok, tc.want, tc.ok)
			}
		})
	}
}
