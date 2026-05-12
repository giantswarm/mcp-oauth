package helpers

import (
	"reflect"
	"testing"
)

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "empty string", input: "", want: nil},
		{name: "single scope", input: "openid", want: []string{"openid"}},
		{name: "multiple scopes", input: "openid email profile", want: []string{"openid", "email", "profile"}},
		{name: "extra spaces collapsed", input: "openid  email   profile", want: []string{"openid", "email", "profile"}},
		{name: "leading whitespace", input: "  openid email profile", want: []string{"openid", "email", "profile"}},
		{name: "trailing whitespace", input: "openid email profile  ", want: []string{"openid", "email", "profile"}},
		{name: "mixed whitespace", input: "  openid   email  profile  ", want: []string{"openid", "email", "profile"}},
		{name: "only whitespace", input: "   ", want: nil},
		{name: "tabs split too (strings.Fields)", input: "openid\t\temail\t profile", want: []string{"openid", "email", "profile"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitScopes(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitScopes(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestJoinScopes(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{name: "nil", input: nil, want: ""},
		{name: "empty", input: []string{}, want: ""},
		{name: "one", input: []string{"openid"}, want: "openid"},
		{name: "many", input: []string{"openid", "profile", "email"}, want: "openid profile email"},
		{name: "drops empties", input: []string{"openid", "", "email"}, want: "openid email"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JoinScopes(tt.input)
			if got != tt.want {
				t.Errorf("JoinScopes(%#v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
