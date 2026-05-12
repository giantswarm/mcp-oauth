package helpers

import "strings"

// SplitScopes splits a space-delimited OAuth scope string (RFC 6749 §3.3)
// into a slice. Any whitespace run is treated as a separator (per
// strings.Fields). Returns nil for an empty or whitespace-only input.
func SplitScopes(scope string) []string {
	fields := strings.Fields(scope)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

// HasScope reports whether the given space-delimited scope string contains the
// named scope as a discrete entry. Case-sensitive per RFC 6749 §3.3.
func HasScope(scope, want string) bool {
	if want == "" {
		return false
	}
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// JoinScopes concatenates non-empty scopes with single spaces per RFC 6749
// §3.3 scope encoding. Empty entries are dropped to avoid stray separators.
// Returns an empty string for nil/empty input.
func JoinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, " ")
}
