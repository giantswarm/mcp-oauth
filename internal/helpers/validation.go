package helpers

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxClientNameLength is the maximum allowed length for client_name in runes.
const MaxClientNameLength = 256

// ValidateClientName validates the client_name field to prevent potential stored XSS
// and log injection attacks. This is a defense-in-depth measure - while client_name
// is typically only used in JSON responses (which escape HTML), validation prevents
// issues if the value is ever displayed in HTML contexts (admin dashboards, log
// viewers, audit reports).
//
// Validation rules:
//   - Must not contain HTML-like characters (< or >)
//   - Must not exceed 256 characters (runes, not bytes)
//   - Must contain only printable characters (no control characters)
//   - Must not contain newlines (prevents log line splitting attacks)
//
// Returns nil if the name is valid, or an error describing the validation failure.
func ValidateClientName(name string) error {
	// Empty names are valid (optional field)
	if name == "" {
		return nil
	}

	// Check length limit (count Unicode code points, not bytes)
	if utf8.RuneCountInString(name) > MaxClientNameLength {
		return fmt.Errorf("client_name must be %d characters or less", MaxClientNameLength)
	}

	// Reject HTML-like content to prevent potential XSS if displayed in HTML context
	if strings.ContainsAny(name, "<>") {
		return fmt.Errorf("client_name must not contain HTML characters (< or >)")
	}

	// Validate all characters are printable and don't contain newlines
	// Newlines are rejected to prevent log line splitting/injection attacks
	for i, r := range name {
		// Reject newlines explicitly (even though they pass unicode.IsSpace)
		if r == '\n' || r == '\r' {
			return fmt.Errorf("client_name must not contain newline characters (invalid character at position %d)", i)
		}

		// Allow printable characters and horizontal whitespace (space, tab)
		if !unicode.IsPrint(r) && r != '\t' && r != ' ' {
			return fmt.Errorf("client_name must contain only printable characters (invalid character at position %d)", i)
		}
	}

	return nil
}
