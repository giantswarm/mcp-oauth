package helpers

import (
	"strings"
	"testing"
)

func TestValidateClientName(t *testing.T) {
	tests := []struct {
		name       string
		clientName string
		wantErr    bool
		errContain string
	}{
		{
			name:       "valid simple name",
			clientName: "My Application",
			wantErr:    false,
		},
		{
			name:       "valid name with numbers",
			clientName: "App v2.0",
			wantErr:    false,
		},
		{
			name:       "valid name with special chars",
			clientName: "Test App (Production) - 2026",
			wantErr:    false,
		},
		{
			name:       "valid unicode name",
			clientName: "アプリケーション", // Japanese: "Application"
			wantErr:    false,
		},
		{
			name:       "valid name with emoji",
			clientName: "Cool App",
			wantErr:    false,
		},
		{
			name:       "empty name is valid",
			clientName: "",
			wantErr:    false,
		},
		{
			name:       "max length name",
			clientName: strings.Repeat("a", 256),
			wantErr:    false,
		},
		{
			name:       "max length name with multibyte chars",
			clientName: strings.Repeat("日", 256), // 256 runes, but 768 bytes
			wantErr:    false,
		},
		{
			name:       "rejects script tag",
			clientName: "<script>alert(1)</script>",
			wantErr:    true,
			errContain: "HTML characters",
		},
		{
			name:       "rejects opening angle bracket",
			clientName: "App <version>",
			wantErr:    true,
			errContain: "HTML characters",
		},
		{
			name:       "rejects closing angle bracket",
			clientName: "App >name",
			wantErr:    true,
			errContain: "HTML characters",
		},
		{
			name:       "rejects img tag",
			clientName: "<img src=x onerror=alert(1)>",
			wantErr:    true,
			errContain: "HTML characters",
		},
		{
			name:       "rejects SVG XSS",
			clientName: "<svg onload=alert(1)>",
			wantErr:    true,
			errContain: "HTML characters",
		},
		{
			name:       "rejects name exceeding max length",
			clientName: strings.Repeat("a", 257),
			wantErr:    true,
			errContain: "256 characters or less",
		},
		{
			name:       "rejects multibyte name exceeding max length",
			clientName: strings.Repeat("日", 257), // 257 runes, 771 bytes
			wantErr:    true,
			errContain: "256 characters or less",
		},
		{
			name:       "rejects name way over max length",
			clientName: strings.Repeat("x", 1000),
			wantErr:    true,
			errContain: "256 characters or less",
		},
		{
			name:       "rejects null byte",
			clientName: "App\x00Name",
			wantErr:    true,
			errContain: "printable characters",
		},
		{
			name:       "rejects control character",
			clientName: "App\x07Name",
			wantErr:    true,
			errContain: "printable characters",
		},
		{
			name:       "rejects escape character",
			clientName: "App\x1BName",
			wantErr:    true,
			errContain: "printable characters",
		},
		{
			name:       "allows tabs",
			clientName: "App\tName",
			wantErr:    false,
		},
		{
			name:       "rejects newline (LF)",
			clientName: "App\nName",
			wantErr:    true,
			errContain: "newline characters",
		},
		{
			name:       "rejects carriage return (CR)",
			clientName: "App\rName",
			wantErr:    true,
			errContain: "newline characters",
		},
		{
			name:       "rejects CRLF",
			clientName: "App\r\nName",
			wantErr:    true,
			errContain: "newline characters",
		},
		{
			name:       "rejects log injection attempt",
			clientName: "Legit App\nWARN Security violation detected",
			wantErr:    true,
			errContain: "newline characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientName(tt.clientName)
			switch {
			case tt.wantErr && err == nil:
				t.Errorf("ValidateClientName(%q) = nil, want error containing %q",
					tt.clientName, tt.errContain)
			case tt.wantErr && !strings.Contains(err.Error(), tt.errContain):
				t.Errorf("ValidateClientName(%q) error = %q, want error containing %q",
					tt.clientName, err.Error(), tt.errContain)
			case !tt.wantErr && err != nil:
				t.Errorf("ValidateClientName(%q) = %v, want nil", tt.clientName, err)
			}
		})
	}
}
