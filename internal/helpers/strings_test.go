package helpers

import (
	"strings"
	"testing"
)

func TestSafeTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "string shorter than maxLen",
			input:  "short",
			maxLen: 10,
			want:   "short",
		},
		{
			name:   "string equal to maxLen",
			input:  "exactly10c",
			maxLen: 10,
			want:   "exactly10c",
		},
		{
			name:   "string longer than maxLen",
			input:  "this-is-a-very-long-token-string",
			maxLen: 8,
			want:   "this-is-",
		},
		{
			name:   "empty string",
			input:  "",
			maxLen: 5,
			want:   "",
		},
		{
			name:   "maxLen is zero",
			input:  "test",
			maxLen: 0,
			want:   "",
		},
		{
			name:   "maxLen is negative (edge case)",
			input:  "test",
			maxLen: -1,
			want:   "",
		},
		{
			name:   "unicode characters",
			input:  "hello世界test",
			maxLen: 8,
			want:   "hello世",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SafeTruncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("SafeTruncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestSafeTruncate_NoPanic(t *testing.T) {
	// Ensure SafeTruncate never panics, even with edge cases
	testCases := []struct {
		input  string
		maxLen int
	}{
		{"", 0},
		{"", -1},
		{"test", 0},
		{"test", -1},
		{"test", 100},
	}

	for _, tc := range testCases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("SafeTruncate(%q, %d) panicked: %v", tc.input, tc.maxLen, r)
				}
			}()
			_ = SafeTruncate(tc.input, tc.maxLen)
		}()
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "URL with trailing slash",
			input: "https://example.com/",
			want:  "https://example.com",
		},
		{
			name:  "URL without trailing slash",
			input: "https://example.com",
			want:  "https://example.com",
		},
		{
			name:  "URL with multiple trailing slashes",
			input: "https://example.com///",
			want:  "https://example.com",
		},
		{
			name:  "URL with path and trailing slash",
			input: "https://example.com/api/v1/",
			want:  "https://example.com/api/v1",
		},
		{
			name:  "URL with path without trailing slash",
			input: "https://example.com/api/v1",
			want:  "https://example.com/api/v1",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "just slashes",
			input: "///",
			want:  "",
		},
		{
			name:  "URL with port and trailing slash",
			input: "https://example.com:8080/",
			want:  "https://example.com:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeURL(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeURL_Comparison(t *testing.T) {
	// Test that URLs with and without trailing slashes are equal after normalization
	testCases := []struct {
		url1 string
		url2 string
	}{
		{"https://example.com", "https://example.com/"},
		{"https://example.com/api", "https://example.com/api/"},
		{"https://mcp.example.com:8080", "https://mcp.example.com:8080/"},
		{"https://inboxfewer.k8s-internal.home.derstappen.com", "https://inboxfewer.k8s-internal.home.derstappen.com/"},
	}

	for _, tc := range testCases {
		normalized1 := NormalizeURL(tc.url1)
		normalized2 := NormalizeURL(tc.url2)
		if normalized1 != normalized2 {
			t.Errorf("Expected NormalizeURL(%q) == NormalizeURL(%q), got %q != %q",
				tc.url1, tc.url2, normalized1, normalized2)
		}
	}
}

func TestValidateMetadataPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid simple path",
			path:    "/mcp",
			wantErr: false,
		},
		{
			name:    "valid nested path",
			path:    "/api/v1/mcp",
			wantErr: false,
		},
		{
			name:    "valid deep path within limits",
			path:    "/a/b/c/d/e/f/g/h/i/j",
			wantErr: false,
		},
		{
			name:    "path traversal attempt",
			path:    "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "path traversal in middle",
			path:    "/api/../secret",
			wantErr: true,
		},
		{
			name:    "path with null byte",
			path:    "/mcp\x00/files",
			wantErr: true,
		},
		{
			name:    "excessively long path",
			path:    "/" + strings.Repeat("a", 300),
			wantErr: true,
		},
		{
			name:    "path at max length is valid",
			path:    "/" + strings.Repeat("a", 254),
			wantErr: false,
		},
		{
			name:    "too many segments",
			path:    "/a/b/c/d/e/f/g/h/i/j/k/l",
			wantErr: true,
		},
		{
			name:    "empty path is valid",
			path:    "",
			wantErr: false,
		},
		{
			name:    "root path is valid",
			path:    "/",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMetadataPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMetadataPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestPathValidationError(t *testing.T) {
	err := &PathValidationError{
		Path:   "/bad/../path",
		Reason: "path contains '..' sequence (path traversal attempt)",
	}

	if err.Error() != "path contains '..' sequence (path traversal attempt)" {
		t.Errorf("PathValidationError.Error() = %q, want %q",
			err.Error(), "path contains '..' sequence (path traversal attempt)")
	}
}

func TestPathMatchesPrefix(t *testing.T) {
	tests := []struct {
		resourcePath string
		prefix       string
		expected     bool
	}{
		{"/mcp", "/mcp", true},         // Exact match
		{"/mcp/files", "/mcp", true},   // Prefix match
		{"/mcp/files/a", "/mcp", true}, // Longer path
		{"/mcpx", "/mcp", false},       // Not a path boundary match
		{"/mc", "/mcp", false},         // Shorter than prefix
		{"/other/mcp", "/mcp", false},  // Not a prefix
		{"/mcp-test", "/mcp", false},   // Hyphen after prefix
		{"/mcp/", "/mcp", true},        // Trailing slash
		{"/mcp/files", "/mcp/", false}, // Trailing slash in prefix
		{"/api/v1", "/api", true},      // API versioning
		{"/api", "/api/v1", false},     // Shorter resource path
		{"", "", true},                 // Both empty
		{"/", "/", true},               // Both root
		{"/a", "", false},              // Empty prefix
		{"", "/a", false},              // Empty resource path
	}

	for _, tt := range tests {
		name := tt.resourcePath + "_" + tt.prefix
		t.Run(name, func(t *testing.T) {
			got := PathMatchesPrefix(tt.resourcePath, tt.prefix)
			if got != tt.expected {
				t.Errorf("PathMatchesPrefix(%q, %q) = %v, want %v",
					tt.resourcePath, tt.prefix, got, tt.expected)
			}
		})
	}
}
