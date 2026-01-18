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
		// Trailing slash normalization
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

		// Case normalization (scheme and host only)
		{
			name:  "uppercase scheme",
			input: "HTTPS://example.com",
			want:  "https://example.com",
		},
		{
			name:  "mixed case scheme",
			input: "HtTpS://example.com",
			want:  "https://example.com",
		},
		{
			name:  "uppercase host",
			input: "https://EXAMPLE.COM",
			want:  "https://example.com",
		},
		{
			name:  "mixed case host",
			input: "https://Example.COM",
			want:  "https://example.com",
		},
		{
			name:  "path case preserved",
			input: "https://example.com/Path/To/Resource",
			want:  "https://example.com/Path/To/Resource",
		},
		{
			name:  "full mixed case with path",
			input: "HTTPS://Example.COM/Path/To/Resource/",
			want:  "https://example.com/Path/To/Resource",
		},

		// Default port normalization
		{
			name:  "HTTPS default port 443 removed",
			input: "https://example.com:443",
			want:  "https://example.com",
		},
		{
			name:  "HTTPS default port 443 with path",
			input: "https://example.com:443/api/v1/",
			want:  "https://example.com/api/v1",
		},
		{
			name:  "HTTP default port 80 removed",
			input: "http://example.com:80",
			want:  "http://example.com",
		},
		{
			name:  "non-default port preserved",
			input: "https://example.com:8443/",
			want:  "https://example.com:8443",
		},
		{
			name:  "URL with port and trailing slash",
			input: "https://example.com:8080/",
			want:  "https://example.com:8080",
		},

		// Query and fragment preservation
		{
			name:  "URL with query string",
			input: "https://example.com/path?foo=bar",
			want:  "https://example.com/path?foo=bar",
		},
		{
			name:  "URL with fragment",
			input: "https://example.com/path#section",
			want:  "https://example.com/path#section",
		},
		{
			name:  "URL with query and fragment",
			input: "https://example.com/path?foo=bar#section",
			want:  "https://example.com/path?foo=bar#section",
		},

		// Non-URL values (backwards compatibility)
		{
			name:  "simple client ID",
			input: "client-id",
			want:  "client-id",
		},
		{
			name:  "client ID with trailing slashes",
			input: "client-id///",
			want:  "client-id",
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
	// Test that semantically equivalent URLs are equal after normalization
	testCases := []struct {
		name string
		url1 string
		url2 string
	}{
		// Trailing slash equivalence
		{"trailing slash", "https://example.com", "https://example.com/"},
		{"trailing slash with path", "https://example.com/api", "https://example.com/api/"},
		{"trailing slash with port", "https://mcp.example.com:8080", "https://mcp.example.com:8080/"},
		{"long hostname", "https://inboxfewer.k8s-internal.home.derstappen.com", "https://inboxfewer.k8s-internal.home.derstappen.com/"},

		// Case insensitivity (scheme and host)
		{"case scheme", "https://example.com", "HTTPS://example.com"},
		{"case host", "https://example.com", "https://EXAMPLE.COM"},
		{"case both", "https://example.com", "HTTPS://EXAMPLE.COM"},
		{"mixed case", "https://example.com/Path", "HTTPS://EXAMPLE.COM/Path"},

		// Default port equivalence
		{"https default port", "https://example.com", "https://example.com:443"},
		{"https default port with path", "https://example.com/api", "https://example.com:443/api"},
		{"http default port", "http://example.com", "http://example.com:80"},

		// Combined normalizations
		{"case and port", "https://example.com", "HTTPS://EXAMPLE.COM:443/"},
		{"case port and trailing", "https://example.com/api", "HTTPS://EXAMPLE.COM:443/api/"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			normalized1 := NormalizeURL(tc.url1)
			normalized2 := NormalizeURL(tc.url2)
			if normalized1 != normalized2 {
				t.Errorf("Expected NormalizeURL(%q) == NormalizeURL(%q), got %q != %q",
					tc.url1, tc.url2, normalized1, normalized2)
			}
		})
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

func TestMatchAudienceSecure(t *testing.T) {
	tests := []struct {
		name             string
		tokenAudience    string
		trustedAudiences []string
		want             string
	}{
		{
			name:             "exact match",
			tokenAudience:    "https://example.com",
			trustedAudiences: []string{"https://example.com"},
			want:             "https://example.com",
		},
		{
			name:             "case insensitive match",
			tokenAudience:    "https://example.com",
			trustedAudiences: []string{"HTTPS://EXAMPLE.COM"},
			want:             "HTTPS://EXAMPLE.COM",
		},
		{
			name:             "trailing slash normalization",
			tokenAudience:    "https://example.com/",
			trustedAudiences: []string{"https://example.com"},
			want:             "https://example.com",
		},
		{
			name:             "default port normalization",
			tokenAudience:    "https://example.com:443",
			trustedAudiences: []string{"https://example.com"},
			want:             "https://example.com",
		},
		{
			name:             "combined normalization",
			tokenAudience:    "HTTPS://Example.COM:443/",
			trustedAudiences: []string{"https://example.com"},
			want:             "https://example.com",
		},
		{
			name:             "no match",
			tokenAudience:    "https://other.com",
			trustedAudiences: []string{"https://example.com"},
			want:             "",
		},
		{
			name:             "empty trusted audiences",
			tokenAudience:    "https://example.com",
			trustedAudiences: []string{},
			want:             "",
		},
		{
			name:             "multiple trusted audiences first match",
			tokenAudience:    "https://example.com",
			trustedAudiences: []string{"https://example.com", "https://other.com"},
			want:             "https://example.com",
		},
		{
			name:             "multiple trusted audiences second match",
			tokenAudience:    "https://other.com",
			trustedAudiences: []string{"https://example.com", "https://other.com"},
			want:             "https://other.com",
		},
		{
			name:             "non-URL audience",
			tokenAudience:    "my-client-id",
			trustedAudiences: []string{"my-client-id"},
			want:             "my-client-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchAudienceSecure(tt.tokenAudience, tt.trustedAudiences)
			if got != tt.want {
				t.Errorf("MatchAudienceSecure(%q, %v) = %q, want %q",
					tt.tokenAudience, tt.trustedAudiences, got, tt.want)
			}
		})
	}
}

func TestFindMatchingAudience(t *testing.T) {
	tests := []struct {
		name             string
		tokenAudiences   []string
		trustedAudiences []string
		want             string
	}{
		{
			name:             "single audience matches",
			tokenAudiences:   []string{"https://example.com"},
			trustedAudiences: []string{"https://example.com"},
			want:             "https://example.com",
		},
		{
			name:             "multiple token audiences first matches",
			tokenAudiences:   []string{"https://example.com", "https://other.com"},
			trustedAudiences: []string{"https://example.com"},
			want:             "https://example.com",
		},
		{
			name:             "multiple token audiences second matches",
			tokenAudiences:   []string{"https://other.com", "https://example.com"},
			trustedAudiences: []string{"https://example.com"},
			want:             "https://example.com",
		},
		{
			name:             "case insensitive match",
			tokenAudiences:   []string{"https://example.com"},
			trustedAudiences: []string{"HTTPS://EXAMPLE.COM"},
			want:             "https://example.com",
		},
		{
			name:             "no match",
			tokenAudiences:   []string{"https://other.com"},
			trustedAudiences: []string{"https://example.com"},
			want:             "",
		},
		{
			name:             "empty token audiences",
			tokenAudiences:   []string{},
			trustedAudiences: []string{"https://example.com"},
			want:             "",
		},
		{
			name:             "empty trusted audiences",
			tokenAudiences:   []string{"https://example.com"},
			trustedAudiences: []string{},
			want:             "",
		},
		{
			name:             "both empty",
			tokenAudiences:   []string{},
			trustedAudiences: []string{},
			want:             "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindMatchingAudience(tt.tokenAudiences, tt.trustedAudiences)
			if got != tt.want {
				t.Errorf("FindMatchingAudience(%v, %v) = %q, want %q",
					tt.tokenAudiences, tt.trustedAudiences, got, tt.want)
			}
		})
	}
}
