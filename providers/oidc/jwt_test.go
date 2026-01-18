package oidc

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestIsJWT(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "valid JWT structure",
			token:    "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			expected: true,
		},
		{
			name:     "opaque access token",
			token:    "ya29.a0AfH6SMBmPxM6LwF7X8u9z",
			expected: false,
		},
		{
			name:     "empty string",
			token:    "",
			expected: false,
		},
		{
			name:     "two parts only",
			token:    "header.payload",
			expected: false,
		},
		{
			name:     "four parts",
			token:    "a.b.c.d",
			expected: false,
		},
		{
			name:     "empty parts",
			token:    "..",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsJWT(tt.token)
			if got != tt.expected {
				t.Errorf("IsJWT() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseUnverifiedClaims(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		wantAudience []string
		wantSubject  string
		wantError    bool
	}{
		{
			name: "valid JWT with single audience",
			token: createTestJWTWithClaims(t, map[string]any{
				"sub": "user123",
				"aud": "client-id",
				"iss": "https://auth.example.com",
				"exp": time.Now().Add(time.Hour).Unix(),
			}),
			wantAudience: []string{"client-id"},
			wantSubject:  "user123",
			wantError:    false,
		},
		{
			name: "valid JWT with multiple audiences",
			token: createTestJWTWithClaims(t, map[string]any{
				"sub": "user456",
				"aud": []string{"client-a", "client-b"},
				"iss": "https://auth.example.com",
				"exp": time.Now().Add(time.Hour).Unix(),
			}),
			wantAudience: []string{"client-a", "client-b"},
			wantSubject:  "user456",
			wantError:    false,
		},
		{
			name:      "invalid token",
			token:     "not-a-jwt",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ParseUnverifiedClaims(tt.token)

			if tt.wantError {
				if err == nil {
					t.Errorf("ParseUnverifiedClaims() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseUnverifiedClaims() unexpected error: %v", err)
				return
			}

			// Check subject
			if sub, ok := claims["sub"].(string); ok {
				if sub != tt.wantSubject {
					t.Errorf("subject = %q, want %q", sub, tt.wantSubject)
				}
			}

			// Check audience using helper
			audiences := GetAudienceFromClaims(claims)
			if len(audiences) != len(tt.wantAudience) {
				t.Errorf("audience = %v, want %v", audiences, tt.wantAudience)
			}
		})
	}
}

func TestGetAudienceFromClaims(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwt.MapClaims
		expected []string
	}{
		{
			name:     "no audience",
			claims:   jwt.MapClaims{},
			expected: nil,
		},
		{
			name:     "single string audience",
			claims:   jwt.MapClaims{"aud": "client-id"},
			expected: []string{"client-id"},
		},
		{
			name:     "array audience",
			claims:   jwt.MapClaims{"aud": []any{"client-a", "client-b"}},
			expected: []string{"client-a", "client-b"},
		},
		{
			name:     "invalid type",
			claims:   jwt.MapClaims{"aud": 12345},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetAudienceFromClaims(tt.claims)

			if len(got) != len(tt.expected) {
				t.Errorf("GetAudienceFromClaims() = %v, want %v", got, tt.expected)
				return
			}

			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("GetAudienceFromClaims()[%d] = %q, want %q", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestValidateAudience(t *testing.T) {
	tests := []struct {
		name             string
		tokenAudiences   []string
		trustedAudiences []string
		wantError        bool
	}{
		{
			name:             "empty trusted audiences - no validation",
			tokenAudiences:   []string{"any-client"},
			trustedAudiences: nil,
			wantError:        false,
		},
		{
			name:             "exact match - single audience",
			tokenAudiences:   []string{"client-a"},
			trustedAudiences: []string{"client-a"},
			wantError:        false,
		},
		{
			name:             "exact match - multiple token audiences",
			tokenAudiences:   []string{"client-a", "client-b"},
			trustedAudiences: []string{"client-b"},
			wantError:        false,
		},
		{
			name:             "no match",
			tokenAudiences:   []string{"client-a"},
			trustedAudiences: []string{"client-b"},
			wantError:        true,
		},
		{
			name:             "empty token audiences",
			tokenAudiences:   []string{},
			trustedAudiences: []string{"client-a"},
			wantError:        true,
		},
		{
			name:             "URL normalization - trailing slash match",
			tokenAudiences:   []string{"https://example.com"},
			trustedAudiences: []string{"https://example.com/"},
			wantError:        false,
		},
		{
			name:             "URL normalization - reverse trailing slash match",
			tokenAudiences:   []string{"https://example.com/"},
			trustedAudiences: []string{"https://example.com"},
			wantError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &IDTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: tt.tokenAudiences,
				},
			}

			err := validateAudience(claims, tt.trustedAudiences)

			if tt.wantError && err == nil {
				t.Error("validateAudience() expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("validateAudience() unexpected error: %v", err)
			}
		})
	}
}

func TestValidateIssuer(t *testing.T) {
	tests := []struct {
		name           string
		tokenIssuer    string
		expectedIssuer string
		wantError      bool
	}{
		{
			name:           "empty expected issuer - no validation",
			tokenIssuer:    "any-issuer",
			expectedIssuer: "",
			wantError:      false,
		},
		{
			name:           "exact match",
			tokenIssuer:    "https://auth.example.com",
			expectedIssuer: "https://auth.example.com",
			wantError:      false,
		},
		{
			name:           "mismatch",
			tokenIssuer:    "https://auth.example.com",
			expectedIssuer: "https://other.example.com",
			wantError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &IDTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: tt.tokenIssuer,
				},
			}

			err := validateIssuer(claims, tt.expectedIssuer)

			if tt.wantError && err == nil {
				t.Error("validateIssuer() expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("validateIssuer() unexpected error: %v", err)
			}
		})
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"https://example.com///", "https://example.com"},
		{"https://example.com/path/", "https://example.com/path"},
		{"client-id", "client-id"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeURL(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// createTestJWTWithClaims creates a JWT token for testing purposes.
// The token has valid structure but an invalid signature (for parsing tests only).
func createTestJWTWithClaims(t *testing.T, claims map[string]any) string {
	t.Helper()

	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("Failed to marshal header: %v", err)
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Failed to marshal claims: %v", err)
	}

	// Create unsigned JWT (header.payload.signature)
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(claimsBytes) + ".signature"
}
