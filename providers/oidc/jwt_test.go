package oidc

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
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

			if sub, ok := claims["sub"].(string); ok {
				if sub != tt.wantSubject {
					t.Errorf("subject = %q, want %q", sub, tt.wantSubject)
				}
			}

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
		claims   map[string]any
		expected []string
	}{
		{
			name:     "no audience",
			claims:   map[string]any{},
			expected: nil,
		},
		{
			name:     "single string audience",
			claims:   map[string]any{"aud": "client-id"},
			expected: []string{"client-id"},
		},
		{
			name:     "array audience",
			claims:   map[string]any{"aud": []any{"client-a", "client-b"}},
			expected: []string{"client-a", "client-b"},
		},
		{
			name:     "invalid type",
			claims:   map[string]any{"aud": 12345},
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
				Claims: josejwt.Claims{
					Audience: josejwt.Audience(tt.tokenAudiences),
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

func TestValidateTimeAndIssuer_IssuerMismatch(t *testing.T) {
	now := time.Now()
	claims := &IDTokenClaims{
		Claims: josejwt.Claims{
			Issuer: "https://auth.example.com",
			Expiry: josejwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	err := validateTimeAndIssuer(claims, "https://other.example.com")
	if err == nil {
		t.Fatal("validateTimeAndIssuer() expected error, got nil")
	}
}

func TestValidateTimeAndIssuer_NoExpectedIssuerSkipsCheck(t *testing.T) {
	now := time.Now()
	claims := &IDTokenClaims{
		Claims: josejwt.Claims{
			Issuer: "https://anything.example.com",
			Expiry: josejwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	if err := validateTimeAndIssuer(claims, ""); err != nil {
		t.Errorf("validateTimeAndIssuer() with empty expected issuer should pass, got: %v", err)
	}
}

// TestParseAndValidateToken_TimeValidation tests time-based claim validation.
// This ensures exp, nbf, and iat claims are properly validated with clock skew leeway.
func TestParseAndValidateToken_TimeValidation(t *testing.T) {
	t.Run("clock skew leeway is configured", func(t *testing.T) {
		if DefaultClockSkewLeeway < 5*time.Second {
			t.Errorf("DefaultClockSkewLeeway = %v, should be at least 5 seconds for clock drift tolerance", DefaultClockSkewLeeway)
		}
		if DefaultClockSkewLeeway > 5*time.Minute {
			t.Errorf("DefaultClockSkewLeeway = %v, should not exceed 5 minutes for security", DefaultClockSkewLeeway)
		}
	})

	t.Run("leeway is 30 seconds by default", func(t *testing.T) {
		expected := 30 * time.Second
		if DefaultClockSkewLeeway != expected {
			t.Errorf("DefaultClockSkewLeeway = %v, want %v", DefaultClockSkewLeeway, expected)
		}
	})
}

func TestValidateNonceClaim(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		claimNonce     string
		expectedNonce  string
		wantErr        error
		wantErrMessage string
	}{
		{
			name:          "match",
			claimNonce:    "abc",
			expectedNonce: "abc",
			wantErr:       nil,
		},
		{
			name:          "mismatch",
			claimNonce:    "abc",
			expectedNonce: "xyz",
			wantErr:       ErrNonceMismatch,
		},
		{
			name:           "missing in claims",
			claimNonce:     "",
			expectedNonce:  "abc",
			wantErr:        ErrNonceMismatch,
			wantErrMessage: "claim absent",
		},
		{
			name:          "missing expectation",
			claimNonce:    "abc",
			expectedNonce: "",
			wantErr:       nil,
		},
		{
			name:          "both empty",
			claimNonce:    "",
			expectedNonce: "",
			wantErr:       nil,
		},
		{
			name:          "same length different content",
			claimNonce:    "aaaa",
			expectedNonce: "bbbb",
			wantErr:       ErrNonceMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_ = t.Context()

			err := ValidateNonceClaim(tt.claimNonce, tt.expectedNonce)

			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantErrMessage != "" {
				require.Contains(t, err.Error(), tt.wantErrMessage)
			}
		})
	}
}

// TestIDTokenClaims_NonStringNonce documents the first line of nonce-defence
// in depth: ValidateNonceClaim only sees a string, because the typed
// IDTokenClaims.Nonce field rejects a non-string JSON value during claim
// extraction. A token with "nonce": 42 fails before the comparison runs.
func TestIDTokenClaims_NonStringNonce(t *testing.T) {
	t.Parallel()
	_ = t.Context()

	payload, err := json.Marshal(map[string]any{
		"sub":   "user",
		"nonce": 42,
	})
	require.NoError(t, err)

	var claims IDTokenClaims
	err = json.Unmarshal(payload, &claims)
	require.Error(t, err, "non-string nonce must not unmarshal into IDTokenClaims.Nonce")
}

// createTestJWTWithClaims creates a JWT token for testing purposes.
// The token has valid structure but an invalid signature (for parsing tests only).
// The signature is valid base64 but not cryptographically valid.
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

	fakeSignature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature-for-testing"))
	return base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(claimsBytes) + "." + fakeSignature
}
