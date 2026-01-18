package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
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
			token: createTestJWTWithClaims(t, map[string]interface{}{
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
			token: createTestJWTWithClaims(t, map[string]interface{}{
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
			claims:   jwt.MapClaims{"aud": []interface{}{"client-a", "client-b"}},
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

func TestJWKToRSAPublicKey(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert to JWK format
	n := base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes())

	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: "test-kid",
		Alg: "RS256",
		N:   n,
		E:   e,
	}

	// Convert back to RSA public key
	pubKey, err := jwk.RSAPublicKey()
	if err != nil {
		t.Fatalf("RSAPublicKey() error: %v", err)
	}

	// Verify the key matches
	if pubKey.N.Cmp(privateKey.N) != 0 {
		t.Error("Modulus mismatch")
	}
	if pubKey.E != privateKey.E {
		t.Error("Exponent mismatch")
	}
}

func TestJWKToRSAPublicKey_UnsupportedKeyType(t *testing.T) {
	jwk := JWK{
		Kty: "EC", // Unsupported
		Kid: "test-kid",
	}

	_, err := jwk.RSAPublicKey()
	if err == nil {
		t.Error("Expected error for unsupported key type")
	}
}

func TestJWKSClient_Creation(t *testing.T) {
	// Test that client is created with defaults
	client := NewJWKSClient(nil, 0, nil)
	if client == nil {
		t.Fatal("NewJWKSClient returned nil")
	}
	if client.cacheTTL != 1*time.Hour {
		t.Errorf("Expected default cacheTTL 1h, got %v", client.cacheTTL)
	}

	// Test with custom values
	customHTTP := &http.Client{Timeout: 5 * time.Second}
	customClient := NewJWKSClient(customHTTP, 30*time.Minute, slog.Default())
	if customClient == nil {
		t.Fatal("NewJWKSClient with custom values returned nil")
	}
	if customClient.httpClient != customHTTP {
		t.Error("Expected custom HTTP client to be used")
	}
	if customClient.cacheTTL != 30*time.Minute {
		t.Errorf("Expected cacheTTL 30m, got %v", customClient.cacheTTL)
	}
}

func TestJWKS_GetKey(t *testing.T) {
	jwks := &JWKS{
		Keys: []JWK{
			{Kid: "key-1", Kty: "RSA"},
			{Kid: "key-2", Kty: "RSA"},
			{Kid: "key-3", Kty: "RSA"},
		},
	}

	tests := []struct {
		name     string
		kid      string
		expected string
	}{
		{"find first key", "key-1", "key-1"},
		{"find middle key", "key-2", "key-2"},
		{"find last key", "key-3", "key-3"},
		{"key not found", "key-4", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := jwks.GetKey(tt.kid)
			if tt.expected == "" {
				if key != nil {
					t.Errorf("Expected nil, got key with kid=%s", key.Kid)
				}
			} else {
				if key == nil {
					t.Errorf("Expected key with kid=%s, got nil", tt.expected)
				} else if key.Kid != tt.expected {
					t.Errorf("Expected kid=%s, got kid=%s", tt.expected, key.Kid)
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
			name:             "exact match - multiple trusted",
			tokenAudiences:   []string{"client-b"},
			trustedAudiences: []string{"client-a", "client-b", "client-c"},
			wantError:        false,
		},
		{
			name:             "multiple token audiences - one matches",
			tokenAudiences:   []string{"client-x", "client-a"},
			trustedAudiences: []string{"client-a"},
			wantError:        false,
		},
		{
			name:             "no match",
			tokenAudiences:   []string{"unknown-client"},
			trustedAudiences: []string{"client-a", "client-b"},
			wantError:        true,
		},
		{
			name:             "empty token audience",
			tokenAudiences:   nil,
			trustedAudiences: []string{"client-a"},
			wantError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &IDTokenClaims{}
			claims.Audience = tt.tokenAudiences

			err := validateAudience(claims, tt.trustedAudiences)

			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
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
			name:           "empty expected - no validation",
			tokenIssuer:    "https://any.issuer.com",
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
			tokenIssuer:    "https://other.issuer.com",
			expectedIssuer: "https://auth.example.com",
			wantError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &IDTokenClaims{}
			claims.Issuer = tt.tokenIssuer

			err := validateIssuer(claims, tt.expectedIssuer)

			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// createTestJWTWithClaims creates an unsigned JWT for testing purposes.
// This is only for testing ParseUnverifiedClaims - not for production use.
func createTestJWTWithClaims(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	// Create header
	header := map[string]interface{}{
		"alg": "none",
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

func TestValidateIDToken_Integration(t *testing.T) {
	// Generate RSA key for signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create JWKS
	testJWKS := JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: "test-key-1",
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
			},
		},
	}

	// Create JWKS server
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(testJWKS); err != nil {
			t.Errorf("Failed to encode JWKS: %v", err)
		}
	}))
	defer jwksServer.Close()

	// Create a valid signed JWT
	claims := &IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user123",
			Issuer:    "https://auth.example.com",
			Audience:  []string{"client-a", "client-b"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Create JWKS client that skips HTTPS validation for test server
	client := &JWKSClient{
		httpClient:   jwksServer.Client(),
		cacheTTL:     1 * time.Minute,
		timeProvider: realTime{},
		logger:       slog.Default(),
	}

	// Manually add to cache since we can't use the test server URL (localhost)
	client.cache.Store(jwksServer.URL, &cachedJWKS{
		keys:      &testJWKS,
		fetchedAt: time.Now(),
	})

	// Test valid token
	t.Run("valid token", func(t *testing.T) {
		validatedClaims, err := ValidateIDToken(
			context.Background(),
			signedToken,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"client-a"},
		)
		if err != nil {
			t.Errorf("ValidateIDToken() error: %v", err)
			return
		}

		if validatedClaims.Subject != "user123" {
			t.Errorf("Subject = %q, want %q", validatedClaims.Subject, "user123")
		}
		if validatedClaims.Email != "user@example.com" {
			t.Errorf("Email = %q, want %q", validatedClaims.Email, "user@example.com")
		}
	})

	// Test audience mismatch
	t.Run("audience mismatch", func(t *testing.T) {
		_, err := ValidateIDToken(
			context.Background(),
			signedToken,
			client,
			jwksServer.URL,
			"https://auth.example.com",
			[]string{"untrusted-client"},
		)

		if err == nil {
			t.Error("Expected error for audience mismatch")
		}
	})

	// Test issuer mismatch
	t.Run("issuer mismatch", func(t *testing.T) {
		_, err := ValidateIDToken(
			context.Background(),
			signedToken,
			client,
			jwksServer.URL,
			"https://wrong.issuer.com",
			[]string{"client-a"},
		)

		if err == nil {
			t.Error("Expected error for issuer mismatch")
		}
	})
}
