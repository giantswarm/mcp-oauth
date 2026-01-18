package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

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

func TestJWKToRSAPublicKey_WrongKeyType(t *testing.T) {
	jwk := JWK{
		Kty: "EC",
		Kid: "test-kid",
	}

	_, err := jwk.RSAPublicKey()
	if err == nil {
		t.Error("Expected error for EC key type when calling RSAPublicKey")
	}
}

func TestJWKToECDSAPublicKey(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		crv   string
	}{
		{"P-256", elliptic.P256(), "P-256"},
		{"P-384", elliptic.P384(), "P-384"},
		{"P-521", elliptic.P521(), "P-521"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a test ECDSA key
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			// Convert to JWK format
			x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
			y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

			jwk := JWK{
				Kty: "EC",
				Use: "sig",
				Kid: "test-ec-kid",
				Alg: "ES256",
				Crv: tt.crv,
				X:   x,
				Y:   y,
			}

			// Convert back to ECDSA public key
			pubKey, err := jwk.ECDSAPublicKey()
			if err != nil {
				t.Fatalf("ECDSAPublicKey() error: %v", err)
			}

			// Verify the key matches
			if pubKey.X.Cmp(privateKey.X) != 0 {
				t.Error("X coordinate mismatch")
			}
			if pubKey.Y.Cmp(privateKey.Y) != 0 {
				t.Error("Y coordinate mismatch")
			}
			if pubKey.Curve != tt.curve {
				t.Errorf("Curve mismatch: got %v, want %v", pubKey.Curve, tt.curve)
			}
		})
	}
}

func TestJWKToECDSAPublicKey_WrongKeyType(t *testing.T) {
	jwk := JWK{
		Kty: "RSA",
		Kid: "test-kid",
	}

	_, err := jwk.ECDSAPublicKey()
	if err == nil {
		t.Error("Expected error for RSA key type when calling ECDSAPublicKey")
	}
}

func TestJWKToECDSAPublicKey_UnsupportedCurve(t *testing.T) {
	jwk := JWK{
		Kty: "EC",
		Kid: "test-kid",
		Crv: "P-192", // Unsupported curve
		X:   "test",
		Y:   "test",
	}

	_, err := jwk.ECDSAPublicKey()
	if err == nil {
		t.Error("Expected error for unsupported curve")
	}
	if !strings.Contains(err.Error(), "unsupported EC curve") {
		t.Errorf("Expected error about unsupported curve, got: %v", err)
	}
}

func TestJWKPublicKey(t *testing.T) {
	t.Run("RSA key", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		jwk := JWK{
			Kty: "RSA",
			Kid: "test-rsa",
			N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
		}

		key, err := jwk.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey() error: %v", err)
		}
		if _, ok := key.(*rsa.PublicKey); !ok {
			t.Errorf("Expected *rsa.PublicKey, got %T", key)
		}
	})

	t.Run("EC key", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		jwk := JWK{
			Kty: "EC",
			Kid: "test-ec",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes()),
			Y:   base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes()),
		}

		key, err := jwk.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey() error: %v", err)
		}
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			t.Errorf("Expected *ecdsa.PublicKey, got %T", key)
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		jwk := JWK{
			Kty: "OKP", // Unsupported (EdDSA)
			Kid: "test-okp",
		}

		_, err := jwk.PublicKey()
		if err == nil {
			t.Error("Expected error for unsupported key type")
		}
		if !strings.Contains(err.Error(), "unsupported key type") {
			t.Errorf("Expected error about unsupported key type, got: %v", err)
		}
	})
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
