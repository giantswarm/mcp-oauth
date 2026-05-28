package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// generateRSAKey returns a fresh small RSA key for tests. 2048 bits is the
// minimum NIST-recommended size and enough for unit tests; production keys
// should be larger.
func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

// generateECKey returns a fresh ECDSA key on the requested curve.
func generateECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return k
}

func TestConfigValidate_MissingIssuer(t *testing.T) {
	err := (&Config{}).Validate()
	require.ErrorIs(t, err, ErrMissingIssuer)
}

func TestConfigValidate_OpaqueMode(t *testing.T) {
	t.Run("empty AccessTokenFormat is opaque and accepted", func(t *testing.T) {
		require.NoError(t, (&Config{Issuer: testIssuer}).Validate())
	})

	t.Run("explicit opaque is accepted", func(t *testing.T) {
		require.NoError(t, (&Config{Issuer: testIssuer, AccessTokenFormat: AccessTokenFormatOpaque}).Validate())
	})

	t.Run("unknown AccessTokenFormat is rejected", func(t *testing.T) {
		err := (&Config{Issuer: testIssuer, AccessTokenFormat: "JWT"}).Validate() // wrong case
		require.Error(t, err)
		require.Contains(t, err.Error(), "not recognized")
	})

	t.Run("opaque mode ignores signing key fields", func(t *testing.T) {
		cfg := &Config{
			Issuer:                      testIssuer,
			AccessTokenFormat:           AccessTokenFormatOpaque,
			AccessTokenSigningKey:       generateRSAKey(t),
			AccessTokenSigningKeyID:     "k1",
			AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		}
		require.NoError(t, cfg.Validate())
	})
}

func TestConfigValidate_JWTMode_RequiredFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "missing key",
			cfg: &Config{
				Issuer:                      testIssuer,
				AccessTokenFormat:           AccessTokenFormatJWT,
				AccessTokenSigningKeyID:     "k1",
				AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
			},
			want: "AccessTokenSigningKey is required",
		},
		{
			name: "missing kid",
			cfg: &Config{
				Issuer:                      testIssuer,
				AccessTokenFormat:           AccessTokenFormatJWT,
				AccessTokenSigningKey:       generateRSAKey(t),
				AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
			},
			want: "AccessTokenSigningKeyID is required",
		},
		{
			name: "missing alg",
			cfg: &Config{
				Issuer:                  testIssuer,
				AccessTokenFormat:       AccessTokenFormatJWT,
				AccessTokenSigningKey:   generateRSAKey(t),
				AccessTokenSigningKeyID: "k1",
			},
			want: "AccessTokenSigningAlgorithm is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestConfigValidate_JWTMode_AlgorithmAccepted(t *testing.T) {
	for _, alg := range []string{
		SigningAlgorithmRS256,
		SigningAlgorithmRS384,
		SigningAlgorithmRS512,
	} {
		t.Run(alg, func(t *testing.T) {
			cfg := &Config{
				Issuer:                      testIssuer,
				AccessTokenFormat:           AccessTokenFormatJWT,
				AccessTokenSigningKey:       generateRSAKey(t),
				AccessTokenSigningKeyID:     "rsa-1",
				AccessTokenSigningAlgorithm: alg,
			}
			require.NoError(t, cfg.Validate())
		})
	}
	t.Run(SigningAlgorithmES256, func(t *testing.T) {
		cfg := &Config{
			Issuer:                      testIssuer,
			AccessTokenFormat:           AccessTokenFormatJWT,
			AccessTokenSigningKey:       generateECKey(t, elliptic.P256()),
			AccessTokenSigningKeyID:     "ec-1",
			AccessTokenSigningAlgorithm: SigningAlgorithmES256,
		}
		require.NoError(t, cfg.Validate())
	})
	t.Run(SigningAlgorithmES384, func(t *testing.T) {
		cfg := &Config{
			Issuer:                      testIssuer,
			AccessTokenFormat:           AccessTokenFormatJWT,
			AccessTokenSigningKey:       generateECKey(t, elliptic.P384()),
			AccessTokenSigningKeyID:     "ec-2",
			AccessTokenSigningAlgorithm: SigningAlgorithmES384,
		}
		require.NoError(t, cfg.Validate())
	})
}

func TestConfigValidate_JWTMode_AlgorithmRejected(t *testing.T) {
	for _, alg := range []string{"none", "HS256", "HS384", "HS512", "RS128", ""} {
		t.Run(alg, func(t *testing.T) {
			cfg := &Config{
				Issuer:                      testIssuer,
				AccessTokenFormat:           AccessTokenFormatJWT,
				AccessTokenSigningKey:       generateRSAKey(t),
				AccessTokenSigningKeyID:     "k1",
				AccessTokenSigningAlgorithm: alg,
			}
			err := cfg.Validate()
			require.Error(t, err)
			if alg == "" {
				require.Contains(t, err.Error(), "AccessTokenSigningAlgorithm is required")
			} else {
				require.Contains(t, err.Error(), "not supported")
			}
		})
	}
}

func TestConfigValidate_JWTMode_KeyAlgMismatch(t *testing.T) {
	t.Run("RSA key with ES256 alg rejected", func(t *testing.T) {
		cfg := &Config{
			Issuer:                      testIssuer,
			AccessTokenFormat:           AccessTokenFormatJWT,
			AccessTokenSigningKey:       generateRSAKey(t),
			AccessTokenSigningKeyID:     "k1",
			AccessTokenSigningAlgorithm: SigningAlgorithmES256,
		}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires an *ecdsa.PrivateKey")
	})

	t.Run("ECDSA key with RS256 alg rejected", func(t *testing.T) {
		cfg := &Config{
			Issuer:                      testIssuer,
			AccessTokenFormat:           AccessTokenFormatJWT,
			AccessTokenSigningKey:       generateECKey(t, elliptic.P256()),
			AccessTokenSigningKeyID:     "k1",
			AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires an *rsa.PrivateKey")
	})

	t.Run("ECDSA P-384 key with ES256 alg rejected", func(t *testing.T) {
		cfg := &Config{
			Issuer:                      testIssuer,
			AccessTokenFormat:           AccessTokenFormatJWT,
			AccessTokenSigningKey:       generateECKey(t, elliptic.P384()),
			AccessTokenSigningKeyID:     "k1",
			AccessTokenSigningAlgorithm: SigningAlgorithmES256,
		}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires curve P-256")
	})

	t.Run("ECDSA P-256 key with ES384 alg rejected", func(t *testing.T) {
		cfg := &Config{
			Issuer:                      testIssuer,
			AccessTokenFormat:           AccessTokenFormatJWT,
			AccessTokenSigningKey:       generateECKey(t, elliptic.P256()),
			AccessTokenSigningKeyID:     "k1",
			AccessTokenSigningAlgorithm: SigningAlgorithmES384,
		}
		err := cfg.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "requires curve P-384")
	})
}

func TestConfigIsJWTAccessTokenFormat(t *testing.T) {
	require.False(t, (&Config{}).IsJWTAccessTokenFormat())
	require.False(t, (&Config{AccessTokenFormat: AccessTokenFormatOpaque}).IsJWTAccessTokenFormat())
	require.True(t, (&Config{AccessTokenFormat: AccessTokenFormatJWT}).IsJWTAccessTokenFormat())
}

func TestConfigJWKSEndpoint(t *testing.T) {
	cfg := &Config{Issuer: testAuthIssuer}
	require.Equal(t, "https://auth.example.com/.well-known/jwks.json", cfg.JWKSEndpoint())
}
