package server

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

func TestClientAssertion_TypHeader(t *testing.T) {
	key := assertionKey(t, jose.ES256)
	client := assertionClient(t, key)
	tests := []struct {
		typ           string
		wantDeprecate bool
	}{
		{typ: ""},
		{typ: "JWT"},
		{typ: "jwt"},
		{typ: "client-authentication+jwt"},
		{typ: "application/client-authentication+jwt"},
		{typ: "at+jwt", wantDeprecate: true},
		{typ: "dpop+jwt", wantDeprecate: true},
	}
	for _, tt := range tests {
		t.Run("typ="+tt.typ, func(t *testing.T) {
			var logs bytes.Buffer
			srv := &Server{
				Config:                     &Config{Issuer: "https://auth.example.com"},
				Logger:                     slog.New(slog.NewTextHandler(&logs, nil)),
				clientAssertionReplayStore: NewMemoryClientAssertionReplayStore(),
			}
			options := &jose.SignerOptions{}
			if tt.typ != "" {
				options = options.WithType(jose.ContentType(tt.typ))
			}
			signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
			require.NoError(t, err)
			assertion, err := jwt.Signed(signer).Claims(validAssertionClaims()).Serialize()
			require.NoError(t, err)

			require.NoError(t, srv.ValidateClientAssertion(t.Context(), client, assertion))
			if tt.wantDeprecate {
				require.Contains(t, logs.String(), "DEPRECATED")
				require.Contains(t, logs.String(), tt.typ)
			} else {
				require.NotContains(t, logs.String(), "DEPRECATED")
			}
		})
	}
}

func TestJWTIssuer_ExtraDeprecatedClaims(t *testing.T) {
	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       generateRSAKey(t),
		AccessTokenSigningKeyID:     "kid-1",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
	}
	issuer, err := newJWTIssuer(cfg)
	require.NoError(t, err)

	for _, claim := range []string{"scope", "cnf", "act", "family_id"} {
		t.Run(claim, func(t *testing.T) {
			var logs bytes.Buffer
			issuer.logger = slog.New(slog.NewTextHandler(&logs, nil))
			_, err := issuer.Issue(t.Context(), AccessTokenClaims{
				Subject: "u", Audience: "a", ExpiresAt: time.Now().Add(time.Minute),
				Extra: map[string]any{claim: "injected"},
			})
			require.NoError(t, err)
			require.Contains(t, logs.String(), "DEPRECATED")
			require.Contains(t, logs.String(), claim)
		})
	}

	var logs bytes.Buffer
	issuer.logger = slog.New(slog.NewTextHandler(&logs, nil))
	_, err = issuer.Issue(t.Context(), AccessTokenClaims{
		Subject: "u", Audience: "a", ExpiresAt: time.Now().Add(time.Minute),
		Extra: map[string]any{"tenant": "t1"},
	})
	require.NoError(t, err)
	require.NotContains(t, logs.String(), "DEPRECATED")
}
