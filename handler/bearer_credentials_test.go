package handler

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
)

func TestValidateToken_BearerCredentialTypesHTTP(t *testing.T) {
	for _, format := range []server.AccessTokenFormat{server.AccessTokenFormatOpaque, server.AccessTokenFormatJWT} {
		t.Run(string(format), func(t *testing.T) {
			environment := newOutageEnvWithFormat(t, format)
			pair := environment.login(t)
			protected := httptest.NewServer(environment.handler.ValidateToken(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusNoContent)
			})))
			t.Cleanup(protected.Close)
			encode := base64.RawURLEncoding.EncodeToString
			unsecuredJWT := encode([]byte(`{"alg":"none"}`)) + "." + encode([]byte(`{"aud":"another-resource","exp":1}`)) + "."
			var rejectionBody, rejectionChallenge string
			for _, test := range []struct {
				name   string
				bearer string
				status int
			}{
				{"issued access token", pair.AccessToken, http.StatusNoContent},
				{"issued refresh token", pair.RefreshToken, http.StatusUnauthorized},
				{"unknown opaque token", "unknown-provider-token", http.StatusUnauthorized},
				{"unsecured JWT", unsecuredJWT, http.StatusUnauthorized},
				{"malformed JWT", "header.payload.signature", http.StatusUnauthorized},
			} {
				t.Run(test.name, func(t *testing.T) {
					calls := environment.provider.GetCallCount("ValidateToken")
					request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, protected.URL+"/mcp", nil)
					require.NoError(t, err)
					request.Header.Set("Authorization", "Bearer "+test.bearer)
					response, err := protected.Client().Do(request)
					require.NoError(t, err)
					defer func() { require.NoError(t, response.Body.Close()) }()
					body, err := io.ReadAll(response.Body)
					require.NoError(t, err)
					require.Equal(t, test.status, response.StatusCode)
					if test.status == http.StatusUnauthorized {
						require.Equal(t, calls, environment.provider.GetCallCount("ValidateToken"))
						challenge := response.Header.Get("WWW-Authenticate")
						if rejectionBody == "" {
							rejectionBody, rejectionChallenge = string(body), challenge
						}
						require.Equal(t, rejectionBody, string(body))
						require.Equal(t, rejectionChallenge, challenge)
					}
				})
			}
			response := environment.postToken(environment.refreshForm(pair.RefreshToken))
			require.Equal(t, http.StatusOK, response.Code)
		})
	}
}
