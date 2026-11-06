package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/server"
	storagemock "github.com/giantswarm/mcp-oauth/storage/mock"
)

func TestTokenGrant_MetadataWriteFailureHTTP(t *testing.T) {
	for _, format := range []server.AccessTokenFormat{server.AccessTokenFormatOpaque, server.AccessTokenFormatJWT} {
		for _, grant := range []string{"authorization_code", "refresh_token"} {
			t.Run(string(format)+"/"+grant, func(t *testing.T) {
				environment := newOutageEnvWithFormat(t, format)
				var form url.Values
				if grant == "authorization_code" {
					code, verifier := environment.issueCode(t)
					form = environment.codeForm(code, verifier)
				} else {
					pair := environment.login(t)
					form = environment.refreshForm(pair.RefreshToken)
				}
				environment.faulty.Fail(storagemock.OnOperation("save_token_metadata", storagemock.ConnectionRefused))
				response := environment.postToken(form)
				require.Equal(t, http.StatusServiceUnavailable, response.Code)
				require.NotEmpty(t, response.Header().Get("Retry-After"))
				var failure map[string]any
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &failure))
				require.Equal(t, "temporarily_unavailable", failure["error"])
				require.NotContains(t, failure, "access_token")
				environment.faulty.Heal()
				response = environment.postToken(form)
				require.Equal(t, http.StatusOK, response.Code)
				var pair struct {
					AccessToken string `json:"access_token"`
				}
				require.NoError(t, json.Unmarshal(response.Body.Bytes(), &pair))
				protected, _ := environment.callProtected(pair.AccessToken)
				require.Equal(t, http.StatusOK, protected.Code)
			})
		}
	}
}
