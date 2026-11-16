package server

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
)

func TestPrepareAuthorization_RefusalCarriesOAuthErrorCode(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)
	client, _, err := srv.RegisterClient(t.Context(), "Test Client", ClientTypePublic, "",
		[]string{"https://example.com/callback"}, []string{"openid", "email"}, "192.168.1.100", 10)
	require.NoError(t, err)
	redirectURI, err := url.Parse("https://example.com/callback")
	require.NoError(t, err)

	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	validState := testutil.GenerateRandomString(43)

	tests := []struct {
		name            string
		scope           string
		resource        string
		challenge       string
		challengeMethod string
		state           string
		wantCode        string
		wantDescription string
	}{
		{
			name:            "missing code_challenge",
			scope:           "openid",
			state:           validState,
			wantCode:        ErrorCodeInvalidRequest,
			wantDescription: "PKCE is required: code_challenge and code_challenge_method parameters are mandatory",
		},
		{
			name:            "missing code_challenge_method",
			scope:           "openid",
			challenge:       challenge,
			state:           validState,
			wantCode:        ErrorCodeInvalidRequest,
			wantDescription: "PKCE is required: code_challenge and code_challenge_method parameters are mandatory",
		},
		{
			name:            "plain method not allowed",
			scope:           "openid",
			challenge:       challenge,
			challengeMethod: PKCEMethodPlain,
			state:           validState,
			wantCode:        ErrorCodeInvalidRequest,
			wantDescription: "code_challenge_method plain is not allowed, use S256",
		},
		{
			name:            "unknown method is not echoed",
			scope:           "openid",
			challenge:       challenge,
			challengeMethod: "BOGUS<script>",
			state:           validState,
			wantCode:        ErrorCodeInvalidRequest,
			wantDescription: "code_challenge_method is not supported, use S256",
		},
		{
			name:            "short state",
			scope:           "openid",
			challenge:       challenge,
			challengeMethod: PKCEMethodS256,
			state:           "short",
			wantCode:        ErrorCodeInvalidRequest,
		},
		{
			name:            "scope too long",
			scope:           strings.Repeat("a", 2000),
			challenge:       challenge,
			challengeMethod: PKCEMethodS256,
			state:           validState,
			wantCode:        ErrorCodeInvalidScope,
		},
		{
			name:            "scope not supported by the server",
			scope:           "openid admin",
			challenge:       challenge,
			challengeMethod: PKCEMethodS256,
			state:           validState,
			wantCode:        ErrorCodeInvalidScope,
			wantDescription: "scope is not supported by this server",
		},
		{
			name:            "scope not allowed for the client",
			scope:           "openid profile",
			challenge:       challenge,
			challengeMethod: PKCEMethodS256,
			state:           validState,
			wantCode:        ErrorCodeInvalidScope,
			wantDescription: "scope is not allowed for this client",
		},
		{
			name:            "invalid resource",
			scope:           "openid",
			resource:        "not-a-uri",
			challenge:       challenge,
			challengeMethod: PKCEMethodS256,
			state:           validState,
			wantCode:        ErrorCodeInvalidTarget,
			wantDescription: "resource parameter is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := srv.PrepareAuthorization(t.Context(), client.ClientID, redirectURI, tt.scope, tt.resource, tt.challenge, tt.challengeMethod, tt.state, nil)
			var refused *AuthorizationRequestError
			require.ErrorAs(t, err, &refused)
			require.Equal(t, tt.wantCode, refused.Code)
			if tt.wantDescription != "" {
				require.Equal(t, tt.wantDescription, refused.Description)
			}
			require.NotContains(t, refused.Description, "BOGUS")
		})
	}
}

func TestPrepareAuthorization_UnknownClientIsNotARefusal(t *testing.T) {
	srv, _, _ := setupFlowTestServer(t)
	redirectURI, err := url.Parse("https://example.com/callback")
	require.NoError(t, err)

	_, err = srv.PrepareAuthorization(t.Context(), "no-such-client", redirectURI, "openid", "",
		"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", PKCEMethodS256, testutil.GenerateRandomString(43), nil)
	require.Error(t, err)
	var refused *AuthorizationRequestError
	require.False(t, errors.As(err, &refused), "a failed client lookup is a server failure: %v", err)
}
