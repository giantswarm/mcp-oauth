package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

func newResourceTargetServer(t *testing.T, resourceIdentifier string, pathResources map[string]ProtectedResourceConfig) (*Server, *memory.Store, *storage.Client, *bytes.Buffer) {
	t.Helper()
	logger, logs := captureLogger()
	store := memory.New()
	t.Cleanup(store.Stop)
	srv, err := New(mock.NewProvider(), store, store, store, &Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          resourceIdentifier,
		ResourceMetadataByPath:      pathResources,
		RequirePKCE:                 true,
		DisableNonceEchoRequirement: true,
	}, logger)
	require.NoError(t, err)
	srv.Auditor = security.NewAuditor(logger, true)
	client, _, err := srv.RegisterClient(t.Context(), "Test Client", ClientTypePublic, "",
		[]string{"https://example.com/callback"}, []string{"openid"}, "192.168.1.100", 10)
	require.NoError(t, err)
	return srv, store, client, logs
}

func TestStartAuthorizationFlow_ResourceTarget(t *testing.T) {
	pathResources := map[string]ProtectedResourceConfig{
		"/mcp/files": {},
		"/mcp/admin": {ResourceIdentifier: "https://admin.example.com/mcp"},
		"mcp/notes":  {},
	}
	tests := []struct {
		name               string
		resourceIdentifier string
		resource           string
		wantRefused        bool
	}{
		{name: "configured identifier", resourceIdentifier: "https://mcp.example.com/mcp", resource: "https://mcp.example.com/mcp"},
		{name: "configured identifier with trailing slash", resourceIdentifier: "https://mcp.example.com/mcp", resource: "https://mcp.example.com/mcp/"},
		{name: "configured identifier with upper-case host", resourceIdentifier: "https://mcp.example.com/mcp", resource: "https://MCP.example.com/mcp"},
		{name: "issuer when no identifier is configured", resource: "https://auth.example.com"},
		{name: "path resource derived from the identifier", resourceIdentifier: "https://mcp.example.com", resource: "https://mcp.example.com/mcp/files"},
		{name: "path resource whose key has no leading slash", resourceIdentifier: "https://mcp.example.com", resource: "https://mcp.example.com/mcp/notes"},
		{name: "path resource with its own identifier", resourceIdentifier: "https://mcp.example.com", resource: "https://admin.example.com/mcp"},
		{name: "another server", resourceIdentifier: "https://mcp.example.com/mcp", resource: "https://other.example.com/mcp", wantRefused: true},
		{name: "another path on this host", resourceIdentifier: "https://mcp.example.com/mcp", resource: "https://mcp.example.com/other", wantRefused: true},
		{name: "a sub-path of the identifier", resourceIdentifier: "https://mcp.example.com/mcp", resource: "https://mcp.example.com/mcp/tools", wantRefused: true},
		{name: "another port", resourceIdentifier: "https://mcp.example.com/mcp", resource: "https://mcp.example.com:8443/mcp", wantRefused: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, client, logs := newResourceTargetServer(t, tt.resourceIdentifier, pathResources)
			codeChallenge, _ := generatePKCEPair()

			_, err := srv.StartAuthorizationFlow(t.Context(), client.ClientID,
				mustParseURL(t, client.RedirectURIs[0]), "openid", tt.resource,
				codeChallenge, PKCEMethodS256, generateRandomToken(), nil)

			if !tt.wantRefused {
				require.NoError(t, err)
				return
			}
			var authErr *AuthorizationRequestError
			require.True(t, errors.As(err, &authErr), "got %v", err)
			require.Equal(t, ErrorCodeInvalidTarget, authErr.Code)
			require.True(t, containsAuthFailure(logs.String(), "invalid_resource"), "audit log: %s", logs.String())
		})
	}
}

func TestExchangeAuthorizationCode_ResourceTarget(t *testing.T) {
	const servedResource = "https://mcp.example.com/mcp"
	tests := []struct {
		name          string
		codeResource  string
		tokenResource string
		wantErr       error
	}{
		{name: "configured identifier", codeResource: servedResource, tokenResource: servedResource},
		{name: "another server without a resource on the code", tokenResource: "https://other.example.com/mcp", wantErr: ErrInvalidTarget},
		{name: "another server with a resource on the code", codeResource: servedResource, tokenResource: "https://other.example.com/mcp", wantErr: ErrInvalidTarget},
		{name: "malformed resource", codeResource: servedResource, tokenResource: "https://mcp.example.com/mcp#fragment", wantErr: ErrInvalidTarget},
		{name: "served resource that differs from the code's", codeResource: servedResource, tokenResource: "https://mcp.example.com", wantErr: errInvalidGrant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, store, client, logs := newResourceTargetServer(t, servedResource,
				map[string]ProtectedResourceConfig{"/": {ResourceIdentifier: "https://mcp.example.com"}})
			verifier := testutil.GenerateRandomString(50)
			challengeHash := sha256.Sum256([]byte(verifier))
			authCode := &storage.AuthorizationCode{
				Code:                testutil.GenerateRandomString(32),
				ClientID:            client.ClientID,
				RedirectURI:         client.RedirectURIs[0],
				Scope:               "openid",
				Resource:            tt.codeResource,
				CodeChallenge:       base64.RawURLEncoding.EncodeToString(challengeHash[:]),
				CodeChallengeMethod: PKCEMethodS256,
				UserID:              "user-123",
				ProviderToken:       testutil.GenerateTestToken(),
				CreatedAt:           time.Now(),
				ExpiresAt:           time.Now().Add(10 * time.Minute),
			}
			require.NoError(t, store.SaveAuthorizationCode(t.Context(), authCode))

			_, _, err := srv.ExchangeAuthorizationCode(t.Context(), authCode.Code, client.ClientID,
				client.RedirectURIs[0], tt.tokenResource, verifier, "")

			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
			if errors.Is(tt.wantErr, ErrInvalidTarget) {
				require.True(t, containsAuthFailure(logs.String(), "invalid_resource"), "audit log: %s", logs.String())
			}
		})
	}
}

func TestRefreshAccessToken_ResourceNoLongerServed(t *testing.T) {
	const servedResource = "https://mcp.example.com/mcp"
	srv, store, client, logs := newResourceTargetServer(t, servedResource, nil)
	verifier := testutil.GenerateRandomString(50)
	challengeHash := sha256.Sum256([]byte(verifier))
	authCode := &storage.AuthorizationCode{
		Code:                testutil.GenerateRandomString(32),
		ClientID:            client.ClientID,
		RedirectURI:         client.RedirectURIs[0],
		Scope:               "openid",
		Resource:            servedResource,
		CodeChallenge:       base64.RawURLEncoding.EncodeToString(challengeHash[:]),
		CodeChallengeMethod: PKCEMethodS256,
		UserID:              "user-123",
		ProviderToken:       testutil.GenerateTestToken(),
		CreatedAt:           time.Now(),
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}
	require.NoError(t, store.SaveAuthorizationCode(t.Context(), authCode))
	tokens, _, err := srv.ExchangeAuthorizationCode(t.Context(), authCode.Code, client.ClientID,
		client.RedirectURIs[0], servedResource, verifier, "")
	require.NoError(t, err)
	require.NotEmpty(t, tokens.RefreshToken)
	require.NoError(t, store.SaveUserProviderToken(t.Context(), authCode.UserID, authCode.ProviderToken))

	srv.Config.ResourceIdentifier = "https://mcp.example.com/v2"
	_, err = srv.RefreshAccessToken(t.Context(), tokens.RefreshToken, client.ClientID)
	require.ErrorIs(t, err, errInvalidGrant)
	require.True(t, containsAuthFailure(logs.String(), auditReasonRefreshResourceNotServed), "audit log: %s", logs.String())
	require.False(t, containsAuditEvent(logs.String(), "refresh_token_reuse_detected"), "audit log: %s", logs.String())

	srv.Config.ResourceIdentifier = servedResource
	_, err = srv.RefreshAccessToken(t.Context(), tokens.RefreshToken, client.ClientID)
	require.NoError(t, err, "the refused refresh token is neither consumed nor revoked")
}

func TestSelfIssuedExchange_AllowedResourceComparedNormalized(t *testing.T) {
	tests := []struct {
		name        string
		resource    string
		wantRefused bool
	}{
		{name: "listed value", resource: "https://backend.example.com"},
		{name: "listed value with upper-case host, default port and trailing slash", resource: "https://BACKEND.example.com:443/"},
		{name: "own identifier with trailing slash", resource: "https://api.example.com/"},
		{name: "another path on the listed host", resource: "https://backend.example.com/other", wantRefused: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := newActorExchangeServer(t)
			srv.Config.TokenExchangeAllowedResources = []string{"https://backend.example.com"}
			srv.subjectValidators = map[string]SubjectTokenValidator{
				SubjectTokenTypeIDToken: &stubTokenValidator{byToken: map[string]*SubjectIdentity{
					"sub-tok": {Subject: testSubject, Issuer: testIssuer},
				}},
			}

			_, err := srv.SelfIssuedExchange(t.Context(), SelfIssuedExchangeRequest{ClientID: registerExchangeClient(t, srv), SubjectExchange: SubjectExchange{
				Subject:  TypedToken{Token: "sub-tok", Type: SubjectTokenTypeIDToken},
				Resource: tt.resource,
			}})

			if tt.wantRefused {
				require.ErrorIs(t, err, ErrInvalidTarget)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRefuseRefreshResourceMismatch_GrantWithoutAudience(t *testing.T) {
	srv, _, client, logs := newResourceTargetServer(t, "https://mcp.example.com/mcp", nil)

	require.NoError(t, srv.refuseRefreshResourceMismatch(t.Context(), "https://MCP.example.com/mcp/", "", "user-123", client.ClientID))
	require.NoError(t, srv.refuseRefreshResourceMismatch(t.Context(), "", "", "user-123", client.ClientID))

	err := srv.refuseRefreshResourceMismatch(t.Context(), "https://other.example.com/mcp", "", "user-123", client.ClientID)
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.True(t, containsAuthFailure(logs.String(), auditReasonRefreshResourceMismatch), "audit log: %s", logs.String())
}
