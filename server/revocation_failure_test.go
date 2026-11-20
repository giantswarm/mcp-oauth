package server

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type unavailableJWTRevocationStore struct{ storage.RevokedTokenStore }

func (unavailableJWTRevocationStore) RevokeJTI(context.Context, string, time.Time) error {
	return errors.New("revocation write unavailable")
}

func TestJWTRevocationWriteFailureIsRetryable(t *testing.T) {
	server, _, _ := setupJWTFlowTestServer(t)
	auditor, audit := newRecordingAuditor()
	server.Auditor = auditor
	accessToken, err := server.accessTokenIssuer.Issue(t.Context(), AccessTokenClaims{
		Subject: "person", ClientID: "client", Audience: server.Config.GetResourceIdentifier(), ExpiresAt: time.Now().Add(time.Minute),
	})
	require.NoError(t, err)
	store := server.revokedTokenStore
	server.revokedTokenStore = unavailableJWTRevocationStore{store}
	require.ErrorIs(t, server.RevokeToken(t.Context(), accessToken, "client", "192.0.2.1"), ErrStorageUnavailable)
	for _, record := range decodeAuditRecords(t, audit.Bytes()) {
		require.NotEqual(t, security.EventSelfIssuedJWTRevoked, record.EventType)
	}
	_, err = server.ValidateToken(t.Context(), accessToken)
	require.NoError(t, err)
	server.revokedTokenStore = store
	require.NoError(t, server.RevokeToken(t.Context(), accessToken, "client", "192.0.2.1"))
	_, err = server.ValidateToken(t.Context(), accessToken)
	require.Error(t, err)
}

func TestJWTRevocationWithoutStorePreservesInvalidTokenResponse(t *testing.T) {
	server, _, _ := setupJWTFlowTestServer(t)
	accessToken, err := server.accessTokenIssuer.Issue(t.Context(), AccessTokenClaims{
		Subject: "person", ClientID: "client", Audience: server.Config.GetResourceIdentifier(), ExpiresAt: time.Now().Add(time.Minute),
	})
	require.NoError(t, err)
	server.revokedTokenStore = nil
	require.NoError(t, server.RevokeToken(t.Context(), accessToken, "other-client", "192.0.2.1"))
	require.ErrorIs(t, server.RevokeToken(t.Context(), accessToken, "client", "192.0.2.1"), ErrStorageUnavailable)
}

func TestCIMDJWTRevocationChecksOwnershipWithoutMetadata(t *testing.T) {
	server := newJWTModeServer(t, "https://api.example.com/mcp")
	server.Config.EnableClientIDMetadataDocuments = true
	clientID := "https://client.example.com/metadata.json"
	accessToken, err := server.issueAccessToken(t.Context(), accessTokenIssueParams{
		UserID: "person", ClientID: clientID, ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	client, err := server.GetRevocationClient(t.Context(), clientID)
	require.NoError(t, err)
	require.False(t, client.IsConfidential())
	require.NoError(t, server.RevokeToken(t.Context(), accessToken, "https://other.example.com/metadata.json", "192.0.2.1"))
	_, err = server.ValidateToken(t.Context(), accessToken)
	require.NoError(t, err)
	parts := strings.Split(accessToken, ".")
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	require.NoError(t, server.RevokeToken(t.Context(), strings.Join(parts, "."), clientID, "192.0.2.1"))
	_, err = server.ValidateToken(t.Context(), accessToken)
	require.NoError(t, err)
	require.NoError(t, server.RevokeToken(t.Context(), accessToken, clientID, "192.0.2.1"))
	_, err = server.ValidateToken(t.Context(), accessToken)
	require.Error(t, err)
}

func TestJWTRevocationIncludesClockSkewGracePeriod(t *testing.T) {
	server := newJWTModeServer(t, "https://api.example.com/mcp")
	server.Config.ClockSkewGracePeriod = 60
	accessToken, err := server.accessTokenIssuer.Issue(t.Context(), AccessTokenClaims{
		Subject: "person", ClientID: "client", Audience: server.Config.GetResourceIdentifier(), ExpiresAt: time.Now().Add(-time.Second),
	})
	require.NoError(t, err)
	_, err = server.ValidateToken(t.Context(), accessToken)
	require.NoError(t, err)
	require.NoError(t, server.RevokeToken(t.Context(), accessToken, "client", "192.0.2.1"))
	_, err = server.ValidateToken(t.Context(), accessToken)
	require.Error(t, err)
}

type unavailableLocalRevocationStore struct {
	*memory.Store
	failure string
}

func (s *unavailableLocalRevocationStore) DeleteProviderTokenRef(ctx context.Context, token string) error {
	if s.failure == "reference" {
		return errors.New("reference deletion unavailable")
	}
	return s.Store.DeleteProviderTokenRef(ctx, token)
}

func (s *unavailableLocalRevocationStore) DeleteRefreshToken(ctx context.Context, token string) error {
	if s.failure == "refresh" {
		return errors.New("refresh deletion unavailable")
	}
	return s.Store.DeleteRefreshToken(ctx, token)
}

func (s *unavailableLocalRevocationStore) RevokeRefreshTokenFamily(ctx context.Context, family string) error {
	if s.failure == "family" {
		return errors.New("family revocation unavailable")
	}
	return s.Store.RevokeRefreshTokenFamily(ctx, family)
}

func (s *unavailableLocalRevocationStore) RevokeTokensForFamily(ctx context.Context, userID, clientID, familyID string) (int, error) {
	if s.failure == "family" {
		return 0, errors.New("family revocation unavailable")
	}
	return s.Store.RevokeTokensForFamily(ctx, userID, clientID, familyID)
}

func TestRefreshRevocationInvalidatesOnlyItsOpaqueAccessFamily(t *testing.T) {
	server, store, provider := setupFlowTestServer(t)
	provider.RevokeTokenFunc = func(context.Context, string) error { return nil }
	require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), "refresh", "person", "client", "revoked-family", 1, time.Now().Add(time.Hour)))
	for _, familyID := range []string{"revoked-family", "other-family"} {
		seedProviderToken(t, store, familyID, "person", &oauth2.Token{AccessToken: "provider-access", Expiry: time.Now().Add(time.Hour)})
		require.NoError(t, store.SaveTokenMetadata(t.Context(), familyID, storage.TokenMetadata{
			UserID: "person", ClientID: "client", TokenType: "access", FamilyID: familyID,
			Audience: server.Config.GetResourceIdentifier(), ExpiresAt: time.Now().Add(time.Hour),
		}))
		_, err := server.ValidateToken(t.Context(), familyID)
		require.NoError(t, err)
	}
	require.NoError(t, server.RevokeToken(t.Context(), "refresh", "client", "192.0.2.1"))
	_, err := server.ValidateToken(t.Context(), "revoked-family")
	require.Error(t, err)
	_, err = server.ValidateToken(t.Context(), "other-family")
	require.NoError(t, err)
}

func TestLocalRevocationWriteFailureIsRetryable(t *testing.T) {
	for _, failure := range []string{"reference", "refresh", "family"} {
		t.Run(failure, func(t *testing.T) {
			server, store, provider := setupFlowTestServer(t)
			provider.RevokeTokenFunc = func(context.Context, string) error { return nil }
			for _, token := range []string{"refresh", "sibling"} {
				seedProviderToken(t, store, token, "person", &oauth2.Token{AccessToken: "provider-access", Expiry: time.Now().Add(time.Hour)})
				require.NoError(t, store.SaveRefreshTokenWithFamily(t.Context(), token, "person", "client", "family", 1, time.Now().Add(time.Hour)))
			}
			wrapped := &unavailableLocalRevocationStore{Store: store, failure: failure}
			server.tokenStore = wrapped
			auditor, audit := newRecordingAuditor()
			server.Auditor = auditor
			require.ErrorIs(t, server.RevokeToken(t.Context(), "refresh", "client", "192.0.2.1"), ErrStorageUnavailable)
			for _, record := range decodeAuditRecords(t, audit.Bytes()) {
				require.NotEqual(t, security.EventTokenRevoked, record.EventType)
			}
			wrapped.failure = ""
			require.NoError(t, server.RevokeToken(t.Context(), "refresh", "client", "192.0.2.1"))
			_, err := store.GetRefreshTokenInfo(t.Context(), "refresh")
			require.ErrorIs(t, err, storage.ErrTokenNotFound)
			_, err = store.GetProviderTokenRef(t.Context(), "refresh")
			require.ErrorIs(t, err, storage.ErrTokenNotFound)
			family, err := store.GetRefreshTokenFamily(t.Context(), "sibling")
			require.NoError(t, err)
			require.True(t, family.Revoked)
		})
	}
}

func TestClientDeletionAuditedForOpaqueAndJWTAccess(t *testing.T) {
	for _, jwtMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "opaque", true: "jwt"}[jwtMode], func(t *testing.T) {
			server, store, _ := setupFlowTestServer(t)
			if jwtMode {
				server = newJWTModeServer(t, "https://api.example.com/mcp")
			}
			auditor, audit := newRecordingAuditor()
			server.Auditor = auditor
			require.NoError(t, server.SaveClient(t.Context(), &storage.Client{ClientID: "client"}))
			accessToken := "opaque-access"
			if jwtMode {
				var err error
				accessToken, err = server.issueAccessToken(t.Context(), accessTokenIssueParams{UserID: "person", ClientID: "client", ExpiresAt: time.Now().Add(time.Hour)})
				require.NoError(t, err)
			} else {
				seedProviderToken(t, store, accessToken, "person", &oauth2.Token{AccessToken: "provider-access", Expiry: time.Now().Add(time.Hour)})
				require.NoError(t, store.SaveTokenMetadata(t.Context(), accessToken, storage.TokenMetadata{UserID: "person", ClientID: "client", TokenType: "access", Audience: server.Config.GetResourceIdentifier(), ExpiresAt: time.Now().Add(time.Hour)}))
			}
			_, err := server.ValidateToken(t.Context(), accessToken)
			require.NoError(t, err)
			require.NoError(t, server.DeleteClient(t.Context(), "client"))
			_, err = server.ValidateToken(t.Context(), accessToken)
			require.ErrorIs(t, err, errInvalidAccessToken)
			events := map[string]string{}
			for _, record := range decodeAuditRecords(t, audit.Bytes()) {
				if record.ClientID == "client" {
					if reason, ok := record.Details["reason"].(string); ok {
						events[reason], _ = record.Details["severity"].(string)
					}
				}
			}
			require.Equal(t, "info", events["client_deleted"])
			require.Equal(t, "warning", events["client_revoked"])
		})
	}
}
