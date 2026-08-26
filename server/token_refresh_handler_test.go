package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

// errMetadataRead is the transient read failure the error case injects.
var errMetadataRead = errors.New("metadata backend unavailable")

// errMetadataAbsent is the miss every in-tree store returns: a wrapped
// storage.ErrTokenNotFound, not a nil record.
var errMetadataAbsent = fmt.Errorf("token metadata: %w", storage.ErrTokenNotFound)

// metadataGetterStore reports metadata from its own func, so a test can inject a
// read error. The embedded TokenStore serves every other call.
type metadataGetterStore struct {
	storage.TokenStore
	get func(tokenID string) (*storage.TokenMetadata, error)
}

func (s metadataGetterStore) GetTokenMetadata(tokenID string) (*storage.TokenMetadata, error) {
	return s.get(tokenID)
}

// noMetadataTokenStore does not implement storage.TokenMetadataGetter: embedding
// the interface promotes none of the getter's methods. Every other call reaches
// the embedded store.
type noMetadataTokenStore struct {
	storage.TokenStore
}

// TestFireTokenRefreshHandler_RequiresAttribution asserts the validation-path
// invariant: the handler receives a non-empty userID and familyID, or no event
// at all. Consumers key per-session state on both. The metadata reads go through
// an injected getter, because the in-memory store rejects a metadata record with
// an empty user ID and so cannot express every miss.
func TestFireTokenRefreshHandler_RequiresAttribution(t *testing.T) {
	newToken := &oauth2.Token{AccessToken: "provider-access"}

	tests := []struct {
		name           string
		metadata       *storage.TokenMetadata
		readErr        error
		wantFired      bool
		wantUserID     string
		wantFamilyID   string
		wantReadFailed bool
		wantAuditedID  string
	}{
		{
			name:         "both ids resolved",
			metadata:     &storage.TokenMetadata{UserID: "user-1", ClientID: "client-1", FamilyID: "family-1"},
			wantFired:    true,
			wantUserID:   "user-1",
			wantFamilyID: "family-1",
		},
		{
			name: "no metadata at all",
		},
		{
			name:    "metadata absent",
			readErr: errMetadataAbsent,
		},
		{
			name:           "metadata read error",
			readErr:        errMetadataRead,
			wantReadFailed: true,
		},
		{
			name:          "metadata without family id",
			metadata:      &storage.TokenMetadata{UserID: "user-1", ClientID: "client-1"},
			wantAuditedID: "client-1",
		},
		{
			name:          "metadata without user id",
			metadata:      &storage.TokenMetadata{ClientID: "client-1", FamilyID: "family-1"},
			wantAuditedID: "client-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				fired            bool
				gotUserID        string
				gotFamilyID      string
				gotProviderToken *oauth2.Token
			)
			srv, store, _ := setupFlowTestServer(t, WithTokenRefreshHandler(
				func(_ context.Context, userID, familyID string, token *oauth2.Token) {
					fired = true
					gotUserID = userID
					gotFamilyID = familyID
					gotProviderToken = token
				}))
			srv.tokenStore = metadataGetterStore{
				TokenStore: store,
				get: func(string) (*storage.TokenMetadata, error) {
					return tt.metadata, tt.readErr
				},
			}
			logger, logBuf := captureLogger()
			srv.Logger = logger
			srv.Auditor = security.NewAuditor(logger, true)

			srv.fireTokenRefreshHandler(t.Context(), "at-refresh-handler", newToken)

			require.Equal(t, tt.wantFired, fired)
			require.Equal(t, tt.wantUserID, gotUserID)
			require.Equal(t, tt.wantFamilyID, gotFamilyID)
			if tt.wantFired {
				require.Same(t, newToken, gotProviderToken)
				return
			}

			// metadata_read_failed separates a backend outage from an absent
			// record, so the drop event must not claim a failure for a miss.
			logOutput := logBuf.String()
			require.True(t, containsAuditEvent(logOutput, security.EventTokenRefreshHandlerSkipped))
			require.Contains(t, logOutput, fmt.Sprintf("metadata_read_failed:%t", tt.wantReadFailed))
			require.Equal(t, tt.wantReadFailed, strings.Contains(logOutput, "token metadata read failed"))

			// Partial metadata still attributes the drop, so an operator can
			// find the session the consumer never heard about.
			auditedClientID := `audit.client_id=""`
			if tt.wantAuditedID != "" {
				auditedClientID = "audit.client_id=" + tt.wantAuditedID
			}
			require.Contains(t, logOutput, auditedClientID)
		})
	}
}

// TestFireTokenRefreshHandler_ResolvesFromStoredMetadata is the same happy path
// against the real store, so the resolved case does not depend on the injected
// getter alone.
func TestFireTokenRefreshHandler_ResolvesFromStoredMetadata(t *testing.T) {
	const accessToken = "at-stored-metadata"

	var gotUserID, gotFamilyID string
	srv, store, _ := setupFlowTestServer(t, WithTokenRefreshHandler(
		func(_ context.Context, userID, familyID string, _ *oauth2.Token) {
			gotUserID = userID
			gotFamilyID = familyID
		}))

	require.NoError(t, store.SaveTokenMetadata(t.Context(), accessToken, storage.TokenMetadata{
		UserID: "user-1", ClientID: "client-1", FamilyID: "family-1",
	}))

	srv.fireTokenRefreshHandler(t.Context(), accessToken, &oauth2.Token{AccessToken: "provider-access"})

	require.Equal(t, "user-1", gotUserID)
	require.Equal(t, "family-1", gotFamilyID)
}

// TestFireTokenRefreshHandler_StoreWithoutMetadataGetter covers a store that
// cannot report metadata at all. WithTokenRefreshHandler warns about it at
// startup; the handler must not fire with empty IDs either.
func TestFireTokenRefreshHandler_StoreWithoutMetadataGetter(t *testing.T) {
	fired := false
	srv, store, _ := setupFlowTestServer(t, WithTokenRefreshHandler(
		func(_ context.Context, _, _ string, _ *oauth2.Token) { fired = true }))
	srv.tokenStore = noMetadataTokenStore{TokenStore: store}

	srv.fireTokenRefreshHandler(t.Context(), "at-no-metadata-getter", &oauth2.Token{AccessToken: "provider-access"})

	require.False(t, fired)
}
