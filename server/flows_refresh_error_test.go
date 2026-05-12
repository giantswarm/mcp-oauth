package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// TestHandleRefreshTokenError covers the three classification branches of
// handleRefreshTokenError: not-found / expired errors map to invalid_grant
// directly, transient errors map to invalid_grant after a "transient" audit
// reason, and not-found errors with a family-store-supporting backend
// additionally trigger reuse-detection.
func TestHandleRefreshTokenError(t *testing.T) {
	tests := []struct {
		name             string
		err              error
		supportsFamilies bool
		wantSubstr       string
	}{
		{
			name:             "not-found classifies as invalid_grant",
			err:              storage.ErrTokenNotFound,
			supportsFamilies: false,
			wantSubstr:       ErrorCodeInvalidGrant,
		},
		{
			name:             "expired classifies as invalid_grant",
			err:              storage.ErrTokenExpired,
			supportsFamilies: false,
			wantSubstr:       ErrorCodeInvalidGrant,
		},
		{
			name:             "transient storage error classifies as invalid_grant",
			err:              errors.New("valkey: connection refused"),
			supportsFamilies: false,
			wantSubstr:       ErrorCodeInvalidGrant,
		},
		{
			name:             "not-found with family support invokes reuse path",
			err:              storage.ErrTokenNotFound,
			supportsFamilies: true,
			wantSubstr:       ErrorCodeInvalidGrant,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := memory.New()
			t.Cleanup(func() { store.Stop() })

			srv, err := New(mock.NewProvider(), store, store, store, &Config{Issuer: "https://auth.example.com"}, nil)
			require.NoError(t, err)

			gotErr := srv.handleRefreshTokenError(context.Background(), tt.err, "rt-test-token", "client-x", store, tt.supportsFamilies)
			require.Error(t, gotErr)
			require.True(t, strings.Contains(gotErr.Error(), tt.wantSubstr),
				"err %q must mention %q", gotErr.Error(), tt.wantSubstr)
		})
	}
}
