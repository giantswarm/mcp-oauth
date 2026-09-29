package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"golang.org/x/oauth2"
)

func TestIsTransientProviderError(t *testing.T) {
	retrieve := func(code int) error {
		return fmt.Errorf("failed to refresh token: %w", &oauth2.RetrieveError{Response: &http.Response{StatusCode: code}})
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"provider 503", retrieve(http.StatusServiceUnavailable), true},
		{"provider 500", retrieve(http.StatusInternalServerError), true},
		{"provider 429", retrieve(http.StatusTooManyRequests), true},
		{"provider invalid_grant", retrieve(http.StatusBadRequest), false},
		{"provider 401", retrieve(http.StatusUnauthorized), false},
		{"retrieve error without response", &oauth2.RetrieveError{}, false},
		{"timeout", fmt.Errorf("gave up waiting for in-flight provider refresh: %w", context.DeadlineExceeded), true},
		{"connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, true},
		{"no refresh token", errors.New("shared provider token for user has no refresh token"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransientProviderError(tt.err); got != tt.want {
				t.Fatalf("isTransientProviderError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestRefreshAccessToken_ProviderUnavailable classifies the grant error: a
// provider 5xx is ErrProviderUnavailable and leaves the refresh token usable;
// a provider rejection is not.
func TestRefreshAccessToken_ProviderUnavailable(t *testing.T) {
	ctx := context.Background()

	t.Run("provider 503", func(t *testing.T) {
		dex := newSingleUseDex()
		down := true
		srv, clientID, rt := setupNoOrphanServer(t, dex, func(reqCtx context.Context, rt string) (*oauth2.Token, error) {
			if down {
				return nil, fmt.Errorf("failed to refresh token: %w", &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusServiceUnavailable}})
			}
			return dex.refresh(reqCtx, rt)
		})
		_, err := srv.RefreshAccessToken(ctx, rt, clientID)
		if !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("want ErrProviderUnavailable, got %v", err)
		}
		down = false
		if _, err := srv.RefreshAccessToken(ctx, rt, clientID); err != nil {
			t.Fatalf("retry after the provider recovered should succeed, got %v", err)
		}
	})

	t.Run("provider invalid_grant", func(t *testing.T) {
		dex := newSingleUseDex()
		srv, clientID, rt := setupNoOrphanServer(t, dex, func(context.Context, string) (*oauth2.Token, error) {
			return nil, &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusBadRequest}, ErrorCode: "invalid_grant"}
		})
		_, err := srv.RefreshAccessToken(ctx, rt, clientID)
		if err == nil || errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("a provider rejection must not be ErrProviderUnavailable, got %v", err)
		}
	})
}
