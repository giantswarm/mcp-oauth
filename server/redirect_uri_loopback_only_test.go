package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRestrictRegistrationToLoopbackRedirectURIs(t *testing.T) {
	ctx := context.Background()
	loopback := []string{
		"http://127.0.0.1:43210/callback",
		"http://127.0.0.2/callback",
		"http://[::1]:43210/callback",
		"http://localhost:8080/callback",
		"https://localhost/callback",
	}
	other := []string{
		"https://app.example.com/callback",
		"cursor://anysphere.cursor-retrieval/oauth/callback",
		"myapp://localhost/callback",
		"https://localhost.example.com/callback",
	}

	t.Run("off", func(t *testing.T) {
		srv := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
		for _, uri := range append(loopback, other...) {
			require.NoError(t, srv.ValidateRedirectURIForRegistration(ctx, uri), uri)
		}
	})

	t.Run("on", func(t *testing.T) {
		srv := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
		srv.Config.RestrictRegistrationToLoopbackRedirectURIs = true
		for _, uri := range loopback {
			require.NoError(t, srv.ValidateRedirectURIForRegistration(ctx, uri), uri)
		}
		for _, uri := range other {
			err := srv.ValidateRedirectURIForRegistration(ctx, uri)
			require.Error(t, err, uri)
			require.Equal(t, RedirectURIErrorCategoryLoopbackRequired, GetRedirectURIErrorCategory(err), uri)
		}
		// One non-loopback URI refuses the whole registration.
		err := srv.ValidateRedirectURIsForRegistration(ctx, []string{loopback[0], other[0]})
		require.Equal(t, RedirectURIErrorCategoryLoopbackRequired, GetRedirectURIErrorCategory(err))
	})

	t.Run("on refuses RegisterClient", func(t *testing.T) {
		srv := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
		srv.Config.RestrictRegistrationToLoopbackRedirectURIs = true

		_, _, err := srv.RegisterClient(ctx, "Web Client", ClientTypePublic, TokenEndpointAuthMethodNone,
			[]string{"https://app.example.com/callback"}, nil, "192.0.2.1", 10)
		require.True(t, errors.Is(err, ErrRedirectURIRejected), "err = %v", err)

		client, _, err := srv.RegisterClient(ctx, "Native Client", ClientTypePublic, TokenEndpointAuthMethodNone,
			[]string{"http://127.0.0.1:43210/callback"}, nil, "192.0.2.1", 10)
		require.NoError(t, err)
		require.NotEmpty(t, client.ClientID)
	})

	t.Run("on leaves authorization-time validation unchanged", func(t *testing.T) {
		srv := newTestServerWithSecurityConfig(defaultTestSecurityConfig())
		srv.Config.RestrictRegistrationToLoopbackRedirectURIs = true
		srv.Config.ValidateRedirectURIAtAuthorization = true
		require.NoError(t, srv.ValidateRedirectURIAtAuthorizationTime(ctx, "https://app.example.com/callback"))
	})
}
