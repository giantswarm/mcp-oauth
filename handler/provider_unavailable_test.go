package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/constants"
)

// providerRefreshFailures are the provider answers a refresh grant meets when
// the identity provider is briefly unavailable, as Dex's evicted pods answer.
var providerRefreshFailures = []struct {
	name string
	err  error
}{
	{"provider 503", &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusServiceUnavailable}}},
	{"provider 429", &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusTooManyRequests}}},
	{"provider timeout", context.DeadlineExceeded},
}

// loginWithStaleProviderToken logs in with a provider token inside the refresh
// threshold, so the next refresh grant calls the provider.
func (e *outageEnv) loginWithStaleProviderToken(t *testing.T) string {
	t.Helper()
	e.provider.ExchangeCodeFunc = func(context.Context, string, string) (*oauth2.Token, error) {
		return &oauth2.Token{
			AccessToken: "provider-at", TokenType: "Bearer", RefreshToken: "provider-rt",
			Expiry: time.Now().Add(time.Minute),
		}, nil
	}
	return e.login(t).RefreshToken
}

// TestServeToken_RefreshGrant_ProviderUnavailable: a refresh grant whose
// provider-token refresh meets a provider 5xx, 429 or timeout answers 503
// temporarily_unavailable with Retry-After, and the same refresh token
// refreshes once the provider answers again.
func TestServeToken_RefreshGrant_ProviderUnavailable(t *testing.T) {
	for _, failure := range providerRefreshFailures {
		t.Run(failure.name, func(t *testing.T) {
			e := newOutageEnv(t)
			rt := e.loginWithStaleProviderToken(t)

			var down atomic.Bool
			down.Store(true)
			e.provider.RefreshTokenFunc = func(context.Context, string) (*oauth2.Token, error) {
				if down.Load() {
					return nil, failure.err
				}
				return &oauth2.Token{
					AccessToken: "provider-at-2", TokenType: "Bearer", RefreshToken: "provider-rt-2",
					Expiry: time.Now().Add(time.Hour),
				}, nil
			}

			w := e.postToken(e.refreshForm(rt))
			require.Equal(t, http.StatusServiceUnavailable, w.Code, "body: %s", w.Body.String())
			var body map[string]string
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			require.Equal(t, constants.ErrorCodeTemporarilyUnavailable, body["error"])
			require.Equal(t, "5", w.Header().Get("Retry-After"))
			require.Contains(t, e.logs.String(), "provider_unavailable", "the transient failure is audited as such")
			require.NotContains(t, e.logs.String(), "provider_refresh_failed")

			down.Store(false)
			w = e.postToken(e.refreshForm(rt))
			require.Equal(t, http.StatusOK, w.Code, "the same refresh token must work once the provider answers: %s", w.Body.String())
		})
	}
}

// TestServeToken_RefreshGrant_ProviderRejects: a provider that rejects the
// refresh (its own invalid_grant) still ends the grant with 400 invalid_grant.
func TestServeToken_RefreshGrant_ProviderRejects(t *testing.T) {
	e := newOutageEnv(t)
	rt := e.loginWithStaleProviderToken(t)
	e.provider.RefreshTokenFunc = func(context.Context, string) (*oauth2.Token, error) {
		return nil, &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusBadRequest}, ErrorCode: "invalid_grant"}
	}

	w := e.postToken(e.refreshForm(rt))
	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, constants.ErrorCodeInvalidGrant, body["error"])
	require.Empty(t, w.Header().Get("Retry-After"))
	require.Contains(t, e.logs.String(), "provider_refresh_failed")
}
