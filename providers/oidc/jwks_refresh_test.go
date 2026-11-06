package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

const (
	rotationKeysURL = "https://issuer.example.com/keys"
	otherKeysURL    = "https://issuer.example.com/other-keys"
)

type jwksRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip jwksRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func newJWKSRotationFixture(t *testing.T) (validate func(context.Context, string) error, started <-chan struct{}, release func()) {
	t.Helper()
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	oldDocument, err := json.Marshal(publicJWKS(t, oldKey, "RS256", "old-kid"))
	require.NoError(t, err)
	newDocument, err := json.Marshal(publicJWKS(t, newKey, "RS256", "new-kid"))
	require.NoError(t, err)
	fetchStarted := make(chan struct{})
	releaseFetch := make(chan struct{})
	var rotated atomic.Bool
	client := NewJWKSClientWithOptions(JWKSClientOptions{
		AllowPrivateIP: true,
		HTTPClient: &http.Client{Transport: jwksRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			document := oldDocument
			if rotated.Load() {
				document = newDocument
				if request.URL.String() == rotationKeysURL {
					close(fetchStarted)
					select {
					case <-releaseFetch:
					case <-request.Context().Done():
						return nil, request.Context().Err()
					}
				}
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(document)))}, nil
		})},
	})
	for _, keysURL := range []string{rotationKeysURL, otherKeysURL} {
		_, err = client.FetchJWKS(t.Context(), keysURL)
		require.NoError(t, err)
	}
	rotated.Store(true)
	token := signTestToken(t, newKey, jose.RS256, "new-kid", IDTokenClaims{Claims: josejwt.Claims{
		Issuer: "https://issuer.example.com", Subject: "rotated-user",
		Audience: josejwt.Audience{"client-a"}, Expiry: josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}})
	validate = func(ctx context.Context, keysURL string) error {
		_, err := ValidateIDToken(ctx, token, client, keysURL, "https://issuer.example.com", []string{"client-a"})
		return err
	}
	return validate, fetchStarted, sync.OnceFunc(func() { close(releaseFetch) })
}

func TestValidateIDToken_CancelledWaiterLeavesRefetch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		validate, started, release := newJWKSRotationFixture(t)
		defer release()
		first := make(chan error, 1)
		go func() { first <- validate(t.Context(), rotationKeysURL) }()
		<-started
		waiterContext, cancelWaiter := context.WithCancel(t.Context())
		defer cancelWaiter()
		waiter := make(chan error, 1)
		go func() { waiter <- validate(waiterContext, rotationKeysURL) }()
		synctest.Wait()
		cancelWaiter()
		synctest.Wait()
		select {
		case err := <-waiter:
			require.ErrorIs(t, err, context.Canceled)
		default:
			t.Error("a cancelled waiter must return before the shared fetch completes")
		}
		release()
		require.NoError(t, <-first)
	})
}

func TestValidateIDToken_CancelledInitiatorDoesNotCancelSharedRefetch(t *testing.T) {
	validate, started, release := newJWKSRotationFixture(t)
	defer release()
	initiatorContext, cancelInitiator := context.WithCancel(t.Context())
	defer cancelInitiator()
	first := make(chan error, 1)
	go func() { first <- validate(initiatorContext, rotationKeysURL) }()
	<-started
	cancelInitiator()
	require.Eventually(t, func() bool { return len(first) > 0 }, time.Second, time.Millisecond)
	require.ErrorIs(t, <-first, context.Canceled)
	second := make(chan error, 1)
	go func() { second <- validate(t.Context(), rotationKeysURL) }()
	release()
	require.NoError(t, <-second)
}

func TestValidateIDToken_SlowRefetchDoesNotBlockOtherURI(t *testing.T) {
	validate, started, release := newJWKSRotationFixture(t)
	defer release()
	first := make(chan error, 1)
	go func() { first <- validate(t.Context(), rotationKeysURL) }()
	<-started
	second := make(chan error, 1)
	go func() { second <- validate(t.Context(), otherKeysURL) }()
	require.Eventually(t, func() bool { return len(second) > 0 }, time.Second, time.Millisecond,
		"a slow endpoint must not block another URI's key rotation")
	require.NoError(t, <-second)
	release()
	require.NoError(t, <-first)
}

func TestValidateIDToken_SharedRefetchHasDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		validate, _, release := newJWKSRotationFixture(t)
		defer release()
		start := time.Now()
		err := validate(t.Context(), rotationKeysURL)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Equal(t, DefaultHTTPTimeout, time.Since(start))
		err = validate(t.Context(), rotationKeysURL)
		require.ErrorIs(t, err, context.DeadlineExceeded, "backoff must preserve a provider outage")
	})
}
