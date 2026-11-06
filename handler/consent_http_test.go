package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
	"github.com/giantswarm/mcp-oauth/storage/valkey"
)

func TestConsent_HTTPAcrossReplicasWithAutomaticKeys(t *testing.T) {
	address := os.Getenv("VALKEY_TEST_ADDR")
	if address == "" {
		address = "127.0.0.1:6379"
	}
	for _, encrypted := range []bool{false, true} {
		t.Run(map[bool]string{false: "stored key", true: "derived key"}[encrypted], func(t *testing.T) {
			prefix := "consent-http:" + testutil.GenerateRandomString(12) + ":"
			key, err := security.GenerateKey()
			require.NoError(t, err)
			stores := make([]storage.Combined, 2)
			for index := range stores {
				var options []valkey.Option
				if encrypted {
					encryptor, err := security.NewEncryptor(key)
					require.NoError(t, err)
					options = append(options, valkey.WithEncryptor(encryptor))
				}
				store, err := valkey.New(valkey.Config{Address: address, KeyPrefix: prefix, StartupTimeout: time.Second}, options...)
				if err != nil {
					t.Skipf("no server at VALKEY_TEST_ADDR=%s: %v", address, err)
				}
				t.Cleanup(store.Close)
				stores[index] = store
			}
			runConsentHTTP(t, stores, "")
		})
	}
}

func TestConsent_HTTPWithPrefixAndRewrittenHost(t *testing.T) {
	store := memory.New()
	runConsentHTTP(t, []storage.Combined{store, store}, "/tenant")
}

func runConsentHTTP(t *testing.T, stores []storage.Combined, prefix string) {
	t.Helper()
	backend := http.NewServeMux()
	var outer http.Handler = backend
	if prefix != "" {
		outer = http.StripPrefix(prefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Host = "backend.internal:8090"
			backend.ServeHTTP(w, r)
		}))
	}
	transport := httptest.NewTLSServer(outer)
	t.Cleanup(transport.Close)
	issuer := transport.URL + prefix
	handlers := make([]*Handler, 2)
	servers := make([]*server.Server, 2)
	for index, store := range stores {
		if index > 0 && store == stores[0] {
			handlers[index] = New(servers[0], nil)
			servers[index] = servers[0]
			continue
		}
		authorizationServer, err := server.NewWithCombined(mock.NewProvider(), store, &server.Config{Issuer: issuer, DisableNonceEchoRequirement: true}, nil)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, authorizationServer.Shutdown(context.WithoutCancel(t.Context()))) })
		handlers[index] = New(authorizationServer, nil)
		servers[index] = authorizationServer
	}
	require.Equal(t, servers[0].Config.ConsentCookieKey, servers[1].Config.ConsentCookieKey)
	backend.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handlers[1].ServeAuthorization(w, r)
		} else {
			handlers[0].ServeAuthorization(w, r)
		}
	})
	backend.HandleFunc("/oauth/callback", handlers[0].ServeCallback)
	backend.HandleFunc("/oauth/token", handlers[1].ServeToken)
	client, _, err := servers[0].RegisterClient(t.Context(), "browser", "public", "none", []string{consentTestRedirect}, nil, "203.0.113.1", 10)
	require.NoError(t, err)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	httpClient := transport.Client()
	httpClient.Jar = jar
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	flow := &consentFlow{client: client.ClientID}
	response, err := httpClient.Get(issuer + flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	match := consentIDInPage.FindStringSubmatch(string(body))
	require.Len(t, match, 2)
	require.Contains(t, string(body), `action="`+issuer+`/oauth/authorize"`)
	form := url.Values{"consent_id": {match[1]}, "decision": {consentDecisionApprove}}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, issuer+"/oauth/authorize", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", transport.URL)
	response, err = httpClient.Do(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusFound, response.StatusCode)
	upstream, err := url.Parse(response.Header.Get("Location"))
	require.NoError(t, err)
	callback := issuer + "/oauth/callback?state=" + upstream.Query().Get("state") + "&code=provider-code"
	otherBrowser := *httpClient
	otherBrowser.Jar = nil
	response, err = otherBrowser.Get(callback)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	response, err = httpClient.Get(callback)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusFound, response.StatusCode)
	destination, err := url.Parse(response.Header.Get("Location"))
	require.NoError(t, err)
	response, err = httpClient.PostForm(issuer+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {destination.Query().Get("code")}, "client_id": {client.ClientID}, "redirect_uri": {consentTestRedirect}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	})
	require.NoError(t, err)
	var token map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&token))
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusOK, response.StatusCode, token)
	require.NotEmpty(t, token["access_token"])
	response, err = httpClient.Get(issuer + flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusFound, response.StatusCode, "the second replica must remember the authenticated subject's consent")
	for range storage.MaxPendingConsentsPerBrowser + 1 {
		response, err = httpClient.Get(issuer + flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusFound, response.StatusCode)
		upstream, err := url.Parse(response.Header.Get("Location"))
		require.NoError(t, err)
		callback := issuer + "/oauth/callback?state=" + upstream.Query().Get("state") + "&error=access_denied"
		response, err = httpClient.Get(callback)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.Equal(t, http.StatusBadRequest, response.StatusCode)
		for _, cookie := range jar.Cookies(mustParseURL(t, issuer)) {
			require.NotEqual(t, handlers[0].consent.flowName(upstream.Query().Get("state")), cookie.Name)
		}
		_, err = stores[1].GetAuthorizationStateByProviderState(t.Context(), upstream.Query().Get("state"))
		require.ErrorIs(t, err, storage.ErrAuthorizationStateNotFound)
	}
}
