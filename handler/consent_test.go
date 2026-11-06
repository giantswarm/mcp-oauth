package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const consentTestRedirect = "https://example.com/callback"

var consentIDInPage = regexp.MustCompile(`name="consent_id" value="([A-Za-z0-9_-]+)"`)

type consentFlow struct {
	t      *testing.T
	h      *Handler
	store  *memory.Store
	jar    map[string]*http.Cookie
	client string
}

func newConsentFlow(t *testing.T, configure func(*server.Config), redirectURIs ...string) *consentFlow {
	t.Helper()
	return newConsentFlowWithProvider(t, mock.NewProvider(), configure, redirectURIs...)
}

func newConsentFlowWithProvider(t *testing.T, provider providers.Provider, configure func(*server.Config), redirectURIs ...string) *consentFlow {
	t.Helper()
	store := memory.New()
	cfg := &server.Config{Issuer: testIssuer, DisableNonceEchoRequirement: true}
	if configure != nil {
		configure(cfg)
	}
	srv, err := server.New(provider, store, store, store, cfg, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, srv.Shutdown(context.WithoutCancel(t.Context()))) })
	h := New(srv, nil)

	if len(redirectURIs) == 0 {
		redirectURIs = []string{consentTestRedirect}
	}
	client, _, err := srv.RegisterClient(t.Context(), "Friendly <b>Client</b>", "public", "none", redirectURIs, nil, "203.0.113.1", 10)
	require.NoError(t, err)

	return &consentFlow{t: t, h: h, store: store, jar: map[string]*http.Cookie{}, client: client.ClientID}
}

func (f *consentFlow) authorizeTarget(redirectURI, state string, extra url.Values) string {
	q := url.Values{
		"client_id":             {f.client},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"state":                 {state},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return "/oauth/authorize?" + q.Encode()
}

func (f *consentFlow) do(req *http.Request) *httptest.ResponseRecorder {
	for _, c := range f.jar {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	if req.URL.Path == "/oauth/callback" {
		f.h.ServeCallback(w, req)
	} else {
		f.h.ServeAuthorization(w, req)
	}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(f.jar, c.Name)
			continue
		}
		f.jar[c.Name] = c
	}
	return w
}

func (f *consentFlow) callback(redirect *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	f.t.Helper()
	provider, err := url.Parse(redirect.Header().Get("Location"))
	require.NoError(f.t, err)
	return f.do(httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+provider.Query().Get("state")+"&code=provider-code", nil))
}

func (f *consentFlow) get(target string) *httptest.ResponseRecorder {
	return f.do(httptest.NewRequest(http.MethodGet, target, nil))
}

func (f *consentFlow) post(id, decision string, header http.Header) *httptest.ResponseRecorder {
	form := url.Values{"consent_id": {id}, "decision": {decision}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header[k] = v
	}
	return f.do(req)
}

func consentID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := consentIDInPage.FindStringSubmatch(w.Body.String())
	require.Len(t, m, 2, "consent page has no consent_id; body: %s", w.Body.String())
	return m[1]
}

func requireConsentPage(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	require.Empty(t, w.Header().Get("Location"))
	require.Contains(t, w.Header().Get("Content-Type"), "text/html")
	require.Contains(t, w.Body.String(), `name="decision" value="approve"`)
}

func requireProviderRedirect(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusFound, w.Code, "body: %s", w.Body.String())
	location, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.NotEqual(t, "example.com", location.Host, "must go to the provider, not the client")
	require.NotEmpty(t, location.Query().Get("state"))
}

func TestConsent_UntrustedClientGetsPageAndNoState(t *testing.T) {
	f := newConsentFlow(t, nil)
	state := testutil.GenerateRandomString(43)

	w := f.get(f.authorizeTarget(consentTestRedirect, state, nil))

	requireConsentPage(t, w)
	_, err := f.store.GetAuthorizationState(t.Context(), state)
	require.Error(t, err, "no authorization state may exist before the person approves")

	body := w.Body.String()
	require.Contains(t, body, "example.com", "redirect host must be shown")
	require.Contains(t, body, consentTestRedirect)
	require.Contains(t, body, "<code>openid</code>")
	require.Contains(t, body, "Friendly &lt;b&gt;Client&lt;/b&gt;", "client name must be escaped")
	require.NotContains(t, body, "<b>Client</b>")
	require.NotContains(t, body, "<script")

	require.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	require.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
	require.Contains(t, w.Header().Get("Cache-Control"), "no-store")

	var pending *http.Cookie
	for name, c := range f.jar {
		if strings.HasPrefix(name, "__Host-mcp_oauth_consent_req_") {
			pending = c
		}
	}
	require.NotNil(t, pending, "pending request cookie must be set")
	require.True(t, pending.Secure)
	require.True(t, pending.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, pending.SameSite)
	require.Equal(t, "/", pending.Path)
	require.Empty(t, pending.Domain)
	require.NotContains(t, pending.Value, f.client, "pending request must be encrypted")
}

func TestConsent_ApproveThenCodeAndRemembered(t *testing.T) {
	f := newConsentFlow(t, nil)
	state := testutil.GenerateRandomString(43)

	page := f.get(f.authorizeTarget(consentTestRedirect, state, nil))
	requireConsentPage(t, page)

	approved := f.post(consentID(t, page), consentDecisionApprove, http.Header{"Sec-Fetch-Site": {"same-origin"}})
	requireProviderRedirect(t, approved)

	cb := f.callback(approved)
	require.Equal(t, http.StatusFound, cb.Code, "body: %s", cb.Body.String())
	location, err := url.Parse(cb.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "example.com", location.Host)
	require.NotEmpty(t, location.Query().Get("code"))
	require.Equal(t, state, location.Query().Get("state"))

	again := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	requireProviderRedirect(t, again)

	t.Run("broader scopes ask again", func(t *testing.T) {
		w := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), url.Values{"scope": {"openid email profile"}}))
		requireConsentPage(t, w)
	})
	t.Run("another resource asks again", func(t *testing.T) {
		w := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), url.Values{"resource": {"https://other.example.com"}}))
		requireConsentPage(t, w)
	})
	t.Run("prompt=consent asks again", func(t *testing.T) {
		w := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), url.Values{"prompt": {"consent"}}))
		requireConsentPage(t, w)
	})
}

func TestConsent_ChangedRedirectURIAsksAgain(t *testing.T) {
	const second = "https://example.org/callback"
	f := newConsentFlow(t, nil, consentTestRedirect, second)

	page := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	requireProviderRedirect(t, f.post(consentID(t, page), consentDecisionApprove, nil))

	requireConsentPage(t, f.get(f.authorizeTarget(second, testutil.GenerateRandomString(43), nil)))
}

func TestConsent_LoopbackAlwaysRequiresConsent(t *testing.T) {
	f := newConsentFlow(t, func(c *server.Config) { c.AllowLocalhostRedirectURIs = true }, "http://127.0.0.1/callback")

	page := f.get(f.authorizeTarget("http://127.0.0.1:50001/callback", testutil.GenerateRandomString(43), nil))
	requireConsentPage(t, page)
	require.Contains(t, page.Body.String(), "This client runs on your computer")
	approved := f.post(consentID(t, page), consentDecisionApprove, nil)
	requireProviderRedirect(t, approved)
	require.Equal(t, http.StatusFound, f.callback(approved).Code)

	require.Nil(t, f.jar[f.h.consent.approvedName()])
	for _, redirectURI := range []string{"http://127.0.0.1:50001/callback", "http://127.0.0.1:50002/callback"} {
		request, err := f.h.server.PrepareAuthorization(t.Context(), f.client, mustParseURL(t, redirectURI), "openid email", "", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256", testutil.GenerateRandomString(43), nil)
		require.NoError(t, err)
		remembered := httptest.NewRecorder()
		require.NoError(t, f.h.consent.remember(remembered, httptest.NewRequest(http.MethodGet, "/", nil), request.ConsentKey(), time.Now(), "prior-subject"))
		for _, cookie := range remembered.Result().Cookies() {
			f.jar[cookie.Name] = cookie
		}
		requireConsentPage(t, f.get(f.authorizeTarget(redirectURI, testutil.GenerateRandomString(43), nil)))
		silent := f.get(f.authorizeTarget(redirectURI, testutil.GenerateRandomString(43), url.Values{"prompt": {"none"}}))
		require.Equal(t, http.StatusFound, silent.Code)
		silentTarget := mustParseURL(t, silent.Header().Get("Location"))
		require.Equal(t, "consent_required", silentTarget.Query().Get("error"))
	}
}

func TestConsent_NoWarningWithAPublicRedirectURI(t *testing.T) {
	f := newConsentFlow(t, func(c *server.Config) { c.AllowLocalhostRedirectURIs = true }, "http://127.0.0.1/callback", consentTestRedirect)

	page := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	requireConsentPage(t, page)
	require.NotContains(t, page.Body.String(), "This client runs on your computer")
}

func TestConsent_AnswerRefused(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(f *consentFlow, id string) (string, http.Header)
		wantStatus int
	}{
		{
			name: "replay after the answer",
			prepare: func(f *consentFlow, id string) (string, http.Header) {
				requireProviderRedirect(f.t, f.post(id, consentDecisionApprove, nil))
				return id, nil
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "cross-site Sec-Fetch-Site",
			prepare: func(_ *consentFlow, id string) (string, http.Header) {
				return id, http.Header{"Sec-Fetch-Site": {"cross-site"}}
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "foreign Origin",
			prepare: func(_ *consentFlow, id string) (string, http.Header) {
				return id, http.Header{"Origin": {"https://attacker.example"}}
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "another browser without the pending cookie",
			prepare: func(f *consentFlow, id string) (string, http.Header) {
				clear(f.jar)
				return id, nil
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "unknown consent id",
			prepare: func(_ *consentFlow, _ string) (string, http.Header) {
				return newConsentID(), nil
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "tampered pending cookie",
			prepare: func(f *consentFlow, id string) (string, http.Header) {
				f.setCookie(f.h.consent.pendingName(), tamper(f.jar[f.h.consent.pendingName()].Value))
				return id, nil
			},
			wantStatus: http.StatusBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newConsentFlow(t, nil)
			state := testutil.GenerateRandomString(43)
			page := f.get(f.authorizeTarget(consentTestRedirect, state, nil))
			requireConsentPage(t, page)

			id, header := tt.prepare(f, consentID(t, page))
			w := f.post(id, consentDecisionApprove, header)

			require.Equal(t, tt.wantStatus, w.Code, "body: %s", w.Body.String())
			require.Empty(t, w.Header().Get("Location"))
		})
	}
}

func TestConsent_Deny(t *testing.T) {
	f := newConsentFlow(t, nil)
	state := testutil.GenerateRandomString(43)
	page := f.get(f.authorizeTarget(consentTestRedirect, state, nil))

	w := f.post(consentID(t, page), consentDecisionDeny, nil)

	require.Equal(t, http.StatusFound, w.Code)
	link, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "example.com", link.Host)
	require.Equal(t, constants.ErrorCodeAccessDenied, link.Query().Get("error"))
	require.Equal(t, state, link.Query().Get("state"))
	require.Equal(t, testIssuer, link.Query().Get("iss"))
	require.Empty(t, link.Query().Get("code"))
	require.Equal(t, http.StatusBadRequest, f.post(consentID(t, page), consentDecisionDeny, nil).Code)

	requireConsentPage(t, f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil)))
}

func TestConsent_DenialRevalidatesClient(t *testing.T) {
	f := newConsentFlow(t, nil)
	page := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	require.NoError(t, f.store.DeleteClient(t.Context(), f.client))
	denied := f.post(consentID(t, page), consentDecisionDeny, nil)
	require.Equal(t, http.StatusBadRequest, denied.Code)
	require.Empty(t, denied.Header().Get("Location"))
}

func TestConsent_ValidatedClientErrorsAreRedirected(t *testing.T) {
	f := newConsentFlow(t, nil)

	for name, extra := range map[string]url.Values{
		"unsupported response_type": {"response_type": {"token"}},
		"short state":               {"state": {"short"}},
		"unsupported PKCE method":   {"code_challenge_method": {"plain"}},
		"silent sign-in":            {"prompt": {"none"}},
	} {
		t.Run(name, func(t *testing.T) {
			w := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), extra))
			require.Equal(t, http.StatusFound, w.Code, "body: %s", w.Body.String())
			target := mustParseURL(t, w.Header().Get("Location"))
			require.Equal(t, "example.com", target.Host)
			require.NotEmpty(t, target.Query().Get("error"))
			require.Equal(t, testIssuer, target.Query().Get("iss"))
			require.Empty(t, target.Query().Get("code"))
		})
	}
}

func TestConsent_PromptNoneNeedsConsent(t *testing.T) {
	f := newConsentFlow(t, nil)

	w := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), url.Values{"prompt": {"none"}}))

	require.Equal(t, http.StatusFound, w.Code)
	target := mustParseURL(t, w.Header().Get("Location"))
	require.Equal(t, constants.ErrorCodeConsentRequired, target.Query().Get("error"))

	page := f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	approved := f.post(consentID(t, page), consentDecisionApprove, nil)
	requireProviderRedirect(t, approved)
	require.Equal(t, http.StatusFound, f.callback(approved).Code)
	requireProviderRedirect(t, f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), url.Values{"prompt": {"none"}})))
}

func TestConsent_TrustedClient(t *testing.T) {
	f := newConsentFlow(t, nil, consentTestRedirect, "https://example.org/callback")
	trustClient(f.h.server, f.client)

	requireProviderRedirect(t, f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil)))
	requireConsentPage(t, f.get(f.authorizeTarget("https://example.org/callback", testutil.GenerateRandomString(43), nil)))
}

func TestConsent_ApprovedCookieIgnoredWhenInvalid(t *testing.T) {
	tests := map[string]func(f *consentFlow, key string){
		"tampered": func(f *consentFlow, _ string) {
			f.setCookie(f.h.consent.approvedName(), tamper(f.jar[f.h.consent.approvedName()].Value))
		},
		"expired": func(f *consentFlow, key string) {
			value, err := f.h.consent.seal(approvedConsents{Purpose: consentPurposeApproved, Entries: []approvedConsent{{Key: key, Expiry: time.Now().Add(-time.Second).Unix()}}})
			require.NoError(f.t, err)
			f.setCookie(f.h.consent.approvedName(), value)
		},
		"sealed with another key": func(f *consentFlow, key string) {
			other := newConsentCookies(&server.Config{Issuer: testIssuer})
			value, err := other.seal(approvedConsents{Purpose: consentPurposeApproved, Entries: []approvedConsent{{Key: key, Expiry: time.Now().Add(time.Hour).Unix()}}})
			require.NoError(f.t, err)
			f.setCookie(f.h.consent.approvedName(), value)
		},
		"pending record in the approval cookie": func(f *consentFlow, _ string) {
			value, err := f.h.consent.seal(pendingConsent{Purpose: consentPurposePending, ID: newConsentID(), Expiry: time.Now().Add(time.Hour).Unix()})
			require.NoError(f.t, err)
			f.setCookie(f.h.consent.approvedName(), value)
		},
	}
	for name, spoil := range tests {
		t.Run(name, func(t *testing.T) {
			f := newConsentFlow(t, nil)
			target := f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil)
			page := f.get(target)
			approved := f.post(consentID(t, page), consentDecisionApprove, nil)
			requireProviderRedirect(t, approved)
			require.Equal(t, http.StatusFound, f.callback(approved).Code)

			req, err := f.h.server.PrepareAuthorization(t.Context(), f.client, mustParseURL(t, consentTestRedirect), "openid email", "", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256", testutil.GenerateRandomString(43), nil)
			require.NoError(t, err)
			spoil(f, req.ConsentKey())

			requireConsentPage(t, f.get(f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil)))
		})
	}
}

func TestConsent_RememberKeepsNewest(t *testing.T) {
	c := newConsentCookies(&server.Config{Issuer: testIssuer})
	now := time.Now()
	jar := map[string]*http.Cookie{}
	for i := range maxRememberedConsents + 4 {
		w := httptest.NewRecorder()
		require.NoError(t, c.remember(w, cookieRequest(jar), strings.Repeat("k", 21)+string(rune('a'+i)), now, strings.Repeat("s", 43)))
		for _, set := range w.Result().Cookies() {
			jar[set.Name] = set
		}
	}

	got := c.approved(cookieRequest(jar), now)
	require.Len(t, got, maxRememberedConsents)
	require.Equal(t, strings.Repeat("k", 21)+string(rune('a'+maxRememberedConsents+3)), got[len(got)-1].Key)
	require.Less(t, len(jar[c.approvedName()].Value), maxConsentCookieValue)
}

func TestConsent_PlainHTTPLocalhostIssuer(t *testing.T) {
	c := newConsentCookies(&server.Config{Issuer: "http://localhost:8080"})

	cookie := c.cookie(c.approvedName(), "v", time.Minute)

	require.False(t, strings.HasPrefix(cookie.Name, "__Host-"))
	require.False(t, cookie.Secure)
	require.True(t, cookie.HttpOnly)
}

func TestConsent_IssuersOnOneHostUseSeparateCookies(t *testing.T) {
	a := newConsentCookies(&server.Config{Issuer: "https://auth.example.com/a"})
	b := newConsentCookies(&server.Config{Issuer: "https://auth.example.com/b"})

	require.NotEqual(t, a.approvedName(), b.approvedName())
}

func TestConsent_MethodNotAllowed(t *testing.T) {
	f := newConsentFlow(t, nil)

	w := f.do(httptest.NewRequest(http.MethodPut, "/oauth/authorize", nil))

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
	require.Equal(t, "GET, POST", w.Header().Get("Allow"))
}

func cookieRequest(jar map[string]*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range jar {
		req.AddCookie(c)
	}
	return req
}

// tamper changes one byte in the middle of a sealed cookie value.
func tamper(value string) string {
	b := []byte(value)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func (f *consentFlow) setCookie(name, value string) {
	f.jar[name] = f.h.consent.cookie(name, value, time.Hour)
}

func TestConsent_RealHTTPClientWithCookieJar(t *testing.T) {
	for name, start := range map[string]func(*httptest.Server){
		"plain-http localhost issuer": (*httptest.Server).Start,
		"https issuer":                (*httptest.Server).StartTLS,
	} {
		t.Run(name, func(t *testing.T) {
			mux := http.NewServeMux()
			ts := httptest.NewUnstartedServer(mux)
			start(ts)
			t.Cleanup(ts.Close)

			store := memory.New()
			t.Cleanup(store.Stop)
			srv, err := server.New(mock.NewProvider(), store, store, store, &server.Config{
				Issuer:                      ts.URL,
				AllowInsecureHTTP:           true,
				DisableNonceEchoRequirement: true,
			}, nil)
			require.NoError(t, err)
			h := New(srv, nil)
			mux.HandleFunc("/oauth/authorize", h.ServeAuthorization)
			mux.HandleFunc("/oauth/callback", h.ServeCallback)
			client, _, err := srv.RegisterClient(t.Context(), "cli", "public", "none", []string{consentTestRedirect}, nil, "203.0.113.1", 10)
			require.NoError(t, err)

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			httpClient := ts.Client()
			httpClient.Jar = jar
			httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

			f := &consentFlow{client: client.ClientID}
			resp, err := httpClient.Get(ts.URL + f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusOK, resp.StatusCode)
			m := consentIDInPage.FindStringSubmatch(string(body))
			require.Len(t, m, 2)

			resp, err = httpClient.PostForm(ts.URL+"/oauth/authorize", url.Values{"consent_id": {m[1]}, "decision": {consentDecisionApprove}})
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusFound, resp.StatusCode)
			require.NotContains(t, resp.Header.Get("Location"), "example.com/callback")
			provider, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			resp, err = httpClient.Get(ts.URL + "/oauth/callback?state=" + provider.Query().Get("state") + "&code=provider-code")
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusFound, resp.StatusCode)

			resp, err = httpClient.Get(ts.URL + f.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusFound, resp.StatusCode, "the approval must be remembered by the jar")
		})
	}
}

func TestConsent_PendingExpires(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		flow := newConsentFlow(t, nil)
		page := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
		id := consentID(t, page)
		time.Sleep(consentPendingTTL + time.Second)
		require.Equal(t, http.StatusBadRequest, flow.post(id, consentDecisionApprove, nil).Code)
	})
}

func TestConsent_ExpiredCallbackReleasesCookie(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		flow := newConsentFlow(t, nil)
		page := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
		approved := flow.post(consentID(t, page), consentDecisionApprove, nil)
		upstream, err := url.Parse(approved.Header().Get("Location"))
		require.NoError(t, err)
		state := upstream.Query().Get("state")
		time.Sleep(time.Duration(flow.h.server.Config.AuthorizationCodeTTL+flow.h.server.Config.ClockSkewGracePeriod+1) * time.Second)
		response := flow.callback(approved)
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Nil(t, flow.jar[flow.h.consent.flowName(state)])
	})
}
