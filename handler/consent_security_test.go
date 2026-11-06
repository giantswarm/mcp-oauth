package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/internal/testutil"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/providers/google"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/storage"
)

func TestConsent_CallbackBoundToApprovingBrowser(t *testing.T) {
	provider := mock.NewProvider()
	flow := newConsentFlowWithProvider(t, provider, nil)
	page := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	approved := flow.post(consentID(t, page), consentDecisionApprove, nil)
	requireProviderRedirect(t, approved)
	upstream, err := url.Parse(approved.Header().Get("Location"))
	require.NoError(t, err)
	callbackURL := "/oauth/callback?state=" + upstream.Query().Get("state") + "&code=provider-code"
	for _, binding := range []string{"", "another-browser"} {
		request := httptest.NewRequest(http.MethodGet, callbackURL, nil)
		if binding != "" {
			request.AddCookie(flow.h.consent.cookie(flow.h.consent.flowName(upstream.Query().Get("state")), binding, time.Minute))
		}
		response := httptest.NewRecorder()
		flow.h.ServeCallback(response, request)
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Empty(t, response.Header().Get("Location"))
	}
	require.Zero(t, provider.CallCounts["ExchangeCode"])
	require.Equal(t, http.StatusFound, flow.callback(approved).Code)
	require.Equal(t, 1, provider.CallCounts["ExchangeCode"])
	require.Equal(t, http.StatusBadRequest, flow.callback(approved).Code)
	require.Equal(t, 1, provider.CallCounts["ExchangeCode"])
}

func TestConsent_RestoredPendingCookieCannotReplay(t *testing.T) {
	flow := newConsentFlow(t, nil)
	page := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	id := consentID(t, page)
	cookie := *flow.jar[flow.h.consent.pendingName()]
	requireProviderRedirect(t, flow.post(id, consentDecisionApprove, nil))
	flow.jar[cookie.Name] = &cookie
	require.Equal(t, http.StatusBadRequest, flow.post(id, consentDecisionApprove, nil).Code)
}

func TestConsent_ParallelAnswersAndCallbacks(t *testing.T) {
	flow := newConsentFlow(t, nil)
	state := testutil.GenerateRandomString(43)
	page := flow.get(flow.authorizeTarget(consentTestRedirect, state, nil))
	id := consentID(t, page)
	var successes atomic.Int32
	var group sync.WaitGroup
	var winner *httptest.ResponseRecorder
	for range 16 {
		group.Go(func() {
			form := url.Values{"consent_id": {id}, "decision": {consentDecisionApprove}}
			request := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, cookie := range flow.jar {
				request.AddCookie(cookie)
			}
			response := httptest.NewRecorder()
			flow.h.ServeAuthorization(response, request)
			if response.Code == http.StatusFound {
				successes.Add(1)
				winner = response
			} else {
				require.Equal(t, http.StatusBadRequest, response.Code)
			}
		})
	}
	group.Wait()
	require.Equal(t, int32(1), successes.Load())
	upstream, err := url.Parse(winner.Header().Get("Location"))
	require.NoError(t, err)
	successes.Store(0)
	callbackCookies := winner.Result().Cookies()
	for range 16 {
		group.Go(func() {
			request := httptest.NewRequest(http.MethodGet, "/oauth/callback?state="+upstream.Query().Get("state")+"&code=provider-code", nil)
			for _, cookie := range callbackCookies {
				request.AddCookie(cookie)
			}
			response := httptest.NewRecorder()
			flow.h.ServeCallback(response, request)
			if response.Code == http.StatusFound {
				successes.Add(1)
			} else {
				require.Equal(t, http.StatusBadRequest, response.Code)
			}
		})
	}
	group.Wait()
	require.Equal(t, int32(1), successes.Load())
}

func TestConsent_AccountSwitchRequiresFreshApproval(t *testing.T) {
	for _, decision := range []string{consentDecisionApprove, consentDecisionDeny} {
		t.Run(decision, func(t *testing.T) {
			provider := mock.NewProvider()
			subject := "account-a"
			provider.ValidateTokenFunc = func(context.Context, string) (*providers.UserInfo, error) {
				return &providers.UserInfo{ID: subject, Email: subject + "@example.com", EmailVerified: true}, nil
			}
			flow := newConsentFlowWithProvider(t, provider, nil)
			page := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
			approved := flow.post(consentID(t, page), consentDecisionApprove, nil)
			require.Nil(t, flow.jar[flow.h.consent.approvedName()])
			require.Equal(t, http.StatusFound, flow.callback(approved).Code)
			subject = "account-b"
			again := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
			requireProviderRedirect(t, again)
			confirmation := flow.callback(again)
			requireConsentPage(t, confirmation)
			require.Contains(t, confirmation.Body.String(), "account-b@example.com")
			_, err := flow.store.GetUserInfo(t.Context(), subject)
			require.ErrorIs(t, err, storage.ErrUserInfoNotFound)
			answer := flow.post(consentID(t, confirmation), decision, nil)
			if decision == consentDecisionDeny {
				require.Equal(t, http.StatusOK, answer.Code)
				require.Empty(t, answer.Header().Get("Location"))
				return
			}
			require.Equal(t, http.StatusFound, answer.Code)
			destination, err := url.Parse(answer.Header().Get("Location"))
			require.NoError(t, err)
			code, err := flow.store.GetAuthorizationCode(t.Context(), destination.Query().Get("code"))
			require.NoError(t, err)
			require.Equal(t, subject, code.UserID)
			require.Equal(t, 2, provider.CallCounts["ExchangeCode"])
			reused := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
			requireProviderRedirect(t, reused)
			require.Equal(t, http.StatusFound, flow.callback(reused).Code)
		})
	}
}

func TestConsent_ProviderFailureDoesNotRememberApproval(t *testing.T) {
	provider := mock.NewProvider()
	provider.ExchangeCodeFunc = func(context.Context, string, string) (*oauth2.Token, error) {
		return nil, errors.New("provider refused")
	}
	flow := newConsentFlowWithProvider(t, provider, nil)
	page := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	approved := flow.post(consentID(t, page), consentDecisionApprove, nil)
	require.Equal(t, http.StatusInternalServerError, flow.callback(approved).Code)
	require.Nil(t, flow.jar[flow.h.consent.approvedName()])
}

func TestConsent_EffectiveScopesAreDisplayedAndFrozen(t *testing.T) {
	provider, err := google.NewProvider(&google.Config{ClientID: "test-client", ClientSecret: "test-secret", RedirectURL: testIssuer + "/oauth/callback", Scopes: []string{"openid", "email"}})
	require.NoError(t, err)
	flow := newConsentFlowWithProvider(t, provider, nil)
	state := testutil.GenerateRandomString(43)
	page := flow.get(flow.authorizeTarget(consentTestRedirect, state, url.Values{"scope": {"email"}}))
	requireConsentPage(t, page)
	require.Contains(t, page.Body.String(), "<code>openid</code>")
	provider.Scopes = append(provider.Scopes, "profile")
	changed := flow.post(consentID(t, page), consentDecisionApprove, nil)
	requireConsentPage(t, changed)
	require.Contains(t, changed.Body.String(), "<code>profile</code>")
	_, err = flow.store.GetAuthorizationState(t.Context(), state)
	require.ErrorIs(t, err, storage.ErrAuthorizationStateNotFound)
	approved := flow.post(consentID(t, changed), consentDecisionApprove, nil)
	requireProviderRedirect(t, approved)
	upstream, err := url.Parse(approved.Header().Get("Location"))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"email", "openid", "profile"}, strings.Fields(upstream.Query().Get("scope")))
	require.NotEmpty(t, upstream.Query().Get("nonce"))
}

func TestConsent_LargeHintAndPendingLimit(t *testing.T) {
	flow := newConsentFlow(t, nil)
	for range storage.MaxPendingConsentsPerBrowser {
		page := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), url.Values{"id_token_hint": {strings.Repeat("x", 8192)}}))
		requireConsentPage(t, page)
		for _, cookie := range page.Result().Cookies() {
			require.Less(t, len(cookie.String()), 300)
		}
	}
	require.Len(t, flow.jar, 1)
	overflow := flow.get(flow.authorizeTarget(consentTestRedirect, testutil.GenerateRandomString(43), nil))
	require.Equal(t, http.StatusTooManyRequests, overflow.Code)
}

func TestConsent_ChangedPermissionsWithPromptNoneReturnsError(t *testing.T) {
	provider, err := google.NewProvider(&google.Config{ClientID: "test-client", ClientSecret: "test-secret", RedirectURL: testIssuer + "/oauth/callback", Scopes: []string{"openid", "email"}})
	require.NoError(t, err)
	flow := newConsentFlowWithProvider(t, provider, nil)
	request, err := flow.h.server.PrepareAuthorization(t.Context(), flow.client, mustParseURL(t, consentTestRedirect), "email", "", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256", testutil.GenerateRandomString(43), &providers.AuthorizationURLOptions{Prompt: "none"})
	require.NoError(t, err)
	provider.Scopes = append(provider.Scopes, "profile")
	response := httptest.NewRecorder()
	httpRequest := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	flow.h.redirectToProvider(response, httpRequest, trace.SpanFromContext(t.Context()), time.Now(), http.MethodGet, request, false)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Contains(t, response.Body.String(), "consent_required")
	require.Empty(t, response.Header().Get("Location"))
	require.NotContains(t, response.Body.String(), "<form")
}
