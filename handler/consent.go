package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	oauth "github.com/giantswarm/mcp-oauth"
	"github.com/giantswarm/mcp-oauth/instrumentation"
	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/internal/helpers"
	"github.com/giantswarm/mcp-oauth/providers"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage"
)

const (
	// consentPendingTTL bounds how long the consent page can be answered.
	consentPendingTTL = 10 * time.Minute

	// consentRememberTTL is how long an approval is remembered in the browser.
	consentRememberTTL = 30 * 24 * time.Hour

	// maxRememberedConsents bounds the approvals one browser keeps per issuer;
	// the oldest is dropped first.
	maxRememberedConsents = 16

	// maxConsentCookieValue keeps every consent cookie under the 4096-byte
	// limit browsers apply to a cookie's name and value together.
	maxConsentCookieValue = 3800

	// maxConsentFormBytes bounds the body of the consent form submission.
	maxConsentFormBytes = 4096

	consentPurposePending  = "pending"
	consentPurposeApproved = "approved_v2"

	consentDecisionApprove = "approve"
	consentDecisionDeny    = "deny"
)

// consentIDPattern matches the IDs newConsentID produces.
var consentIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

//go:embed consent.html
var consentPageTemplate string

var consentPageTmpl = template.Must(template.New("consent").Parse(consentPageTemplate))

// consentCookies authenticates remembered grants and encrypts server-side
// pending requests. Browser binding cookies contain opaque random secrets.
type consentCookies struct {
	encryptor *security.Encryptor

	// secure is false only for a plain-http issuer, where browsers
	// and HTTP clients drop Secure cookies.
	secure bool

	// suffix keeps the cookies of two issuers on one host apart.
	suffix string
}

type pendingConsent struct {
	Purpose string                       `json:"p"`
	ID      string                       `json:"id"`
	Expiry  int64                        `json:"exp"`
	Request *server.AuthorizationRequest `json:"req"`
	Result  *server.AuthorizationResult  `json:"result,omitempty"`
}

type approvedConsents struct {
	Purpose string            `json:"p"`
	Entries []approvedConsent `json:"e"`
}

type approvedConsent struct {
	Key     string `json:"k"`
	Subject string `json:"s"`
	Expiry  int64  `json:"x"`
}

func newConsentCookies(configuration *server.Config) *consentCookies {
	key := configuration.ConsentCookieKey
	if len(key) == 0 {
		key, _ = security.GenerateKey()
	}
	encryptor, err := security.NewEncryptor(key)
	if err != nil || !encryptor.IsEnabled() {
		encryptor = nil
	}
	issuer, _ := url.Parse(configuration.Issuer)
	sum := sha256.Sum256([]byte(configuration.Issuer))
	return &consentCookies{
		encryptor: encryptor,
		secure:    issuer == nil || issuer.Scheme != oauth.SchemeHTTP,
		suffix:    hex.EncodeToString(sum[:4]),
	}
}

func (c *consentCookies) name(base string) string {
	if c.secure {
		return "__Host-" + base + "_" + c.suffix
	}
	return base + "_" + c.suffix
}

func (c *consentCookies) pendingName() string {
	return c.name("mcp_oauth_consent_req")
}

func (c *consentCookies) flowName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return c.name("mcp_oauth_flow") + "_" + hex.EncodeToString(sum[:8])
}

func (c *consentCookies) approvedName() string {
	return c.name("mcp_oauth_consent")
}

func (c *consentCookies) cookie(name, value string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is off only for a plain-http issuer
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   c.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (c *consentCookies) clear(w http.ResponseWriter, name string) {
	cookie := c.cookie(name, "", 0) //nolint:gosec // see cookie
	cookie.MaxAge = -1
	http.SetCookie(w, cookie)
}

func (c *consentCookies) seal(v any) (string, error) {
	if c.encryptor == nil {
		return "", errors.New("consent cookie key is not usable")
	}
	plaintext, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sealed, err := c.encryptor.Encrypt(string(plaintext))
	if err != nil {
		return "", err
	}
	if len(sealed) > maxConsentCookieValue {
		return "", errors.New("consent cookie value too large")
	}
	return sealed, nil
}

func (c *consentCookies) open(r *http.Request, name string, v any) error {
	if c.encryptor == nil {
		return errors.New("consent cookie key is not usable")
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return err
	}
	plaintext, err := c.encryptor.Decrypt(cookie.Value)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(plaintext), v)
}

// approved returns the person's unexpired approvals, newest last. A missing,
// tampered or foreign cookie yields none.
func (c *consentCookies) approved(r *http.Request, now time.Time) []approvedConsent {
	var stored approvedConsents
	if err := c.open(r, c.approvedName(), &stored); err != nil || stored.Purpose != consentPurposeApproved {
		return nil
	}
	return slices.DeleteFunc(stored.Entries, func(e approvedConsent) bool {
		return e.Expiry <= now.Unix()
	})
}

func (c *consentCookies) isApproved(r *http.Request, key string, now time.Time) bool {
	return slices.ContainsFunc(c.approved(r, now), func(e approvedConsent) bool {
		return e.Key == key && e.Subject != ""
	})
}

func (c *consentCookies) approvedForSubject(r *http.Request, key, subject string) bool {
	return slices.ContainsFunc(c.approved(r, time.Now()), func(e approvedConsent) bool { return e.Key == key && e.Subject == subject && subject != "" })
}

// remember adds key to the person's approvals.
func (c *consentCookies) remember(w http.ResponseWriter, r *http.Request, key string, now time.Time, subject string) error {
	entries := slices.DeleteFunc(c.approved(r, now), func(e approvedConsent) bool {
		return e.Key == key && e.Subject == subject
	})
	entries = append(entries, approvedConsent{Key: key, Subject: subject, Expiry: now.Add(consentRememberTTL).Unix()})
	if len(entries) > maxRememberedConsents {
		entries = entries[len(entries)-maxRememberedConsents:]
	}
	value, err := c.seal(approvedConsents{Purpose: consentPurposeApproved, Entries: entries})
	if err != nil {
		return err
	}
	http.SetCookie(w, c.cookie(c.approvedName(), value, consentRememberTTL))
	return nil
}

func newConsentID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// promptIncludes reports whether the request's OIDC prompt lists value.
func promptIncludes(authorizationRequest *server.AuthorizationRequest, value string) bool {
	return authorizationRequest.Options != nil && slices.Contains(strings.Fields(authorizationRequest.Options.Prompt), value)
}

// consentNeeded reports whether the person has to answer the consent page for
// the request: the client is not trusted for its redirect URI, and the person has not
// approved this request before or the client asks for consent again.
func (h *Handler) consentNeeded(r *http.Request, authorizationRequest *server.AuthorizationRequest) bool {
	if !h.server.RequiresConsent(authorizationRequest.ClientID, authorizationRequest.RedirectURI) {
		return false
	}
	return !authorizationRequest.CanRememberConsent() || promptIncludes(authorizationRequest, "consent") || !h.consent.isApproved(r, authorizationRequest.ConsentKey(), time.Now())
}

// showConsentPage stores the request and renders the consent page.
func (h *Handler) showConsentPage(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, authorizationRequest *server.AuthorizationRequest) {
	h.showPendingConsent(w, r, span, startTime, authorizationRequest, nil)
}

func browserID(binding string) string {
	sum := sha256.Sum256([]byte(binding))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (h *Handler) showPendingConsent(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, authorizationRequest *server.AuthorizationRequest, result *server.AuthorizationResult) {
	id := newConsentID()
	binding := ""
	if cookie, err := r.Cookie(h.consent.pendingName()); err == nil && consentIDPattern.MatchString(cookie.Value) {
		binding = cookie.Value
	}
	if binding == "" {
		binding = newConsentID()
	}
	pending := pendingConsent{
		Purpose: consentPurposePending,
		ID:      id,
		Expiry:  time.Now().Add(consentPendingTTL).Unix(),
		Request: authorizationRequest,
		Result:  result,
	}
	err := h.storePendingConsent(r, binding, pending)
	if err != nil {
		h.logger.Warn("Authorization request cannot be held for consent", "client_id", authorizationRequest.ClientID, paramError, err)
		if errors.Is(err, storage.ErrPendingConsentLimit) {
			h.failRequest(w, r, span, endpointAuthorize, r.Method, http.StatusTooManyRequests, constants.ErrorCodeInvalidRequest, "too many pending sign-ins", startTime)
			return
		}
		h.failRequest(w, r, span, endpointAuthorize, r.Method, http.StatusServiceUnavailable, constants.ErrorCodeTemporarilyUnavailable, "consent is temporarily unavailable", startTime)
		return
	}

	var buf bytes.Buffer
	data := h.consentPageData(r, authorizationRequest, id)
	if result != nil {
		data.Account = result.User.Email
		if data.Account == "" {
			data.Account = result.User.ID
		}
	}
	if err := consentPageTmpl.Execute(&buf, data); err != nil {
		h.logger.Error("Failed to render consent page", paramError, err)
		h.failRequest(w, r, span, endpointAuthorize, http.MethodGet, http.StatusInternalServerError, constants.ErrorCodeServerError, "Failed to render consent page", startTime)
		return
	}

	h.auditConsent(r, security.EventClientConsentShown, authorizationRequest)
	http.SetCookie(w, h.consent.cookie(h.consent.pendingName(), binding, consentPendingTTL))
	security.SetConsentPageSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
	_, _ = buf.WriteTo(w)
}

func (h *Handler) storePendingConsent(r *http.Request, binding string, pending pendingConsent) error {
	plaintext, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	if len(plaintext) > storage.MaxPendingConsentSize/2 {
		return errors.New("pending consent is too large")
	}
	if h.consent.encryptor == nil {
		return errors.New("consent key is unavailable")
	}
	sealed, err := h.consent.encryptor.Encrypt(string(plaintext))
	if err != nil {
		return err
	}
	return h.server.SavePendingConsent(r.Context(), browserID(binding), pending.ID, []byte(sealed), time.Unix(pending.Expiry, 0))
}

func (h *Handler) consumePendingConsent(r *http.Request, id string) (*pendingConsent, error) {
	cookie, err := r.Cookie(h.consent.pendingName())
	if err != nil || !consentIDPattern.MatchString(cookie.Value) {
		return nil, storage.ErrPendingConsentNotFound
	}
	sealed, err := h.server.ConsumePendingConsent(r.Context(), browserID(cookie.Value), id)
	if err != nil {
		return nil, err
	}
	plaintext, err := h.consent.encryptor.Decrypt(string(sealed))
	if err != nil {
		return nil, storage.ErrPendingConsentNotFound
	}
	var pending pendingConsent
	if err := json.Unmarshal([]byte(plaintext), &pending); err != nil {
		return nil, storage.ErrPendingConsentNotFound
	}
	if pending.Purpose != consentPurposePending || pending.ID != id || pending.Request == nil || pending.Expiry <= time.Now().Unix() {
		return nil, storage.ErrPendingConsentNotFound
	}
	return &pending, nil
}

// serveConsentDecision handles the person's answer to the consent page.
func (h *Handler) serveConsentDecision(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time) {
	if err := h.crossOrigin.Check(r); err != nil {
		h.logger.Warn("Consent answer refused: cross-origin request", "ip", h.clientIP(r))
		h.failRequest(w, r, span, endpointAuthorize, http.MethodPost, http.StatusForbidden, constants.ErrorCodeAccessDenied, "cross-origin request refused", startTime)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxConsentFormBytes)
	if err := r.ParseForm(); err != nil {
		h.failRequest(w, r, span, endpointAuthorize, http.MethodPost, http.StatusBadRequest, constants.ErrorCodeInvalidRequest, "invalid consent form", startTime)
		return
	}

	id := r.PostForm.Get("consent_id")
	decision := r.PostForm.Get("decision")
	if !consentIDPattern.MatchString(id) || (decision != consentDecisionApprove && decision != consentDecisionDeny) {
		h.failRequest(w, r, span, endpointAuthorize, http.MethodPost, http.StatusBadRequest, constants.ErrorCodeInvalidRequest, "invalid consent form", startTime)
		return
	}

	pending, err := h.consumePendingConsent(r, id)
	if err != nil {
		if storage.IsTransientError(err) {
			h.failRequest(w, r, span, endpointAuthorize, http.MethodPost, http.StatusServiceUnavailable, constants.ErrorCodeTemporarilyUnavailable, "consent is temporarily unavailable", startTime)
			return
		}
		h.failRequest(w, r, span, endpointAuthorize, http.MethodPost, http.StatusBadRequest, constants.ErrorCodeInvalidRequest, "the consent page expired or was already answered; start signing in again", startTime)
		return
	}
	authorizationRequest := pending.Request

	if decision == consentDecisionDeny {
		h.auditConsent(r, security.EventClientConsentDenied, authorizationRequest)
		h.serveConsentDenied(w, r, span, startTime, authorizationRequest)
		return
	}

	h.auditConsent(r, security.EventClientConsentApproved, authorizationRequest)
	if pending.Result != nil {
		h.finishBrowserAuthorization(w, r, span, startTime, authorizationRequest, pending.Result)
		return
	}
	authorizationRequest.ConsentApproved = true
	h.redirectToProvider(w, r, span, startTime, http.MethodPost, authorizationRequest)
}

func (h *Handler) requestForResult(r *http.Request, result *server.AuthorizationResult) (*server.AuthorizationRequest, error) {
	state := result.State
	redirect, err := url.Parse(state.RedirectURI)
	if err != nil {
		return nil, err
	}
	request, err := h.server.PrepareAuthorization(r.Context(), state.ClientID, redirect, state.Scope, state.Resource, state.CodeChallenge, state.CodeChallengeMethod, state.OriginalClientState, &providers.AuthorizationURLOptions{Prompt: state.Prompt})
	if err != nil {
		return nil, err
	}
	request.UpstreamScopes = slices.Clone(state.UpstreamScopes)
	return request, nil
}

func (h *Handler) finishBrowserAuthorization(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, request *server.AuthorizationRequest, result *server.AuthorizationResult) {
	code, state, err := h.server.IssueAuthorizationCode(r.Context(), result)
	if err != nil {
		h.logger.Error("Authorization code issuance failed", paramError, err)
		h.failRequest(w, r, span, endpointCallback, r.Method, http.StatusInternalServerError, constants.ErrorCodeServerError, "Authorization failed", startTime)
		return
	}
	if request != nil && request.CanRememberConsent() && h.server.RequiresConsent(request.ClientID, request.RedirectURI) {
		if err := h.consent.remember(w, r, request.ConsentKey(), time.Now(), result.Subject); err != nil {
			h.logger.Warn("Consent approval could not be remembered", paramError, err)
		}
	}
	h.redirectAuthorizationCode(w, r, span, startTime, code, state)
}

func (h *Handler) serveConsentDenied(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, authorizationRequest *server.AuthorizationRequest) {
	h.respondConsentError(w, r, span, startTime, authorizationRequest, constants.ErrorCodeAccessDenied, "the resource owner denied access")
}

func (h *Handler) respondConsentError(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, request *server.AuthorizationRequest, code, description string) {
	redirect, err := h.server.ValidateRedirectURIForAuthorization(r.Context(), request.ClientID, request.RedirectURI)
	if err != nil {
		h.failRequest(w, r, span, endpointAuthorize, r.Method, http.StatusBadRequest, constants.ErrorCodeInvalidRequest, "client or redirect URI is no longer valid", startTime)
		return
	}
	h.respondAuthorizationError(w, r, span, startTime, authorizationError{
		method: r.Method, redirectURI: redirect,
		state: request.State, code: code, description: description, spanError: code,
	})
}

func (h *Handler) auditConsent(r *http.Request, eventType string, authorizationRequest *server.AuthorizationRequest) {
	if h.server.Auditor == nil {
		return
	}
	h.server.Auditor.LogEvent(r.Context(), security.Event{
		Type:      eventType,
		ClientID:  authorizationRequest.ClientID,
		IPAddress: h.clientIP(r),
		UserAgent: r.UserAgent(),
		Details: map[string]any{
			"redirect_uri":    authorizationRequest.RedirectURI,
			"upstream_scopes": slices.Clone(authorizationRequest.UpstreamScopes),
			"scope":           authorizationRequest.Scope,
			"resource":        authorizationRequest.Resource,
			"loopback_only":   authorizationRequest.LoopbackOnly,
		},
	})
}

type consentBranding struct {
	LogoURL            string
	LogoAlt            string
	PrimaryColor       template.CSS
	BackgroundGradient template.CSS
	CustomCSS          template.CSS
}

type consentPageData struct {
	consentBranding
	IssuerHost   string
	ClientHost   string
	ClientName   string
	RedirectURI  string
	RedirectHost string
	Scopes       []string
	Resource     string
	LoopbackOnly bool
	ConsentID    string
	Action       string
	Account      string
	MCPScopes    []string
}

func (h *Handler) consentBranding() consentBranding {
	cfg := h.server.Config.Interstitial
	if cfg == nil || cfg.Branding == nil {
		return consentBranding{}
	}
	b := cfg.Branding
	alt := b.LogoAlt
	if alt == "" && b.LogoURL != "" {
		alt = "Logo"
	}
	return consentBranding{
		LogoURL:            b.LogoURL,
		LogoAlt:            alt,
		PrimaryColor:       template.CSS(b.PrimaryColor),       //nolint:gosec // Validated in validateInterstitialBranding
		BackgroundGradient: template.CSS(b.BackgroundGradient), //nolint:gosec // Validated in validateInterstitialBranding
		CustomCSS:          template.CSS(b.CustomCSS),          //nolint:gosec // Validated in validateInterstitialBranding
	}
}

func (h *Handler) consentPageData(r *http.Request, authorizationRequest *server.AuthorizationRequest, id string) consentPageData {
	data := consentPageData{
		consentBranding: h.consentBranding(),
		ClientName:      authorizationRequest.ClientName,
		RedirectURI:     authorizationRequest.RedirectURI,
		Scopes:          slices.Clone(authorizationRequest.UpstreamScopes),
		MCPScopes:       helpers.SplitScopes(authorizationRequest.Scope),
		Resource:        authorizationRequest.Resource,
		LoopbackOnly:    authorizationRequest.LoopbackOnly,
		ConsentID:       id,
		Action:          h.server.Config.AuthorizationEndpoint(),
	}
	if issuer, err := url.Parse(h.server.Config.Issuer); err == nil {
		data.IssuerHost = issuer.Host
	}
	if redirect, err := url.Parse(authorizationRequest.RedirectURI); err == nil {
		data.RedirectHost = redirect.Host
		if data.RedirectHost == "" {
			data.RedirectHost = redirect.Scheme + ":"
		}
	}
	if clientURL, err := url.Parse(authorizationRequest.ClientID); err == nil && clientURL.Scheme == oauth.SchemeHTTPS && clientURL.Host != "" {
		data.ClientHost = clientURL.Host
	}
	return data
}
