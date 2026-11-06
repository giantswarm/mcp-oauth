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
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
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
	consentPurposeApproved = "approved"

	consentDecisionApprove = "approve"
	consentDecisionDeny    = "deny"
)

// consentIDPattern matches the IDs newConsentID produces.
var consentIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

//go:embed consent.html
var consentPageTemplate string

var consentPageTmpl = template.Must(template.New("consent").Parse(consentPageTemplate))

// consentCookies seals the consent state the browser carries: the pending
// request between the consent page and the person's answer, and the
// approvals the person gave. Both are encrypted and authenticated with the
// server's ConsentCookieKey, so the browser can neither read nor forge them.
type consentCookies struct {
	encryptor *security.Encryptor

	// secure is false only for a plain-http localhost issuer, where browsers
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
}

type approvedConsents struct {
	Purpose string            `json:"p"`
	Entries []approvedConsent `json:"e"`
}

type approvedConsent struct {
	Key    string `json:"k"`
	Expiry int64  `json:"x"`
}

func newConsentCookies(cfg *server.Config) *consentCookies {
	key := cfg.ConsentCookieKey
	if len(key) == 0 {
		key, _ = security.GenerateKey()
	}
	encryptor, err := security.NewEncryptor(key)
	if err != nil || !encryptor.IsEnabled() {
		encryptor = nil
	}
	issuer, _ := url.Parse(cfg.Issuer)
	sum := sha256.Sum256([]byte(cfg.Issuer))
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

func (c *consentCookies) pendingName(id string) string {
	return c.name("mcp_oauth_consent_req") + "_" + id
}

func (c *consentCookies) approvedName() string {
	return c.name("mcp_oauth_consent")
}

func (c *consentCookies) cookie(name, value string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is off only for a plain-http localhost issuer
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
		return e.Key == key
	})
}

// remember adds key to the person's approvals.
func (c *consentCookies) remember(w http.ResponseWriter, r *http.Request, key string, now time.Time) error {
	entries := slices.DeleteFunc(c.approved(r, now), func(e approvedConsent) bool {
		return e.Key == key
	})
	entries = append(entries, approvedConsent{Key: key, Expiry: now.Add(consentRememberTTL).Unix()})
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

// promptIncludes reports whether the OIDC prompt of req lists value.
func promptIncludes(req *server.AuthorizationRequest, value string) bool {
	return req.Options != nil && slices.Contains(strings.Fields(req.Options.Prompt), value)
}

// consentNeeded reports whether the person has to answer the consent page for
// req: the client is not trusted for its redirect URI, and the person has not
// approved this request before or the client asks for consent again.
func (h *Handler) consentNeeded(r *http.Request, req *server.AuthorizationRequest) bool {
	if !h.server.RequiresConsent(req.ClientID, req.RedirectURI) {
		return false
	}
	return promptIncludes(req, "consent") || !h.consent.isApproved(r, req.ConsentKey(), time.Now())
}

// showConsentPage stores req in a pending cookie and renders the consent page.
func (h *Handler) showConsentPage(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, req *server.AuthorizationRequest) {
	id := newConsentID()
	value, err := h.consent.seal(pendingConsent{
		Purpose: consentPurposePending,
		ID:      id,
		Expiry:  time.Now().Add(consentPendingTTL).Unix(),
		Request: req,
	})
	if err != nil {
		h.logger.Warn("Authorization request cannot be held for consent", "client_id", req.ClientID, paramError, err)
		h.failRequest(w, r, span, endpointAuthorize, http.MethodGet, http.StatusBadRequest, constants.ErrorCodeInvalidRequest, "authorization request is too large", startTime)
		return
	}

	var buf bytes.Buffer
	if err := consentPageTmpl.Execute(&buf, h.consentPageData(r, req, id)); err != nil {
		h.logger.Error("Failed to render consent page", paramError, err)
		h.failRequest(w, r, span, endpointAuthorize, http.MethodGet, http.StatusInternalServerError, constants.ErrorCodeServerError, "Failed to render consent page", startTime)
		return
	}

	h.auditConsent(r, security.EventClientConsentShown, req)
	http.SetCookie(w, h.consent.cookie(h.consent.pendingName(id), value, consentPendingTTL))
	security.SetConsentPageSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodGet, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
	_, _ = buf.WriteTo(w)
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

	name := h.consent.pendingName(id)
	var pending pendingConsent
	err := h.consent.open(r, name, &pending)
	h.consent.clear(w, name)
	if err != nil || pending.Purpose != consentPurposePending || pending.ID != id || pending.Request == nil || pending.Expiry <= time.Now().Unix() {
		h.failRequest(w, r, span, endpointAuthorize, http.MethodPost, http.StatusBadRequest, constants.ErrorCodeInvalidRequest, "the consent page expired or was already answered; start signing in again", startTime)
		return
	}
	req := pending.Request

	if decision == consentDecisionDeny {
		h.auditConsent(r, security.EventClientConsentDenied, req)
		h.serveConsentDenied(w, r, span, startTime, req)
		return
	}

	h.auditConsent(r, security.EventClientConsentApproved, req)
	if err := h.consent.remember(w, r, req.ConsentKey(), time.Now()); err != nil {
		h.logger.Warn("Consent approval could not be remembered", "client_id", req.ClientID, paramError, err)
	}
	h.redirectToProvider(w, r, span, startTime, http.MethodPost, req, false)
}

// serveConsentDenied tells the person access was denied. The client is not
// trusted, so the browser is not sent to its redirect URI automatically; the
// page links there with access_denied so the client can stop waiting.
func (h *Handler) serveConsentDenied(w http.ResponseWriter, r *http.Request, span trace.Span, startTime time.Time, req *server.AuthorizationRequest) {
	target, err := url.Parse(req.RedirectURI)
	data := consentDeniedData{consentBranding: h.consentBranding()}
	if err == nil {
		q := target.Query()
		q.Set(paramError, constants.ErrorCodeAccessDenied)
		if req.State != "" {
			q.Set("state", req.State)
		}
		q.Set("iss", h.server.Config.Issuer)
		target.RawQuery = q.Encode()
		data.ReturnURL = template.URL(target.String()) //nolint:gosec // registered redirect URI of the client, checked when the request was prepared
		data.ReturnHost = target.Host
	}

	var buf bytes.Buffer
	if err := consentPageTmpl.ExecuteTemplate(&buf, "denied", data); err != nil {
		h.logger.Error("Failed to render consent denied page", paramError, err)
		h.failRequest(w, r, span, endpointAuthorize, http.MethodPost, http.StatusInternalServerError, constants.ErrorCodeServerError, "access denied", startTime)
		return
	}
	security.SetConsentPageSecurityHeaders(w, h.server.Config.Issuer)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.recordHTTPMetrics(r.Context(), endpointAuthorize, http.MethodPost, http.StatusOK, startTime)
	instrumentation.SetSpanSuccess(span)
	_, _ = buf.WriteTo(w)
}

func (h *Handler) auditConsent(r *http.Request, eventType string, req *server.AuthorizationRequest) {
	if h.server.Auditor == nil {
		return
	}
	h.server.Auditor.LogEvent(r.Context(), security.Event{
		Type:      eventType,
		ClientID:  req.ClientID,
		IPAddress: h.clientIP(r),
		UserAgent: r.UserAgent(),
		Details: map[string]any{
			"redirect_uri":  req.RedirectURI,
			"scope":         req.Scope,
			"resource":      req.Resource,
			"loopback_only": req.LoopbackOnly,
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
}

type consentDeniedData struct {
	consentBranding
	ReturnURL  template.URL
	ReturnHost string
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

func (h *Handler) consentPageData(r *http.Request, req *server.AuthorizationRequest, id string) consentPageData {
	data := consentPageData{
		consentBranding: h.consentBranding(),
		ClientName:      req.ClientName,
		RedirectURI:     req.RedirectURI,
		Scopes:          helpers.SplitScopes(req.Scope),
		Resource:        req.Resource,
		LoopbackOnly:    req.LoopbackOnly,
		ConsentID:       id,
		Action:          r.URL.Path,
	}
	if issuer, err := url.Parse(h.server.Config.Issuer); err == nil {
		data.IssuerHost = issuer.Host
	}
	if redirect, err := url.Parse(req.RedirectURI); err == nil {
		data.RedirectHost = redirect.Host
		if data.RedirectHost == "" {
			data.RedirectHost = redirect.Scheme + ":"
		}
	}
	if clientURL, err := url.Parse(req.ClientID); err == nil && clientURL.Scheme == oauth.SchemeHTTPS && clientURL.Host != "" {
		data.ClientHost = clientURL.Host
	}
	return data
}
