package handler

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/internal/constants"
	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/server"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

type fakeSubjectValidator struct {
	identity server.SubjectIdentity
	byToken  map[string]*server.SubjectIdentity
	err      error
}

func (f *fakeSubjectValidator) Validate(_ context.Context, token string, _ []string) (*server.SubjectIdentity, error) {
	if f.err != nil {
		return nil, f.err
	}
	if id, ok := f.byToken[token]; ok {
		return id, nil
	}
	return &f.identity, nil
}

type tokenExchangeHarnessOption func(*tokenExchangeHarnessConfig)

type tokenExchangeHarnessConfig struct {
	validator                 server.SubjectTokenValidator
	maxRequestBodySize        int64
	nonceProvider             server.DPoPNonceProvider
	delegationDefaultResource string
	actorDelegationPolicy     []server.DelegationGrant
}

func withSubjectValidator(v server.SubjectTokenValidator) tokenExchangeHarnessOption {
	return func(c *tokenExchangeHarnessConfig) { c.validator = v }
}

func withMaxRequestBodySize(n int64) tokenExchangeHarnessOption {
	return func(c *tokenExchangeHarnessConfig) { c.maxRequestBodySize = n }
}

func withDelegationDefaultResource(resource string) tokenExchangeHarnessOption {
	return func(c *tokenExchangeHarnessConfig) { c.delegationDefaultResource = resource }
}

func withActorDelegationPolicy(grants ...server.DelegationGrant) tokenExchangeHarnessOption {
	return func(c *tokenExchangeHarnessConfig) { c.actorDelegationPolicy = grants }
}

func withDPoPNonceProvider(p server.DPoPNonceProvider) tokenExchangeHarnessOption {
	return func(c *tokenExchangeHarnessConfig) { c.nonceProvider = p }
}

func setupTokenExchangeHandler(t *testing.T, opts ...tokenExchangeHarnessOption) (*Handler, *bytes.Buffer) {
	t.Helper()

	cfg := tokenExchangeHarnessConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serverCfg := &server.Config{
		Issuer:                      "https://auth.example.com",
		ResourceIdentifier:          "https://api.example.com",
		SupportedScopes:             []string{"read", "write"},
		AccessTokenTTL:              600,
		AccessTokenFormat:           server.AccessTokenFormatJWT,
		AccessTokenSigningKey:       signingKey,
		AccessTokenSigningKeyID:     "handler-exchange-kid",
		AccessTokenSigningAlgorithm: server.SigningAlgorithmRS256,
		DisableNonceEchoRequirement: true,
		MaxRequestBodySize:          cfg.maxRequestBodySize,
		DelegationDefaultResource:   cfg.delegationDefaultResource,
		ActorDelegationPolicy:       cfg.actorDelegationPolicy,
	}

	srvOpts := []server.Option{
		server.WithAuditor(security.NewAuditor(logger, true)),
	}
	if cfg.validator != nil {
		srvOpts = append(srvOpts,
			server.WithSubjectTokenValidator(server.SubjectTokenTypeIDToken, cfg.validator),
		)
	}
	if cfg.nonceProvider != nil {
		srvOpts = append(srvOpts, server.WithDPoPNonceProvider(cfg.nonceProvider))
	}

	srv, err := server.New(mock.NewProvider(), store, store, store, serverCfg, logger, srvOpts...)
	require.NoError(t, err)

	return New(srv, logger), &buf
}

func newTokenExchangeRequest(form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func happyExchangeForm() url.Values {
	return url.Values{
		"grant_type":         {server.GrantTypeTokenExchange},
		"subject_token":      {"opaque-subject-token"},
		"subject_token_type": {server.SubjectTokenTypeIDToken},
		"resource":           {"https://api.example.com"},
		"scope":              {"read"},
	}
}

func TestHandleTokenExchangeGrant(t *testing.T) {
	happy := func() server.SubjectTokenValidator {
		return &fakeSubjectValidator{
			identity: server.SubjectIdentity{
				Subject: "system:serviceaccount:default:test",
				Issuer:  "https://oidc.example.com",
			},
		}
	}
	reject := func() server.SubjectTokenValidator {
		return &fakeSubjectValidator{err: fmt.Errorf("token expired")}
	}

	type wantHeaders struct {
		contentTypeJSON bool
		cacheNoStore    bool
	}

	cases := []struct {
		name             string
		newValidator     func() server.SubjectTokenValidator
		form             url.Values
		mutateRequest    func(*testing.T, *http.Request)
		extraHarnessOpts []tokenExchangeHarnessOption
		wantStatus       int
		wantErrorCode    string
		wantHeaders      wantHeaders
		wantAuditReason  string
		wantTokenIssued  bool
	}{
		{
			name:            "happy path",
			newValidator:    happy,
			form:            happyExchangeForm(),
			wantStatus:      http.StatusOK,
			wantHeaders:     wantHeaders{contentTypeJSON: true, cacheNoStore: true},
			wantTokenIssued: true,
		},
		{
			name:         "missing subject_token",
			newValidator: happy,
			form: func() url.Values {
				v := happyExchangeForm()
				v.Del("subject_token")
				return v
			}(),
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   constants.ErrorCodeInvalidRequest,
			wantHeaders:     wantHeaders{contentTypeJSON: true, cacheNoStore: true},
			wantAuditReason: "token_exchange_subject_token_missing",
		},
		{
			name:         "unsupported subject_token_type",
			newValidator: happy,
			form: func() url.Values {
				v := happyExchangeForm()
				v.Set("subject_token_type", "urn:ietf:params:oauth:token-type:saml2")
				return v
			}(),
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   constants.ErrorCodeUnsupportedGrantType,
			wantHeaders:     wantHeaders{contentTypeJSON: true, cacheNoStore: true},
			wantAuditReason: "unsupported_subject_token_type",
		},
		{
			name:            "subject_token_type missing",
			newValidator:    happy,
			form:            func() url.Values { v := happyExchangeForm(); v.Del("subject_token_type"); return v }(),
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   constants.ErrorCodeInvalidRequest,
			wantHeaders:     wantHeaders{contentTypeJSON: true, cacheNoStore: true},
			wantAuditReason: "token_exchange_subject_token_type_missing",
		},
		{
			name:            "missing resource",
			newValidator:    happy,
			form:            func() url.Values { v := happyExchangeForm(); v.Del("resource"); return v }(),
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   constants.ErrorCodeInvalidRequest,
			wantHeaders:     wantHeaders{contentTypeJSON: true, cacheNoStore: true},
			wantAuditReason: "token_exchange_resource_missing",
		},
		{
			name:            "subject-token validation failure",
			newValidator:    reject,
			form:            happyExchangeForm(),
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   constants.ErrorCodeInvalidGrant,
			wantHeaders:     wantHeaders{contentTypeJSON: true, cacheNoStore: true},
			wantAuditReason: "subject_token_validation_failed",
		},
		{
			name:         "malformed DPoP proof",
			newValidator: happy,
			form:         happyExchangeForm(),
			mutateRequest: func(_ *testing.T, r *http.Request) {
				r.Header.Set("DPoP", "not-a-valid-dpop-proof")
			},
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   constants.ErrorCodeInvalidDPoPProof,
			wantHeaders:     wantHeaders{contentTypeJSON: true, cacheNoStore: true},
			wantAuditReason: "token_exchange_dpop_proof_invalid",
		},
		{
			// httptest.NewRequest(POST, "/token") + no TLS resolves to host
			// "example.com", so dpopHTU computes htu as http://example.com/token.
			name:         "DPoP nonce required",
			newValidator: happy,
			form:         happyExchangeForm(),
			extraHarnessOpts: []tokenExchangeHarnessOption{
				withDPoPNonceProvider(server.NewHMACNonceProvider([]byte("nonce-secret"), 10*time.Minute, nil)),
			},
			mutateRequest: func(t *testing.T, r *http.Request) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				proof := buildDPoPProofWithATH(t, key, http.MethodPost, "http://example.com/token", "jti-nonce-required", "")
				r.Header.Set("DPoP", proof)
			},
			wantStatus:      http.StatusBadRequest,
			wantErrorCode:   constants.ErrorCodeUseDPoPNonce,
			wantHeaders:     wantHeaders{contentTypeJSON: true, cacheNoStore: true},
			wantAuditReason: "token_exchange_dpop_nonce_required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := append([]tokenExchangeHarnessOption{withSubjectValidator(tc.newValidator())}, tc.extraHarnessOpts...)
			h, buf := setupTokenExchangeHandler(t, opts...)

			req := newTokenExchangeRequest(tc.form)
			if tc.mutateRequest != nil {
				tc.mutateRequest(t, req)
			}
			w := httptest.NewRecorder()

			h.ServeToken(w, req)

			require.Equal(t, tc.wantStatus, w.Code, "body: %s", w.Body.String())
			if tc.wantHeaders.contentTypeJSON {
				require.Equal(t, "application/json", w.Header().Get("Content-Type"))
			}
			if tc.wantHeaders.cacheNoStore {
				require.Contains(t, w.Header().Get("Cache-Control"), "no-store")
			}

			if tc.wantStatus == http.StatusOK {
				var body map[string]any
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				require.NotEmpty(t, body["access_token"])
				require.Equal(t, server.SubjectTokenTypeAccessToken, body["issued_token_type"])
				require.Equal(t, "Bearer", body["token_type"])
				expiresIn, ok := body["expires_in"].(float64)
				require.True(t, ok, "expires_in must be a number, got %T", body["expires_in"])
				require.Positive(t, expiresIn)
			} else if tc.wantErrorCode != "" {
				var body map[string]string
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
				require.Equal(t, tc.wantErrorCode, body["error"])
			}

			if tc.wantTokenIssued {
				require.True(t, auditEventLogged(t, buf, security.EventTokenIssued),
					"missing token_issued audit in: %s", buf.String())
			} else if tc.wantAuditReason != "" {
				require.True(t, auditAuthFailureWithReason(t, buf, tc.wantAuditReason),
					"missing auth_failure with reason %q in: %s", tc.wantAuditReason, buf.String())
			}
		})
	}
}

// DelegationDefaultResource lets an on-behalf-of caller omit resource: the
// local exchange binds the mint to the configured default. Gated to the actor
// path and opt-in.
func TestHandleTokenExchangeGrant_DelegationDefaultResource(t *testing.T) {
	const selfResource = "https://api.example.com" // matches harness ResourceIdentifier

	identity := server.SubjectIdentity{
		Subject: "system:serviceaccount:kagent:sre-agent",
		Issuer:  "https://oidc.example.com",
	}
	allowSelf := server.DelegationGrant{
		ActorIssuer:    identity.Issuer,
		ActorSubject:   identity.Subject,
		SubjectIssuer:  identity.Issuer,
		SubjectSubject: identity.Subject,
	}
	delegationForm := func() url.Values {
		v := happyExchangeForm()
		v.Del("resource")
		v.Set("actor_token", "opaque-actor-token")
		v.Set("actor_token_type", server.SubjectTokenTypeIDToken)
		return v
	}

	t.Run("delegation defaults missing resource and mints", func(t *testing.T) {
		h, buf := setupTokenExchangeHandler(t,
			withSubjectValidator(&fakeSubjectValidator{identity: identity}),
			withDelegationDefaultResource(selfResource),
			withActorDelegationPolicy(allowSelf),
		)
		w := httptest.NewRecorder()
		h.ServeToken(w, newTokenExchangeRequest(delegationForm()))

		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		require.True(t, auditEventLogged(t, buf, security.EventTokenIssued),
			"missing token_issued audit in: %s", buf.String())
	})

	t.Run("no actor token still requires resource", func(t *testing.T) {
		h, buf := setupTokenExchangeHandler(t,
			withSubjectValidator(&fakeSubjectValidator{identity: identity}),
			withDelegationDefaultResource(selfResource),
		)
		form := happyExchangeForm()
		form.Del("resource") // no actor_token: not a delegation request
		w := httptest.NewRecorder()
		h.ServeToken(w, newTokenExchangeRequest(form))

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.True(t, auditAuthFailureWithReason(t, buf, "token_exchange_resource_missing"),
			"want resource_missing in: %s", buf.String())
	})

	t.Run("disabled default still requires resource", func(t *testing.T) {
		h, buf := setupTokenExchangeHandler(t,
			withSubjectValidator(&fakeSubjectValidator{identity: identity}),
			withActorDelegationPolicy(allowSelf),
			// opt-in off: no withDelegationDefaultResource
		)
		w := httptest.NewRecorder()
		h.ServeToken(w, newTokenExchangeRequest(delegationForm()))

		require.Equal(t, http.StatusBadRequest, w.Code)
		require.True(t, auditAuthFailureWithReason(t, buf, "token_exchange_resource_missing"),
			"want resource_missing in: %s", buf.String())
	})
}

// The 405 comes from ServeToken before handleTokenExchangeGrant runs.
func TestHandleTokenExchangeGrant_MethodGet(t *testing.T) {
	h, _ := setupTokenExchangeHandler(t, withSubjectValidator(&fakeSubjectValidator{}))

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()
	h.ServeToken(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// 413 is enforced by ServeToken's MaxBytesReader, inherited by the token-exchange grant.
func TestHandleTokenExchangeGrant_BodyTooLarge(t *testing.T) {
	h, _ := setupTokenExchangeHandler(t,
		withSubjectValidator(&fakeSubjectValidator{}),
		withMaxRequestBodySize(8),
	)

	form := happyExchangeForm()
	req := newTokenExchangeRequest(form)
	w := httptest.NewRecorder()
	h.ServeToken(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code, "body: %s", w.Body.String())
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, constants.ErrorCodeInvalidRequest, body["error"])
}

// Pins the response writer's shape and RFC 6749 §5.1 cache headers without HTTP plumbing.
func TestWriteTokenExchangeResponse_ShapeAndHeaders(t *testing.T) {
	h, _ := setupTokenExchangeHandler(t)

	result := &server.TokenExchangeResult{
		AccessToken:     "issued-token",
		ExpiresAt:       time.Date(2099, time.January, 1, 0, 0, 0, 0, time.UTC),
		Scope:           "read write",
		IssuedTokenType: server.SubjectTokenTypeAccessToken,
	}

	w := httptest.NewRecorder()
	h.writeTokenExchangeResponse(w, result)

	require.Equal(t, "application/json", w.Header().Get("Content-Type"))
	require.Contains(t, w.Header().Get("Cache-Control"), "no-store")

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "issued-token", body["access_token"])
	require.Equal(t, server.SubjectTokenTypeAccessToken, body["issued_token_type"])
	require.Equal(t, "Bearer", body["token_type"])
	require.Equal(t, "read write", body["scope"])

	expiresIn, ok := body["expires_in"].(float64)
	require.True(t, ok)
	require.Positive(t, expiresIn)
}

func TestHandleTokenExchangeError_UnsupportedSubjectTokenType(t *testing.T) {
	h, _ := setupTokenExchangeHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	r, _, end := h.startHandlerSpan(req, "test")
	defer end()
	w := httptest.NewRecorder()

	unsupported := &server.TokenExchangeUnsupportedTypeError{}
	h.handleTokenExchangeError(w, r, unsupported, "1.1.1.1", time.Time{}, nil)

	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, constants.ErrorCodeUnsupportedGrantType, body["error"])
}
