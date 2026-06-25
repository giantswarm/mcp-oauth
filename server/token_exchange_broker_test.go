package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/providers/oidc"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

const (
	brokerTestUserSub  = "user@example.com"
	brokerTestActorSub = "system:serviceaccount:ns:actor"
)

type stubSubjectValidator struct {
	identity SubjectIdentity
	err      error
}

func (f *stubSubjectValidator) Validate(_ context.Context, _ string, _ []string) (*SubjectIdentity, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &f.identity, nil
}

// recordingValidator captures the defaultAudiences passed to its last Validate call.
type recordingValidator struct {
	identity        SubjectIdentity
	lastDefaultAuds []string
}

func (f *recordingValidator) Validate(_ context.Context, _ string, defaultAuds []string) (*SubjectIdentity, error) {
	f.lastDefaultAuds = defaultAuds
	return &f.identity, nil
}

// stubTokenValidator returns distinct identities or errors keyed by the raw
// token string. Unrecognised tokens fall back to the default outcome.
type stubTokenValidator struct {
	byToken         map[string]*SubjectIdentity
	byErr           map[string]error
	defaultIdentity *SubjectIdentity
	defaultErr      error
}

func (f *stubTokenValidator) Validate(_ context.Context, token string, _ []string) (*SubjectIdentity, error) {
	if err, ok := f.byErr[token]; ok {
		return nil, err
	}
	if id, ok := f.byToken[token]; ok {
		return id, nil
	}
	if f.defaultErr != nil {
		return nil, f.defaultErr
	}
	return f.defaultIdentity, nil
}

type stubExchanger struct {
	gotReq *ExchangerRequest
	result *ExchangerResult
	err    error
}

func (f *stubExchanger) Exchange(_ context.Context, req *ExchangerRequest) (*ExchangerResult, error) {
	f.gotReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func newBrokerTestServer(t *testing.T, exchanger Exchanger, allowlist map[string][]string, validator SubjectTokenValidator) (*Server, *bytes.Buffer) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &Config{
		Issuer:                       "https://broker.example.com",
		DisableNonceEchoRequirement:  true,
		TokenExchangeClientAudiences: allowlist,
	}

	opts := []Option{WithAuditor(security.NewAuditor(logger, true))}
	if exchanger != nil {
		opts = append(opts, WithExchanger(exchanger))
	}
	if validator != nil {
		opts = append(opts, WithSubjectTokenValidator(SubjectTokenTypeIDToken, validator))
	}

	srv, err := New(mock.NewProvider(), store, store, store, cfg, logger, opts...)
	require.NoError(t, err)
	return srv, &buf
}

func happyBrokerValidator() SubjectTokenValidator {
	return &stubSubjectValidator{identity: SubjectIdentity{
		Subject: brokerTestUserSub,
		Issuer:  "https://dex.example.com",
	}}
}

func newWorkloadTestServer(t *testing.T, exchanger Exchanger, workloadAudiences []WorkloadGrant, validator SubjectTokenValidator) (*Server, *bytes.Buffer) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := &Config{
		Issuer:                      "https://broker.example.com",
		DisableNonceEchoRequirement: true,
		EnableWorkloadTokenExchange: true,
		WorkloadAudiences:           workloadAudiences,
	}

	opts := []Option{WithAuditor(security.NewAuditor(logger, true))}
	if exchanger != nil {
		opts = append(opts, WithExchanger(exchanger))
	}
	if validator != nil {
		opts = append(opts, WithSubjectTokenValidator(SubjectTokenTypeIDToken, validator))
	}

	srv, err := New(mock.NewProvider(), store, store, store, cfg, logger, opts...)
	require.NoError(t, err)
	return srv, &buf
}

func auditDetails(t *testing.T, buf *bytes.Buffer, eventType string) map[string]any {
	t.Helper()
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry struct {
			Audit struct {
				EventType string         `json:"event_type"`
				ClientID  string         `json:"client_id"`
				Details   map[string]any `json:"details"`
			} `json:"audit"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.Audit.EventType == eventType {
			entry.Audit.Details["__client_id"] = entry.Audit.ClientID
			return entry.Audit.Details
		}
	}
	t.Fatalf("no audit event of type %q in: %s", eventType, buf.String())
	return nil
}

func TestBrokerExchangeSubjectToken_HappyPath(t *testing.T) {
	expiry := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "downstream-token",
		ExpiresAt:   expiry,
		Scope:       "openid groups",
	}}
	srv, buf := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle", "gauss"}}, happyBrokerValidator())

	result, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "", "", "gaggle", "", "openid groups")
	require.NoError(t, err)

	// Pass-through of the downstream token, expiry bounded by it, no refresh token by construction.
	require.Equal(t, "downstream-token", result.AccessToken)
	require.Equal(t, expiry, result.ExpiresAt)
	require.Equal(t, "openid groups", result.Scope)
	require.Equal(t, SubjectTokenTypeAccessToken, result.IssuedTokenType)

	// Exchanger received the validated identity and raw subject token.
	require.NotNil(t, ex.gotReq)
	require.Equal(t, "gaggle", ex.gotReq.Audience)
	require.Equal(t, "backstage", ex.gotReq.ClientID)
	require.Equal(t, "subject-jwt", ex.gotReq.SubjectToken)
	require.Equal(t, SubjectTokenTypeIDToken, ex.gotReq.SubjectTokenType)
	require.Equal(t, brokerTestUserSub, ex.gotReq.Subject.Subject)
	require.Equal(t, "https://dex.example.com", ex.gotReq.Subject.Issuer)

	// Audit carries client ID, audience, scope, and the deterministic session ID.
	details := auditDetails(t, buf, security.EventTokenIssued)
	require.Equal(t, "backstage", details["__client_id"])
	require.Equal(t, "brokered", details["exchange"])
	require.Equal(t, "gaggle", details["audience"])
	require.Equal(t, "openid groups", details["scope"])
	require.Equal(t, srv.deriveForwardedSessionID("subject-jwt"), details["session_id"])
}

func TestBrokerExchangeSubjectToken_DefaultIssuedTokenType(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken:     "downstream-token",
		IssuedTokenType: SubjectTokenTypeIDToken,
		ExpiresAt:       time.Now().Add(time.Minute),
	}}
	srv, _ := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	result, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "", "", "gaggle", "", "")
	require.NoError(t, err)
	require.Equal(t, SubjectTokenTypeIDToken, result.IssuedTokenType)
}

func TestBrokerExchangeSubjectToken_AudienceNotAllowed(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "x"}}
	srv, buf := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "", "", "other-mc", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq, "exchanger must not be invoked on allowlist miss")

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "token_exchange_audience_not_allowed", details["reason"])
	require.Equal(t, "other-mc", details["audience"])
}

func TestBrokerExchangeSubjectToken_UnknownClient(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "x"}}
	srv, _ := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"unknown-client", "subject-jwt", SubjectTokenTypeIDToken, "", "", "gaggle", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
}

func TestBrokerExchangeSubjectToken_NoExchanger(t *testing.T) {
	srv, buf := newBrokerTestServer(t, nil,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "", "", "gaggle", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "token_exchange_no_exchanger", details["reason"])
}

func TestBrokerExchangeSubjectToken_SubjectValidationFailure(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "x"}}
	srv, buf := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}},
		&stubSubjectValidator{err: fmt.Errorf("token expired")})

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "bad-token", SubjectTokenTypeIDToken, "", "", "gaggle", "", "")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq, "exchanger must not be invoked on subject validation failure")

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "subject_token_validation_failed", details["reason"])
	// Brokered-flow context must appear in the same event so it can be correlated.
	require.Equal(t, "brokered", details["exchange"])
	require.Equal(t, "backstage", details["client_id"])
	require.Equal(t, "gaggle", details["audience"])
	require.NotEmpty(t, details["session_id"])
}

func TestBrokerExchangeSubjectToken_UnsupportedSubjectTokenType(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "x"}}
	srv, _ := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject", "urn:ietf:params:oauth:token-type:saml2", "", "", "gaggle", "", "")
	var unsupported *TokenExchangeUnsupportedTypeError
	require.ErrorAs(t, err, &unsupported)
}

func TestBrokerExchangeSubjectToken_DownstreamFailure(t *testing.T) {
	ex := &stubExchanger{err: fmt.Errorf("dex unreachable")}
	srv, buf := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "", "", "gaggle", "", "")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrInvalidTarget)

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "token_exchange_downstream_failed", details["reason"])
}

func TestBrokerExchangeSubjectToken_DownstreamInvalidTarget(t *testing.T) {
	ex := &stubExchanger{err: fmt.Errorf("%w: unmapped audience", ErrInvalidTarget)}
	srv, _ := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "", "", "gaggle", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
}

func TestBrokerExchangeSubjectToken_DownstreamEmptyToken(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{}}
	srv, buf := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "", "", "gaggle", "", "")
	require.Error(t, err)

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "token_exchange_downstream_empty_token", details["reason"])
}

func TestBrokerExchangeSubjectToken_ActorPresent(t *testing.T) {
	actorIdentity := SubjectIdentity{Subject: "service-a", Issuer: "https://idp.example.com"}
	validator := &stubTokenValidator{
		byToken: map[string]*SubjectIdentity{
			"actor-jwt": &actorIdentity,
		},
		defaultIdentity: &SubjectIdentity{Subject: brokerTestUserSub, Issuer: "https://dex.example.com"},
	}
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "downstream-token",
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Scope:       "openid",
	}}
	srv, buf := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, validator)
	srv.Config.ActorDelegationPolicy = []DelegationGrant{
		{ActorIssuer: "*", ActorSubject: "service-a", SubjectIssuer: "*", SubjectSubject: brokerTestUserSub},
	}

	result, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "actor-jwt", SubjectTokenTypeIDToken, "gaggle", "", "openid")
	require.NoError(t, err)
	require.Equal(t, "downstream-token", result.AccessToken)

	// Exchanger receives both validated identities and raw actor token.
	require.NotNil(t, ex.gotReq)
	require.NotNil(t, ex.gotReq.Actor)
	require.Equal(t, "service-a", ex.gotReq.Actor.Subject)
	require.Equal(t, "https://idp.example.com", ex.gotReq.Actor.Issuer)
	require.Equal(t, "actor-jwt", ex.gotReq.ActorToken)
	require.Equal(t, SubjectTokenTypeIDToken, ex.gotReq.ActorTokenType)

	// Success audit carries actor and subject issuer fields.
	details := auditDetails(t, buf, security.EventTokenIssued)
	require.Equal(t, "https://dex.example.com", details["subject_iss"])
	require.Equal(t, "https://idp.example.com", details["actor_iss"])
	require.Equal(t, "service-a", details["actor_sub"])
}

func TestBrokerExchangeSubjectToken_ActorAbsent(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "downstream-token",
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}}
	srv, _ := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "", "", "gaggle", "", "")
	require.NoError(t, err)

	require.NotNil(t, ex.gotReq)
	require.Nil(t, ex.gotReq.Actor)
	require.Empty(t, ex.gotReq.ActorToken)
	require.Empty(t, ex.gotReq.ActorTokenType)
}

func TestBrokerExchangeSubjectToken_ActorUntrustedIssuer(t *testing.T) {
	untrustedErr := fmt.Errorf("issuer not trusted")
	validator := &stubTokenValidator{
		byErr: map[string]error{
			"actor-jwt": untrustedErr,
		},
		defaultIdentity: &SubjectIdentity{Subject: brokerTestUserSub, Issuer: "https://dex.example.com"},
	}
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "downstream-token"}}
	srv, buf := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, validator)

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "actor-jwt", SubjectTokenTypeIDToken, "gaggle", "", "")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq, "exchanger must not be invoked when actor validation fails")

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "actor_token_validation_failed", details["reason"])
	// Brokered-flow context must appear in the same event.
	require.Equal(t, "brokered", details["exchange"])
	require.Equal(t, "backstage", details["client_id"])
	require.Equal(t, "gaggle", details["audience"])
	require.NotEmpty(t, details["session_id"])
}

func TestBrokerExchangeSubjectToken_ActorTokenTypeNormalizedWhenActorAbsent(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "downstream-token",
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}}
	srv, _ := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, happyBrokerValidator())

	// actorToken is empty but actorTokenType is non-empty — caller mistake per RFC 8693 §2.1.
	// BrokerExchangeSubjectToken must normalize ActorTokenType to "" so Exchangers
	// cannot observe a non-empty type with a nil Actor.
	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "", SubjectTokenTypeIDToken, "gaggle", "", "")
	require.NoError(t, err)

	require.NotNil(t, ex.gotReq)
	require.Nil(t, ex.gotReq.Actor)
	require.Empty(t, ex.gotReq.ActorToken)
	require.Empty(t, ex.gotReq.ActorTokenType, "ActorTokenType must be empty when ActorToken is empty")
}

func TestBrokerExchangeSubjectToken_ActorDelegationDeniedWhenNoPolicyConfigured(t *testing.T) {
	actorIdentity := SubjectIdentity{Subject: "service-a", Issuer: "https://idp.example.com"}
	validator := &stubTokenValidator{
		byToken: map[string]*SubjectIdentity{
			"actor-jwt": &actorIdentity,
		},
		defaultIdentity: &SubjectIdentity{Subject: brokerTestUserSub, Issuer: "https://dex.example.com"},
	}
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "downstream-token", ExpiresAt: time.Now().Add(time.Minute)}}
	// ActorDelegationPolicy is nil — delegation must be denied even though both tokens validate.
	srv, buf := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, validator)

	_, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "actor-jwt", SubjectTokenTypeIDToken, "gaggle", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq, "exchanger must not be invoked when delegation is denied")

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "actor_delegation_not_authorized", details["reason"])
	require.Equal(t, "service-a", details["actor_sub"])
	require.Equal(t, brokerTestUserSub, details["sub"])
}

func TestBrokerExchangeSubjectToken_SelfDelegationIsNoOp(t *testing.T) {
	// When actor token resolves to the same identity as the subject token, the
	// actor must be silently dropped: the exchange proceeds as pure M2M with no
	// act claim and no delegation-policy check.
	const sub = "service-a"
	const iss = "https://idp.example.com"
	identity := SubjectIdentity{Subject: sub, Issuer: iss}
	validator := &stubTokenValidator{
		byToken: map[string]*SubjectIdentity{
			"actor-jwt":   &identity,
			"subject-jwt": &identity,
		},
	}
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "downstream-token", ExpiresAt: time.Now().Add(time.Minute)}}
	srv, _ := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, validator)
	// No ActorDelegationPolicy — would fail if the actor reached the delegation check.

	tok, err := srv.BrokerExchangeSubjectToken(t.Context(),
		"backstage", "subject-jwt", SubjectTokenTypeIDToken, "actor-jwt", SubjectTokenTypeIDToken, "gaggle", "", "")
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.NotNil(t, ex.gotReq)
	require.Nil(t, ex.gotReq.Actor, "actor must be stripped when actor==subject")
}

// Workload-authenticated exchange tests.

// TestWorkloadExchangeSubjectToken_RateLimited asserts the mint path honours the
// configured UserRateLimiter when the method is called directly (not via the
// HTTP middleware): a second request from the same session is rejected before
// any mint, keyed on the per-session ID.
func TestWorkloadExchangeSubjectToken_RateLimited(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "workload-token",
		ExpiresAt:   time.Now().Add(time.Minute),
	}}
	const sub = "system:serviceaccount:ns:robot"
	validator := &stubSubjectValidator{identity: SubjectIdentity{Subject: sub, Issuer: "https://kube.example.com"}}
	srv, buf := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: sub, Audiences: []string{"target-service"}}}, validator)
	srv.UserRateLimiter = security.NewRateLimiter(0, 1, nil) // burst of 1, no refill
	t.Cleanup(srv.UserRateLimiter.Stop)

	// First call consumes the single token and mints.
	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "target-service", "", "")
	require.NoError(t, err)
	require.NotNil(t, ex.gotReq)

	ex.gotReq = nil
	// Second call from the same session (same subject token) is rate-limited.
	_, err = srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "target-service", "", "")
	require.ErrorIs(t, err, ErrExchangeRateLimited)
	require.Nil(t, ex.gotReq, "exchanger must not be invoked when rate-limited")

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "token_exchange_rate_limited", details["reason"])
}

func TestWorkloadExchangeSubjectToken_HappyPath(t *testing.T) {
	expiry := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "workload-token",
		ExpiresAt:   expiry,
		Scope:       "openid",
	}}
	const sub = "system:serviceaccount:ns:robot"
	validator := &stubSubjectValidator{identity: SubjectIdentity{
		Subject: sub,
		Issuer:  "https://kube.example.com",
	}}
	srv, buf := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: sub, Audiences: []string{"target-service"}}}, validator)

	result, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "target-service", "", "openid")
	require.NoError(t, err)
	require.Equal(t, "workload-token", result.AccessToken)
	require.Equal(t, expiry, result.ExpiresAt)
	require.Equal(t, SubjectTokenTypeAccessToken, result.IssuedTokenType)

	// Exchanger received empty ClientID on the workload path.
	require.NotNil(t, ex.gotReq)
	require.Empty(t, ex.gotReq.ClientID)
	require.Equal(t, "target-service", ex.gotReq.Audience)
	require.Equal(t, sub, ex.gotReq.Subject.Subject)

	// Audit carries exchange="workload" and no ClientID.
	details := auditDetails(t, buf, security.EventTokenIssued)
	require.Equal(t, "workload", details["exchange"])
	require.Empty(t, details["__client_id"])
	require.Equal(t, "target-service", details["audience"])
}

// TestWorkloadExchangeSubjectToken_AuditsMintJTI asserts the jti the Exchanger
// surfaces on its result is recorded in the success audit event, so every mint
// is attributable to a specific issued token.
func TestWorkloadExchangeSubjectToken_AuditsMintJTI(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "workload-token",
		ExpiresAt:   time.Now().Add(time.Minute),
		JTI:         "jti-12345",
	}}
	const sub = "system:serviceaccount:ns:robot"
	validator := &stubSubjectValidator{identity: SubjectIdentity{Subject: sub, Issuer: "https://kube.example.com"}}
	srv, buf := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: sub, Audiences: []string{"target-service"}}}, validator)

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "target-service", "", "")
	require.NoError(t, err)

	details := auditDetails(t, buf, security.EventTokenIssued)
	require.Equal(t, "jti-12345", details["jti"])
}

// TestWorkloadExchangeSubjectToken_RebindDeniedWhenActorNotGranted asserts a
// self-minted token carrying a delegation chain, re-presented without a fresh
// actor, is gated on the recorded acting principal: when that actor holds no
// grant for the requested audience the re-bind is denied. This is the boundary
// that stops the minted human subject from reaching arbitrary audiences.
func TestWorkloadExchangeSubjectToken_RebindDeniedWhenActorNotGranted(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "must-not-mint"}}
	validator := &stubSubjectValidator{identity: SubjectIdentity{
		Subject: brokerTestUserSub,
		Issuer:  "https://broker.example.com", // self-minted: equals cfg.Issuer
		Claims:  &oidc.IDTokenClaims{Act: &oidc.ActorClaim{Issuer: "https://kube.example.com", Subject: "agentA"}},
	}}
	// The grant is for a different subject than the recorded acting principal.
	srv, buf := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: "someone-else", Audiences: []string{"target-service"}}}, validator)

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"self-minted-obo", SubjectTokenTypeIDToken, "", "", "target-service", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Contains(t, err.Error(), "audience")
	require.Nil(t, ex.gotReq, "exchanger must not be invoked when the audience is denied")

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "token_exchange_audience_not_allowed", details["reason"])
	require.Equal(t, "agentA", details["sub"], "denial is attributed to the recorded acting principal")
}

// TestWorkloadExchangeSubjectToken_RebindAllowedPreservesActChain asserts a
// self-minted delegated token re-presented without a fresh actor is re-bound to
// the new audience when the recorded acting principal holds the grant, and the
// existing act chain is carried to the exchanger for preservation (no fresh
// actor and no group injection).
func TestWorkloadExchangeSubjectToken_RebindAllowedPreservesActChain(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "rebound-token", ExpiresAt: time.Now().Add(time.Minute)}}
	validator := &stubSubjectValidator{identity: SubjectIdentity{
		Subject: brokerTestUserSub,
		Issuer:  "https://broker.example.com", // self-minted: equals cfg.Issuer
		Claims:  &oidc.IDTokenClaims{Act: &oidc.ActorClaim{Issuer: "https://kube.example.com", Subject: "agentA"}},
	}}
	// Grant keyed on the recorded acting principal (agentA) for the audience.
	srv, _ := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: "agentA", Audiences: []string{"target-service"}}}, validator)

	result, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"self-minted-obo", SubjectTokenTypeIDToken, "", "", "target-service", "", "")
	require.NoError(t, err)
	require.Equal(t, "rebound-token", result.AccessToken)
	require.NotNil(t, ex.gotReq)
	require.Nil(t, ex.gotReq.Actor, "a re-bind injects no fresh actor")
	require.Equal(t, brokerTestUserSub, ex.gotReq.Subject.Subject, "minted subject stays the human")
	require.NotNil(t, ex.gotReq.Subject.Claims.Act, "existing act chain reaches the exchanger for preservation")
	require.Equal(t, "agentA", ex.gotReq.Subject.Claims.Act.Subject)
	require.Empty(t, ex.gotReq.GrantedGroups, "no group injection on the re-bind path")
	require.Empty(t, ex.gotReq.GrantedSubject)
}

// TestWorkloadExchangeSubjectToken_FederationEscalationGuardAllowsDelegation
// asserts the guard is narrow: the same self-minted delegated token re-exchanged
// with a fresh actor_token (the delegation path) proceeds, re-evaluating policy
// against that actor — this is the legitimate multi-hop A2A re-exchange.
func TestWorkloadExchangeSubjectToken_FederationEscalationGuardAllowsDelegation(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "workload-token",
		ExpiresAt:   time.Now().Add(time.Minute),
	}}
	const agentB = "system:serviceaccount:ns:agent-b"
	validator := &stubTokenValidator{
		byToken: map[string]*SubjectIdentity{
			"agent-b-jwt": {Subject: agentB, Issuer: "https://kube.example.com"},
		},
		defaultIdentity: &SubjectIdentity{
			Subject: brokerTestUserSub,
			Issuer:  "https://broker.example.com", // self-minted subject
			Claims:  &oidc.IDTokenClaims{Act: &oidc.ActorClaim{Issuer: "https://kube.example.com", Subject: "agentA"}},
		},
	}
	srv, _ := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: agentB, Audiences: []string{"target-service"}}}, validator)
	srv.Config.ActorDelegationPolicy = []DelegationGrant{
		{ActorIssuer: "*", ActorSubject: agentB, SubjectIssuer: "*", SubjectSubject: brokerTestUserSub},
	}

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"self-minted-obo", SubjectTokenTypeIDToken, "agent-b-jwt", SubjectTokenTypeIDToken, "target-service", "", "")
	require.NoError(t, err)
	require.NotNil(t, ex.gotReq, "delegation re-exchange must proceed to the exchanger")
}

func TestWorkloadExchangeSubjectToken_ImpersonationSubjectBoundToBrokerIssuer(t *testing.T) {
	// On the workload+no-actor path the subject token authenticates the caller,
	// so the validator must receive the broker's own issuer as defaultAudiences.
	const sub = "system:serviceaccount:ns:robot"
	rec := &recordingValidator{identity: SubjectIdentity{Subject: sub, Issuer: "https://kube.example.com"}}
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "workload-token",
		ExpiresAt:   time.Now().Add(time.Minute),
	}}
	srv, _ := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: sub, Audiences: []string{"target-service"}}}, rec)

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "target-service", "", "")
	require.NoError(t, err)
	require.Equal(t, []string{"https://broker.example.com"}, rec.lastDefaultAuds,
		"impersonation path must bind subject token to broker issuer")
}

func TestWorkloadExchangeSubjectToken_DelegationSubjectNotBoundToBrokerIssuer(t *testing.T) {
	// On the delegation path (actor present), the subject token is the user's credential
	// and must NOT be broker-bound — only the actor token is broker-bound.
	actorSub := brokerTestActorSub
	subjectSub := brokerTestUserSub
	actorValidator := &stubTokenValidator{
		byToken: map[string]*SubjectIdentity{
			"actor-jwt": {Subject: actorSub, Issuer: "https://kube.example.com"},
		},
		defaultIdentity: &SubjectIdentity{Subject: subjectSub, Issuer: "https://idp.example.com"},
	}
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "workload-token",
		ExpiresAt:   time.Now().Add(time.Minute),
	}}
	srv, _ := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: actorSub, Audiences: []string{"target-service"}}}, actorValidator)
	srv.Config.ActorDelegationPolicy = []DelegationGrant{
		{ActorIssuer: "*", ActorSubject: actorSub, SubjectIssuer: "*", SubjectSubject: subjectSub},
	}

	// We can't easily verify the defaultAudiences for the subject on this path via
	// stubTokenValidator since it drops defaultAuds. Instead verify functional correctness:
	// delegation succeeds (proving subject token is not rejected for lacking broker audience).
	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"user-jwt", SubjectTokenTypeIDToken, "actor-jwt", SubjectTokenTypeIDToken, "target-service", "", "")
	require.NoError(t, err)
}

func TestWorkloadExchangeSubjectToken_AudienceNotAllowed(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "x"}}
	const sub = "system:serviceaccount:ns:robot"
	validator := &stubSubjectValidator{identity: SubjectIdentity{Subject: sub, Issuer: "https://kube.example.com"}}
	srv, buf := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: sub, Audiences: []string{"allowed-service"}}}, validator)

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "other-service", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq, "exchanger must not be invoked on allowlist miss")

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "token_exchange_audience_not_allowed", details["reason"])
	require.Equal(t, "workload", details["exchange"])
	require.Empty(t, details["__client_id"])
}

func TestWorkloadExchangeSubjectToken_SubjectNotInMap(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "x"}}
	validator := &stubSubjectValidator{identity: SubjectIdentity{
		Subject: "system:serviceaccount:other:robot",
		Issuer:  "https://kube.example.com",
	}}
	srv, _ := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: "system:serviceaccount:ns:robot", Audiences: []string{"svc"}}}, validator)

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "svc", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq)
}

func TestWorkloadExchangeSubjectToken_GlobMatch(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "workload-token",
		ExpiresAt:   time.Now().Add(time.Minute),
	}}
	const sub = "system:serviceaccount:ns:robot"
	validator := &stubSubjectValidator{identity: SubjectIdentity{Subject: sub, Issuer: "https://kube.example.com"}}
	srv, _ := newWorkloadTestServer(t, ex,
		// Glob covers all service accounts in ns.
		[]WorkloadGrant{{Issuer: "*", Subject: "system:serviceaccount:ns:*", Audiences: []string{"target-service"}}}, validator)

	result, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "target-service", "", "")
	require.NoError(t, err)
	require.Equal(t, "workload-token", result.AccessToken)
}

func TestWorkloadExchangeSubjectToken_GlobNoMatch(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "x"}}
	// Subject is in a different namespace than the glob.
	validator := &stubSubjectValidator{identity: SubjectIdentity{
		Subject: "system:serviceaccount:other:robot",
		Issuer:  "https://kube.example.com",
	}}
	srv, _ := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: "system:serviceaccount:ns:*", Audiences: []string{"target-service"}}}, validator)

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "target-service", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq)
}

func TestWorkloadExchangeSubjectToken_DelegationUsesActorSubject(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "workload-token",
		ExpiresAt:   time.Now().Add(time.Minute),
	}}
	actorSub := brokerTestActorSub
	subjectSub := brokerTestUserSub
	validator := &stubTokenValidator{
		byToken: map[string]*SubjectIdentity{
			"actor-jwt": {Subject: actorSub, Issuer: "https://kube.example.com"},
		},
		defaultIdentity: &SubjectIdentity{Subject: subjectSub, Issuer: "https://idp.example.com"},
	}
	// Allowlist is keyed on the actor subject, not the user subject.
	srv, _ := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: actorSub, Audiences: []string{"target-service"}}}, validator)
	srv.Config.ActorDelegationPolicy = []DelegationGrant{
		{ActorIssuer: "*", ActorSubject: actorSub, SubjectIssuer: "*", SubjectSubject: subjectSub},
	}

	result, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"user-jwt", SubjectTokenTypeIDToken, "actor-jwt", SubjectTokenTypeIDToken, "target-service", "", "")
	require.NoError(t, err)
	require.Equal(t, "workload-token", result.AccessToken)

	// Exchanger got both identities.
	require.NotNil(t, ex.gotReq)
	require.Equal(t, subjectSub, ex.gotReq.Subject.Subject)
	require.NotNil(t, ex.gotReq.Actor)
	require.Equal(t, actorSub, ex.gotReq.Actor.Subject)
}

func TestWorkloadExchangeSubjectToken_DelegationDeniedWhenNoPolicyConfigured(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "x"}}
	actorSub := brokerTestActorSub
	subjectSub := brokerTestUserSub
	validator := &stubTokenValidator{
		byToken: map[string]*SubjectIdentity{
			"actor-jwt": {Subject: actorSub, Issuer: "https://kube.example.com"},
		},
		defaultIdentity: &SubjectIdentity{Subject: subjectSub, Issuer: "https://idp.example.com"},
	}
	// ActorDelegationPolicy is nil — all delegation must be denied regardless of audience config.
	srv, buf := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: actorSub, Audiences: []string{"target-service"}}}, validator)

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"user-jwt", SubjectTokenTypeIDToken, "actor-jwt", SubjectTokenTypeIDToken, "target-service", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq)

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "actor_delegation_not_authorized", details["reason"])
	require.Equal(t, actorSub, details["actor_sub"])
	require.Equal(t, subjectSub, details["sub"])
}

func TestWorkloadExchangeSubjectToken_DelegationDeniedByPolicy(t *testing.T) {
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "x"}}
	actorSub := brokerTestActorSub
	subjectSub := brokerTestUserSub
	validator := &stubTokenValidator{
		byToken: map[string]*SubjectIdentity{
			"actor-jwt": {Subject: actorSub, Issuer: "https://kube.example.com"},
		},
		defaultIdentity: &SubjectIdentity{Subject: subjectSub, Issuer: "https://idp.example.com"},
	}
	// Policy only covers the user subject as the actor key, not the SA — delegation denied.
	srv, _ := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: actorSub, Audiences: []string{"target-service"}}}, validator)
	srv.Config.ActorDelegationPolicy = []DelegationGrant{
		{ActorIssuer: "*", ActorSubject: subjectSub, SubjectIssuer: "*", SubjectSubject: actorSub},
	}

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"user-jwt", SubjectTokenTypeIDToken, "actor-jwt", SubjectTokenTypeIDToken, "target-service", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq)
}

func TestWorkloadExchangeSubjectToken_SelfDelegationIsNoOp(t *testing.T) {
	// When subject and actor tokens resolve to the same identity, the actor must
	// be stripped and the exchange proceeds as pure M2M with no act claim and no
	// delegation-policy check.
	const sub = "system:serviceaccount:ns:robot"
	const iss = "https://kube.example.com"
	identity := SubjectIdentity{Subject: sub, Issuer: iss}
	validator := &stubTokenValidator{
		byToken: map[string]*SubjectIdentity{
			"subject-jwt": &identity,
			"actor-jwt":   &identity,
		},
	}
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "workload-token",
		ExpiresAt:   time.Now().Add(time.Minute),
	}}
	// No ActorDelegationPolicy — would fail if the actor reached the delegation check.
	srv, _ := newWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: sub, Audiences: []string{"target-service"}}}, validator)

	tok, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"subject-jwt", SubjectTokenTypeIDToken, "actor-jwt", SubjectTokenTypeIDToken, "target-service", "", "")
	require.NoError(t, err)
	require.NotNil(t, tok)
	require.NotNil(t, ex.gotReq)
	require.Nil(t, ex.gotReq.Actor, "actor must be stripped when actor==subject")
}

func TestWorkloadExchangeSubjectToken_NoExchanger(t *testing.T) {
	validator := &stubSubjectValidator{identity: SubjectIdentity{
		Subject: "system:serviceaccount:ns:robot",
		Issuer:  "https://kube.example.com",
	}}
	srv, buf := newWorkloadTestServer(t, nil,
		[]WorkloadGrant{{Issuer: "*", Subject: "system:serviceaccount:ns:robot", Audiences: []string{"svc"}}}, validator)

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "svc", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)

	details := auditDetails(t, buf, security.EventAuthFailure)
	require.Equal(t, "token_exchange_no_exchanger", details["reason"])
	require.Equal(t, "workload", details["exchange"])
}

// workloadAudienceAllowed unit tests.

func newMatchTestServer(t *testing.T) *Server {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })
	srv, err := New(mock.NewProvider(), store, store, store, &Config{
		Issuer:                      "https://broker.example.com",
		DisableNonceEchoRequirement: true,
	}, slog.Default())
	require.NoError(t, err)
	return srv
}

func TestWorkloadAudienceAllowed(t *testing.T) {
	grants := []WorkloadGrant{
		{Issuer: "*", Subject: "system:serviceaccount:ns:robot", Audiences: []string{"svc-a", "svc-b"}},
		{Issuer: "*", Subject: "system:serviceaccount:ns:*", Audiences: []string{"svc-c"}},
	}

	tests := []struct {
		name      string
		issuer    string
		subject   string
		audience  string
		grants    []WorkloadGrant
		wantAllow bool
	}{
		{"exact match, allowed audience", "https://kube.example.com", "system:serviceaccount:ns:robot", "svc-a", grants, true},
		{"exact match, second audience", "https://kube.example.com", "system:serviceaccount:ns:robot", "svc-b", grants, true},
		{"exact match, audience also covered by glob", "https://kube.example.com", "system:serviceaccount:ns:robot", "svc-c", grants, true},
		{"glob match", "https://kube.example.com", "system:serviceaccount:ns:other", "svc-c", grants, true},
		{"glob no match different ns", "https://kube.example.com", "system:serviceaccount:prod:robot", "svc-c", grants, false},
		{"unknown subject", "https://kube.example.com", "system:serviceaccount:ns:unknown", "svc-a", grants, false},
		{"nil grants", "https://kube.example.com", "system:serviceaccount:ns:robot", "svc-a", nil, false},
		{"audience not in list, no glob", "https://kube.example.com", "system:serviceaccount:ns:robot", "svc-x", grants, false},
		// Issuer-qualified grant: same subject from a different issuer is denied.
		{
			"issuer mismatch denied", "https://other-cluster.example.com", "system:serviceaccount:ns:robot", "svc-a",
			[]WorkloadGrant{{Issuer: "https://kube.example.com", Subject: "system:serviceaccount:ns:robot", Audiences: []string{"svc-a"}}},
			false,
		},
		// Wildcard Issuer matches any issuer.
		{
			"wildcard issuer matches any", "https://other-cluster.example.com", "system:serviceaccount:ns:robot", "svc-a",
			[]WorkloadGrant{{Issuer: "*", Subject: "system:serviceaccount:ns:robot", Audiences: []string{"svc-a"}}},
			true,
		},
	}

	srv := newMatchTestServer(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv.Config.WorkloadAudiences = tc.grants
			got := srv.workloadAudienceAllowed(tc.issuer, tc.subject, tc.audience)
			require.Equal(t, tc.wantAllow, got)
		})
	}
}

func TestActorDelegationAllowed(t *testing.T) {
	const (
		kubeIss  = "https://kube.example.com"
		idpIss   = "https://idp.example.com"
		otherIss = "https://other-cluster.example.com"
	)
	grants := []DelegationGrant{
		{ActorIssuer: "*", ActorSubject: "system:serviceaccount:ns:robot", SubjectIssuer: "*", SubjectSubject: brokerTestUserSub},
		{ActorIssuer: "*", ActorSubject: "system:serviceaccount:ns:robot", SubjectIssuer: "*", SubjectSubject: "other@example.com"},
		{ActorIssuer: "*", ActorSubject: "system:serviceaccount:ns:*", SubjectIssuer: "*", SubjectSubject: "admin@example.com"},
	}

	tests := []struct {
		name        string
		actorIssuer string
		actorSub    string
		subjIssuer  string
		subjSub     string
		grants      []DelegationGrant
		wantAllow   bool
	}{
		{"exact actor, first subject", kubeIss, "system:serviceaccount:ns:robot", idpIss, brokerTestUserSub, grants, true},
		{"exact actor, second subject", kubeIss, "system:serviceaccount:ns:robot", idpIss, "other@example.com", grants, true},
		{"exact actor, subject not in any entry", kubeIss, "system:serviceaccount:ns:robot", idpIss, "nobody@example.com", grants, false},
		{"glob actor, allowed subject", kubeIss, "system:serviceaccount:ns:other", idpIss, "admin@example.com", grants, true},
		{"glob actor, wrong subject", kubeIss, "system:serviceaccount:ns:other", idpIss, brokerTestUserSub, grants, false},
		{"glob no match different ns", kubeIss, "system:serviceaccount:prod:robot", idpIss, brokerTestUserSub, grants, false},
		{"unknown actor", kubeIss, "unknown-service", idpIss, brokerTestUserSub, grants, false},
		{"nil grants", kubeIss, "system:serviceaccount:ns:robot", idpIss, brokerTestUserSub, nil, false},
		// Issuer-qualified: actor from a different issuer must not match an issuer-scoped grant.
		{
			"actor issuer mismatch denied", otherIss, "system:serviceaccount:ns:robot", idpIss, brokerTestUserSub,
			[]DelegationGrant{{ActorIssuer: kubeIss, ActorSubject: "system:serviceaccount:ns:robot", SubjectIssuer: idpIss, SubjectSubject: brokerTestUserSub}},
			false,
		},
		// Subject issuer mismatch.
		{
			"subject issuer mismatch denied", kubeIss, "system:serviceaccount:ns:robot", otherIss, brokerTestUserSub,
			[]DelegationGrant{{ActorIssuer: kubeIss, ActorSubject: "system:serviceaccount:ns:robot", SubjectIssuer: idpIss, SubjectSubject: brokerTestUserSub}},
			false,
		},
		// Wildcard issuers match any.
		{
			"wildcard issuers match any", otherIss, "system:serviceaccount:ns:robot", otherIss, brokerTestUserSub,
			[]DelegationGrant{{ActorIssuer: "*", ActorSubject: "system:serviceaccount:ns:robot", SubjectIssuer: "*", SubjectSubject: brokerTestUserSub}},
			true,
		},
	}

	srv := newMatchTestServer(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv.Config.ActorDelegationPolicy = tc.grants
			got := srv.actorDelegationAllowed(tc.actorIssuer, tc.actorSub, tc.subjIssuer, tc.subjSub)
			require.Equal(t, tc.wantAllow, got)
		})
	}
}

func TestSubjectMatchesBadPattern(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	store := memory.New()
	t.Cleanup(func() { store.Stop() })
	srv, err := New(mock.NewProvider(), store, store, store, &Config{
		Issuer:                      "https://broker.example.com",
		DisableNonceEchoRequirement: true,
	}, logger)
	require.NoError(t, err)

	// An unclosed bracket is a malformed glob that path.Match rejects with ErrBadPattern.
	got := srv.subjectMatches("[unclosed", "anything")
	require.False(t, got, "malformed pattern must fail closed")
	require.Contains(t, buf.String(), "malformed", "bad pattern must emit a Warn log")
}

func TestWorkloadAudienceAllowed_MalformedGlobFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	store := memory.New()
	t.Cleanup(func() { store.Stop() })
	srv, err := New(mock.NewProvider(), store, store, store, &Config{
		Issuer:                      "https://broker.example.com",
		DisableNonceEchoRequirement: true,
		WorkloadAudiences: []WorkloadGrant{
			{Issuer: "*", Subject: "[bad", Audiences: []string{"svc"}},
		},
	}, logger)
	require.NoError(t, err)

	got := srv.workloadAudienceAllowed("https://kube.example.com", "anything", "svc")
	require.False(t, got)
	require.Contains(t, buf.String(), "malformed")
}

func TestConfig_ValidateRejectsEmptyGrantIssuers(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name: "WorkloadGrant empty Issuer",
			cfg: &Config{
				Issuer:                      "https://broker.example.com",
				DisableNonceEchoRequirement: true,
				WorkloadAudiences: []WorkloadGrant{
					{Subject: "system:serviceaccount:ns:sa", Audiences: []string{"svc"}},
				},
			},
			wantErr: "WorkloadAudiences[0].Issuer is empty",
		},
		{
			name: "DelegationGrant empty ActorIssuer",
			cfg: &Config{
				Issuer:                      "https://broker.example.com",
				DisableNonceEchoRequirement: true,
				ActorDelegationPolicy: []DelegationGrant{
					{ActorSubject: "actor", SubjectIssuer: "https://idp.example.com", SubjectSubject: "user"},
				},
			},
			wantErr: "ActorDelegationPolicy[0].ActorIssuer is empty",
		},
		{
			name: "DelegationGrant empty SubjectIssuer",
			cfg: &Config{
				Issuer:                      "https://broker.example.com",
				DisableNonceEchoRequirement: true,
				ActorDelegationPolicy: []DelegationGrant{
					{ActorIssuer: "https://kube.example.com", ActorSubject: "actor", SubjectSubject: "user"},
				},
			},
			wantErr: "ActorDelegationPolicy[0].SubjectIssuer is empty",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(mock.NewProvider(), store, store, store, tc.cfg, logger)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestWorkloadExchange_M2MGroupsInjected(t *testing.T) {
	const saIssuer = "https://kubernetes.default.svc"
	const saSub = "system:serviceaccount:kagent:sre-agent"

	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "minted", ExpiresAt: time.Now().Add(time.Minute)}}
	srv, _ := newWorkloadTestServer(t, ex, []WorkloadGrant{{
		Issuer:    saIssuer,
		Subject:   saSub,
		Audiences: []string{"mcp-prometheus"},
		Granted:   WorkloadGrantedIdentity{Groups: []string{"giantswarm-ad:sre"}},
	}}, &stubSubjectValidator{identity: SubjectIdentity{Subject: saSub, Issuer: saIssuer}})

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "mcp-prometheus", "", "")
	require.NoError(t, err)

	require.NotNil(t, ex.gotReq)
	require.Nil(t, ex.gotReq.Actor, "M2M path must carry no actor")
	require.Equal(t, []string{"giantswarm-ad:sre"}, ex.gotReq.GrantedGroups, "grant groups travel on GrantedGroups")
	require.Nil(t, ex.gotReq.Subject.Claims, "the validated subject identity must never be mutated to carry granted groups")
}

func TestWorkloadExchange_M2MNoGroupsWhenUngranted(t *testing.T) {
	const saIssuer = "https://kubernetes.default.svc"
	const saSub = "system:serviceaccount:kagent:sre-agent"

	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "minted", ExpiresAt: time.Now().Add(time.Minute)}}
	// Grant authorizes the audience but carries no groups.
	srv, _ := newWorkloadTestServer(t, ex, []WorkloadGrant{{
		Issuer:    saIssuer,
		Subject:   saSub,
		Audiences: []string{"mcp-prometheus"},
	}}, &stubSubjectValidator{identity: SubjectIdentity{Subject: saSub, Issuer: saIssuer}})

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "mcp-prometheus", "", "")
	require.NoError(t, err)

	require.NotNil(t, ex.gotReq)
	require.Empty(t, ex.gotReq.GrantedGroups, "a grant without groups grants none")
	require.Nil(t, ex.gotReq.Subject.Claims, "no groups grant must not synthesize claims")
}

func TestWorkloadExchange_DelegationDoesNotInjectWorkloadGroups(t *testing.T) {
	const saIssuer = "https://kubernetes.default.svc"
	const saSub = "system:serviceaccount:kagent:sre-agent"
	const userIssuer = "https://dex.example.com"
	const userSub = "alice@example.com"

	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "minted", ExpiresAt: time.Now().Add(time.Minute)}}
	validator := &stubTokenValidator{byToken: map[string]*SubjectIdentity{
		"user-jwt": {Subject: userSub, Issuer: userIssuer, Claims: &oidc.IDTokenClaims{Groups: []string{"giantswarm-ad:devs"}}},
		"sa-jwt":   {Subject: saSub, Issuer: saIssuer},
	}}
	srv, _ := newWorkloadTestServer(t, ex, []WorkloadGrant{{
		Issuer:    saIssuer,
		Subject:   saSub,
		Audiences: []string{"mcp-prometheus"},
		Granted:   WorkloadGrantedIdentity{Groups: []string{"giantswarm-ad:sre"}},
	}}, validator)
	srv.Config.ActorDelegationPolicy = []DelegationGrant{{
		ActorIssuer: saIssuer, ActorSubject: saSub, SubjectIssuer: userIssuer, SubjectSubject: userSub,
	}}

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"user-jwt", SubjectTokenTypeIDToken, "sa-jwt", SubjectTokenTypeIDToken, "mcp-prometheus", "", "")
	require.NoError(t, err)

	require.NotNil(t, ex.gotReq)
	require.NotNil(t, ex.gotReq.Actor)
	require.Equal(t, saSub, ex.gotReq.Actor.Subject)
	require.Equal(t, userSub, ex.gotReq.Subject.Subject)
	require.Empty(t, ex.gotReq.GrantedGroups, "delegation path grants no workload groups")
	require.Equal(t, []string{"giantswarm-ad:devs"}, ex.gotReq.Subject.Claims.Groups,
		"delegation preserves the human subject's own token groups untouched")
}

func TestConfigValidate_WorkloadIdentityGrantRequiresExplicit(t *testing.T) {
	tests := []struct {
		name  string
		grant WorkloadGrant
	}{
		{"wildcard issuer + groups", WorkloadGrant{Issuer: "*", Subject: "system:serviceaccount:kagent:sre-agent", Audiences: []string{"a"}, Granted: WorkloadGrantedIdentity{Groups: []string{"g"}}}},
		{"glob subject + groups", WorkloadGrant{Issuer: "https://k8s", Subject: "system:serviceaccount:kagent:*", Audiences: []string{"a"}, Granted: WorkloadGrantedIdentity{Groups: []string{"g"}}}},
		{"wildcard issuer + granted subject", WorkloadGrant{Issuer: "*", Subject: "system:serviceaccount:kagent:sre-agent", Audiences: []string{"a"}, Granted: WorkloadGrantedIdentity{Subject: "agent:sre"}}},
		{"glob subject + granted subject", WorkloadGrant{Issuer: "https://k8s", Subject: "system:serviceaccount:kagent:*", Audiences: []string{"a"}, Granted: WorkloadGrantedIdentity{Subject: "agent:sre"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{WorkloadAudiences: []WorkloadGrant{tc.grant}}
			err := cfg.validateGrants()
			require.Error(t, err)
			require.Contains(t, err.Error(), "injects identity")
		})
	}
}

func TestConfigValidate_WorkloadGrantedSubjectExplicitOK(t *testing.T) {
	grant := WorkloadGrant{
		Issuer:    "https://kubernetes.default.svc",
		Subject:   "system:serviceaccount:kagent:sre-agent",
		Audiences: []string{"mcp-kubernetes"},
		Granted:   WorkloadGrantedIdentity{Subject: "agent:sre"},
	}
	cfg := &Config{WorkloadAudiences: []WorkloadGrant{grant}}
	require.NoError(t, cfg.validateGrants())
}

func TestWorkloadExchange_M2MGrantedSubjectInjected(t *testing.T) {
	const saIssuer = "https://kubernetes.default.svc"
	const saSub = "system:serviceaccount:kagent:sre-agent"

	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "minted", ExpiresAt: time.Now().Add(time.Minute)}}
	srv, _ := newWorkloadTestServer(t, ex, []WorkloadGrant{{
		Issuer:    saIssuer,
		Subject:   saSub,
		Audiences: []string{"mcp-kubernetes"},
		Granted:   WorkloadGrantedIdentity{Subject: "agent:sre"},
	}}, &stubSubjectValidator{identity: SubjectIdentity{Subject: saSub, Issuer: saIssuer}})

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"sa-jwt", SubjectTokenTypeIDToken, "", "", "mcp-kubernetes", "", "")
	require.NoError(t, err)

	require.NotNil(t, ex.gotReq)
	require.Equal(t, "agent:sre", ex.gotReq.GrantedSubject, "granted subject travels on GrantedSubject")
	require.Equal(t, saSub, ex.gotReq.Subject.Subject, "validated subject must not be mutated")
}

func TestWorkloadExchange_DelegationDoesNotInjectGrantedSubject(t *testing.T) {
	const saIssuer = "https://kubernetes.default.svc"
	const saSub = "system:serviceaccount:kagent:sre-agent"
	const userIssuer = "https://dex.example.com"
	const userSub = "alice@example.com"

	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "minted", ExpiresAt: time.Now().Add(time.Minute)}}
	validator := &stubTokenValidator{byToken: map[string]*SubjectIdentity{
		"user-jwt": {Subject: userSub, Issuer: userIssuer},
		"sa-jwt":   {Subject: saSub, Issuer: saIssuer},
	}}
	srv, _ := newWorkloadTestServer(t, ex, []WorkloadGrant{{
		Issuer:    saIssuer,
		Subject:   saSub,
		Audiences: []string{"mcp-kubernetes"},
		Granted:   WorkloadGrantedIdentity{Subject: "agent:sre"},
	}}, validator)
	srv.Config.ActorDelegationPolicy = []DelegationGrant{{
		ActorIssuer: saIssuer, ActorSubject: saSub, SubjectIssuer: userIssuer, SubjectSubject: userSub,
	}}

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		"user-jwt", SubjectTokenTypeIDToken, "sa-jwt", SubjectTokenTypeIDToken, "mcp-kubernetes", "", "")
	require.NoError(t, err)

	require.NotNil(t, ex.gotReq)
	require.Empty(t, ex.gotReq.GrantedSubject, "delegation path grants no workload subject")
}

// newJWTWorkloadTestServer builds a JWT-mode broker (so it can mint and verify
// its own tokens) wired for the workload exchange. No trustedIssuers entry for
// the broker's own issuer is configured, so these tests exercise self-trust.
func newJWTWorkloadTestServer(t *testing.T, exchanger Exchanger, grants []WorkloadGrant) *Server {
	t.Helper()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })
	key := generateRSAKey(t)
	cfg := &Config{
		Issuer:                      "https://broker.example.com",
		ResourceIdentifier:          "https://broker.example.com/mcp",
		SupportedScopes:             []string{"openid"},
		AuthorizationCodeTTL:        600,
		AccessTokenTTL:              3600,
		RequirePKCE:                 true,
		ClockSkewGracePeriod:        5,
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       key,
		AccessTokenSigningKeyID:     "test-kid-1",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		EnableWorkloadTokenExchange: true,
		WorkloadAudiences:           grants,
		DisableNonceEchoRequirement: true,
	}
	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil, WithExchanger(exchanger))
	require.NoError(t, err)
	return srv
}

// mintSelfOBO mints a self-issued delegated access token (sub=human, act=actor,
// aud=resourceIdentifier) the way the front-door delegation exchange would.
func mintSelfOBO(t *testing.T, srv *Server, human, actorIssuer, actorSub string) string {
	t.Helper()
	now := time.Now().UTC()
	tok, err := srv.accessTokenIssuer.Issue(t.Context(), AccessTokenClaims{
		Subject:   human,
		Audience:  srv.Config.GetResourceIdentifier(),
		Email:     human,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
		Act:       &Actor{Iss: actorIssuer, Sub: actorSub},
	})
	require.NoError(t, err)
	return tok
}

// TestWorkloadExchangeSubjectToken_SelfTrustEnablesRebind asserts the broker
// accepts its own self-minted delegated token as an exchange subject with no
// trustedIssuers self-entry, and re-binds it to the requested audience when the
// recorded acting principal holds the grant.
func TestWorkloadExchangeSubjectToken_SelfTrustEnablesRebind(t *testing.T) {
	const human = "user@example.com"
	const saIssuer = "https://kube.example.com"
	const saSub = "system:serviceaccount:ns:agent"

	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "rebound", ExpiresAt: time.Now().Add(time.Minute)}}
	srv := newJWTWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: saSub, Audiences: []string{"target-service"}}})

	selfOBO := mintSelfOBO(t, srv, human, saIssuer, saSub)

	result, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		selfOBO, SubjectTokenTypeJWT, "", "", "target-service", "", "")
	require.NoError(t, err)
	require.Equal(t, "rebound", result.AccessToken)
	require.NotNil(t, ex.gotReq)
	require.Nil(t, ex.gotReq.Actor, "re-bind injects no fresh actor")
	require.Equal(t, human, ex.gotReq.Subject.Subject, "minted subject stays the human")
	require.NotNil(t, ex.gotReq.Subject.Claims.Act, "act chain reaches the exchanger for preservation")
	require.Equal(t, saSub, ex.gotReq.Subject.Claims.Act.Subject)
}

// TestWorkloadExchangeSubjectToken_SelfTrustDeniesUngrantedActor asserts the
// re-bind of a self-minted delegated token is denied when the recorded acting
// principal holds no grant for the requested audience.
func TestWorkloadExchangeSubjectToken_SelfTrustDeniesUngrantedActor(t *testing.T) {
	const human = "user@example.com"
	const saIssuer = "https://kube.example.com"
	const saSub = "system:serviceaccount:ns:agent"

	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "must-not-mint"}}
	srv := newJWTWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: "someone-else", Audiences: []string{"target-service"}}})

	selfOBO := mintSelfOBO(t, srv, human, saIssuer, saSub)

	_, err := srv.WorkloadExchangeSubjectToken(t.Context(),
		selfOBO, SubjectTokenTypeJWT, "", "", "target-service", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Contains(t, err.Error(), "audience")
	require.Nil(t, ex.gotReq, "exchanger must not run when the acting principal lacks the grant")
}

// TestWorkloadExchangeSubjectToken_SelfTrustRejectsPlainUserToken asserts the
// self-trust path does not let an ordinary self-minted user token (no act) reach
// a backend audience: with no actor it falls to the M2M branch, where the human
// subject holds no workload grant.
func TestWorkloadExchangeSubjectToken_SelfTrustRejectsPlainUserToken(t *testing.T) {
	const human = "user@example.com"
	ex := &stubExchanger{result: &ExchangerResult{AccessToken: "must-not-mint"}}
	srv := newJWTWorkloadTestServer(t, ex,
		[]WorkloadGrant{{Issuer: "*", Subject: "system:serviceaccount:ns:agent", Audiences: []string{"target-service"}}})

	now := time.Now().UTC()
	plain, err := srv.accessTokenIssuer.Issue(t.Context(), AccessTokenClaims{
		Subject:   human,
		Audience:  srv.Config.GetResourceIdentifier(),
		Email:     human,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	})
	require.NoError(t, err)

	_, err = srv.WorkloadExchangeSubjectToken(t.Context(),
		plain, SubjectTokenTypeJWT, "", "", "target-service", "", "")
	require.ErrorIs(t, err, ErrInvalidTarget)
	require.Nil(t, ex.gotReq, "a plain self-minted user token must not reach a backend audience")
}
