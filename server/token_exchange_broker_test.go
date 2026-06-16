package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage/memory"
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
		Subject: "user@example.com",
		Issuer:  "https://dex.example.com",
	}}
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
	require.Equal(t, "user@example.com", ex.gotReq.Subject.Subject)
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
		defaultIdentity: &SubjectIdentity{Subject: "user@example.com", Issuer: "https://dex.example.com"},
	}
	ex := &stubExchanger{result: &ExchangerResult{
		AccessToken: "downstream-token",
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Scope:       "openid",
	}}
	srv, buf := newBrokerTestServer(t, ex,
		map[string][]string{"backstage": {"gaggle"}}, validator)

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

	// Success audit carries actor fields.
	details := auditDetails(t, buf, security.EventTokenIssued)
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
		defaultIdentity: &SubjectIdentity{Subject: "user@example.com", Issuer: "https://dex.example.com"},
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
