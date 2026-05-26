package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/providers/mock"
	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// auditRecord is the shape of one slog record emitted by [security.Auditor]
// after JSON-encoding via [slog.NewJSONHandler]. Only the audit group is
// exercised in tests; top-level slog fields (time, level, msg) are ignored.
type auditRecord struct {
	EventType string         `json:"event_type"`
	ClientID  string         `json:"client_id"`
	Details   map[string]any `json:"details"`
}

func decodeAuditRecords(t *testing.T, raw []byte) []auditRecord {
	t.Helper()
	var out []auditRecord
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var envelope struct {
			Audit auditRecord `json:"audit"`
		}
		require.NoError(t, json.Unmarshal(line, &envelope), "unmarshal %s", line)
		if envelope.Audit.EventType != "" {
			out = append(out, envelope.Audit)
		}
	}
	return out
}

func newRecordingAuditor() (*security.Auditor, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	return security.NewAuditor(logger, true), buf
}

// newJWTIntrospectionServer wires a JWT-mode server, an opaque-mode mock
// provider, and three registered clients (token owner, probing client,
// allowlisted resource server). It returns the server and the issued JWT
// access token.
func newJWTIntrospectionServer(t *testing.T) (srv *Server, accessToken, ownerClientID, probingClientID, resourceServerID string) {
	t.Helper()

	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:                      "https://auth.example.com",
		AccessTokenFormat:           AccessTokenFormatJWT,
		AccessTokenSigningKey:       generateRSAKey(t),
		AccessTokenSigningKeyID:     "kid-introspect",
		AccessTokenSigningAlgorithm: SigningAlgorithmRS256,
		AccessTokenTTL:              3600,
		ClockSkewGracePeriod:        5,
	}
	require.NoError(t, cfg.Validate())

	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)

	owner, _, err := srv.RegisterClient(context.Background(), "Owner", ClientTypeConfidential, "", []string{"https://example.com/cb-owner"}, []string{"openid"}, "192.168.1.1", 10)
	require.NoError(t, err)
	probe, _, err := srv.RegisterClient(context.Background(), "Probe", ClientTypeConfidential, "", []string{"https://example.com/cb-probe"}, []string{"openid"}, "192.168.1.2", 10)
	require.NoError(t, err)
	rs, _, err := srv.RegisterClient(context.Background(), "Resource Server", ClientTypeConfidential, "", []string{"https://example.com/cb-rs"}, []string{"openid"}, "192.168.1.3", 10)
	require.NoError(t, err)

	now := time.Now().UTC()
	issuer, err := newJWTIssuer(cfg)
	require.NoError(t, err)
	token, err := issuer.Issue(context.Background(), AccessTokenClaims{
		Subject:       "user-42",
		ClientID:      owner.ClientID,
		Audience:      cfg.GetResourceIdentifier(),
		Scopes:        []string{"openid", "email"},
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "User Forty-Two",
		IssuedAt:      now,
		ExpiresAt:     now.Add(15 * time.Minute),
	})
	require.NoError(t, err)

	return srv, token, owner.ClientID, probe.ClientID, rs.ClientID
}

func TestServer_IntrospectToken_JWTPath_OwnerSeesProjection(t *testing.T) {
	srv, token, owner, _, _ := newJWTIntrospectionServer(t)

	response := srv.IntrospectToken(context.Background(), token, owner)

	require.Equal(t, true, response["active"])
	require.Equal(t, "Bearer", response["token_type"])
	require.Equal(t, owner, response["client_id"])
	require.Equal(t, "user-42", response["sub"])
	require.Equal(t, "https://auth.example.com", response["iss"])
	require.Equal(t, "openid email", response["scope"])
	require.Equal(t, "user@example.com", response["email"])
	require.Equal(t, true, response["email_verified"], "JWT mode must project email_verified for parity with opaque mode")
	require.Equal(t, "User Forty-Two", response["name"], "JWT mode must project name for parity with opaque mode")
	require.Equal(t, srv.Config.GetResourceIdentifier(), response["aud"])
	require.Contains(t, response, "exp")
	require.Contains(t, response, "iat")
	_, expIsInt := response["exp"].(int64)
	require.True(t, expIsInt, "exp should be int64 after projection (got %T)", response["exp"])
}

func TestServer_IntrospectToken_JWTPath_CrossClientDenied(t *testing.T) {
	srv, token, _, probe, _ := newJWTIntrospectionServer(t)

	response := srv.IntrospectToken(context.Background(), token, probe)

	require.Equal(t, false, response["active"])
	for _, leaked := range []string{"sub", "email", "client_id", "scope", "aud", "iss", "exp", "iat", "token_type"} {
		require.NotContains(t, response, leaked, "cross-client JWT probe leaked %q", leaked)
	}
}

func TestServer_IntrospectToken_JWTPath_AllowlistedResourceServer(t *testing.T) {
	srv, token, owner, _, rs := newJWTIntrospectionServer(t)
	srv.Config.IntrospectionResourceServers = []string{rs}

	response := srv.IntrospectToken(context.Background(), token, rs)

	require.Equal(t, true, response["active"])
	require.Equal(t, owner, response["client_id"], "client_id must reflect the token's owner, not the introspecting RS")
}

func TestServer_Config_Validate_EmptyIntrospectionResourceServerEntryFailsClosed(t *testing.T) {
	cfg := &Config{
		Issuer:                       "https://auth.example.com",
		IntrospectionResourceServers: []string{"valid-client", ""},
	}
	err := cfg.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "IntrospectionResourceServers[1] is empty")
}

// TestServer_IntrospectToken_JWTPath_GarbageToken_RejectedBeforeValidation
// pins the timing-oracle defence: a forged JWT with client_id == requester
// must still return inactive (signature verify rejects it). Both the "valid
// JWT I don't own" and "garbage JWT" paths return identical responses; the
// only timing artefact is the unverified parse + one gate evaluation.
func TestServer_IntrospectToken_JWTPath_GarbageToken_RejectedBeforeValidation(t *testing.T) {
	srv, _, owner, _, _ := newJWTIntrospectionServer(t)

	// A garbage JWT whose unverified client_id claim matches the requester:
	// the gate would let it through, but signature verification rejects it.
	garbage := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC1pbnRyb3NwZWN0IiwidHlwIjoiYXQrand0In0." +
		"eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJjbGllbnRfaWQiOiIiLCJzdWIiOiJ4In0." +
		"aW52YWxpZF9zaWduYXR1cmU"

	response := srv.IntrospectToken(context.Background(), garbage, owner)
	require.Equal(t, false, response["active"])
	require.Len(t, response, 1, "garbage JWT must return only {active: false}")
}

func TestServer_IntrospectToken_JWTPath_CrossClientDenied_EmitsAuditEvent(t *testing.T) {
	srv, token, _, probe, _ := newJWTIntrospectionServer(t)
	auditor, buf := newRecordingAuditor()
	srv.Auditor = auditor

	response := srv.IntrospectToken(context.Background(), token, probe)
	require.Equal(t, false, response["active"])

	records := decodeAuditRecords(t, buf.Bytes())
	require.Len(t, records, 1)
	require.Equal(t, security.EventIntrospectionRequesterDenied, records[0].EventType)
	require.Equal(t, probe, records[0].ClientID)
	require.Equal(t, "medium", records[0].Details["severity"])
	require.Equal(t, "cross_client_probe", records[0].Details["reason"])
}

func TestServer_IntrospectToken_OpaquePath_CrossClientDenied_EmitsAuditEvent(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:            "https://auth.example.com",
		AccessTokenFormat: AccessTokenFormatOpaque,
	}
	require.NoError(t, cfg.Validate())

	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)

	owner, _, err := srv.RegisterClient(ctx, "Owner", ClientTypeConfidential, "", []string{"https://example.com/cb-owner"}, []string{"openid"}, "192.168.1.1", 10)
	require.NoError(t, err)
	probe, _, err := srv.RegisterClient(ctx, "Probe", ClientTypeConfidential, "", []string{"https://example.com/cb-probe"}, []string{"openid"}, "192.168.1.2", 10)
	require.NoError(t, err)

	auditor, buf := newRecordingAuditor()
	srv.Auditor = auditor

	const accessToken = "opaque-audit-token" //nolint:gosec // G101 false positive — test fixture label, not a credential
	require.NoError(t, store.SaveTokenMetadata(ctx, accessToken, storage.TokenMetadata{
		UserID:    "user-1",
		ClientID:  owner.ClientID,
		TokenType: "access",
		Audience:  cfg.GetResourceIdentifier(),
		Scopes:    []string{"openid"},
	}))

	response := srv.IntrospectToken(ctx, accessToken, probe.ClientID)
	require.Equal(t, false, response["active"])

	records := decodeAuditRecords(t, buf.Bytes())
	require.Len(t, records, 1)
	require.Equal(t, security.EventIntrospectionRequesterDenied, records[0].EventType)
	require.Equal(t, probe.ClientID, records[0].ClientID)
	require.Equal(t, "medium", records[0].Details["severity"])
	require.Equal(t, "cross_client_probe", records[0].Details["reason"])
	require.Equal(t, owner.ClientID, records[0].Details["token_bound_client"])
}

func TestServer_IntrospectToken_OpaquePath_OwnerSeesExpAndIat(t *testing.T) {
	ctx := t.Context()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:            "https://auth.example.com",
		AccessTokenFormat: AccessTokenFormatOpaque,
	}
	require.NoError(t, cfg.Validate())

	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)

	owner, _, err := srv.RegisterClient(ctx, "Owner", ClientTypeConfidential, "", []string{"https://example.com/cb"}, []string{"openid"}, "192.168.1.1", 10)
	require.NoError(t, err)

	const accessToken = "opaque-owner-token" //nolint:gosec
	issuedAt := time.Now().Truncate(time.Second)
	expiresAt := issuedAt.Add(time.Hour)

	require.NoError(t, store.SaveToken(ctx, accessToken, &oauth2.Token{AccessToken: accessToken}))
	require.NoError(t, store.SaveTokenMetadata(ctx, accessToken, storage.TokenMetadata{
		UserID:    "user-1",
		ClientID:  owner.ClientID,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		TokenType: "access",
		Audience:  cfg.GetResourceIdentifier(),
		Scopes:    []string{"openid", "email"},
	}))

	response := srv.IntrospectToken(ctx, accessToken, owner.ClientID)

	require.Equal(t, true, response["active"])
	require.Equal(t, "Bearer", response["token_type"])
	require.Equal(t, owner.ClientID, response["client_id"])

	expVal, hasExp := response["exp"].(int64)
	require.True(t, hasExp, "exp must be present in opaque introspection response (got %T)", response["exp"])
	require.Equal(t, expiresAt.Unix(), expVal)

	iatVal, hasIat := response["iat"].(int64)
	require.True(t, hasIat, "iat must be present in opaque introspection response (got %T)", response["iat"])
	require.Equal(t, issuedAt.Unix(), iatVal)
}

func TestServer_IntrospectToken_OpaquePath_ZeroExpiresAt_OmitsExp(t *testing.T) {
	ctx := t.Context()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:            "https://auth.example.com",
		AccessTokenFormat: AccessTokenFormatOpaque,
	}
	require.NoError(t, cfg.Validate())

	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)

	owner, _, err := srv.RegisterClient(ctx, "Owner", ClientTypeConfidential, "", []string{"https://example.com/cb"}, []string{"openid"}, "192.168.1.1", 10)
	require.NoError(t, err)

	const accessToken = "opaque-no-exp-token" //nolint:gosec
	require.NoError(t, store.SaveToken(ctx, accessToken, &oauth2.Token{AccessToken: accessToken}))
	require.NoError(t, store.SaveTokenMetadata(ctx, accessToken, storage.TokenMetadata{
		UserID:    "user-1",
		ClientID:  owner.ClientID,
		TokenType: "access",
		Audience:  cfg.GetResourceIdentifier(),
		Scopes:    []string{"openid"},
	}))

	response := srv.IntrospectToken(ctx, accessToken, owner.ClientID)

	require.Equal(t, true, response["active"])
	require.NotContains(t, response, "exp", "exp must be absent when ExpiresAt is zero")
}

func TestNew_RejectsUnregisteredIntrospectionResourceServer(t *testing.T) {
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:                       "https://auth.example.com",
		AccessTokenFormat:            AccessTokenFormatOpaque,
		IntrospectionResourceServers: []string{"not-registered"},
	}

	_, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "IntrospectionResourceServers[0] \"not-registered\" is not a registered client")
}

func TestServer_IntrospectToken_OpaquePath_ExtraClaimsForwarded(t *testing.T) {
	ctx := t.Context()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:            "https://auth.example.com",
		AccessTokenFormat: AccessTokenFormatOpaque,
	}
	require.NoError(t, cfg.Validate())

	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)

	owner, _, err := srv.RegisterClient(ctx, "Owner", ClientTypeConfidential, "", []string{"https://example.com/cb"}, []string{"openid"}, "192.168.1.1", 10)
	require.NoError(t, err)

	const accessToken = "opaque-extra-token" //nolint:gosec // G101 false positive — test fixture label
	require.NoError(t, store.SaveTokenMetadata(ctx, accessToken, storage.TokenMetadata{
		UserID:    "user-1",
		ClientID:  owner.ClientID,
		TokenType: "access",
		Audience:  cfg.GetResourceIdentifier(),
		Scopes:    []string{"openid"},
		ExtraClaims: map[string]any{
			"allowed_backends": []any{"backend-a", "backend-b"},
			"muster_sid":       "sess-abc123",
		},
	}))

	response := srv.IntrospectToken(ctx, accessToken, owner.ClientID)

	require.Equal(t, true, response["active"])
	require.Equal(t, "sess-abc123", response["muster_sid"])
	require.Equal(t, []any{"backend-a", "backend-b"}, response["allowed_backends"])
}

func TestServer_IntrospectToken_OpaquePath_NilExtraClaimsOK(t *testing.T) {
	ctx := t.Context()
	store := memory.New()
	t.Cleanup(func() { store.Stop() })

	cfg := &Config{
		Issuer:            "https://auth.example.com",
		AccessTokenFormat: AccessTokenFormatOpaque,
	}
	require.NoError(t, cfg.Validate())

	srv, err := New(mock.NewProvider(), store, store, store, cfg, nil)
	require.NoError(t, err)

	owner, _, err := srv.RegisterClient(ctx, "Owner", ClientTypeConfidential, "", []string{"https://example.com/cb"}, []string{"openid"}, "192.168.1.1", 10)
	require.NoError(t, err)

	const accessToken = "opaque-nil-extra-token" //nolint:gosec // G101 false positive — test fixture label
	require.NoError(t, store.SaveTokenMetadata(ctx, accessToken, storage.TokenMetadata{
		UserID:    "user-1",
		ClientID:  owner.ClientID,
		TokenType: "access",
		Audience:  cfg.GetResourceIdentifier(),
		Scopes:    []string{"openid"},
		// ExtraClaims intentionally nil
	}))

	response := srv.IntrospectToken(ctx, accessToken, owner.ClientID)
	require.Equal(t, true, response["active"])
}

func TestServer_IntrospectToken_JWTPath_AppClaimsForwarded(t *testing.T) {
	srv, _, ownerClientID, _, _ := newJWTIntrospectionServer(t)

	// Issue a JWT that includes application-defined claims.
	cfg := srv.Config
	issuer, err := newJWTIssuer(cfg)
	require.NoError(t, err)

	now := time.Now().UTC()
	token, err := issuer.Issue(t.Context(), AccessTokenClaims{
		Subject:   "user-app",
		ClientID:  ownerClientID,
		Audience:  cfg.GetResourceIdentifier(),
		Scopes:    []string{"openid"},
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
		Extra: map[string]any{
			"allowed_backends": []any{"backend-x"},
			"muster_sid":       "sess-xyz",
		},
	})
	require.NoError(t, err)

	response := srv.IntrospectToken(t.Context(), token, ownerClientID)
	require.Equal(t, true, response["active"])
	require.Equal(t, "sess-xyz", response["muster_sid"])
	require.Equal(t, []any{"backend-x"}, response["allowed_backends"])
}
