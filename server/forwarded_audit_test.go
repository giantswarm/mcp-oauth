package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/giantswarm/mcp-oauth/security"
)

const forwardedAuditRequestID = "req-forwarded-audit"

func captureAudit(srv *Server) *bytes.Buffer {
	var buf bytes.Buffer
	srv.Auditor = security.NewAuditor(slog.New(slog.NewJSONHandler(&buf, nil)), true)
	return &buf
}

type auditLine struct {
	EventType string         `json:"event_type"`
	RequestID string         `json:"request_id"`
	Details   map[string]any `json:"details"`
}

func onlyAuditLine(t *testing.T, buf *bytes.Buffer, eventType string) auditLine {
	t.Helper()
	var found []auditLine
	for line := range bytes.SplitSeq(buf.Bytes(), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry struct {
			Audit auditLine `json:"audit"`
		}
		require.NoError(t, json.Unmarshal(line, &entry))
		if entry.Audit.EventType == eventType {
			found = append(found, entry.Audit)
		}
	}
	require.Len(t, found, 1, "audit lines of type %q in: %s", eventType, buf.String())
	return found[0]
}

func TestAcceptForwardedIDToken_AuditCarriesRequestAndSessionID(t *testing.T) {
	h := newForwardedTokenHarness(t)
	buf := captureAudit(h.srv)
	token := h.signToken(t, h.validClaims())

	acc, err := h.srv.AcceptForwardedIDToken(security.WithRequestID(t.Context(), forwardedAuditRequestID), token)
	require.NoError(t, err)

	line := onlyAuditLine(t, buf, security.EventForwardedIDTokenAccepted)
	require.Equal(t, forwardedAuditRequestID, line.RequestID)
	require.Equal(t, acc.SessionID, line.Details["session_id"])
}

func TestValidateForwardedIDToken_AuditCarriesRequestAndSessionID(t *testing.T) {
	h := newForwardedTokenHarness(t)
	buf := captureAudit(h.srv)
	token := h.signToken(t, h.validClaims())

	userInfo, err := h.srv.validateForwardedIDToken(security.WithRequestID(t.Context(), forwardedAuditRequestID), token)
	require.NoError(t, err)
	require.NotNil(t, userInfo)

	line := onlyAuditLine(t, buf, security.EventForwardedIDTokenAccepted)
	require.Equal(t, forwardedAuditRequestID, line.RequestID)
	require.Equal(t, h.srv.SessionIDForBearer(token), line.Details["session_id"])
}

func TestAcceptTrustedIssuerToken_AuditCarriesRequestAndSessionID(t *testing.T) {
	srv, sign, resourceID := newSATrustedIssuerServer(t)
	buf := captureAudit(srv)
	token := sign(saTokenClaims("https://kubernetes.default.svc.cluster.local", "system:serviceaccount:ai-platform:my-svc", resourceID))

	acc, err := srv.AcceptTrustedIssuerToken(security.WithRequestID(t.Context(), forwardedAuditRequestID), token)
	require.NoError(t, err)

	line := onlyAuditLine(t, buf, security.EventForwardedIDTokenAccepted)
	require.Equal(t, forwardedAuditRequestID, line.RequestID)
	require.Equal(t, acc.SessionID, line.Details["session_id"])
}

func TestValidateToken_TrustedIssuer_AuditCarriesRequestAndSessionID(t *testing.T) {
	key := newTestECKey(t)
	const kid = "ti-kid"
	jwksURL, jwksClient := serveStaticJWKS(t, key, kid)

	srv, _, _ := setupFlowTestServer(t)
	v, err := newOIDCValidatorWithClient([]TrustedIssuer{{
		Issuer:           testIssuer,
		JwksURL:          jwksURL,
		AllowedAudiences: []string{srv.Config.GetResourceIdentifier()},
	}}, jwksClient)
	require.NoError(t, err)
	srv.trustedIssuerValidator = v
	buf := captureAudit(srv)

	token := signSubjectTokenWithType(t, key, kid, rfc9068TokenType, josejwt.Claims{
		Issuer:   testIssuer,
		Subject:  testSubject,
		Audience: josejwt.Audience{srv.Config.GetResourceIdentifier()},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(time.Now()),
	})

	_, err = srv.ValidateToken(security.WithRequestID(t.Context(), forwardedAuditRequestID), token)
	require.NoError(t, err)

	line := onlyAuditLine(t, buf, security.EventForwardedIDTokenAccepted)
	require.Equal(t, forwardedAuditRequestID, line.RequestID)
	require.Equal(t, srv.SessionIDForBearer(token), line.Details["session_id"])
}
