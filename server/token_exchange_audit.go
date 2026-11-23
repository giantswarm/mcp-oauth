package server

import (
	"context"

	"github.com/giantswarm/mcp-oauth/security"
)

type exchangeAuditContextKey struct{}

type exchangeAuditContext struct {
	clientID  string
	sessionID string
}

// withExchangeAuditContext records the requesting client and session so that
// every failure audit emitted while serving the exchange, including those from
// shared storage, provider and revocation helpers, correlates with it.
func withExchangeAuditContext(ctx context.Context, clientID, sessionID string) context.Context {
	return context.WithValue(ctx, exchangeAuditContextKey{}, exchangeAuditContext{clientID: clientID, sessionID: sessionID})
}

func exchangeFailureAuditDetails(ctx context.Context, details map[string]any) map[string]any {
	exchange, ok := ctx.Value(exchangeAuditContextKey{}).(exchangeAuditContext)
	if !ok {
		return details
	}
	details[paramClientID] = exchange.clientID
	details[logKeySessionID] = exchange.sessionID
	details[paramGrantType] = GrantTypeTokenExchange
	details[logKeySeverity] = severityWarning
	return details
}

// auditLocalExchangeFailure audits a refused local issuance. ctx must carry the
// exchange audit context set by SelfIssuedExchange.
func (s *Server) auditLocalExchangeFailure(ctx context.Context, subject string, details map[string]any) {
	exchange, _ := ctx.Value(exchangeAuditContextKey{}).(exchangeAuditContext)
	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventAuthFailure, ClientID: exchange.clientID, UserID: subject,
		Details: exchangeFailureAuditDetails(ctx, details),
	})
}

func exchangeFailureReason(reason string) map[string]any {
	return map[string]any{logKeyReason: reason}
}
