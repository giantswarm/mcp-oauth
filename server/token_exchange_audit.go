package server

import (
	"context"
	"maps"
)

type exchangeAuditContextKey struct{}

func withExchangeAuditContext(ctx context.Context, clientID, sessionID string) context.Context {
	return context.WithValue(ctx, exchangeAuditContextKey{}, map[string]any{
		paramClientID: clientID, logKeySessionID: sessionID,
		paramGrantType: GrantTypeTokenExchange, logKeySeverity: severityWarning,
	})
}

func exchangeFailureAuditDetails(ctx context.Context, details map[string]any) map[string]any {
	if extra, ok := ctx.Value(exchangeAuditContextKey{}).(map[string]any); ok {
		maps.Copy(details, extra)
	}
	return details
}
