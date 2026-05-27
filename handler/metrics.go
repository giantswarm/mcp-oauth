package handler

import (
	"context"
	_ "embed"
	"time"
)

// recordHTTPMetrics records an HTTP request metric.
func (h *Handler) recordHTTPMetrics(ctx context.Context, endpoint, method string, status int, startTime time.Time) {
	duration := time.Since(startTime).Seconds() * 1000
	h.server.Instrumentation().Metrics().RecordHTTPRequest(ctx, method, endpoint, status, duration)
}

// recordClientRegistered records when a client is registered.
func (h *Handler) recordClientRegistered(ctx context.Context, clientType string) {
	h.server.Instrumentation().Metrics().RecordClientRegistration(ctx, clientType)
}
