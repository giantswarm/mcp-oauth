package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/giantswarm/mcp-oauth/security"
)

// ErrStorageUnavailable marks a request that failed because the token store did
// not answer: the backend was unreachable, refused the connection, or did not
// reply within its per-operation deadline (see storage.DefaultOperationTimeout).
// The presented grant was neither validated nor rejected and nothing was
// consumed, rotated or revoked, so the client must retry the same request.
// HTTP handlers answer it as 503 temporarily_unavailable with a Retry-After
// header — never as invalid_grant, which clients read as "the token is dead"
// and answer by discarding the token and forcing a new sign-in.
//
// Match it with errors.Is; it wraps the underlying storage error.
var ErrStorageUnavailable = errors.New("storage temporarily unavailable")

// storageUnavailable classifies a transient storage failure met on a request
// path: it logs the failure, audits it under the reason
// transient_storage_error and returns err wrapped in ErrStorageUnavailable.
// operation names the store call that failed; userID may be empty when the
// grant's subject is not yet known. No credential material is logged: the
// operation and the store's error are what an operator needs.
func (s *Server) storageUnavailable(ctx context.Context, operation, clientID, userID string, err error) error {
	attrs := []any{"operation", operation, logKeyError, err.Error(), paramClientID, clientID}
	if userID != "" {
		attrs = append(attrs, "user_id", userID)
	}
	s.Logger.Warn("Storage temporarily unavailable", attrs...)

	s.Auditor.LogEvent(ctx, security.Event{
		Type: security.EventAuthFailure, UserID: userID, ClientID: clientID,
		Details: map[string]any{logKeyReason: "transient_storage_error", "operation": operation},
	})
	return fmt.Errorf("%w: %s: %w", ErrStorageUnavailable, operation, err)
}
