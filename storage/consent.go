package storage

import (
	"context"
	"errors"
	"time"
)

const (
	MaxPendingConsentsPerBrowser = 8
	MaxPendingConsentSize        = 1024 * 1024
)

var (
	ErrPendingConsentNotFound = errors.New("pending consent not found")
	ErrPendingConsentLimit    = errors.New("too many pending consents")
)

// ConsentStore keeps browser requests separate from upstream authorization
// state and consumes each request once across replicas.
type ConsentStore interface {
	ConsentCookieKey(ctx context.Context, issuer string) ([]byte, error)
	SavePendingConsent(ctx context.Context, browserID, consentID string, data []byte, expiresAt time.Time) error
	ConsumePendingConsent(ctx context.Context, browserID, consentID string) ([]byte, error)
}

// AuthorizationStateConsumer arbitrates concurrent callbacks before either
// callback exchanges an upstream code.
type AuthorizationStateConsumer interface {
	ConsumeAuthorizationState(ctx context.Context, providerState string) (*AuthorizationState, error)
}
