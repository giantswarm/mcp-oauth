package memory

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

type pendingConsent struct {
	browserID string
	data      []byte
	expiresAt time.Time
}

func (s *Store) cleanupExpiredConsents() int {
	count := 0
	for key, pending := range s.pendingConsents {
		if !pending.expiresAt.After(time.Now()) {
			delete(s.pendingConsents, key)
			count++
		}
	}
	return count
}

func (s *Store) ConsentCookieKey(_ context.Context, issuer string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key, err := s.encryptor.ConsentCookieKey(issuer); err != nil || len(key) != 0 {
		return key, err
	}
	if s.consentCookieKeys == nil {
		s.consentCookieKeys = make(map[string][]byte)
	}
	if key := s.consentCookieKeys[issuer]; key != nil {
		return bytes.Clone(key), nil
	}
	key, err := security.GenerateKey()
	if err != nil {
		return nil, err
	}
	s.consentCookieKeys[issuer] = bytes.Clone(key)
	return key, nil
}

func (s *Store) SavePendingConsent(_ context.Context, browserID, consentID string, data []byte, expiresAt time.Time) error {
	if browserID == "" || consentID == "" || len(data) > storage.MaxPendingConsentSize || !expiresAt.After(time.Now()) {
		return fmt.Errorf("invalid pending consent")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingConsents == nil {
		s.pendingConsents = make(map[string]pendingConsent)
	}
	count, size := 0, 0
	for key, pending := range s.pendingConsents {
		if !pending.expiresAt.After(time.Now()) {
			delete(s.pendingConsents, key)
			continue
		}
		if pending.browserID == browserID {
			count++
		}
		size += len(pending.data)
	}
	if count >= storage.MaxPendingConsentsPerBrowser || len(s.pendingConsents) >= 4096 || size+len(data) > 16*1024*1024 {
		return storage.ErrPendingConsentLimit
	}
	key := browserID + ":" + consentID
	if _, exists := s.pendingConsents[key]; exists {
		return storage.ErrPendingConsentLimit
	}
	s.pendingConsents[key] = pendingConsent{browserID: browserID, data: bytes.Clone(data), expiresAt: expiresAt}
	return nil
}

func (s *Store) ConsumePendingConsent(_ context.Context, browserID, consentID string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := browserID + ":" + consentID
	pending, exists := s.pendingConsents[key]
	delete(s.pendingConsents, key)
	if !exists || !pending.expiresAt.After(time.Now()) {
		return nil, storage.ErrPendingConsentNotFound
	}
	return bytes.Clone(pending.data), nil
}

func (s *Store) ConsumeAuthorizationState(_ context.Context, providerState string) (*storage.AuthorizationState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, exists := s.authStates[providerState]
	if !exists || state.ProviderState != providerState {
		return nil, storage.ErrAuthorizationStateNotFound
	}
	delete(s.authStates, state.ProviderState)
	if s.authStates[state.StateID] == state {
		delete(s.authStates, state.StateID)
	}
	if state.HasExpired() {
		return nil, storage.ErrTokenExpired
	}
	return state, nil
}
