package valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/giantswarm/mcp-oauth/storage"
)

// ============================================================
// FlowStore Implementation
// ============================================================

// SaveAuthorizationState saves the state of an ongoing authorization flow
// Stores by both client state (StateID) and provider state (ProviderState) for dual lookup
func (s *Store) SaveAuthorizationState(ctx context.Context, state *storage.AuthorizationState) error {
	if state == nil || state.StateID == "" {
		return fmt.Errorf("invalid authorization state")
	}
	if state.ProviderState == "" {
		return fmt.Errorf("provider state is required")
	}

	data, err := json.Marshal(toAuthorizationStateJSON(state))
	if err != nil {
		return fmt.Errorf("failed to marshal authorization state: %w", err)
	}

	// Calculate TTL
	ttl := calculateTTL(state.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("authorization state already expired")
	}

	// Store the state data by StateID
	stateKey := s.stateKey(state.StateID)
	if err := s.client.Do(ctx,
		s.client.B().Set().Key(stateKey).Value(string(data)).Ex(ttl).Build(),
	).Error(); err != nil {
		return fmt.Errorf("failed to save authorization state: %w", err)
	}

	// Store a reverse lookup by provider state -> state ID
	providerKey := s.providerStateKey(state.ProviderState)
	if err := s.client.Do(ctx,
		s.client.B().Set().Key(providerKey).Value(state.StateID).Ex(ttl).Build(),
	).Error(); err != nil {
		return fmt.Errorf("failed to save provider state lookup: %w", err)
	}

	s.logger.Debug("Saved authorization state",
		"state_id", state.StateID,
		"provider_state_prefix", safeTruncate(state.ProviderState, tokenIDLogLength))
	return nil
}

// GetAuthorizationState retrieves an authorization state by client state
func (s *Store) GetAuthorizationState(ctx context.Context, stateID string) (*storage.AuthorizationState, error) {
	key := s.stateKey(stateID)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, fmt.Errorf("%w: %s", storage.ErrAuthorizationStateNotFound, stateID)
		}
		return nil, fmt.Errorf("failed to get authorization state: %w", err)
	}

	var j authorizationStateJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authorization state: %w", err)
	}

	state := fromAuthorizationStateJSON(&j)

	// Check if expired (TTL should handle this, but double-check for safety)
	if time.Now().After(state.ExpiresAt) {
		return nil, fmt.Errorf("%w: authorization state expired", storage.ErrTokenExpired)
	}

	return state, nil
}

// GetAuthorizationStateByProviderState retrieves an authorization state by provider state
// This is used during provider callback validation (separate from client state)
func (s *Store) GetAuthorizationStateByProviderState(ctx context.Context, providerState string) (*storage.AuthorizationState, error) {
	// First, look up the state ID from the provider state
	providerKey := s.providerStateKey(providerState)

	stateID, err := s.client.Do(ctx, s.client.B().Get().Key(providerKey).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, fmt.Errorf("%w: provider state", storage.ErrAuthorizationStateNotFound)
		}
		return nil, fmt.Errorf("failed to get provider state lookup: %w", err)
	}

	// Now get the actual state data
	return s.GetAuthorizationState(ctx, stateID)
}

// DeleteAuthorizationState removes an authorization state
// Removes both client state and provider state entries
func (s *Store) DeleteAuthorizationState(ctx context.Context, stateID string) error {
	// Get the state first to find the provider state key
	key := s.stateKey(stateID)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err == nil {
		// Parse to get provider state for cleanup
		var j authorizationStateJSON
		if err := json.Unmarshal([]byte(data), &j); err == nil {
			// Delete the provider state lookup
			providerKey := s.providerStateKey(j.ProviderState)
			if err := s.client.Do(ctx, s.client.B().Del().Key(providerKey).Build()).Error(); err != nil {
				s.logger.Warn("Failed to delete provider state lookup",
					"state_id", stateID,
					"error", err)
			}
		}
	}

	// Delete the main state entry
	if err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("failed to delete authorization state: %w", err)
	}

	s.logger.Debug("Deleted authorization state", "state_id", stateID)
	return nil
}

// SaveAuthorizationCode saves an issued authorization code
func (s *Store) SaveAuthorizationCode(ctx context.Context, code *storage.AuthorizationCode) error {
	if code == nil || code.Code == "" {
		return fmt.Errorf("invalid authorization code")
	}

	data, err := json.Marshal(toAuthorizationCodeJSON(code))
	if err != nil {
		return fmt.Errorf("failed to marshal authorization code: %w", err)
	}

	// Calculate TTL
	ttl := calculateTTL(code.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("authorization code already expired")
	}

	key := s.codeKey(code.Code)

	if err := s.client.Do(ctx,
		s.client.B().Set().Key(key).Value(string(data)).Ex(ttl).Build(),
	).Error(); err != nil {
		return fmt.Errorf("failed to save authorization code: %w", err)
	}

	s.logger.Debug("Saved authorization code",
		"code_prefix", safeTruncate(code.Code, tokenIDLogLength))
	return nil
}

// GetAuthorizationCode retrieves an authorization code without modifying it.
// NOTE: For actual code exchange, use AtomicCheckAndMarkAuthCodeUsed instead
// to prevent race conditions.
func (s *Store) GetAuthorizationCode(ctx context.Context, code string) (*storage.AuthorizationCode, error) {
	key := s.codeKey(code)

	data, err := s.client.Do(ctx, s.client.B().Get().Key(key).Build()).ToString()
	if err != nil {
		if isNilError(err) {
			return nil, storage.ErrAuthorizationCodeNotFound
		}
		return nil, fmt.Errorf("failed to get authorization code: %w", err)
	}

	var j authorizationCodeJSON
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authorization code: %w", err)
	}

	authCode := fromAuthorizationCodeJSON(&j)

	// Check if expired (TTL should handle this, but double-check)
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("%w: authorization code expired", storage.ErrTokenExpired)
	}

	return authCode, nil
}

// AtomicCheckAndMarkAuthCodeUsed atomically checks if a code is unused and marks it as used.
// This prevents race conditions in authorization code reuse detection.
// Returns the auth code if successful, or an error if code is already used.
//
// SECURITY: This operation is atomic via Lua script - only ONE concurrent request can succeed.
//
// IMPORTANT: The authCode is ONLY returned on reuse errors (Used=true) to enable
// detection and revocation. For other errors (not found, expired), nil is returned
// to prevent information leakage.
func (s *Store) AtomicCheckAndMarkAuthCodeUsed(ctx context.Context, code string) (*storage.AuthorizationCode, error) {
	key := s.codeKey(code)

	// Execute Lua script for atomic operation
	result, err := s.client.Do(ctx,
		s.client.B().Eval().Script(luaAtomicCheckAndMarkCodeUsed).
			Numkeys(1).
			Key(key).
			Arg(fmt.Sprintf("%d", time.Now().Unix())).
			Build(),
	).ToString()
	if err != nil {
		return nil, fmt.Errorf("failed to execute atomic code check: %w", err)
	}

	switch {
	case result == "NOT_FOUND":
		return nil, storage.ErrAuthorizationCodeNotFound
	case result == "EXPIRED":
		return nil, fmt.Errorf("%w: authorization code expired", storage.ErrTokenExpired)
	case strings.HasPrefix(result, "ALREADY_USED:"):
		// Parse the code data to return for reuse detection
		codeData := strings.TrimPrefix(result, "ALREADY_USED:")
		var j authorizationCodeJSON
		if err := json.Unmarshal([]byte(codeData), &j); err != nil {
			return nil, fmt.Errorf("%w: failed to parse reused code", storage.ErrAuthorizationCodeUsed)
		}
		return fromAuthorizationCodeJSON(&j), storage.ErrAuthorizationCodeUsed
	}

	// Success - parse the code data (from before marking as used)
	var j authorizationCodeJSON
	if err := json.Unmarshal([]byte(result), &j); err != nil {
		return nil, fmt.Errorf("failed to parse authorization code: %w", err)
	}

	s.logger.Debug("Marked authorization code as used",
		"code_prefix", safeTruncate(code, tokenIDLogLength))

	return fromAuthorizationCodeJSON(&j), nil
}

// DeleteAuthorizationCode removes an authorization code
func (s *Store) DeleteAuthorizationCode(ctx context.Context, code string) error {
	key := s.codeKey(code)

	if err := s.client.Do(ctx, s.client.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("failed to delete authorization code: %w", err)
	}

	s.logger.Debug("Deleted authorization code")
	return nil
}
