package valkey

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/giantswarm/mcp-oauth/security"
	"github.com/giantswarm/mcp-oauth/storage"
)

func (s *Store) ConsentCookieKey(ctx context.Context, issuer string) (result []byte, err error) {
	op := s.startTracedOp(ctx, "consent_cookie_key")
	defer op.end(&err)
	if key, deriveErr := s.encryptor.ConsentCookieKey(issuer); deriveErr != nil || len(key) != 0 {
		return key, deriveErr
	}
	key, err := security.GenerateKey()
	if err != nil {
		return nil, err
	}
	name := s.prefix + "consent_cookie_key:" + hashKeyComponent(issuer)
	if setErr := s.client.Do(op.ctx, s.client.B().Set().Key(name).Value(hex.EncodeToString(key)).Nx().Build()).Error(); setErr != nil && !isNilError(setErr) {
		return nil, fmt.Errorf("initialize consent cookie key: %w", setErr)
	}
	encoded, err := s.client.Do(op.ctx, s.client.B().Get().Key(name).Build()).ToString()
	if err != nil {
		return nil, fmt.Errorf("load consent cookie key: %w", err)
	}
	return hex.DecodeString(encoded)
}

const savePendingConsent = `
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[1])
if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) then return 0 end
if not redis.call('SET', KEYS[1], ARGV[3], 'PX', ARGV[4], 'NX') then return 0 end
redis.call('ZADD', KEYS[2], ARGV[2], KEYS[1])
redis.call('PEXPIRE', KEYS[2], ARGV[4])
return 1
`

func (s *Store) consentKeys(browserID, consentID string) (string, string) {
	base := s.prefix + "consent:{" + hashKeyComponent(browserID) + "}:"
	return base + hashKeyComponent(consentID), base + "pending"
}

func (s *Store) SavePendingConsent(ctx context.Context, browserID, consentID string, data []byte, expiresAt time.Time) (err error) {
	op := s.startTracedOp(ctx, "save_pending_consent")
	defer op.end(&err)
	if browserID == "" || consentID == "" || len(data) > storage.MaxPendingConsentSize || !expiresAt.After(time.Now()) {
		return fmt.Errorf("invalid pending consent")
	}
	payload, index := s.consentKeys(browserID, consentID)
	result, err := s.client.Do(op.ctx, s.client.B().Eval().Script(savePendingConsent).Numkeys(2).Key(payload, index).Arg(
		strconv.FormatInt(time.Now().UnixMilli(), 10), strconv.FormatInt(expiresAt.UnixMilli(), 10), string(data), strconv.FormatInt(time.Until(expiresAt).Milliseconds(), 10), strconv.Itoa(storage.MaxPendingConsentsPerBrowser),
	).Build()).ToInt64()
	if err != nil {
		return fmt.Errorf("save pending consent: %w", err)
	}
	if result != 1 {
		return storage.ErrPendingConsentLimit
	}
	return nil
}

const consumePendingConsent = `
local value = redis.call('GET', KEYS[1])
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], KEYS[1])
return value
`

func (s *Store) ConsumePendingConsent(ctx context.Context, browserID, consentID string) (data []byte, err error) {
	op := s.startTracedOp(ctx, "consume_pending_consent")
	defer op.end(&err)
	payload, index := s.consentKeys(browserID, consentID)
	data, err = s.client.Do(op.ctx, s.client.B().Eval().Script(consumePendingConsent).Numkeys(2).Key(payload, index).Build()).AsBytes()
	if isNilError(err) {
		return nil, storage.ErrPendingConsentNotFound
	}
	return data, err
}

func (s *Store) ConsumeAuthorizationState(ctx context.Context, providerState string) (result *storage.AuthorizationState, err error) {
	op := s.startTracedOp(ctx, "consume_authorization_state")
	defer op.end(&err)
	stateID, err := s.client.Do(op.ctx, s.client.B().Eval().Script(`
local value = redis.call('GET', KEYS[1])
redis.call('DEL', KEYS[1])
return value
`).Numkeys(1).Key(s.providerStateKey(providerState)).Build()).ToString()
	if isNilError(err) {
		return nil, storage.ErrAuthorizationStateNotFound
	}
	if err != nil {
		return nil, err
	}
	state, err := s.GetAuthorizationState(op.ctx, stateID)
	if err != nil {
		return nil, err
	}
	if state.ProviderState != providerState {
		return nil, storage.ErrAuthorizationStateNotFound
	}
	_, err = s.client.Do(op.ctx, s.client.B().Eval().Script(`
local value = redis.call('GET', KEYS[1])
if value and cjson.decode(value).provider_state == ARGV[1] then redis.call('DEL', KEYS[1]) end
return 1
`).Numkeys(1).Key(s.stateKey(stateID)).Arg(providerState).Build()).ToInt64()
	return state, err
}
