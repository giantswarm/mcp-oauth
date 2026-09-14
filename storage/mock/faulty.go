package mock

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/giantswarm/mcp-oauth/storage"
	"github.com/giantswarm/mcp-oauth/storage/memory"
)

// Fault is a failure injected ahead of a gated FaultyStore operation. It runs
// under the operation's context, which carries the store's per-operation
// deadline, and a non-nil result is returned in place of the operation's own.
type Fault func(ctx context.Context, operation string) error

// Hang is a Fault that behaves like a backend that accepts the connection but
// never answers: it blocks until the operation's deadline passes and returns
// ctx.Err().
func Hang(ctx context.Context, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

// ConnectionRefused is a Fault that fails at once, the way a dial to an
// endpoint with nothing listening does.
func ConnectionRefused(context.Context, string) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
}

// OnOperation narrows fault to a single operation (a FaultyStore operation
// name); every other operation proceeds normally.
func OnOperation(operation string, fault Fault) Fault {
	return func(ctx context.Context, op string) error {
		if op != operation {
			return nil
		}
		return fault(ctx, op)
	}
}

// FaultyStore wraps a *memory.Store and injects failures into the operations
// that gate the token endpoint and bearer validation, so tests can drive a
// storage outage against a server that otherwise runs the real unified
// layout, refresh-token families and JWT revocation list. The wrapper embeds the memory store, so every
// optional storage interface the memory store implements is still detected
// on the wrapper by type assertion.
//
// Each gated operation runs the installed Fault under a context bounded by
// OperationTimeout, mirroring the per-operation deadline a network-backed
// store applies (see storage.DefaultOperationTimeout). Operation names follow
// the Valkey store's tracing names, e.g. "get_refresh_token_info".
type FaultyStore struct {
	*memory.Store

	// OperationTimeout bounds the context a Fault runs under.
	OperationTimeout time.Duration

	mu    sync.Mutex
	fault Fault
	calls map[string]int
}

// NewFaultyStore wraps inner. operationTimeout bounds every injected fault.
func NewFaultyStore(inner *memory.Store, operationTimeout time.Duration) *FaultyStore {
	return &FaultyStore{Store: inner, OperationTimeout: operationTimeout, calls: make(map[string]int)}
}

// Fail installs fault for every gated operation until Heal or another Fail.
func (f *FaultyStore) Fail(fault Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault = fault
}

// Heal removes the installed fault; operations proceed normally again.
func (f *FaultyStore) Heal() { f.Fail(nil) }

// Calls reports how often a gated operation was attempted (faulted or not).
func (f *FaultyStore) Calls(operation string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[operation]
}

// gate runs the installed fault for operation under the operation deadline.
func (f *FaultyStore) gate(ctx context.Context, operation string) error {
	f.mu.Lock()
	f.calls[operation]++
	fault := f.fault
	f.mu.Unlock()
	if fault == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, f.OperationTimeout)
	defer cancel()
	return fault(ctx, operation)
}

// GetToken gates storage.TokenStore.GetToken, the legacy layout's read of the
// provider token backing an issued access token.
func (f *FaultyStore) GetToken(ctx context.Context, accessToken string) (*oauth2.Token, error) {
	if err := f.gate(ctx, "get_token"); err != nil {
		return nil, err
	}
	return f.Store.GetToken(ctx, accessToken)
}

// GetProviderTokenRef gates storage.UserProviderTokenStore.GetProviderTokenRef,
// the unified layout's resolution of an issued token to its user.
func (f *FaultyStore) GetProviderTokenRef(ctx context.Context, tokenID string) (string, error) {
	if err := f.gate(ctx, "get_provider_token_ref"); err != nil {
		return "", err
	}
	return f.Store.GetProviderTokenRef(ctx, tokenID)
}

// GetRefreshTokenInfo gates storage.TokenStore.GetRefreshTokenInfo.
func (f *FaultyStore) GetRefreshTokenInfo(ctx context.Context, refreshToken string) (string, error) {
	if err := f.gate(ctx, "get_refresh_token_info"); err != nil {
		return "", err
	}
	return f.Store.GetRefreshTokenInfo(ctx, refreshToken)
}

// AtomicGetAndDeleteRefreshToken gates storage.TokenStore.AtomicGetAndDeleteRefreshToken.
func (f *FaultyStore) AtomicGetAndDeleteRefreshToken(ctx context.Context, refreshToken string) (string, string, *oauth2.Token, error) {
	if err := f.gate(ctx, "atomic_get_and_delete_refresh_token"); err != nil {
		return "", "", nil, err
	}
	return f.Store.AtomicGetAndDeleteRefreshToken(ctx, refreshToken)
}

// AtomicConsumeRefreshToken gates storage.UserProviderTokenStore.AtomicConsumeRefreshToken.
func (f *FaultyStore) AtomicConsumeRefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	if err := f.gate(ctx, "atomic_consume_refresh_token"); err != nil {
		return "", "", err
	}
	return f.Store.AtomicConsumeRefreshToken(ctx, refreshToken)
}

// GetUserProviderToken gates storage.UserProviderTokenStore.GetUserProviderToken.
func (f *FaultyStore) GetUserProviderToken(ctx context.Context, userID string) (*oauth2.Token, error) {
	if err := f.gate(ctx, "get_user_provider_token"); err != nil {
		return nil, err
	}
	return f.Store.GetUserProviderToken(ctx, userID)
}

// AcquireProviderRefreshLock gates storage.ProviderRefreshLockStore.AcquireProviderRefreshLock.
func (f *FaultyStore) AcquireProviderRefreshLock(ctx context.Context, userID string, ttl time.Duration) (string, bool, error) {
	if err := f.gate(ctx, "acquire_provider_refresh_lock"); err != nil {
		return "", false, err
	}
	return f.Store.AcquireProviderRefreshLock(ctx, userID, ttl)
}

// GetTokenMetadata gates storage.TokenMetadataGetter.GetTokenMetadata. The
// interface carries no context, so the fault runs under the operation
// deadline alone, as the Valkey store's read does.
func (f *FaultyStore) GetTokenMetadata(tokenID string) (*storage.TokenMetadata, error) {
	if err := f.gate(context.Background(), "get_token_metadata"); err != nil {
		return nil, err
	}
	return f.Store.GetTokenMetadata(tokenID)
}

// AtomicCheckAndMarkAuthCodeUsed gates storage.FlowStore.AtomicCheckAndMarkAuthCodeUsed.
func (f *FaultyStore) AtomicCheckAndMarkAuthCodeUsed(ctx context.Context, code string) (*storage.AuthorizationCode, error) {
	if err := f.gate(ctx, "atomic_check_and_mark_auth_code_used"); err != nil {
		return nil, err
	}
	return f.Store.AtomicCheckAndMarkAuthCodeUsed(ctx, code)
}

// GetClient gates storage.ClientStore.GetClient.
func (f *FaultyStore) GetClient(ctx context.Context, clientID string) (*storage.Client, error) {
	if err := f.gate(ctx, "get_client"); err != nil {
		return nil, err
	}
	return f.Store.GetClient(ctx, clientID)
}

// ValidateClientSecret gates storage.ClientStore.ValidateClientSecret.
func (f *FaultyStore) ValidateClientSecret(ctx context.Context, clientID, clientSecret string) error {
	if err := f.gate(ctx, "validate_client_secret"); err != nil {
		return err
	}
	return f.Store.ValidateClientSecret(ctx, clientID, clientSecret)
}

// IsJTIRevoked gates storage.RevokedTokenStore.IsJTIRevoked.
func (f *FaultyStore) IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	if err := f.gate(ctx, "is_jti_revoked"); err != nil {
		return false, err
	}
	return f.Store.IsJTIRevoked(ctx, jti)
}

// GetRefreshTokenFamilyByID gates storage.RefreshTokenFamilyByIDStore.GetRefreshTokenFamilyByID.
func (f *FaultyStore) GetRefreshTokenFamilyByID(ctx context.Context, familyID string) (*storage.RefreshTokenFamilyMetadata, error) {
	if err := f.gate(ctx, "get_refresh_token_family_by_id"); err != nil {
		return nil, err
	}
	return f.Store.GetRefreshTokenFamilyByID(ctx, familyID)
}

// Compile-time checks: the wrapper keeps every interface the server detects
// on the memory store. If one breaks, the memory store's method set drifted
// and the wrapper must follow.
var (
	_ storage.Combined                        = (*FaultyStore)(nil)
	_ storage.RefreshTokenFamilyStore         = (*FaultyStore)(nil)
	_ storage.RefreshTokenFamilyByIDStore     = (*FaultyStore)(nil)
	_ storage.UserProviderTokenStore          = (*FaultyStore)(nil)
	_ storage.ProviderRefreshLockStore        = (*FaultyStore)(nil)
	_ storage.TokenMetadataStore              = (*FaultyStore)(nil)
	_ storage.TokenMetadataGetter             = (*FaultyStore)(nil)
	_ storage.RevokedTokenStore               = (*FaultyStore)(nil)
	_ storage.TokenRevocationStore            = (*FaultyStore)(nil)
	_ storage.ActiveRefreshTokenByFamilyStore = (*FaultyStore)(nil)
)
