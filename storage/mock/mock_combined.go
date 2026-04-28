package mock

import "github.com/giantswarm/mcp-oauth/storage"

// CombinedStore bundles the three per-interface mocks into a single type that
// satisfies [storage.Combined]. It lets tests construct a Server via
// [server.NewWithCombined] with one argument instead of three:
//
//	store := mock.NewCombined()
//	srv, _ := server.NewWithCombined(provider, store, cfg, logger)
//
// The individual mock fields remain accessible when a test wants to install
// custom behavior or inspect CallCounts — e.g. store.TokenStore.SaveTokenFunc
// or store.ClientStore.CallCounts. The embedded ResetCallCounts methods are
// ambiguous at the CombinedStore level by design (Go won't promote a method
// name shared by three embedded types); use the individual pointers or the
// [CombinedStore.ResetAllCallCounts] helper below.
type CombinedStore struct {
	*TokenStore
	*ClientStore
	*FlowStore
}

// NewCombined returns a CombinedStore with freshly constructed
// TokenStore/ClientStore/FlowStore mocks (each via their existing constructors).
func NewCombined() *CombinedStore {
	return &CombinedStore{
		TokenStore:  NewTokenStore(),
		ClientStore: NewClientStore(),
		FlowStore:   NewFlowStore(),
	}
}

// ResetAllCallCounts forwards to each embedded mock's ResetCallCounts. Exists
// because the bare ResetCallCounts method is ambiguous on *CombinedStore — all
// three embedded types expose one.
func (c *CombinedStore) ResetAllCallCounts() {
	c.TokenStore.ResetCallCounts()
	c.ClientStore.ResetCallCounts()
	c.FlowStore.ResetCallCounts()
}

// Compile-time assertion: CombinedStore satisfies the public union interface.
// If this breaks, the embedded mocks' method sets have drifted from the real
// storage interfaces — fix the mock rather than relax this assertion.
var _ storage.Combined = (*CombinedStore)(nil)
