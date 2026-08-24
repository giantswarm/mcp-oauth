package dex

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/giantswarm/mcp-oauth/providers/oidc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const k8sAudienceScope = AudienceScopePrefix + "dex-k8s-authenticator"

// authURLScopes returns the scope values the authorization URL carries.
func authURLScopes(t *testing.T, authURL string) []string {
	t.Helper()

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	return strings.Fields(parsed.Query().Get("scope"))
}

// TestAudienceResolverCoversLateAudiences covers an audience that the caller
// learns about after the provider is built. It must reach the next
// authorization request, through DefaultScopes and through AuthorizationURL.
func TestAudienceResolverCoversLateAudiences(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	var mu sync.Mutex
	audiences := []string{}
	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.AudienceResolver = func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), audiences...)
		}
	}))
	require.NoError(t, err)

	assert.NotContains(t, provider.DefaultScopes(), k8sAudienceScope)
	assert.NotContains(t, authURLScopes(t, provider.AuthorizationURL("state", "", "", nil, nil)), k8sAudienceScope)

	mu.Lock()
	audiences = append(audiences, "dex-k8s-authenticator")
	mu.Unlock()

	assert.Contains(t, provider.DefaultScopes(), k8sAudienceScope)

	t.Run("the audience reaches an explicit scope request too", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"openid", "email"}, nil))

		assert.Contains(t, scopes, k8sAudienceScope)
		assert.Contains(t, scopes, "openid")
		assert.Contains(t, scopes, "email")
	})

	t.Run("the audience reaches a request without scopes", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", nil, nil))

		assert.Contains(t, scopes, k8sAudienceScope)
		assert.Contains(t, scopes, "groups")
		assert.Contains(t, scopes, "offline_access")
	})
}

func TestAudienceResolverScopeMerging(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	newProvider := func(t *testing.T, resolver func() []string, options ...func(*Config)) *Provider {
		t.Helper()

		all := append([]func(*Config){func(cfg *Config) { cfg.AudienceResolver = resolver }}, options...)
		provider, err := NewProvider(testConfig(server, all...))
		require.NoError(t, err)

		return provider
	}

	t.Run("a nil resolver keeps the configured scopes", func(t *testing.T) {
		provider := newProvider(t, nil)

		assert.Equal(t, defaultDexScopes, provider.DefaultScopes())
	})

	t.Run("an empty audience set keeps the configured scopes", func(t *testing.T) {
		provider := newProvider(t, func() []string { return nil })

		assert.Equal(t, defaultDexScopes, provider.DefaultScopes())
	})

	t.Run("every audience contributes one scope", func(t *testing.T) {
		provider := newProvider(t, func() []string { return []string{"first-client", "second-client"} })

		scopes := provider.DefaultScopes()

		assert.Equal(t, append(append([]string(nil), defaultDexScopes...),
			AudienceScopePrefix+"first-client",
			AudienceScopePrefix+"second-client",
		), scopes)
	})

	t.Run("an audience already in Scopes is not duplicated", func(t *testing.T) {
		provider := newProvider(t,
			func() []string { return []string{"dex-k8s-authenticator"} },
			func(cfg *Config) { cfg.Scopes = []string{"openid", k8sAudienceScope} },
		)

		assert.Equal(t, []string{"openid", k8sAudienceScope}, provider.DefaultScopes())
	})

	t.Run("the result is a fresh slice on every call", func(t *testing.T) {
		provider := newProvider(t, func() []string { return []string{"dex-k8s-authenticator"} })

		first := provider.DefaultScopes()
		first[0] = "mutated"

		assert.Equal(t, "openid", provider.DefaultScopes()[0])
		assert.Equal(t, "openid", provider.Scopes[0])
	})
}

// TestAudienceResolverSkipsInvalidAudiences pins the failure mode: one
// malformed audience costs only its own scope, and every valid audience in the
// same set still reaches the request.
func TestAudienceResolverSkipsInvalidAudiences(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.Scopes = []string{"openid"}
		cfg.AudienceResolver = func() []string {
			return []string{"has space", "", "dex-k8s-authenticator", "no/slashes"}
		}
	}))
	require.NoError(t, err)

	assert.Equal(t, []string{"openid", k8sAudienceScope}, provider.DefaultScopes())
}

// numberedAudiences returns count distinct valid audience client IDs.
func numberedAudiences(count int) []string {
	audiences := make([]string, 0, count)
	for i := range count {
		audiences = append(audiences, fmt.Sprintf("client-%d", i))
	}

	return audiences
}

func TestPartitionAudienceScopes(t *testing.T) {
	t.Run("no audiences", func(t *testing.T) {
		scopes, rejected := partitionAudienceScopes(nil, MaxAudienceCount, nil)

		assert.Empty(t, scopes)
		assert.Empty(t, rejected)
	})

	t.Run("an empty entry is skipped without a rejection", func(t *testing.T) {
		scopes, rejected := partitionAudienceScopes([]string{"", "valid-client"}, MaxAudienceCount, nil)

		assert.Equal(t, []string{AudienceScopePrefix + "valid-client"}, scopes)
		assert.Empty(t, rejected)
	})

	t.Run("an invalid entry is reported with its reason", func(t *testing.T) {
		scopes, rejected := partitionAudienceScopes([]string{"valid-client", "has space"}, MaxAudienceCount, nil)

		assert.Equal(t, []string{AudienceScopePrefix + "valid-client"}, scopes)
		require.Len(t, rejected, 1)
		assert.Equal(t, "has space", rejected[0].Audience)
		assert.Contains(t, rejected[0].Reason, "invalid characters")
	})

	t.Run("an over-long entry is reported, not truncated into a scope", func(t *testing.T) {
		long := strings.Repeat("a", MaxAudienceLength+1)

		scopes, rejected := partitionAudienceScopes([]string{long}, MaxAudienceCount, nil)

		assert.Empty(t, scopes)
		require.Len(t, rejected, 1)
		assert.Contains(t, rejected[0].Reason, "maximum length")
	})

	t.Run("audiences past the limit are reported", func(t *testing.T) {
		scopes, rejected := partitionAudienceScopes(numberedAudiences(MaxAudienceCount+2), MaxAudienceCount, nil)

		assert.Len(t, scopes, MaxAudienceCount)
		require.Len(t, rejected, 2)
		assert.Contains(t, rejected[0].Reason, "no room left")
	})

	t.Run("a limit of zero rejects every audience", func(t *testing.T) {
		scopes, rejected := partitionAudienceScopes([]string{"first-client", "second-client"}, 0, nil)

		assert.Empty(t, scopes)
		assert.Len(t, rejected, 2)
	})

	// A duplicate must not consume a slot the limit would otherwise give to a
	// distinct audience.
	t.Run("a duplicate does not consume the limit", func(t *testing.T) {
		audiences := make([]string, 0, MaxAudienceCount+1)
		for range MaxAudienceCount {
			audiences = append(audiences, "same-client")
		}
		audiences = append(audiences, "real-client")

		scopes, rejected := partitionAudienceScopes(audiences, MaxAudienceCount, nil)

		assert.Equal(t, []string{
			AudienceScopePrefix + "same-client",
			AudienceScopePrefix + "real-client",
		}, scopes)
		assert.Empty(t, rejected)
	})

	t.Run("an audience already present does not consume the limit", func(t *testing.T) {
		present := map[string]struct{}{AudienceScopePrefix + "first-client": {}}

		scopes, rejected := partitionAudienceScopes([]string{"first-client", "second-client"}, 1, present)

		assert.Equal(t, []string{AudienceScopePrefix + "second-client"}, scopes)
		assert.Empty(t, rejected)
	})

	t.Run("a repeated invalid audience is reported once", func(t *testing.T) {
		scopes, rejected := partitionAudienceScopes([]string{"has space", "has space"}, MaxAudienceCount, nil)

		assert.Empty(t, scopes)
		assert.Len(t, rejected, 1)
	})
}

// TestEffectiveScopesStaysWithinTheScopeBound pins the merged bound. NewProvider
// rejects a configured set larger than oidc.MaxScopeCount, so the resolver path
// must not push an authorization request past it either.
func TestEffectiveScopesStaysWithinTheScopeBound(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	configured := []string{"openid", "email"}
	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.Scopes = configured
		cfg.AudienceResolver = func() []string { return numberedAudiences(oidc.MaxScopeCount) }
	}))
	require.NoError(t, err)

	scopes := provider.DefaultScopes()

	assert.Len(t, scopes, oidc.MaxScopeCount)
	assert.Equal(t, configured, scopes[:len(configured)])
	assert.NoError(t, oidc.ValidateScopes(scopes))
	assert.NoError(t, oidc.ValidateScopes(authURLScopes(t, provider.AuthorizationURL("state", "", "", nil, nil))))
}

func TestTruncateAudienceForLog(t *testing.T) {
	assert.Equal(t, "short", truncateAudienceForLog("short"))

	long := strings.Repeat("a", maxLoggedAudienceLength+10)
	truncated := truncateAudienceForLog(long)

	assert.True(t, strings.HasSuffix(truncated, "...(truncated)"))
	assert.Len(t, truncated, maxLoggedAudienceLength+len("...(truncated)"))
}

// TestWarnRejectedAudiencesLogsOncePerAudience pins the log-once behaviour. The
// resolver runs on every authorization request, so a repeated log line would
// let one malformed value flood the log.
func TestWarnRejectedAudiencesLogsOncePerAudience(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	handler := &countingHandler{}
	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.Logger = slog.New(handler)
		cfg.AudienceResolver = func() []string { return []string{"has space"} }
	}))
	require.NoError(t, err)

	for range 5 {
		provider.DefaultScopes()
	}

	assert.Equal(t, 1, handler.count(slog.LevelWarn))
}

func TestWarnRejectedAudiencesStopsAtTheMemoCap(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	handler := &countingHandler{}
	audiences := make([]string, 0, maxWarnedAudiences+10)
	for i := range maxWarnedAudiences + 10 {
		audiences = append(audiences, strings.Repeat("a", i+1)+" invalid")
	}

	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.Logger = slog.New(handler)
		cfg.AudienceResolver = func() []string { return audiences }
	}))
	require.NoError(t, err)

	provider.DefaultScopes()
	provider.DefaultScopes()

	assert.Equal(t, maxWarnedAudiences, handler.count(slog.LevelWarn))
}

// countingHandler counts the records a logger emits, per level.
type countingHandler struct {
	mu     sync.Mutex
	counts map[slog.Level]int
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, record slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.counts == nil {
		h.counts = map[slog.Level]int{}
	}
	h.counts[record.Level]++

	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *countingHandler) WithGroup(string) slog.Handler { return h }

func (h *countingHandler) count(level slog.Level) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.counts[level]
}
