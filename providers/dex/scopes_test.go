package dex

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScopeDefaultsAreUnchanged pins the behaviour a caller that sets none of
// the scope knobs gets, because every existing deployment is that caller.
func TestScopeDefaultsAreUnchanged(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	provider, err := NewProvider(testConfig(server))
	require.NoError(t, err)

	assert.Equal(t, []string{"openid", "profile", "email", "groups", "offline_access"}, provider.DefaultScopes())

	t.Run("an unsupported scope is dropped and a Dex-only scope survives", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"openid", "claudeai", "federated:id"}, nil))

		assert.NotContains(t, scopes, "claudeai")
		assert.Contains(t, scopes, "federated:id")
		assert.Contains(t, scopes, "groups")
	})

	t.Run("a cross-client audience scope survives", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"openid", k8sAudienceScope}, nil))

		assert.Contains(t, scopes, k8sAudienceScope)
	})
}

func TestAllowedScopes(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	// A Keycloak realm: no groups scope, but roles and organization exist.
	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.Scopes = []string{"openid", "profile", "email", "offline_access", "roles"}
		cfg.AllowedScopes = []string{"profile", "email", "offline_access", "roles", "organization"}
	}))
	require.NoError(t, err)

	t.Run("a scope the IdP knows reaches it", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"organization"}, nil))

		assert.Contains(t, scopes, "organization")
	})

	// A configured scope outside the mandatory set (providers.CopyScopes) only
	// reaches the IdP when the client requests no scopes of its own.
	t.Run("a configured scope reaches a request that names none", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", nil, nil))

		assert.Contains(t, scopes, "roles")
	})

	t.Run("a scope outside the list is dropped", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"groups", "federated:id"}, nil))

		assert.NotContains(t, scopes, "groups")
		assert.NotContains(t, scopes, "federated:id")
	})

	t.Run("openid survives a list that omits it", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", nil, nil))

		assert.Contains(t, scopes, "openid")
	})

	t.Run("an invalid list is rejected at construction", func(t *testing.T) {
		_, err := NewProvider(testConfig(server, func(cfg *Config) {
			cfg.AllowedScopes = []string{"openid", ""}
		}))

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid allowed scopes")
	})
}

func TestDisableScopeFilter(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	t.Run("every requested scope reaches the IdP", func(t *testing.T) {
		provider, err := NewProvider(testConfig(server, func(cfg *Config) {
			cfg.DisableScopeFilter = true
		}))
		require.NoError(t, err)

		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"claudeai", "urn:example:scope"}, nil))

		assert.Contains(t, scopes, "claudeai")
		assert.Contains(t, scopes, "urn:example:scope")
		assert.Contains(t, scopes, "openid")
	})

	t.Run("an allowlist alongside it is rejected at construction", func(t *testing.T) {
		_, err := NewProvider(testConfig(server, func(cfg *Config) {
			cfg.DisableScopeFilter = true
			cfg.AllowedScopes = []string{"openid", "email"}
		}))

		require.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("audience scopes are still dropped when they are disabled", func(t *testing.T) {
		provider, err := NewProvider(testConfig(server, func(cfg *Config) {
			cfg.DisableScopeFilter = true
			cfg.DisableCrossClientAudienceScopes = true
		}))
		require.NoError(t, err)

		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"claudeai", k8sAudienceScope}, nil))

		assert.Contains(t, scopes, "claudeai")
		assert.NotContains(t, scopes, k8sAudienceScope)
	})
}

// TestDisableCrossClientAudienceScopes covers the invariant an issuer that is
// not Dex depends on: no audience:server:client_id: scope reaches it, whichever
// path put the scope in the set.
func TestDisableCrossClientAudienceScopes(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	resolverCalls := 0
	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.Scopes = []string{"openid", "email", k8sAudienceScope}
		cfg.DisableCrossClientAudienceScopes = true
		cfg.AudienceResolver = func() []string {
			resolverCalls++
			return []string{"late-client"}
		}
	}))
	require.NoError(t, err)

	t.Run("a configured audience scope is dropped from the defaults", func(t *testing.T) {
		assert.Equal(t, []string{"openid", "email"}, provider.DefaultScopes())
	})

	t.Run("the resolver never runs", func(t *testing.T) {
		provider.AuthorizationURL("state", "", "", nil, nil)

		assert.Zero(t, resolverCalls)
	})

	t.Run("a requested audience scope is dropped", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"openid", AudienceScopePrefix + "other-client"}, nil))

		for _, scope := range scopes {
			assert.False(t, strings.HasPrefix(scope, AudienceScopePrefix), "unexpected audience scope %q", scope)
		}
		assert.Contains(t, scopes, "openid")
	})
}

func TestExportedScopeDefaults(t *testing.T) {
	t.Run("DefaultScopes returns the built-in requested set", func(t *testing.T) {
		assert.Equal(t, []string{"openid", "profile", "email", "groups", "offline_access"}, DefaultScopes())
	})

	t.Run("DefaultAllowedScopes returns the built-in allowlist", func(t *testing.T) {
		assert.Equal(t, []string{"openid", "profile", "email", "offline_access", "groups", "federated:id"}, DefaultAllowedScopes())
	})

	t.Run("each call returns a fresh slice", func(t *testing.T) {
		DefaultScopes()[0] = "mutated"
		DefaultAllowedScopes()[0] = "mutated"

		assert.Equal(t, "openid", DefaultScopes()[0])
		assert.Equal(t, "openid", DefaultAllowedScopes()[0])
	})
}
