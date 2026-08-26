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

	// Without MandatoryScopes, a configured scope outside the built-in
	// mandatory set reaches the IdP only for a client that names no scopes.
	t.Run("a configured scope outside the built-in mandatory set is not merged", func(t *testing.T) {
		explicit := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"organization"}, nil))
		implicit := authURLScopes(t, provider.AuthorizationURL("state", "", "", nil, nil))

		assert.NotContains(t, explicit, "roles")
		assert.Contains(t, implicit, "roles")
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

// TestMandatoryScopes covers the set the provider merges into a request that
// names scopes of its own, which is where an IdP vocabulary outside the
// built-in mandatory set would otherwise be dropped.
func TestMandatoryScopes(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	// A Keycloak realm again: roles must survive a client that names one scope.
	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.Scopes = []string{"openid", "profile", "email", "offline_access", "roles", "organization"}
		cfg.AllowedScopes = []string{"profile", "email", "offline_access", "roles", "organization"}
		cfg.MandatoryScopes = []string{"email", "offline_access", "roles"}
	}))
	require.NoError(t, err)

	scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"profile"}, nil))

	t.Run("a mandatory scope is merged", func(t *testing.T) {
		assert.Contains(t, scopes, "roles")
		assert.Contains(t, scopes, "email")
		assert.Contains(t, scopes, "offline_access")
	})

	t.Run("a configured scope outside the set is not merged", func(t *testing.T) {
		assert.NotContains(t, scopes, "organization")
	})

	t.Run("openid is merged whatever the set holds", func(t *testing.T) {
		assert.Contains(t, scopes, "openid")
	})

	t.Run("the requested scope survives", func(t *testing.T) {
		assert.Contains(t, scopes, "profile")
	})

	t.Run("an audience scope is merged whatever the set holds", func(t *testing.T) {
		provider, err := NewProvider(testConfig(server, func(cfg *Config) {
			cfg.Scopes = []string{"openid", "email", k8sAudienceScope}
			cfg.MandatoryScopes = []string{"email"}
		}))
		require.NoError(t, err)

		assert.Contains(t, authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"profile"}, nil)), k8sAudienceScope)
	})

	t.Run("an invalid set is rejected at construction", func(t *testing.T) {
		_, err := NewProvider(testConfig(server, func(cfg *Config) {
			cfg.MandatoryScopes = []string{"email", ""}
		}))

		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid mandatory scopes")
	})
}
