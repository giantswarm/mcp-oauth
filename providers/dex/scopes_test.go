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

	t.Run("a scope the configuration does not name is dropped", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"openid", "claudeai", "federated:id"}, nil))

		assert.NotContains(t, scopes, "claudeai")
		assert.NotContains(t, scopes, "federated:id")
		assert.Contains(t, scopes, "groups")
	})

	t.Run("a cross-client audience scope survives", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"openid", k8sAudienceScope}, nil))

		assert.Contains(t, scopes, k8sAudienceScope)
	})
}

// TestConfiguredScopesAreAlwaysSent covers the reason a separate mandatory set
// is not needed: the provider consumes email and groups itself, so a client
// cannot narrow the configured set by naming scopes of its own.
func TestConfiguredScopesAreAlwaysSent(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	// A Keycloak realm: no groups scope, but roles exists.
	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.Scopes = []string{"openid", "profile", "email", "offline_access", "roles"}
	}))
	require.NoError(t, err)

	scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"profile"}, nil))

	t.Run("a configured scope outside the Dex vocabulary is sent", func(t *testing.T) {
		assert.Contains(t, scopes, "roles")
	})

	t.Run("the rest of the configured set is sent", func(t *testing.T) {
		assert.Contains(t, scopes, "email")
		assert.Contains(t, scopes, "offline_access")
		assert.Contains(t, scopes, "openid")
	})

	t.Run("a scope the configuration does not name is dropped", func(t *testing.T) {
		narrowed := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"groups", "federated:id"}, nil))

		assert.NotContains(t, narrowed, "groups")
		assert.NotContains(t, narrowed, "federated:id")
	})
}

// TestConfiguredScopesAreTheOnlyWayIn pins the rule that replaced the old
// allowlist: a scope reaches the IdP because Config.Scopes names it, never
// because a client asked for it.
func TestConfiguredScopesAreTheOnlyWayIn(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	provider, err := NewProvider(testConfig(server, func(cfg *Config) {
		cfg.Scopes = []string{"openid", "email", "federated:id"}
	}))
	require.NoError(t, err)

	t.Run("a configured Dex-only scope is sent to every client", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"email"}, nil))

		assert.Contains(t, scopes, "federated:id")
	})

	t.Run("a scope the configuration drops cannot be requested back", func(t *testing.T) {
		scopes := authURLScopes(t, provider.AuthorizationURL("state", "", "", []string{"profile", "groups"}, nil))

		assert.NotContains(t, scopes, "profile")
		assert.NotContains(t, scopes, "groups")
	})

	t.Run("openid is sent whatever the configuration holds", func(t *testing.T) {
		other, err := NewProvider(testConfig(server, func(cfg *Config) {
			cfg.Scopes = []string{"email"}
		}))
		require.NoError(t, err)

		assert.Contains(t, authURLScopes(t, other.AuthorizationURL("state", "", "", []string{"email"}, nil)), "openid")
	})
}

// TestDefaultScopesMatchWhatIsForwarded pins the invariant the server depends
// on. server.resolveScopes turns DefaultScopes() into the granted scope string
// for a client that names none, so a scope reported here but dropped by the
// filter would be recorded as granted while the IdP never received it.
func TestDefaultScopesMatchWhatIsForwarded(t *testing.T) {
	server := setupMockDexServer(t)
	defer server.Close()

	configs := map[string]func(*Config){
		"defaults": func(*Config) {},
		"a Keycloak vocabulary": func(cfg *Config) {
			cfg.Scopes = []string{"openid", "profile", "email", "offline_access", "roles"}
			cfg.DisableCrossClientAudienceScopes = true
		},
		"a configured audience scope": func(cfg *Config) {
			cfg.Scopes = []string{"openid", "email", k8sAudienceScope}
		},
		"a configured audience scope with audience scopes disabled": func(cfg *Config) {
			cfg.Scopes = []string{"openid", "email", k8sAudienceScope}
			cfg.DisableCrossClientAudienceScopes = true
		},
	}

	for name, option := range configs {
		t.Run(name, func(t *testing.T) {
			provider, err := NewProvider(testConfig(server, option))
			require.NoError(t, err)

			defaults := provider.DefaultScopes()
			forwarded := authURLScopes(t, provider.AuthorizationURL("state", "", "", defaults, nil))

			for _, scope := range defaults {
				assert.Contains(t, forwarded, scope, "DefaultScopes() reports %q but the IdP never receives it", scope)
			}
		})
	}
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
