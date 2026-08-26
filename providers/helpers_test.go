package providers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEnsureTimeout_AddsDeadlineWhenAbsent(t *testing.T) {
	ctx, cancel := EnsureTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	deadline, ok := ctx.Deadline()
	require.True(t, ok, "EnsureTimeout must add a deadline when none exists")
	require.WithinDuration(t, time.Now().Add(50*time.Millisecond), deadline, 5*time.Millisecond)
}

func TestEnsureTimeout_RespectsExistingDeadline(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	ctx, noop := EnsureTimeout(parent, time.Hour)
	defer noop()
	require.Equal(t, parent, ctx, "EnsureTimeout must return the parent context when it has a deadline")
}

func TestCloneScopes(t *testing.T) {
	orig := []string{"openid", "email"}
	clone := CloneScopes(orig)
	require.Equal(t, orig, clone)
	clone[0] = "mutated"
	require.NotEqual(t, orig[0], clone[0], "callers must not be able to mutate the source slice")

	require.Nil(t, CloneScopes(nil))
	require.Equal(t, []string{}, CloneScopes([]string{}))
}

func TestFilterScopes(t *testing.T) {
	defaults := []string{"openid", "email", "groups"}

	tests := []struct {
		name      string
		requested []string
		supported func(string) bool
		want      []string
	}{
		{
			name:      "nil predicate accepts every scope",
			requested: []string{"openid", "custom"},
			supported: nil,
			want:      []string{"openid", "custom", "email", "groups"},
		},
		{
			name:      "predicate drops unsupported scopes after the mandatory-merge",
			requested: []string{"claudeai"},
			supported: func(s string) bool { return !strings.HasPrefix(s, "claude") },
			want:      []string{"openid", "email", "groups"},
		},
		{
			name:      "empty requested falls back to defaults filtered",
			requested: nil,
			supported: func(s string) bool { return s != "groups" },
			want:      []string{"openid", "email"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, FilterScopes(tt.requested, defaults, tt.supported))
		})
	}
}

func TestFilterScopesFunc(t *testing.T) {
	defaults := []string{"openid", "email", "roles", "organization"}

	t.Run("a nil mandatory predicate applies the built-in set", func(t *testing.T) {
		result := FilterScopesFunc([]string{"profile"}, defaults, nil, nil)

		require.Equal(t, FilterScopes([]string{"profile"}, defaults, nil), result)
		require.Contains(t, result, "email")
		require.NotContains(t, result, "roles")
	})

	t.Run("a mandatory predicate replaces the built-in set", func(t *testing.T) {
		mandatory := func(scope string) bool { return scope == "roles" }

		result := FilterScopesFunc([]string{"profile"}, defaults, nil, mandatory)

		require.Equal(t, []string{"profile", "roles"}, result)
	})

	t.Run("the supported predicate still applies", func(t *testing.T) {
		mandatory := func(scope string) bool { return scope == "roles" }
		supported := func(scope string) bool { return scope != "roles" }

		result := FilterScopesFunc([]string{"profile"}, defaults, supported, mandatory)

		require.Equal(t, []string{"profile"}, result)
	})
}
