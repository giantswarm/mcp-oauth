package providers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUserInfo_IsSSO tests the IsSSO helper method.
func TestUserInfo_IsSSO(t *testing.T) {
	tests := []struct {
		name        string
		tokenSource TokenSource
		expected    bool
	}{
		{
			name:        "SSO token source returns true",
			tokenSource: TokenSourceSSO,
			expected:    true,
		},
		{
			name:        "OAuth token source returns false",
			tokenSource: TokenSourceOAuth,
			expected:    false,
		},
		{
			name:        "empty token source returns false",
			tokenSource: "",
			expected:    false,
		},
		{
			name:        "unknown token source returns false",
			tokenSource: "unknown",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserInfo{
				ID:          "test-user",
				TokenSource: tt.tokenSource,
			}

			got := u.IsSSO()
			if got != tt.expected {
				t.Errorf("IsSSO() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestUserInfo_IsOAuth tests the IsOAuth helper method.
func TestUserInfo_IsOAuth(t *testing.T) {
	tests := []struct {
		name        string
		tokenSource TokenSource
		expected    bool
	}{
		{
			name:        "OAuth token source returns true",
			tokenSource: TokenSourceOAuth,
			expected:    true,
		},
		{
			name:        "empty token source returns true (backward compatibility)",
			tokenSource: "",
			expected:    true,
		},
		{
			name:        "SSO token source returns false",
			tokenSource: TokenSourceSSO,
			expected:    false,
		},
		{
			name:        "unknown token source returns false",
			tokenSource: "unknown",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserInfo{
				ID:          "test-user",
				TokenSource: tt.tokenSource,
			}

			got := u.IsOAuth()
			if got != tt.expected {
				t.Errorf("IsOAuth() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestTokenSource_Constants verifies the token source constants.
func TestTokenSource_Constants(t *testing.T) {
	// Verify constant values are as expected
	if TokenSourceOAuth != "oauth" {
		t.Errorf("TokenSourceOAuth = %q, want %q", TokenSourceOAuth, "oauth")
	}
	if TokenSourceSSO != "sso" {
		t.Errorf("TokenSourceSSO = %q, want %q", TokenSourceSSO, "sso")
	}
}

// TestUserInfo_TokenSourceMutuallyExclusive verifies that IsSSO and IsOAuth are mutually exclusive.
func TestUserInfo_TokenSourceMutuallyExclusive(t *testing.T) {
	// SSO source: IsSSO=true, IsOAuth=false
	ssoUser := &UserInfo{TokenSource: TokenSourceSSO}
	if !ssoUser.IsSSO() || ssoUser.IsOAuth() {
		t.Error("SSO user should have IsSSO=true and IsOAuth=false")
	}

	// OAuth source: IsSSO=false, IsOAuth=true
	oauthUser := &UserInfo{TokenSource: TokenSourceOAuth}
	if oauthUser.IsSSO() || !oauthUser.IsOAuth() {
		t.Error("OAuth user should have IsSSO=false and IsOAuth=true")
	}

	// Empty source (backward compat): treated as OAuth
	emptyUser := &UserInfo{TokenSource: ""}
	if emptyUser.IsSSO() || !emptyUser.IsOAuth() {
		t.Error("Empty token source should be treated as OAuth for backward compatibility")
	}
}

// TestUserInfo_NilReceiver verifies that nil UserInfo is handled safely.
func TestUserInfo_NilReceiver(t *testing.T) {
	var nilUser *UserInfo

	t.Run("IsSSO returns false for nil receiver", func(t *testing.T) {
		if nilUser.IsSSO() {
			t.Error("IsSSO() should return false for nil receiver")
		}
	})

	t.Run("IsOAuth returns true for nil receiver (safe default)", func(t *testing.T) {
		if !nilUser.IsOAuth() {
			t.Error("IsOAuth() should return true for nil receiver as safe default")
		}
	})
}

// TestApplyAuthorizationURLOptions tests the ApplyAuthorizationURLOptions helper.
func TestApplyAuthorizationURLOptions(t *testing.T) {
	t.Run("nil options returns nil", func(t *testing.T) {
		result := ApplyAuthorizationURLOptions(nil)
		if result != nil {
			t.Errorf("ApplyAuthorizationURLOptions(nil) = %v, want nil", result)
		}
	})

	t.Run("empty options returns empty slice", func(t *testing.T) {
		result := ApplyAuthorizationURLOptions(&AuthorizationURLOptions{})
		if len(result) != 0 {
			t.Errorf("ApplyAuthorizationURLOptions(&AuthorizationURLOptions{}) returned %d options, want 0", len(result))
		}
	})

	t.Run("prompt option", func(t *testing.T) {
		opts := &AuthorizationURLOptions{Prompt: "none"}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("login_hint option", func(t *testing.T) {
		opts := &AuthorizationURLOptions{LoginHint: "user@example.com"}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("max_age option", func(t *testing.T) {
		maxAge := 3600
		opts := &AuthorizationURLOptions{MaxAge: &maxAge}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("acr_values option", func(t *testing.T) {
		opts := &AuthorizationURLOptions{ACRValues: "urn:mace:incommon:iap:silver"}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("id_token_hint option", func(t *testing.T) {
		opts := &AuthorizationURLOptions{IDTokenHint: "eyJhbGciOiJSUzI1NiJ9..."}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 1 {
			t.Errorf("expected 1 option, got %d", len(result))
		}
	})

	t.Run("extra parameters", func(t *testing.T) {
		opts := &AuthorizationURLOptions{
			Extra: map[string]string{
				"hd":         "example.com",
				"nonce":      "abc123",
				"ui_locales": "en",
			},
		}
		result := ApplyAuthorizationURLOptions(opts)
		if len(result) != 3 {
			t.Errorf("expected 3 options for 3 extra params, got %d", len(result))
		}
	})

	t.Run("all options combined", func(t *testing.T) {
		maxAge := 0
		opts := &AuthorizationURLOptions{
			Prompt:      "none",
			LoginHint:   "user@example.com",
			MaxAge:      &maxAge,
			ACRValues:   "urn:mace:incommon:iap:silver",
			IDTokenHint: "previous-token",
			Extra: map[string]string{
				"hd": "example.com",
			},
		}
		result := ApplyAuthorizationURLOptions(opts)
		// 5 standard options + 1 extra = 6
		if len(result) != 6 {
			t.Errorf("expected 6 options, got %d", len(result))
		}
	})
}

// Test scope values (avoid goconst warnings)
const (
	testScopeOpenID  = "openid"
	testScopeEmail   = "email"
	testScopeProfile = "profile"
)

// TestCopyScopes tests the CopyScopes helper.
func TestCopyScopes(t *testing.T) {
	t.Run("uses requested scopes and merges mandatory defaults", func(t *testing.T) {
		requested := []string{testScopeOpenID, testScopeEmail}
		defaults := []string{testScopeOpenID, testScopeProfile, testScopeEmail}

		result := CopyScopes(requested, defaults)

		// requested has openid + email; profile is mandatory from defaults
		if len(result) != 3 {
			t.Errorf("expected 3 scopes, got %d: %v", len(result), result)
		}
		if result[0] != testScopeOpenID {
			t.Errorf("expected first scope to be %q, got %q", testScopeOpenID, result[0])
		}
		if result[1] != testScopeEmail {
			t.Errorf("expected second scope to be %q, got %q", testScopeEmail, result[1])
		}
		if result[2] != testScopeProfile {
			t.Errorf("expected third scope to be %q, got %q", testScopeProfile, result[2])
		}
	})

	t.Run("uses default scopes when requested is empty", func(t *testing.T) {
		var requested []string
		defaults := []string{testScopeOpenID, testScopeProfile, testScopeEmail}

		result := CopyScopes(requested, defaults)

		if len(result) != 3 {
			t.Errorf("expected 3 scopes, got %d", len(result))
		}
	})

	t.Run("uses default scopes when requested is nil", func(t *testing.T) {
		defaults := []string{testScopeOpenID, testScopeProfile}

		result := CopyScopes(nil, defaults)

		if len(result) != 2 {
			t.Errorf("expected 2 scopes, got %d", len(result))
		}
	})

	t.Run("returns empty when both are empty", func(t *testing.T) {
		result := CopyScopes(nil, nil)

		if len(result) != 0 {
			t.Errorf("expected 0 scopes, got %d", len(result))
		}
	})

	t.Run("creates deep copy - modifying input doesn't affect result", func(t *testing.T) {
		requested := []string{testScopeOpenID, testScopeEmail}
		defaults := []string{testScopeOpenID, testScopeProfile}

		result := CopyScopes(requested, defaults)

		// Modify input
		requested[0] = "MODIFIED"

		// Result should be unaffected
		if result[0] != testScopeOpenID {
			t.Errorf("result was modified when input changed: %v", result)
		}
	})

	t.Run("creates deep copy - modifying result doesn't affect input", func(t *testing.T) {
		requested := []string{testScopeOpenID, testScopeEmail}
		defaults := []string{testScopeOpenID, testScopeProfile}

		result := CopyScopes(requested, defaults)

		// Modify result
		result[0] = "MODIFIED"

		// Input should be unaffected
		if requested[0] != testScopeOpenID {
			t.Errorf("input was modified when result changed: %v", requested)
		}
	})

	t.Run("merges cross-client audience scopes from defaults", func(t *testing.T) {
		requested := []string{testScopeOpenID, testScopeEmail}
		defaults := []string{
			testScopeOpenID,
			testScopeProfile,
			"audience:server:client_id:dex-k8s-authenticator",
		}

		result := CopyScopes(requested, defaults)

		// requested has openid + email; profile and audience are mandatory from defaults
		if len(result) != 4 {
			t.Errorf("expected 4 scopes, got %d: %v", len(result), result)
		}

		foundAudience := false
		foundProfile := false
		for _, s := range result {
			if s == "audience:server:client_id:dex-k8s-authenticator" {
				foundAudience = true
			}
			if s == testScopeProfile {
				foundProfile = true
			}
		}
		if !foundAudience {
			t.Errorf("audience scope not merged: %v", result)
		}
		if !foundProfile {
			t.Errorf("profile scope not merged: %v", result)
		}
	})

	t.Run("merges multiple cross-client audience scopes", func(t *testing.T) {
		requested := []string{testScopeOpenID}
		defaults := []string{
			testScopeOpenID,
			"audience:server:client_id:k8s-auth",
			"audience:server:client_id:api-gateway",
		}

		result := CopyScopes(requested, defaults)

		// Should have 1 requested + 2 audience scopes = 3
		if len(result) != 3 {
			t.Errorf("expected 3 scopes, got %d: %v", len(result), result)
		}
	})

	t.Run("does not duplicate audience scopes already in requested", func(t *testing.T) {
		audienceScope := "audience:server:client_id:dex-k8s-authenticator"
		requested := []string{testScopeOpenID, audienceScope}
		defaults := []string{testScopeOpenID, testScopeProfile, audienceScope}

		result := CopyScopes(requested, defaults)

		// openid + audience (from requested) + profile (mandatory from defaults) = 3
		if len(result) != 3 {
			t.Errorf("expected 3 scopes, got %d: %v", len(result), result)
		}

		audienceCount := 0
		for _, s := range result {
			if s == audienceScope {
				audienceCount++
			}
		}
		if audienceCount != 1 {
			t.Errorf("expected exactly 1 audience scope, got %d in: %v", audienceCount, result)
		}
	})

	t.Run("merges identity scopes from defaults", func(t *testing.T) {
		requested := []string{testScopeOpenID}
		defaults := []string{testScopeOpenID, testScopeProfile, testScopeEmail}

		result := CopyScopes(requested, defaults)

		if len(result) != 3 {
			t.Errorf("expected 3 scopes, got %d: %v", len(result), result)
		}
		if result[0] != testScopeOpenID {
			t.Errorf("expected first scope to be %q, got %q", testScopeOpenID, result[0])
		}
		if result[1] != testScopeProfile {
			t.Errorf("expected second scope to be %q, got %q", testScopeProfile, result[1])
		}
		if result[2] != testScopeEmail {
			t.Errorf("expected third scope to be %q, got %q", testScopeEmail, result[2])
		}
	})

	t.Run("uses all defaults when requested is empty including audience scopes", func(t *testing.T) {
		var requested []string
		defaults := []string{
			testScopeOpenID,
			testScopeProfile,
			"audience:server:client_id:dex-k8s-authenticator",
		}

		result := CopyScopes(requested, defaults)

		if len(result) != 3 {
			t.Errorf("expected 3 scopes, got %d: %v", len(result), result)
		}
	})

	t.Run("preserves order with requested scopes first then mandatory scopes", func(t *testing.T) {
		requested := []string{testScopeEmail, testScopeOpenID}
		defaults := []string{
			testScopeOpenID,
			"audience:server:client_id:first-client",
			testScopeProfile,
			"audience:server:client_id:second-client",
		}

		result := CopyScopes(requested, defaults)

		// Should have 5 scopes: 2 requested + 2 audience + 1 profile (mandatory, not in requested)
		if len(result) != 5 {
			t.Errorf("expected 5 scopes, got %d: %v", len(result), result)
		}

		if result[0] != testScopeEmail {
			t.Errorf("expected first scope to be %q, got %q", testScopeEmail, result[0])
		}
		if result[1] != testScopeOpenID {
			t.Errorf("expected second scope to be %q, got %q", testScopeOpenID, result[1])
		}
		if result[2] != "audience:server:client_id:first-client" {
			t.Errorf("expected third scope to be audience:server:client_id:first-client, got %q", result[2])
		}
		if result[3] != testScopeProfile {
			t.Errorf("expected fourth scope to be %q, got %q", testScopeProfile, result[3])
		}
		if result[4] != "audience:server:client_id:second-client" {
			t.Errorf("expected fifth scope to be audience:server:client_id:second-client, got %q", result[4])
		}
	})

	t.Run("merges all mandatory scopes from defaults when client omits them", func(t *testing.T) {
		requested := []string{"claudeai"}
		defaults := []string{testScopeOpenID, testScopeProfile, testScopeEmail}

		result := CopyScopes(requested, defaults)

		if len(result) != 4 {
			t.Errorf("expected 4 scopes, got %d: %v", len(result), result)
		}
		if result[0] != "claudeai" {
			t.Errorf("expected first scope to be %q, got %q", "claudeai", result[0])
		}
		if result[1] != testScopeOpenID {
			t.Errorf("expected second scope to be %q, got %q", testScopeOpenID, result[1])
		}
		if result[2] != testScopeProfile {
			t.Errorf("expected third scope to be %q, got %q", testScopeProfile, result[2])
		}
		if result[3] != testScopeEmail {
			t.Errorf("expected fourth scope to be %q, got %q", testScopeEmail, result[3])
		}
	})

	t.Run("does not duplicate openid when already in requested", func(t *testing.T) {
		requested := []string{testScopeOpenID, testScopeEmail}
		defaults := []string{testScopeOpenID, testScopeProfile}

		result := CopyScopes(requested, defaults)

		// openid + email (from requested) + profile (mandatory from defaults) = 3
		if len(result) != 3 {
			t.Errorf("expected 3 scopes, got %d: %v", len(result), result)
		}

		openidCount := 0
		for _, s := range result {
			if s == testScopeOpenID {
				openidCount++
			}
		}
		if openidCount != 1 {
			t.Errorf("expected exactly 1 openid scope, got %d in: %v", openidCount, result)
		}
	})

	t.Run("exact bug scenario: claudeai with full dex defaults", func(t *testing.T) {
		requested := []string{"claudeai"}
		defaults := []string{
			testScopeOpenID,
			testScopeProfile,
			testScopeEmail,
			"groups",
			"offline_access",
			"audience:server:client_id:dex-k8s-authenticator",
		}

		result := CopyScopes(requested, defaults)

		expected := []string{
			"claudeai",
			testScopeOpenID,
			testScopeProfile,
			testScopeEmail,
			"groups",
			"offline_access",
			"audience:server:client_id:dex-k8s-authenticator",
		}
		if len(result) != len(expected) {
			t.Fatalf("expected %d scopes, got %d: %v", len(expected), len(result), result)
		}
		for i, s := range expected {
			if result[i] != s {
				t.Errorf("scope[%d] = %q, want %q", i, result[i], s)
			}
		}
	})

	t.Run("does not inject mandatory scopes when not in defaults", func(t *testing.T) {
		requested := []string{"custom:scope"}
		defaults := []string{"federated:id"}

		result := CopyScopes(requested, defaults)

		if len(result) != 1 {
			t.Errorf("expected 1 scope, got %d: %v", len(result), result)
		}
		if result[0] != "custom:scope" {
			t.Errorf("unexpected scope: %v", result)
		}
	})

	t.Run("does not merge non-mandatory scopes from defaults", func(t *testing.T) {
		requested := []string{testScopeOpenID}
		defaults := []string{testScopeOpenID, "federated:id", "custom:admin"}

		result := CopyScopes(requested, defaults)

		if len(result) != 1 {
			t.Errorf("expected 1 scope, got %d: %v", len(result), result)
		}
		if result[0] != testScopeOpenID {
			t.Errorf("unexpected scope: %v", result)
		}
	})

	t.Run("merges all mandatory and audience scopes", func(t *testing.T) {
		requested := []string{"claudeai"}
		defaults := []string{
			testScopeOpenID,
			testScopeProfile,
			"audience:server:client_id:k8s-auth",
		}

		result := CopyScopes(requested, defaults)

		if len(result) != 4 {
			t.Errorf("expected 4 scopes, got %d: %v", len(result), result)
		}
		if result[0] != "claudeai" {
			t.Errorf("expected first scope to be %q, got %q", "claudeai", result[0])
		}
		if result[1] != testScopeOpenID {
			t.Errorf("expected second scope to be %q, got %q", testScopeOpenID, result[1])
		}
		if result[2] != testScopeProfile {
			t.Errorf("expected third scope to be %q, got %q", testScopeProfile, result[2])
		}
		if result[3] != "audience:server:client_id:k8s-auth" {
			t.Errorf("expected fourth scope to be audience scope, got %q", result[3])
		}
	})
}

func TestIsMandatoryScope(t *testing.T) {
	tests := []struct {
		scope    string
		expected bool
	}{
		{"openid", true},
		{"email", true},
		{"profile", true},
		{"groups", true},
		{"offline_access", true},
		{"audience:server:client_id:k8s-auth", true},
		{"audience:server:client_id:", true},
		{"claudeai", false},
		{"custom:scope", false},
		{"federated:id", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			if got := isMandatoryScope(tt.scope); got != tt.expected {
				t.Errorf("isMandatoryScope(%q) = %v, want %v", tt.scope, got, tt.expected)
			}
		})
	}
}

// TestAuthorizationURLOptions_Struct tests the AuthorizationURLOptions struct.
func TestAuthorizationURLOptions_Struct(t *testing.T) {
	t.Run("zero value is usable", func(t *testing.T) {
		opts := AuthorizationURLOptions{}
		if opts.Prompt != "" {
			t.Error("zero value Prompt should be empty")
		}
		if opts.LoginHint != "" {
			t.Error("zero value LoginHint should be empty")
		}
		if opts.MaxAge != nil {
			t.Error("zero value MaxAge should be nil")
		}
		if opts.ACRValues != "" {
			t.Error("zero value ACRValues should be empty")
		}
		if opts.IDTokenHint != "" {
			t.Error("zero value IDTokenHint should be empty")
		}
		if opts.Extra != nil {
			t.Error("zero value Extra should be nil")
		}
	})

	t.Run("all fields can be set", func(t *testing.T) {
		maxAge := 3600
		opts := AuthorizationURLOptions{
			Prompt:      "none",
			LoginHint:   "user@example.com",
			MaxAge:      &maxAge,
			ACRValues:   "urn:mace:incommon:iap:silver",
			IDTokenHint: "eyJhbGciOiJSUzI1NiJ9...",
			Extra: map[string]string{
				"hd": "example.com",
			},
		}

		if opts.Prompt != "none" {
			t.Errorf("Prompt = %q, want %q", opts.Prompt, "none")
		}
		if opts.LoginHint != "user@example.com" {
			t.Errorf("LoginHint = %q, want %q", opts.LoginHint, "user@example.com")
		}
		if *opts.MaxAge != 3600 {
			t.Errorf("MaxAge = %d, want %d", *opts.MaxAge, 3600)
		}
		if opts.ACRValues != "urn:mace:incommon:iap:silver" {
			t.Errorf("ACRValues = %q, want %q", opts.ACRValues, "urn:mace:incommon:iap:silver")
		}
		if opts.Extra["hd"] != "example.com" {
			t.Errorf("Extra[hd] = %q, want %q", opts.Extra["hd"], "example.com")
		}
	})
}

func TestUserInfo_IsM2M(t *testing.T) {
	tests := []struct {
		name     string
		info     *UserInfo
		expected bool
	}{
		{name: "nil receiver", info: nil, expected: false},
		{name: "m2m", info: &UserInfo{TokenSource: TokenSourceM2M}, expected: true},
		{name: "obo", info: &UserInfo{TokenSource: TokenSourceOBO, ActorSubject: "agent@k8s"}, expected: false},
		{name: "sso", info: &UserInfo{TokenSource: TokenSourceSSO}, expected: false},
		{name: "oauth", info: &UserInfo{TokenSource: TokenSourceOAuth}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.info.IsM2M())
		})
	}
}

func TestUserInfo_IsOBO(t *testing.T) {
	tests := []struct {
		name     string
		info     *UserInfo
		expected bool
	}{
		{name: "nil receiver", info: nil, expected: false},
		{name: "obo", info: &UserInfo{TokenSource: TokenSourceOBO, ActorSubject: "agent@k8s"}, expected: true},
		{name: "m2m", info: &UserInfo{TokenSource: TokenSourceM2M}, expected: false},
		{name: "sso with act claim", info: &UserInfo{TokenSource: TokenSourceSSO, ActorSubject: "agent@k8s"}, expected: false},
		{name: "oauth", info: &UserInfo{TokenSource: TokenSourceOAuth}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.info.IsOBO())
		})
	}
}

func TestUserInfo_IsExternalIssuer(t *testing.T) {
	tests := []struct {
		name     string
		info     *UserInfo
		expected bool
	}{
		{name: "nil receiver", info: nil, expected: false},
		{name: "m2m", info: &UserInfo{TokenSource: TokenSourceM2M}, expected: true},
		{name: "obo", info: &UserInfo{TokenSource: TokenSourceOBO, ActorSubject: "agent@k8s"}, expected: true},
		{name: "sso", info: &UserInfo{TokenSource: TokenSourceSSO}, expected: false},
		{name: "oauth", info: &UserInfo{TokenSource: TokenSourceOAuth}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, tt.info.IsExternalIssuer())
		})
	}
}
